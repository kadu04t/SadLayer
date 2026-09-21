#define _GNU_SOURCE

#include "sadlayer/context.h"
#include "sadlayer/kernel32.h"
#include "sadlayer/module.h"
#include "sadlayer/module_space.h"
#include "sadlayer/process.h"
#include "sadlayer/teb.h"
#include "sadlayer/win64_unwind.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define IMAGE_SIZE 0x1000U
#define PDATA_RVA 0x100U
#define FUNCTION_BEGIN 0x400U
#define FUNCTION_END 0x480U

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            return false;                                                       \
        }                                                                      \
    } while (false)

typedef struct {
    _Alignas(16) uint8_t bytes[IMAGE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped;
    sl_module_registry registry;
    const sl_loaded_module *module;
} unwind_fixture;

typedef struct {
    uint8_t *bytes;
    sl_pe_image image;
    sl_mapped_image mapped;
    sl_module_registry registry;
    const sl_loaded_module *module;
} executable_unwind_fixture;

typedef struct {
    uint32_t flags;
    uint64_t establisher_frame;
    sl_win64_context context;
    sl_win64_dispatcher_context dispatcher;
    sl_win64_exception_record *exception_record;
    sl_win64_context *context_pointer;
} unwind_handler_observation;

static unwind_handler_observation unwind_observations[4];
static size_t unwind_observation_count;
static int32_t unwind_probe_disposition =
    SL_WIN64_EXCEPTION_DISPOSITION_CONTINUE_SEARCH;

extern void sl_test_capture_context_probe(sl_win64_context *context,
                                          uint64_t results[12]);

static void put_u16(uint8_t *destination, uint16_t value) {
    destination[0] = (uint8_t)(value & UINT16_C(0xff));
    destination[1] = (uint8_t)(value >> 8U);
}

static void put_u32(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)(value & UINT32_C(0xff));
    destination[1] = (uint8_t)((value >> 8U) & UINT32_C(0xff));
    destination[2] = (uint8_t)((value >> 16U) & UINT32_C(0xff));
    destination[3] = (uint8_t)(value >> 24U);
}

static void put_u64(uint8_t *destination, uint64_t value) {
    put_u32(destination, (uint32_t)value);
    put_u32(destination + 4U, (uint32_t)(value >> 32U));
}

static void put_runtime_function(uint8_t *destination, uint32_t begin,
                                 uint32_t end, uint32_t unwind_data) {
    put_u32(destination, begin);
    put_u32(destination + 4U, end);
    put_u32(destination + 8U, unwind_data);
}

static bool initialize_fixture(unwind_fixture *fixture, size_t entry_count) {
    memset(fixture, 0, sizeof(*fixture));
    fixture->image.machine = SL_PE_MACHINE_AMD64;
    fixture->image.is_pe32_plus = true;
    fixture->image.image_size = IMAGE_SIZE;
    fixture->image.directories[SL_PE_DIRECTORY_EXCEPTION].rva = PDATA_RVA;
    fixture->image.directories[SL_PE_DIRECTORY_EXCEPTION].size =
        (uint32_t)(entry_count * sizeof(sl_win64_runtime_function));
    fixture->mapped.bytes = fixture->bytes;
    fixture->mapped.size = sizeof(fixture->bytes);
    fixture->mapped.load_base = (uint64_t)(uintptr_t)fixture->bytes;
    memset(fixture->bytes + FUNCTION_BEGIN, 0x90,
           FUNCTION_END - FUNCTION_BEGIN);
    sl_module_registry_init(&fixture->registry);
    if (sl_module_registry_add(&fixture->registry, "Fixture.dll",
                               &fixture->image, &fixture->mapped) != SL_OK) {
        return false;
    }
    fixture->module =
        sl_module_registry_find(&fixture->registry, "Fixture.dll");
    return fixture->module != NULL;
}

static const sl_win64_runtime_function *runtime_entry(
    const unwind_fixture *fixture, size_t index) {
    return (const sl_win64_runtime_function *)(const void *)(
        fixture->bytes + PDATA_RVA +
        index * sizeof(sl_win64_runtime_function));
}

static sl_win64_stack_bounds stack_bounds(const void *limit,
                                          const void *base) {
    return (sl_win64_stack_bounds){
        .limit = (uint64_t)(uintptr_t)limit,
        .base = (uint64_t)(uintptr_t)base,
    };
}

static uintptr_t native_stack_pointer(void) {
    uintptr_t stack_pointer = 0U;
    __asm__ volatile("movq %%rsp, %0" : "=r"(stack_pointer));
    return stack_pointer;
}

static uintptr_t exception_routine_address(sl_win64_exception_routine routine) {
    uintptr_t address = 0U;
    _Static_assert(sizeof(routine) <= sizeof(address),
                   "exception routine pointer does not fit uintptr_t");
    memcpy(&address, &routine, sizeof(routine));
    return address;
}

static int32_t SL_WINAPI unwind_handler_probe(
    sl_win64_exception_record *exception_record, uint64_t establisher_frame,
    sl_win64_context *context_record,
    sl_win64_dispatcher_context *dispatcher_context) {
    if (unwind_observation_count <
        sizeof(unwind_observations) / sizeof(unwind_observations[0])) {
        unwind_handler_observation *observation =
            &unwind_observations[unwind_observation_count++];
        observation->flags = exception_record->exception_flags;
        observation->establisher_frame = establisher_frame;
        observation->context = *context_record;
        observation->dispatcher = *dispatcher_context;
        observation->exception_record = exception_record;
        observation->context_pointer = context_record;
    }
    return unwind_probe_disposition;
}

static bool initialize_executable_fixture(executable_unwind_fixture *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    fixture->bytes = mmap(NULL, IMAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fixture->bytes == MAP_FAILED) {
        fixture->bytes = NULL;
        return false;
    }
    fixture->image.machine = SL_PE_MACHINE_AMD64;
    fixture->image.is_pe32_plus = true;
    fixture->image.image_size = IMAGE_SIZE;
    fixture->image.directories[SL_PE_DIRECTORY_EXCEPTION].rva = PDATA_RVA;
    fixture->image.directories[SL_PE_DIRECTORY_EXCEPTION].size =
        2U * (uint32_t)sizeof(sl_win64_runtime_function);
    fixture->mapped.bytes = fixture->bytes;
    fixture->mapped.size = IMAGE_SIZE;
    fixture->mapped.load_base = (uint64_t)(uintptr_t)fixture->bytes;
    sl_module_registry_init(&fixture->registry);
    if (sl_module_registry_add(&fixture->registry, "ExecutableFixture.dll",
                               &fixture->image, &fixture->mapped) != SL_OK) {
        (void)munmap(fixture->bytes, IMAGE_SIZE);
        fixture->bytes = NULL;
        return false;
    }
    fixture->module =
        sl_module_registry_find(&fixture->registry, "ExecutableFixture.dll");
    if (fixture->module == NULL) {
        (void)munmap(fixture->bytes, IMAGE_SIZE);
        fixture->bytes = NULL;
        return false;
    }
    return true;
}

static bool install_unwind_handler_trampoline(
    executable_unwind_fixture *fixture, uint32_t rva) {
    sl_win64_exception_routine routine = unwind_handler_probe;
    uintptr_t target = 0U;
    _Static_assert(sizeof(routine) <= sizeof(target),
                   "exception routine pointer does not fit uintptr_t");
    memcpy(&target, &routine, sizeof(routine));
    uint8_t *code = fixture->bytes + rva;
    code[0] = 0xf3U;
    code[1] = 0x0fU;
    code[2] = 0x1eU;
    code[3] = 0xfaU; /* ENDBR64 for hosts enforcing indirect-branch tracking. */
    code[4] = 0x48U;
    code[5] = 0xb8U;
    put_u64(code + 6U, (uint64_t)target);
    code[14] = 0xffU;
    code[15] = 0xe0U;
    return mprotect(fixture->bytes, IMAGE_SIZE,
                    PROT_READ | PROT_EXEC) == 0;
}

static bool test_windows_layouts(void) {
    CHECK(sizeof(sl_win64_m128a) == 16U);
    CHECK(_Alignof(sl_win64_m128a) == 16U);
    CHECK(sizeof(sl_win64_xmm_save_area32) == 512U);
    CHECK(sizeof(sl_win64_context) == 0x4d0U);
    CHECK(_Alignof(sl_win64_context) == 16U);
    CHECK(offsetof(sl_win64_context, context_flags) == 0x30U);
    CHECK(offsetof(sl_win64_context, rax) == 0x78U);
    CHECK(offsetof(sl_win64_context, rsp) == 0x98U);
    CHECK(offsetof(sl_win64_context, rip) == 0xf8U);
    CHECK(offsetof(sl_win64_context, flt_save) == 0x100U);
    CHECK(sizeof(sl_win64_exception_record) == 0x98U);
    CHECK(offsetof(sl_win64_exception_record, number_parameters) == 0x18U);
    CHECK(offsetof(sl_win64_exception_record, exception_information) == 0x20U);
    CHECK(sizeof(sl_win64_exception_pointers) == 16U);
    CHECK(sizeof(sl_win64_runtime_function) == 12U);
    CHECK(sizeof(sl_win64_unwind_history_table) == 0xd8U);
    CHECK(offsetof(sl_win64_dispatcher_context, history_table) == 0x40U);
    CHECK(sizeof(sl_win64_dispatcher_context) == 0x50U);
    return true;
}

static sl_win64_exception_pointers *observed_exception_pointers;
static uint32_t filter_call_count;
static sl_win64_exception_record captured_raise_record;
static sl_win64_context captured_raise_context;

static int32_t SL_WINAPI continue_filter(
    sl_win64_exception_pointers *exception_pointers) {
    observed_exception_pointers = exception_pointers;
    ++filter_call_count;
    sl_kernel32_set_last_error(UINT32_C(0xaabbccdd));
    return SL_WIN64_EXCEPTION_CONTINUE_EXECUTION;
}

static int32_t SL_WINAPI search_filter(
    sl_win64_exception_pointers *exception_pointers) {
    observed_exception_pointers = exception_pointers;
    ++filter_call_count;
    return SL_WIN64_EXCEPTION_CONTINUE_SEARCH;
}

static int32_t SL_WINAPI capture_raise_filter(
    sl_win64_exception_pointers *exception_pointers) {
    captured_raise_record = *exception_pointers->exception_record;
    captured_raise_context = *exception_pointers->context_record;
    ++filter_call_count;
    return SL_WIN64_EXCEPTION_CONTINUE_EXECUTION;
}

static bool test_process_top_level_filter(void) {
    sl_win32_process *first_process = NULL;
    sl_win32_process *second_process = NULL;
    CHECK(sl_win32_process_create(&first_process) == SL_OK);
    CHECK(sl_win32_process_create(&second_process) == SL_OK);
    sl_win32_thread_context first_thread = {.process = first_process};
    sl_win32_thread_context second_thread = {.process = second_process};
    sl_win32_context_scope first_scope = {0};
    sl_win32_context_scope second_scope = {0};
    sl_win64_exception_record record = {0};
    sl_win64_context context = {0};
    sl_win64_exception_pointers pointers = {&record, &context};

    CHECK(sl_win32_context_enter(&first_thread, &first_scope) == SL_OK);
    sl_kernel32_set_last_error(UINT32_C(0x11223344));
    CHECK(sl_kernel32_set_unhandled_exception_filter(continue_filter) == NULL);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x11223344));
    CHECK(sl_kernel32_set_unhandled_exception_filter(search_filter) ==
          continue_filter);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x11223344));

    filter_call_count = 0U;
    observed_exception_pointers = NULL;
    CHECK(sl_kernel32_unhandled_exception_filter(&pointers) ==
          SL_WIN64_EXCEPTION_EXECUTE_HANDLER);
    CHECK(filter_call_count == 1U);
    CHECK(observed_exception_pointers == &pointers);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x11223344));

    CHECK(sl_win32_context_enter(&second_thread, &second_scope) == SL_OK);
    CHECK(sl_kernel32_set_unhandled_exception_filter(continue_filter) == NULL);
    observed_exception_pointers = NULL;
    CHECK(sl_kernel32_unhandled_exception_filter(&pointers) ==
          SL_WIN64_EXCEPTION_CONTINUE_EXECUTION);
    CHECK(observed_exception_pointers == &pointers);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xaabbccdd));
    CHECK(sl_win32_context_leave(&second_scope) == SL_OK);

    CHECK(sl_kernel32_set_unhandled_exception_filter(NULL) == search_filter);
    sl_kernel32_set_last_error(UINT32_C(0x55667788));
    CHECK(sl_kernel32_unhandled_exception_filter(&pointers) ==
          SL_WIN64_EXCEPTION_EXECUTE_HANDLER);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x55667788));
    CHECK(sl_win32_context_leave(&first_scope) == SL_OK);

    CHECK(sl_win32_process_unhandled_exception_filter(first_process) == 0U);
    CHECK(sl_win32_process_unhandled_exception_filter(second_process) != 0U);
    CHECK(sl_win32_process_destroy(second_process) == SL_OK);
    CHECK(sl_win32_process_destroy(first_process) == SL_OK);
    return true;
}

static bool test_capture_context_amd64(void) {
    _Alignas(16) sl_win64_context context;
    uint64_t results[12] = {0};
    memset(&context, 0xa5, sizeof(context));
    sl_test_capture_context_probe(&context, results);

    CHECK(context.context_flags == SL_WIN64_CONTEXT_CAPTURED);
    CHECK(context.rip == results[0]);
    CHECK(context.rsp == results[1]);
    CHECK(context.rcx == (uint64_t)(uintptr_t)&context);
    CHECK(context.rax == UINT64_C(0x456789abcdef0123));
    CHECK(context.rdx == UINT64_C(0x123456789abcdef0));
    CHECK(context.r8 == UINT64_C(0x23456789abcdef01));
    CHECK(context.r9 == UINT64_C(0x3456789abcdef012));
    CHECK(context.rbx == UINT64_C(0x1111111122222222));
    CHECK(context.rbp == UINT64_C(0x3333333344444444));
    CHECK(context.rsi == UINT64_C(0x5555555566666666));
    CHECK(context.rdi == UINT64_C(0x7777777788888888));
    CHECK(context.r12 == UINT64_C(0x99999999aaaaaaaa));
    CHECK(context.r13 == UINT64_C(0xbbbbbbbbcccccccc));
    CHECK(context.r14 == UINT64_C(0xddddddddeeeeeeee));
    CHECK(context.r15 == UINT64_C(0xf0f0f0f00f0f0f0f));
    CHECK(results[2] == context.rbx);
    CHECK(results[3] == context.rbp);
    CHECK(results[4] == context.rsi);
    CHECK(results[5] == context.rdi);
    CHECK(results[6] == context.r12);
    CHECK(results[7] == context.r13);
    CHECK(results[8] == context.r14);
    CHECK(results[9] == context.r15);
    CHECK(results[10] == UINT64_C(0x0123456789abcdef));
    CHECK(results[11] == UINT64_C(0xfedcba9876543210));
    CHECK(context.flt_save.xmm_registers[6].low == results[10]);
    CHECK((uint64_t)context.flt_save.xmm_registers[6].high == results[11]);
    CHECK(context.mx_csr == context.flt_save.mx_csr);
    CHECK(context.seg_cs != 0U && context.seg_ss != 0U);
    CHECK(context.e_flags != 0U);
    CHECK(context.p1_home == 0U && context.p6_home == 0U);
    CHECK(context.dr0 == 0U && context.dr7 == 0U);
    CHECK(context.vector_control == 0U);
    return true;
}

static bool test_raise_exception_top_level_dispatch(void) {
    sl_win32_process *process = NULL;
    CHECK(sl_win32_process_create(&process) == SL_OK);
    sl_win32_thread_context thread = {
        .process = process,
        .thread_id = UINT32_C(0x1234),
    };
    uintptr_t anchor = native_stack_pointer();
    CHECK(anchor > UINT32_C(0x100000));
    uintptr_t stack_limit = anchor - UINT32_C(0x100000);
    uintptr_t stack_base = anchor + UINT32_C(0x100000);
    sl_win32_teb *teb = NULL;
    CHECK(sl_win32_teb_create(&thread, stack_limit, stack_base, &teb) == SL_OK);
    CHECK(sl_win32_thread_attach_teb(&thread, teb) == SL_OK);
    sl_win32_context_scope scope = {0};
    CHECK(sl_win32_context_enter(&thread, &scope) == SL_OK);
    CHECK(sl_kernel32_set_unhandled_exception_filter(capture_raise_filter) ==
          NULL);

    const uint64_t arguments[] = {
        UINT64_C(0x1111222233334444),
        UINT64_C(0x5555666677778888),
        UINT64_C(0x9999aaaabbbbcccc),
    };
    memset(&captured_raise_record, 0, sizeof(captured_raise_record));
    memset(&captured_raise_context, 0, sizeof(captured_raise_context));
    filter_call_count = 0U;
    sl_kernel32_set_last_error(UINT32_C(0x76543210));
    sl_kernel32_raise_exception(UINT32_C(0xe0424242), 0U, 3U, arguments);
    CHECK(filter_call_count == 1U);
    CHECK(captured_raise_record.exception_code == UINT32_C(0xe0424242));
    CHECK(captured_raise_record.exception_flags == 0U);
    CHECK(captured_raise_record.exception_record == NULL);
    CHECK(captured_raise_record.exception_address ==
          (void *)(uintptr_t)captured_raise_context.rip);
    CHECK(captured_raise_record.number_parameters == 3U);
    CHECK(memcmp(captured_raise_record.exception_information, arguments,
                 sizeof(arguments)) == 0);
    CHECK(captured_raise_context.context_flags ==
          SL_WIN64_CONTEXT_CAPTURED);
    CHECK(captured_raise_context.rcx == UINT64_C(0xe0424242));
    CHECK(captured_raise_context.rdx == 0U);
    CHECK(captured_raise_context.r8 == 3U);
    CHECK(captured_raise_context.r9 == (uint64_t)(uintptr_t)arguments);
    CHECK(captured_raise_context.rsp >= stack_limit);
    CHECK(captured_raise_context.rsp < stack_base);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x76543210));

    CHECK(sl_kernel32_set_unhandled_exception_filter(NULL) ==
          capture_raise_filter);
    CHECK(sl_win32_context_leave(&scope) == SL_OK);
    CHECK(sl_win32_thread_detach_teb(&thread, teb) == SL_OK);
    CHECK(sl_win32_teb_destroy(teb) == SL_OK);
    CHECK(sl_win32_process_destroy(process) == SL_OK);
    return true;
}

static bool test_lookup_static_function_entries(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 2U));
    put_runtime_function(fixture.bytes + PDATA_RVA, 0x400U, 0x440U, 0x200U);
    put_runtime_function(fixture.bytes + PDATA_RVA + 12U, 0x500U, 0x560U,
                         0x220U);
    fixture.bytes[0x200U] = 1U;
    fixture.bytes[0x220U] = 1U;

    uint64_t image_base = UINT64_C(0x1111111111111111);
    const sl_win64_runtime_function *entry = NULL;
    const sl_loaded_module *module = NULL;
    uint64_t base = fixture.mapped.load_base;
    CHECK(sl_win64_lookup_function_entry(&fixture.registry, base + 0x400U,
                                         &image_base, &entry, &module) ==
          SL_OK);
    CHECK(image_base == base);
    CHECK(entry == runtime_entry(&fixture, 0U));
    CHECK(module == fixture.module);
    CHECK(sl_win64_lookup_function_entry(&fixture.registry, base + 0x43fU,
                                         &image_base, &entry, &module) ==
          SL_OK);
    CHECK(entry == runtime_entry(&fixture, 0U));
    CHECK(sl_win64_lookup_function_entry(&fixture.registry, base + 0x500U,
                                         &image_base, &entry, &module) ==
          SL_OK);
    CHECK(entry == runtime_entry(&fixture, 1U));

    image_base = UINT64_C(0x2222222222222222);
    entry = runtime_entry(&fixture, 0U);
    module = fixture.module;
    CHECK(sl_win64_lookup_function_entry(&fixture.registry, base + 0x440U,
                                         &image_base, &entry, &module) ==
          SL_ERROR_ADDRESS_OUT_OF_RANGE);
    CHECK(image_base == UINT64_C(0x2222222222222222));
    CHECK(entry == runtime_entry(&fixture, 0U));
    CHECK(module == fixture.module);

    fixture.image.directories[SL_PE_DIRECTORY_EXCEPTION].size = 13U;
    CHECK(sl_win64_lookup_function_entry(&fixture.registry, base + 0x410U,
                                         &image_base, &entry, &module) ==
          SL_ERROR_ADDRESS_OUT_OF_RANGE);
    fixture.image.directories[SL_PE_DIRECTORY_EXCEPTION].size = 24U;
    put_u32(fixture.bytes + PDATA_RVA + 12U, 0x430U);
    CHECK(sl_win64_lookup_function_entry(&fixture.registry, base + 0x410U,
                                         &image_base, &entry, &module) ==
          SL_ERROR_INVALID_IMAGE);
    put_u32(fixture.bytes + PDATA_RVA + 12U, 0x500U);
    put_u32(fixture.bytes + PDATA_RVA + 4U, 0x400U);
    CHECK(sl_win64_lookup_function_entry(&fixture.registry, base + 0x410U,
                                         &image_base, &entry, &module) ==
          SL_ERROR_INVALID_IMAGE);
    return true;
}

static bool unwind_basic_frame(unwind_fixture *fixture, uint64_t *stack,
                               size_t stack_count, uint32_t control_rva,
                               size_t current_index) {
    sl_win64_context context = {0};
    context.rsp = (uint64_t)(uintptr_t)&stack[current_index];
    context.rax = fixture->mapped.load_base + 0x410U;
    context.rbx = UINT64_C(0xdeadbeefdeadbeef);
    context.rip = fixture->mapped.load_base + control_rva;
    sl_win64_nonvolatile_context_pointers pointers = {0};
    void *handler_data = (void *)(uintptr_t)1U;
    uint64_t establisher = 0U;
    sl_win64_exception_routine handler = NULL;
    sl_win64_stack_bounds bounds =
        stack_bounds(stack, stack + stack_count);
    CHECK(sl_win64_virtual_unwind(
              fixture->module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture->mapped.load_base + control_rva,
              runtime_entry(fixture, 0U), &context, &bounds, &handler_data,
              &establisher, &pointers, &handler) == SL_OK);
    CHECK(context.rbx == UINT64_C(0x1122334455667788));
    CHECK(context.rip == UINT64_C(0x8877665544332211));
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[41]);
    CHECK(handler_data == NULL);
    CHECK(handler == NULL);
    CHECK(pointers.integer_context[3] == &stack[39]);
    return true;
}

static bool test_virtual_unwind_basic_prologue_and_epilogue(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x200U);
    uint8_t *unwind = fixture.bytes + 0x200U;
    unwind[0] = 1U;
    unwind[1] = 5U;
    unwind[2] = 2U;
    unwind[3] = 0U;
    unwind[4] = 5U;
    unwind[5] = 0x32U; /* UWOP_ALLOC_SMALL, 32 bytes. */
    unwind[6] = 1U;
    unwind[7] = 0x30U; /* UWOP_PUSH_NONVOL RBX. */

    _Alignas(16) uint64_t stack[64] = {0};
    stack[39] = UINT64_C(0x1122334455667788);
    stack[40] = UINT64_C(0x8877665544332211);
    CHECK(unwind_basic_frame(&fixture, stack, 64U, 0x410U, 35U));
    CHECK(unwind_basic_frame(&fixture, stack, 64U, 0x402U, 39U));

    fixture.bytes[0x460U] = 0x48U;
    fixture.bytes[0x461U] = 0x83U;
    fixture.bytes[0x462U] = 0xc4U;
    fixture.bytes[0x463U] = 0x20U;
    fixture.bytes[0x464U] = 0x5bU;
    fixture.bytes[0x465U] = 0xc3U;
    CHECK(unwind_basic_frame(&fixture, stack, 64U, 0x460U, 35U));

    /* Tail transfers identify an epilogue but unwind exactly like a ret. */
    fixture.bytes[0x464U] = 0x40U; /* Redundant REX prefix on pop RBX. */
    fixture.bytes[0x465U] = 0x5bU;
    fixture.bytes[0x466U] = 0xf2U; /* Optional prefix before the transfer. */
    fixture.bytes[0x467U] = 0xebU;
    fixture.bytes[0x468U] = 0x97U; /* Tail jump back to FunctionBegin. */
    CHECK(unwind_basic_frame(&fixture, stack, 64U, 0x460U, 35U));

    fixture.bytes[0x464U] = 0x5bU;
    fixture.bytes[0x465U] = 0xffU;
    fixture.bytes[0x466U] = 0x25U; /* jmp qword ptr [rip + disp32] */
    put_u32(fixture.bytes + 0x467U, UINT32_C(0x7fffffff));
    CHECK(unwind_basic_frame(&fixture, stack, 64U, 0x460U, 35U));

    fixture.bytes[0x465U] = 0x48U;
    fixture.bytes[0x466U] = 0xffU;
    fixture.bytes[0x467U] = 0xe0U; /* jmp rax; target value is irrelevant. */
    CHECK(unwind_basic_frame(&fixture, stack, 64U, 0x460U, 35U));

    fixture.bytes[0x467U] = 0x64U;
    fixture.bytes[0x468U] = 0x24U;
    fixture.bytes[0x469U] = 0x08U; /* jmp qword ptr [rsp + 8] */
    CHECK(unwind_basic_frame(&fixture, stack, 64U, 0x460U, 35U));
    return true;
}

static bool test_virtual_unwind_frame_register_and_saves(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x240U);
    uint8_t *unwind = fixture.bytes + 0x240U;
    unwind[0] = 1U;
    unwind[1] = 20U;
    unwind[2] = 6U;
    unwind[3] = 0x25U; /* RBP, frame base = RBP - 32. */
    unwind[4] = 20U;
    unwind[5] = 0x68U; /* SAVE_XMM128 XMM6. */
    put_u16(unwind + 6U, 2U);
    unwind[8] = 14U;
    unwind[9] = 0xc4U; /* SAVE_NONVOL R12. */
    put_u16(unwind + 10U, 2U);
    unwind[12] = 9U;
    unwind[13] = 0x23U; /* SET_FPREG, MSVC repeats FrameOffset in OpInfo. */
    unwind[14] = 4U;
    unwind[15] = 0x72U; /* ALLOC_SMALL, 64 bytes. */

    _Alignas(16) uint8_t stack[512] = {0};
    uint8_t *frame_base = stack + 128U;
    uint8_t *entry_rsp = frame_base + 64U;
    put_u64(frame_base + 16U, UINT64_C(0x13579bdf2468ace0));
    sl_win64_m128a saved_xmm = {
        .low = UINT64_C(0x0123456789abcdef),
        .high = (int64_t)UINT64_C(0xfedcba9876543210),
    };
    memcpy(frame_base + 32U, &saved_xmm, sizeof(saved_xmm));
    put_u64(entry_rsp, UINT64_C(0x1010101020202020));

    sl_win64_context context = {0};
    context.rsp = (uint64_t)(uintptr_t)(frame_base - 32U);
    context.rbp = (uint64_t)(uintptr_t)(frame_base + 32U);
    context.r12 = UINT64_MAX;
    sl_win64_nonvolatile_context_pointers pointers = {0};
    void *handler_data = NULL;
    uint64_t establisher = 0U;
    sl_win64_exception_routine handler = NULL;
    sl_win64_stack_bounds bounds = stack_bounds(stack, stack + sizeof(stack));
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, &pointers,
              &handler) == SL_OK);
    CHECK(context.r12 == UINT64_C(0x13579bdf2468ace0));
    CHECK(context.flt_save.xmm_registers[6].low == saved_xmm.low);
    CHECK(context.flt_save.xmm_registers[6].high == saved_xmm.high);
    CHECK(context.rip == UINT64_C(0x1010101020202020));
    CHECK(context.rsp == (uint64_t)(uintptr_t)(entry_rsp + 8U));
    CHECK(establisher == (uint64_t)(uintptr_t)frame_base);
    CHECK(pointers.integer_context[12] ==
          (uint64_t *)(void *)(frame_base + 16U));
    CHECK(pointers.floating_context[6] ==
          (sl_win64_m128a *)(void *)(frame_base + 32U));
    CHECK(handler == NULL && handler_data == NULL);
    return true;
}

static bool test_virtual_unwind_machine_frame_and_handler(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x280U);
    uint8_t *unwind = fixture.bytes + 0x280U;
    unwind[0] = 1U;
    unwind[1] = 1U;
    unwind[2] = 1U;
    unwind[3] = 0U;
    unwind[4] = 1U;
    unwind[5] = 0x0aU;

    _Alignas(16) uint64_t machine_frame[8] = {0};
    machine_frame[0] = UINT64_C(0x1234567812345678);
    machine_frame[1] = UINT64_C(0x33);
    machine_frame[2] = UINT64_C(0x246);
    machine_frame[3] = UINT64_C(0x70000000);
    machine_frame[4] = UINT64_C(0x2b);
    sl_win64_context context = {0};
    context.rsp = (uint64_t)(uintptr_t)machine_frame;
    sl_win64_context original = context;
    sl_win64_stack_bounds bounds =
        stack_bounds(machine_frame, machine_frame + 8U);
    void *handler_data = NULL;
    uint64_t establisher = 0U;
    sl_win64_exception_routine handler = NULL;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x410U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rip == machine_frame[0]);
    CHECK(context.rsp == machine_frame[3]);
    CHECK(context.e_flags == (uint32_t)machine_frame[2]);
    CHECK(context.seg_cs == (uint16_t)machine_frame[1]);
    CHECK(context.seg_ss == (uint16_t)machine_frame[4]);

    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x2c0U);
    unwind = fixture.bytes + 0x2c0U;
    unwind[0] = (uint8_t)(1U | (SL_WIN64_UNW_FLAG_EHANDLER << 3U));
    unwind[1] = 0U;
    unwind[2] = 0U;
    unwind[3] = 0U;
    put_u32(unwind + 4U, 0x700U);
    uint64_t normal_stack[4] = {UINT64_C(0xa0a0b0b0c0c0d0d0), 0U, 0U, 0U};
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)normal_stack,
    };
    bounds = stack_bounds(normal_stack, normal_stack + 4U);
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x410U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(exception_routine_address(handler) ==
          (uintptr_t)(fixture.bytes + 0x700U));
    CHECK(handler_data == fixture.bytes + 0x2c8U);
    CHECK(context.rip == normal_stack[0]);

    fixture.bytes[0x2c0U] = 2U;
    context = original;
    handler_data = (void *)(uintptr_t)0x1234U;
    establisher = UINT64_C(0xabcdef);
    uintptr_t sentinel_address = UINT64_C(0x12345678);
    memcpy(&handler, &sentinel_address, sizeof(handler));
    sl_win64_context unchanged = context;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x410U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);
    CHECK(memcmp(&context, &unchanged, sizeof(context)) == 0);
    CHECK(handler_data == (void *)(uintptr_t)0x1234U);
    CHECK(establisher == UINT64_C(0xabcdef));
    CHECK(exception_routine_address(handler) == sentinel_address);
    return true;
}

static bool test_virtual_unwind_large_far_and_chain(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x300U);
    uint8_t *unwind = fixture.bytes + 0x300U;
    unwind[0] = 1U;
    unwind[1] = 20U;
    unwind[2] = 8U;
    unwind[3] = 0U;
    unwind[4] = 20U;
    unwind[5] = 0x79U; /* SAVE_XMM128_FAR XMM7. */
    put_u32(unwind + 6U, 0xa0U);
    unwind[10] = 14U;
    unwind[11] = 0xd5U; /* SAVE_NONVOL_FAR R13. */
    put_u32(unwind + 12U, 0x80U);
    unwind[16] = 7U;
    unwind[17] = 0x01U; /* ALLOC_LARGE, scaled 16-bit form. */
    put_u16(unwind + 18U, 64U);

    _Alignas(16) uint8_t stack[1024] = {0};
    uint8_t *current_rsp = stack + 128U;
    uint8_t *entry_rsp = current_rsp + 512U;
    put_u64(current_rsp + 0x80U, UINT64_C(0xabcdef0123456789));
    sl_win64_m128a saved_xmm = {
        .low = UINT64_C(0x1020304050607080),
        .high = (int64_t)UINT64_C(0x90a0b0c0d0e0f000),
    };
    memcpy(current_rsp + 0xa0U, &saved_xmm, sizeof(saved_xmm));
    put_u64(entry_rsp, UINT64_C(0xcafebabedeadc0de));
    sl_win64_context context = {
        .rsp = (uint64_t)(uintptr_t)current_rsp,
        .r13 = UINT64_MAX,
    };
    sl_win64_nonvolatile_context_pointers pointers = {0};
    sl_win64_stack_bounds bounds = stack_bounds(stack, stack + sizeof(stack));
    void *handler_data = NULL;
    uint64_t establisher = 0U;
    sl_win64_exception_routine handler = NULL;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, &pointers,
              &handler) == SL_OK);
    CHECK(context.r13 == UINT64_C(0xabcdef0123456789));
    CHECK(context.flt_save.xmm_registers[7].low == saved_xmm.low);
    CHECK(context.flt_save.xmm_registers[7].high == saved_xmm.high);
    CHECK(context.rip == UINT64_C(0xcafebabedeadc0de));
    CHECK(context.rsp == (uint64_t)(uintptr_t)(entry_rsp + 8U));
    CHECK(pointers.integer_context[13] ==
          (uint64_t *)(void *)(current_rsp + 0x80U));
    CHECK(pointers.floating_context[7] ==
          (sl_win64_m128a *)(void *)(current_rsp + 0xa0U));

    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x340U);
    unwind = fixture.bytes + 0x340U;
    unwind[0] =
        (uint8_t)(1U | (SL_WIN64_UNW_FLAG_CHAININFO << 3U));
    unwind[1] = 12U;
    unwind[2] = 2U;
    unwind[3] = 0U;
    unwind[4] = 12U;
    unwind[5] = 0xc4U; /* SAVE_NONVOL R12 at frame offset zero. */
    put_u16(unwind + 6U, 0U);
    put_runtime_function(unwind + 8U, FUNCTION_BEGIN, FUNCTION_END, 0x370U);
    uint8_t *parent_unwind = fixture.bytes + 0x370U;
    parent_unwind[0] = 1U;
    parent_unwind[1] = 4U;
    parent_unwind[2] = 1U;
    parent_unwind[3] = 0U;
    parent_unwind[4] = 4U;
    parent_unwind[5] = 0x32U; /* ALLOC_SMALL, 32 bytes. */

    _Alignas(16) uint64_t chain_stack[32] = {0};
    chain_stack[8] = UINT64_C(0x0badf00d0ddba11a);
    chain_stack[12] = UINT64_C(0x1234432112344321);
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&chain_stack[8],
        .r12 = UINT64_MAX,
    };
    bounds = stack_bounds(chain_stack, chain_stack + 32U);
    memset(&pointers, 0, sizeof(pointers));
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, &pointers,
              &handler) == SL_OK);
    CHECK(context.r12 == UINT64_C(0x0badf00d0ddba11a));
    CHECK(context.rip == UINT64_C(0x1234432112344321));
    CHECK(context.rsp == (uint64_t)(uintptr_t)&chain_stack[13]);
    CHECK(pointers.integer_context[12] == &chain_stack[8]);

    sl_win64_context original = {
        .rsp = (uint64_t)(uintptr_t)&chain_stack[8],
        .r12 = UINT64_MAX,
    };
    context = original;
    handler_data = (void *)(uintptr_t)0x1234U;
    establisher = UINT64_C(0xabcdef);
    uintptr_t sentinel_address = UINT64_C(0x12345678);
    memcpy(&handler, &sentinel_address, sizeof(handler));
    parent_unwind[4] = 5U; /* CodeOffset exceeds SizeOfProlog. */
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, &pointers,
              &handler) == SL_ERROR_INVALID_IMAGE);
    CHECK(memcmp(&context, &original, sizeof(context)) == 0);
    CHECK(handler_data == (void *)(uintptr_t)0x1234U);
    CHECK(establisher == UINT64_C(0xabcdef));
    CHECK(exception_routine_address(handler) == sentinel_address);

    parent_unwind[4] = 4U;
    unwind[3] = 0x25U; /* Chained records must share FP and offset. */
    context = original;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, &pointers,
              &handler) == SL_ERROR_INVALID_IMAGE);
    CHECK(memcmp(&context, &original, sizeof(context)) == 0);
    return true;
}

static bool test_virtual_unwind_v2_epilogue_descriptors(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x380U);
    uint8_t *unwind = fixture.bytes + 0x380U;
    unwind[0] =
        (uint8_t)(2U | (SL_WIN64_UNW_FLAG_EHANDLER << 3U));
    unwind[1] = 1U;
    unwind[2] = 3U;
    unwind[3] = 0U;
    unwind[4] = 2U;
    unwind[5] = 0x16U; /* Size 2, implicit epilogue at FunctionEnd. */
    unwind[6] = 0U;
    unwind[7] = 0x06U; /* Counted descriptor padding. */
    unwind[8] = 1U;
    unwind[9] = 0x70U; /* PUSH_NONVOL RDI. */
    put_u32(unwind + 12U, 0x700U); /* Trailer follows four code slots. */

    fixture.bytes[0x450U] = 0x5fU;
    fixture.bytes[0x451U] = 0xc3U; /* Looks canonical, but is not declared. */
    fixture.bytes[0x47eU] = 0x5fU;
    fixture.bytes[0x47fU] = 0xc3U;

    _Alignas(16) uint64_t stack[24] = {0};
    stack[8] = UINT64_C(0x1111222233334444);
    stack[9] = UINT64_C(0x5555666677778888);
    sl_win64_stack_bounds bounds = stack_bounds(stack, stack + 24U);
    sl_win64_context context = {
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rdi = UINT64_MAX,
    };
    void *handler_data = NULL;
    uint64_t establisher = 0U;
    sl_win64_exception_routine handler = NULL;

    /* Version 2 must not scan a body instruction sequence as an epilogue. */
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x450U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rdi == stack[8]);
    CHECK(context.rip == stack[9]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[10]);
    CHECK(exception_routine_address(handler) ==
          (uintptr_t)(fixture.bytes + 0x700U));
    CHECK(handler_data == fixture.bytes + 0x390U);

    sl_win64_nonvolatile_context_pointers pointers = {0};
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rdi = UINT64_MAX,
    };
    handler_data = (void *)(uintptr_t)1U;
    handler = NULL;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x47eU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, &pointers,
              &handler) == SL_OK);
    CHECK(context.rdi == stack[8] && context.rip == stack[9]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[10]);
    CHECK(pointers.integer_context[7] == &stack[8]);
    CHECK(handler == NULL && handler_data == NULL);

    /* At the ret, the preceding pop has already changed RSP and RDI. */
    memset(&pointers, 0, sizeof(pointers));
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[9],
        .rdi = stack[8],
    };
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x47fU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, &pointers,
              &handler) == SL_OK);
    CHECK(context.rdi == stack[8] && context.rip == stack[9]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[10]);
    CHECK(pointers.integer_context[7] == NULL);
    CHECK(handler == NULL && handler_data == NULL);

    /* A v2 epilogue may end in a multi-byte tail jump, still unwound as ret. */
    unwind[4] = 6U;
    fixture.bytes[0x47aU] = 0x5fU;
    fixture.bytes[0x47bU] = 0xe9U;
    put_u32(fixture.bytes + 0x47cU, UINT32_C(0x100));
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[9],
        .rdi = stack[8],
    };
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x47cU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rdi == stack[8] && context.rip == stack[9]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[10]);
    CHECK(handler == NULL && handler_data == NULL);

    /* An explicit descriptor is a 12-bit distance back from FunctionEnd. */
    unwind[4] = 2U;
    unwind[5] = 0x06U;
    unwind[6] = 0x20U;
    unwind[7] = 0x06U; /* Epilogue starts at RVA 0x460. */
    fixture.bytes[0x460U] = 0x5fU;
    fixture.bytes[0x461U] = 0xc3U;
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rdi = UINT64_MAX,
    };
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x460U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rdi == stack[8] && context.rip == stack[9]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[10]);
    CHECK(handler == NULL && handler_data == NULL);

    /* The old end sequence is no longer implicit and must expose the handler. */
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rdi = UINT64_MAX,
    };
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x47dU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(exception_routine_address(handler) ==
          (uintptr_t)(fixture.bytes + 0x700U));

    /* Second launcher shape: pop RSI, pop RDI, ret. */
    unwind[1] = 2U;
    unwind[2] = 4U;
    unwind[4] = 3U;
    unwind[5] = 0x16U;
    unwind[6] = 0U;
    unwind[7] = 0x06U;
    unwind[8] = 2U;
    unwind[9] = 0x60U;
    unwind[10] = 1U;
    unwind[11] = 0x70U;
    fixture.bytes[0x47dU] = 0x5eU;
    fixture.bytes[0x47eU] = 0x5fU;
    fixture.bytes[0x47fU] = 0xc3U;
    stack[8] = UINT64_C(0x0102030405060708);
    stack[9] = UINT64_C(0x1112131415161718);
    stack[10] = UINT64_C(0x2122232425262728);
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rsi = UINT64_MAX,
        .rdi = UINT64_MAX,
    };
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x47dU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rsi == stack[8] && context.rdi == stack[9]);
    CHECK(context.rip == stack[10]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[11]);

    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[9],
        .rsi = stack[8],
        .rdi = UINT64_MAX,
    };
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x47eU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rsi == stack[8] && context.rdi == stack[9]);
    CHECK(context.rip == stack[10]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[11]);

    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[10],
        .rsi = stack[8],
        .rdi = stack[9],
    };
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x47fU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rsi == stack[8] && context.rdi == stack[9]);
    CHECK(context.rip == stack[10]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[11]);

    /* Malformed descriptor metadata must fail transactionally. */
    unwind[0] = 2U;
    unwind[1] = 1U;
    unwind[2] = 3U;
    unwind[4] = 0U; /* A zero common epilogue size is invalid. */
    unwind[5] = 0x16U;
    unwind[6] = 0U;
    unwind[7] = 0x06U;
    unwind[8] = 1U;
    unwind[9] = 0x70U;
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rdi = UINT64_MAX,
    };
    sl_win64_context original = context;
    handler_data = (void *)(uintptr_t)0x1234U;
    establisher = UINT64_C(0xabcdef);
    uintptr_t sentinel_address = UINT64_C(0x12345678);
    memcpy(&handler, &sentinel_address, sizeof(handler));
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);
    CHECK(memcmp(&context, &original, sizeof(context)) == 0);
    CHECK(handler_data == (void *)(uintptr_t)0x1234U);
    CHECK(establisher == UINT64_C(0xabcdef));
    CHECK(exception_routine_address(handler) == sentinel_address);

    unwind[4] = 2U;
    unwind[5] = 0x06U;
    unwind[6] = 0x81U; /* Distance exceeds the 0x80-byte function. */
    unwind[7] = 0x06U;
    context = original;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);

    unwind[6] = 0x80U; /* Starts at FunctionBegin, inside the prologue. */
    context = original;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);

    unwind[5] = 0x26U; /* Reserved first-descriptor flag. */
    unwind[6] = 0U;
    unwind[7] = 0x06U;
    context = original;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);

    unwind[2] = 2U;
    unwind[5] = 0x16U;
    unwind[6] = 1U;
    unwind[7] = 0x70U; /* Missing counted padding makes the prefix odd. */
    context = original;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);

    unwind[0] = 1U; /* UWOP_EPILOG is not a version-1 opcode. */
    unwind[2] = 3U;
    unwind[6] = 0U;
    unwind[7] = 0x06U;
    unwind[8] = 1U;
    unwind[9] = 0x70U;
    context = original;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x420U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);
    CHECK(memcmp(&context, &original, sizeof(context)) == 0);

    /* A failure after restoring a candidate must still roll back every output. */
    unwind[0] = 2U;
    unwind[1] = 1U;
    unwind[2] = 3U;
    unwind[4] = 2U;
    unwind[5] = 0x16U;
    unwind[6] = 0U;
    unwind[7] = 0x06U;
    unwind[8] = 1U;
    unwind[9] = 0x70U;
    context = original;
    sl_win64_nonvolatile_context_pointers pointer_sentinel;
    memset(&pointer_sentinel, 0xa5, sizeof(pointer_sentinel));
    sl_win64_nonvolatile_context_pointers late_pointers = pointer_sentinel;
    handler_data = (void *)(uintptr_t)0x1234U;
    establisher = UINT64_C(0xabcdef);
    memcpy(&handler, &sentinel_address, sizeof(handler));
    const sl_win64_stack_bounds short_bounds =
        stack_bounds(stack, &stack[9]);
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x47eU, runtime_entry(&fixture, 0U),
              &context, &short_bounds, &handler_data, &establisher,
              &late_pointers, &handler) == SL_ERROR_INVALID_IMAGE);
    CHECK(memcmp(&context, &original, sizeof(context)) == 0);
    CHECK(memcmp(&late_pointers, &pointer_sentinel,
                 sizeof(late_pointers)) == 0);
    CHECK(handler_data == (void *)(uintptr_t)0x1234U);
    CHECK(establisher == UINT64_C(0xabcdef));
    CHECK(exception_routine_address(handler) == sentinel_address);
    return true;
}

static bool test_virtual_unwind_v2_chain_and_machine_frame(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x380U);
    uint8_t *unwind = fixture.bytes + 0x380U;
    unwind[0] =
        (uint8_t)(2U | (SL_WIN64_UNW_FLAG_CHAININFO << 3U));
    unwind[1] = 2U;
    unwind[2] = 3U;
    unwind[3] = 0U;
    unwind[4] = 2U;
    unwind[5] = 0x16U; /* Two-byte implicit epilogue. */
    unwind[6] = 0U;
    unwind[7] = 0x06U;
    unwind[8] = 2U;
    unwind[9] = 0x70U; /* PUSH_NONVOL RDI in the selected record. */
    put_runtime_function(unwind + 12U, FUNCTION_BEGIN, FUNCTION_END, 0x3c0U);

    uint8_t *parent = fixture.bytes + 0x3c0U;
    parent[0] = 1U;
    parent[1] = 1U;
    parent[2] = 1U;
    parent[3] = 0U;
    parent[4] = 1U;
    parent[5] = 0x60U; /* A second push in the parent is invalid for v2. */

    fixture.bytes[0x47eU] = 0x5fU;
    fixture.bytes[0x47fU] = 0xc3U;
    _Alignas(16) uint64_t stack[32] = {0};
    stack[8] = UINT64_C(0x1111222233334444);
    stack[9] = UINT64_C(0x5555666677778888);
    const sl_win64_stack_bounds bounds = stack_bounds(stack, stack + 32U);
    sl_win64_context context = {
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rsi = UINT64_MAX,
        .rdi = UINT64_MAX,
    };
    const sl_win64_context original = context;
    void *handler_data = (void *)(uintptr_t)0x1234U;
    uint64_t establisher = UINT64_C(0xabcdef);
    sl_win64_exception_routine handler = NULL;
    uintptr_t sentinel_address = UINT64_C(0x12345678);
    memcpy(&handler, &sentinel_address, sizeof(handler));
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x47eU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_ERROR_INVALID_IMAGE);
    CHECK(memcmp(&context, &original, sizeof(context)) == 0);
    CHECK(handler_data == (void *)(uintptr_t)0x1234U);
    CHECK(establisher == UINT64_C(0xabcdef));
    CHECK(exception_routine_address(handler) == sentinel_address);

    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x3c0U);
    unwind = fixture.bytes + 0x3c0U;
    unwind[0] = 2U;
    unwind[1] = 1U;
    unwind[2] = 3U;
    unwind[3] = 0U;
    unwind[4] = 1U;
    unwind[5] = 0x16U; /* One-byte implicit IRETQ region. */
    unwind[6] = 0U;
    unwind[7] = 0x06U;
    unwind[8] = 1U;
    unwind[9] = 0x1aU; /* PUSH_MACHFRAME with an error code. */
    fixture.bytes[0x47fU] = 0xcfU;

    memset(stack, 0, sizeof(stack));
    stack[8] = UINT64_C(0x1111222233334444); /* RIP after error-code pop. */
    stack[9] = UINT64_C(0x33);
    stack[10] = UINT64_C(0x202);
    stack[11] = (uint64_t)(uintptr_t)&stack[24];
    stack[12] = UINT64_C(0x2b);
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .e_flags = UINT32_C(0xa5a5),
        .seg_cs = UINT16_C(0x55),
        .seg_ss = UINT16_C(0x66),
    };
    handler_data = (void *)(uintptr_t)1U;
    establisher = 0U;
    handler = NULL;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_NHANDLER,
              fixture.mapped.load_base + 0x47fU, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rip == UINT64_C(0x1111222233334444));
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[24]);
    CHECK(context.e_flags == UINT32_C(0xa5a5));
    CHECK(context.seg_cs == UINT16_C(0x55));
    CHECK(context.seg_ss == UINT16_C(0x66));
    CHECK(establisher == (uint64_t)(uintptr_t)&stack[8]);
    CHECK(handler == NULL && handler_data == NULL);
    return true;
}

static bool test_epilogue_uses_declared_frame_register(void) {
    unwind_fixture fixture;
    CHECK(initialize_fixture(&fixture, 1U));
    put_runtime_function(fixture.bytes + PDATA_RVA, FUNCTION_BEGIN,
                         FUNCTION_END, 0x3c0U);
    uint8_t *unwind = fixture.bytes + 0x3c0U;
    unwind[0] = (uint8_t)(1U | (SL_WIN64_UNW_FLAG_EHANDLER << 3U));
    unwind[1] = 1U;
    unwind[2] = 1U;
    unwind[3] = 0x05U;
    unwind[4] = 1U;
    unwind[5] = 0x03U;
    put_u32(unwind + 8U, 0x700U);

    fixture.bytes[0x450U] = 0x48U;
    fixture.bytes[0x451U] = 0x8dU;
    fixture.bytes[0x452U] = 0x63U;
    fixture.bytes[0x453U] = 0x08U; /* lea rsp,[rbx+8], not declared RBP. */
    fixture.bytes[0x454U] = 0xc3U;
    _Alignas(16) uint64_t stack[32] = {0};
    stack[8] = UINT64_C(0x1111111122222222);
    stack[17] = UINT64_C(0x3333333344444444);
    sl_win64_context context = {
        .rsp = (uint64_t)(uintptr_t)&stack[4],
        .rbp = (uint64_t)(uintptr_t)&stack[8],
        .rbx = (uint64_t)(uintptr_t)&stack[16],
    };
    sl_win64_stack_bounds bounds = stack_bounds(stack, stack + 32U);
    void *handler_data = NULL;
    uint64_t establisher = 0U;
    sl_win64_exception_routine handler = NULL;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x450U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rip == stack[8]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[9]);
    CHECK(establisher == (uint64_t)(uintptr_t)&stack[8]);
    CHECK(exception_routine_address(handler) ==
          (uintptr_t)(fixture.bytes + 0x700U));

    unwind[3] = 0x0cU;
    fixture.bytes[0x460U] = 0x49U;
    fixture.bytes[0x461U] = 0x8dU;
    fixture.bytes[0x462U] = 0x64U;
    fixture.bytes[0x463U] = 0x24U;
    fixture.bytes[0x464U] = 0x00U; /* lea rsp,[r12], including SIB. */
    fixture.bytes[0x465U] = 0xc3U;
    context = (sl_win64_context){
        .rsp = (uint64_t)(uintptr_t)&stack[4],
        .r12 = (uint64_t)(uintptr_t)&stack[8],
    };
    handler = NULL;
    CHECK(sl_win64_virtual_unwind(
              fixture.module, SL_WIN64_UNW_FLAG_EHANDLER,
              fixture.mapped.load_base + 0x460U, runtime_entry(&fixture, 0U),
              &context, &bounds, &handler_data, &establisher, NULL,
              &handler) == SL_OK);
    CHECK(context.rip == stack[8]);
    CHECK(context.rsp == (uint64_t)(uintptr_t)&stack[9]);
    CHECK(establisher == (uint64_t)(uintptr_t)&stack[8]);
    CHECK(handler == NULL && handler_data == NULL);
    return true;
}

static bool test_unwind_second_pass_handlers(void) {
    executable_unwind_fixture fixture;
    CHECK(initialize_executable_fixture(&fixture));
    put_runtime_function(fixture.bytes + PDATA_RVA, 0x400U, 0x440U,
                         0x200U);
    put_runtime_function(fixture.bytes + PDATA_RVA + 12U, 0x500U, 0x540U,
                         0x220U);

    fixture.bytes[0x200U] =
        (uint8_t)(1U | ((SL_WIN64_UNW_FLAG_EHANDLER |
                        SL_WIN64_UNW_FLAG_UHANDLER)
                       << 3U));
    put_u32(fixture.bytes + 0x204U, 0x700U);
    fixture.bytes[0x208U] = 0x11U;
    fixture.bytes[0x220U] =
        (uint8_t)(1U | (SL_WIN64_UNW_FLAG_UHANDLER << 3U));
    put_u32(fixture.bytes + 0x224U, 0x700U);
    fixture.bytes[0x228U] = 0x22U;
    CHECK(install_unwind_handler_trampoline(&fixture, 0x700U));

    _Alignas(16) uint64_t stack[32] = {0};
    const uint64_t base = fixture.mapped.load_base;
    stack[8] = base + 0x510U;
    stack[9] = base + 0x600U;
    const sl_win64_stack_bounds bounds =
        stack_bounds(stack, stack + 32U);
    const sl_win64_context context = {
        .rax = UINT64_C(0xaaaaaaaaaaaaaaaa),
        .rbx = UINT64_C(0x1122334455667788),
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rip = base + 0x410U,
    };
    const sl_win64_context original = context;
    sl_win64_exception_record record = {
        .exception_code = SL_WIN64_STATUS_UNWIND,
    };
    sl_win64_unwind_history_table history = {0};
    sl_win64_context result;
    const uint64_t target_frame = (uint64_t)(uintptr_t)&stack[9];
    const uint64_t target_ip = base + 0x520U;
    const uint64_t return_value = UINT64_C(0x8877665544332211);

    memset(unwind_observations, 0, sizeof(unwind_observations));
    unwind_observation_count = 0U;
    unwind_probe_disposition =
        SL_WIN64_EXCEPTION_DISPOSITION_CONTINUE_SEARCH;
    CHECK(sl_win64_unwind_to_frame(
              &fixture.registry, target_frame, target_ip, &record,
              return_value, &context, &history, &bounds, &result) == SL_OK);
    CHECK(unwind_observation_count == 2U);
    CHECK(record.exception_flags == SL_WIN64_EXCEPTION_UNWINDING);
    CHECK(memcmp(&context, &original, sizeof(context)) == 0);

    CHECK(unwind_observations[0].flags == SL_WIN64_EXCEPTION_UNWINDING);
    CHECK(unwind_observations[0].establisher_frame ==
          (uint64_t)(uintptr_t)&stack[8]);
    CHECK(unwind_observations[0].context.rip == base + 0x410U);
    CHECK(unwind_observations[0].context.rsp ==
          (uint64_t)(uintptr_t)&stack[8]);
    CHECK(unwind_observations[0].context.rax == return_value);
    CHECK(unwind_observations[0].dispatcher.control_pc == base + 0x410U);
    CHECK(unwind_observations[0].dispatcher.image_base == base);
    CHECK(unwind_observations[0].dispatcher.function_entry ==
          (const sl_win64_runtime_function *)(const void *)(
              fixture.bytes + PDATA_RVA));
    CHECK(unwind_observations[0].dispatcher.establisher_frame ==
          (uint64_t)(uintptr_t)&stack[8]);
    CHECK(unwind_observations[0].dispatcher.target_ip == target_ip);
    CHECK(unwind_observations[0].dispatcher.context_record ==
          unwind_observations[0].context_pointer);
    CHECK(unwind_observations[0].dispatcher.handler_data ==
          fixture.bytes + 0x208U);
    CHECK(unwind_observations[0].dispatcher.history_table == &history);
    CHECK(unwind_observations[0].exception_record == &record);

    CHECK(unwind_observations[1].flags ==
          (SL_WIN64_EXCEPTION_UNWINDING |
           SL_WIN64_EXCEPTION_TARGET_UNWIND));
    CHECK(unwind_observations[1].establisher_frame == target_frame);
    CHECK(unwind_observations[1].context.rip == base + 0x510U);
    CHECK(unwind_observations[1].context.rsp == target_frame);
    CHECK(unwind_observations[1].context.rax == return_value);
    CHECK(unwind_observations[1].dispatcher.control_pc == base + 0x510U);
    CHECK(unwind_observations[1].dispatcher.function_entry ==
          (const sl_win64_runtime_function *)(const void *)(
              fixture.bytes + PDATA_RVA + 12U));
    CHECK(unwind_observations[1].dispatcher.context_record ==
          unwind_observations[1].context_pointer);
    CHECK(unwind_observations[1].dispatcher.handler_data ==
          fixture.bytes + 0x228U);
    CHECK(result.rip == target_ip);
    CHECK(result.rsp == target_frame);
    CHECK(result.rax == return_value);
    CHECK(result.rbx == context.rbx);

    sl_win64_context sentinel;
    memset(&sentinel, 0xa5, sizeof(sentinel));
    result = sentinel;
    unwind_observation_count = 0U;
    unwind_probe_disposition =
        SL_WIN64_EXCEPTION_DISPOSITION_NESTED_EXCEPTION;
    CHECK(sl_win64_unwind_to_frame(
              &fixture.registry, target_frame, target_ip, &record,
              return_value, &context, &history, &bounds, &result) ==
          SL_ERROR_INVALID_STATE);
    CHECK(unwind_observation_count == 1U);
    CHECK(memcmp(&result, &sentinel, sizeof(result)) == 0);

    unwind_observation_count = 0U;
    unwind_probe_disposition =
        SL_WIN64_EXCEPTION_DISPOSITION_COLLIDED_UNWIND;
    CHECK(sl_win64_unwind_to_frame(
              &fixture.registry, target_frame, target_ip, &record,
              return_value, &context, &history, &bounds, &result) ==
          SL_ERROR_NOT_IMPLEMENTED);
    CHECK(unwind_observation_count == 1U);
    CHECK(memcmp(&result, &sentinel, sizeof(result)) == 0);

    const sl_win64_context leaf = {
        .rsp = (uint64_t)(uintptr_t)&stack[8],
        .rip = base + 0x600U,
    };
    unwind_observation_count = 0U;
    unwind_probe_disposition =
        SL_WIN64_EXCEPTION_DISPOSITION_CONTINUE_SEARCH;
    CHECK(sl_win64_unwind_to_frame(
              &fixture.registry, leaf.rsp, target_ip, &record, return_value,
              &leaf, &history, &bounds, &result) == SL_OK);
    CHECK(unwind_observation_count == 0U);
    CHECK(result.rsp == leaf.rsp && result.rip == target_ip);
    CHECK(result.rax == return_value);

    CHECK(munmap(fixture.bytes, IMAGE_SIZE) == 0);
    return true;
}

#define RTL_UNWIND_FIXTURE_SIZE 0x1000U
#define RTL_UNWIND_CONTEXT_RVA 0x2000U
#define RTL_UNWIND_HANDLER_FLAG_RVA 0x24f0U
#define RTL_UNWIND_TARGET_RVA 0x1034U
#define RTL_UNWIND_RESULT UINT32_C(0x12345678)
#define RAISE_UNWIND_TARGET_RVA 0x1020U

static void put_section_header(uint8_t *destination, const char *name,
                               uint32_t virtual_size,
                               uint32_t virtual_address, uint32_t raw_size,
                               uint32_t raw_offset,
                               uint32_t characteristics) {
    size_t name_length = strlen(name);
    if (name_length > 8U) {
        name_length = 8U;
    }
    memcpy(destination, name, name_length);
    put_u32(destination + 8U, virtual_size);
    put_u32(destination + 12U, virtual_address);
    put_u32(destination + 16U, raw_size);
    put_u32(destination + 20U, raw_offset);
    put_u32(destination + 36U, characteristics);
}

static void make_rtl_unwind_fixture(
    uint8_t data[RTL_UNWIND_FIXTURE_SIZE]) {
    const size_t pe = 0x80U;
    const size_t coff = pe + 4U;
    const size_t optional = coff + 20U;
    const size_t sections = optional + 0xf0U;
    static const uint8_t code[] = {
        0x48U, 0x83U, 0xecU, 0x38U, /* sub rsp, 0x38 */
        0x48U, 0x89U, 0xe1U,       /* mov rcx, rsp */
        0x48U, 0x8dU, 0x15U, 0x26U, 0x00U, 0x00U, 0x00U,
        0x45U, 0x31U, 0xc0U, /* xor r8d, r8d */
        0x41U, 0xb9U, 0x78U, 0x56U, 0x34U, 0x12U,
        0x48U, 0x8dU, 0x05U, 0xe2U, 0x0fU, 0x00U, 0x00U,
        0x48U, 0x89U, 0x44U, 0x24U, 0x20U,
        0x48U, 0xc7U, 0x44U, 0x24U, 0x28U, 0x00U, 0x00U, 0x00U,
        0x00U,
        0xffU, 0x15U, 0x4eU, 0x15U, 0x00U, 0x00U,
        0x0fU, 0x0bU,               /* RtlUnwindEx must not return. */
        0x48U, 0x83U, 0xc4U, 0x38U, /* target: add rsp, 0x38 */
        0xc3U,
    };
    static const uint8_t handler[] = {
        0xc6U, 0x05U, 0xa9U, 0x14U, 0x00U, 0x00U, 0x01U,
        0xb8U, 0x01U, 0x00U, 0x00U, 0x00U, 0xc3U,
    };

    memset(data, 0, RTL_UNWIND_FIXTURE_SIZE);
    data[0] = 'M';
    data[1] = 'Z';
    put_u32(data + 0x3cU, (uint32_t)pe);
    memcpy(data + pe, "PE\0\0", 4U);
    put_u16(data + coff, SL_PE_MACHINE_AMD64);
    put_u16(data + coff + 2U, 4U);
    put_u16(data + coff + 16U, 0xf0U);

    put_u16(data + optional, 0x020bU);
    put_u32(data + optional + 16U, 0x1000U);
    put_u64(data + optional + 24U, UINT64_C(0x180000000));
    put_u32(data + optional + 32U, 0x1000U);
    put_u32(data + optional + 36U, 0x200U);
    put_u32(data + optional + 56U, 0x5000U);
    put_u32(data + optional + 60U, 0x400U);
    put_u16(data + optional + 68U, 3U);
    put_u32(data + optional + 108U, 16U);
    put_u32(data + optional + 120U, 0x2500U);
    put_u32(data + optional + 124U, 40U);
    put_u32(data + optional + 136U, 0x3000U);
    put_u32(data + optional + 140U, 12U);
    put_u32(data + optional + 152U, 0x4000U);
    put_u32(data + optional + 156U, 12U);

    put_section_header(data + sections, ".text", 0x200U, 0x1000U,
                       0x200U, 0x400U, UINT32_C(0x60000020));
    put_section_header(data + sections + 40U, ".data", 0x600U, 0x2000U,
                       0x600U, 0x600U, UINT32_C(0xc0000040));
    put_section_header(data + sections + 80U, ".pdata", 0x200U, 0x3000U,
                       0x200U, 0xc00U, UINT32_C(0x40000040));
    put_section_header(data + sections + 120U, ".reloc", 0x200U, 0x4000U,
                       0x200U, 0xe00U, UINT32_C(0x42000040));

    memcpy(data + 0x400U, code, sizeof(code));
    memcpy(data + 0x440U, handler, sizeof(handler));

    put_u32(data + 0xb00U, 0x2560U);
    put_u32(data + 0xb0cU, 0x2540U);
    put_u32(data + 0xb10U, 0x2580U);
    memcpy(data + 0xb40U, "KERNEL32.dll", sizeof("KERNEL32.dll"));
    put_u64(data + 0xb60U, 0x25a0U);
    put_u64(data + 0xb80U, 0x25a0U);
    put_u16(data + 0xba0U, 0U);
    memcpy(data + 0xba2U, "RtlUnwindEx", sizeof("RtlUnwindEx"));

    put_runtime_function(data + 0xc00U, 0x1000U, 0x1039U, 0x3010U);
    data[0xc10U] =
        (uint8_t)(1U | (SL_WIN64_UNW_FLAG_UHANDLER << 3U));
    data[0xc11U] = 4U;
    data[0xc12U] = 1U;
    data[0xc14U] = 4U;
    data[0xc15U] = 0x62U; /* UWOP_ALLOC_SMALL, 56 bytes. */
    put_u32(data + 0xc18U, 0x1040U);

    put_u32(data + 0xe00U, 0U);
    put_u32(data + 0xe04U, 12U);
}

static void make_raise_exception_fixture(
    uint8_t data[RTL_UNWIND_FIXTURE_SIZE]) {
    static const uint8_t code[] = {
        0x48U, 0x83U, 0xecU, 0x28U, /* sub rsp, 0x28 */
        0xb9U, 0x42U, 0x42U, 0x42U, 0xe0U,
        0x31U, 0xd2U, /* xor edx, edx */
        0x41U, 0xb8U, 0x02U, 0x00U, 0x00U, 0x00U,
        0x4cU, 0x8dU, 0x0dU, 0xe8U, 0x13U, 0x00U, 0x00U,
        0xffU, 0x15U, 0x62U, 0x15U, 0x00U, 0x00U,
        0x0fU, 0x0bU,               /* ContinueExecution must skip this. */
        0x48U, 0x83U, 0xc4U, 0x28U, /* continuation */
        0xc3U,
    };
    static const uint8_t handler[] = {
        0xf3U, 0x0fU, 0x1eU, 0xfaU, /* ENDBR64 */
        0xc6U, 0x05U, 0xa5U, 0x14U, 0x00U, 0x00U, 0x01U,
        0x48U, 0x8dU, 0x05U, 0xceU, 0xffU, 0xffU, 0xffU,
        0x49U, 0x89U, 0x80U, 0xf8U, 0x00U, 0x00U, 0x00U,
        0x49U, 0xc7U, 0x40U, 0x78U, 0x78U, 0x56U, 0x34U, 0x12U,
        0x31U, 0xc0U, /* ExceptionContinueExecution. */
        0xc3U,
    };

    make_rtl_unwind_fixture(data);
    memset(data + 0x400U, 0x90, 0x200U);
    memcpy(data + 0x400U, code, sizeof(code));
    memcpy(data + 0x440U, handler, sizeof(handler));
    memcpy(data + 0xba2U, "RaiseException", sizeof("RaiseException"));
    put_u64(data + 0xa00U, UINT64_C(0x1111222233334444));
    put_u64(data + 0xa08U, UINT64_C(0x5555666677778888));

    put_runtime_function(data + 0xc00U, 0x1000U, 0x1025U, 0x3010U);
    memset(data + 0xc10U, 0, 16U);
    data[0xc10U] =
        (uint8_t)(1U | (SL_WIN64_UNW_FLAG_EHANDLER << 3U));
    data[0xc11U] = 4U;
    data[0xc12U] = 1U;
    data[0xc14U] = 4U;
    data[0xc15U] = 0x42U; /* UWOP_ALLOC_SMALL, 40 bytes. */
    put_u32(data + 0xc18U, 0x1040U);
}

static uint32_t protected_handler_call_count;
static uint32_t protected_unwind_handler_flags;
static uint64_t protected_handler_establisher;
static uintptr_t protected_handler_context_address;
static uintptr_t protected_dispatcher_context_address;
static sl_win64_exception_record protected_handler_record;
static sl_win64_context protected_handler_original_context;
static sl_win64_context protected_handler_caller_context;
static sl_win64_dispatcher_context protected_handler_dispatcher;

static int32_t SL_WINAPI protected_unwind_handler(
    sl_win64_exception_record *exception_record, uint64_t establisher_frame,
    sl_win64_context *context_record,
    sl_win64_dispatcher_context *dispatcher_context) {
    ++protected_handler_call_count;
    if ((exception_record->exception_flags &
         SL_WIN64_EXCEPTION_UNWINDING) != 0U) {
        protected_unwind_handler_flags = exception_record->exception_flags;
        return SL_WIN64_EXCEPTION_DISPOSITION_CONTINUE_SEARCH;
    }
    protected_handler_establisher = establisher_frame;
    protected_handler_context_address = (uintptr_t)context_record;
    protected_dispatcher_context_address =
        (uintptr_t)dispatcher_context->context_record;
    protected_handler_record = *exception_record;
    protected_handler_original_context = *context_record;
    protected_handler_caller_context = *dispatcher_context->context_record;
    protected_handler_dispatcher = *dispatcher_context;

    sl_kernel32_rtl_unwind_ex(
        (void *)(uintptr_t)establisher_frame,
        (void *)(uintptr_t)(dispatcher_context->image_base +
                            RAISE_UNWIND_TARGET_RVA),
        exception_record, (void *)(uintptr_t)RTL_UNWIND_RESULT,
        dispatcher_context->context_record, dispatcher_context->history_table);
}

static void make_raise_unwind_fixture(
    uint8_t data[RTL_UNWIND_FIXTURE_SIZE]) {
    make_raise_exception_fixture(data);
    data[0xc10U] =
        (uint8_t)(1U | ((SL_WIN64_UNW_FLAG_EHANDLER |
                        SL_WIN64_UNW_FLAG_UHANDLER)
                       << 3U));
    sl_win64_exception_routine routine = protected_unwind_handler;
    uintptr_t target = 0U;
    _Static_assert(sizeof(routine) <= sizeof(target),
                   "handler pointer does not fit uintptr_t");
    memcpy(&target, &routine, sizeof(routine));
    uint8_t *handler = data + 0x440U;
    memset(handler, 0x90, 48U);
    handler[0] = 0xf3U;
    handler[1] = 0x0fU;
    handler[2] = 0x1eU;
    handler[3] = 0xfaU;
    handler[4] = 0x48U;
    handler[5] = 0xb8U;
    put_u64(handler + 6U, (uint64_t)target);
    handler[14] = 0xffU;
    handler[15] = 0xe0U;
}

static bool test_raise_exception_guest_ehandler_and_restore(void) {
    static const uint16_t image_path[] = {
        'C', ':', '\\', 'S', 'a', 'd', 'L', 'a', 'y', 'e', 'r', '\\',
        'R', 'a', 'i', 's', 'e', '.', 'e', 'x', 'e',
    };
    uint8_t fixture[RTL_UNWIND_FIXTURE_SIZE];
    sl_module_space *space = NULL;
    sl_win32_process *process = NULL;
    sl_win32_teb *teb = NULL;
    const sl_loaded_module *main_module = NULL;
    sl_win32_thread_context thread = {0};
    sl_win32_context_scope scope = {0};
    bool attached = false;
    bool entered = false;
    bool passed = false;

    make_raise_exception_fixture(fixture);
    if (sl_module_space_create(&space) != SL_OK ||
        sl_kernel32_register_space(space) != SL_OK ||
        sl_module_space_add_pe(
            space, "Raise.exe", (sl_byte_view){fixture, sizeof(fixture)},
            &main_module) != SL_OK) {
        goto cleanup;
    }
    size_t bound_count = 0U;
    if (sl_module_space_bind_imports(space, main_module, &bound_count) !=
            SL_OK ||
        bound_count != 1U ||
        sl_module_space_finalize(space, main_module) != SL_OK ||
        sl_win32_process_create(&process) != SL_OK ||
        sl_win32_process_adopt_module_space(
            process, &space, main_module, image_path,
            sizeof(image_path) / sizeof(image_path[0])) != SL_OK) {
        goto cleanup;
    }

    thread.process = process;
    thread.thread_id = UINT32_C(0x4243);
    uintptr_t rsp = native_stack_pointer();
    if (rsp < UINT32_C(0x100000) ||
        rsp > UINTPTR_MAX - UINT32_C(0x100000) ||
        sl_win32_teb_create(&thread, rsp - UINT32_C(0x100000),
                            rsp + UINT32_C(0x100000), &teb) != SL_OK ||
        sl_win32_thread_attach_teb(&thread, teb) != SL_OK) {
        goto cleanup;
    }
    attached = true;
    if (sl_win32_context_enter(&thread, &scope) != SL_OK) {
        goto cleanup;
    }
    entered = true;

    typedef uint64_t(SL_WINAPI *raise_entry)(void);
    raise_entry entry = NULL;
    uintptr_t entry_address =
        (uintptr_t)(main_module->mapped->bytes + 0x1000U);
    _Static_assert(sizeof(entry) <= sizeof(entry_address),
                   "entry pointer does not fit uintptr_t");
    memcpy(&entry, &entry_address, sizeof(entry));
    uint64_t result = entry();
    passed = result == UINT64_C(0x12345678) &&
             main_module->mapped->bytes[RTL_UNWIND_HANDLER_FLAG_RVA] == 1U;

cleanup:
    if (entered && sl_win32_context_leave(&scope) != SL_OK) {
        passed = false;
    }
    if (attached && sl_win32_thread_detach_teb(&thread, teb) != SL_OK) {
        passed = false;
    }
    if (teb != NULL && sl_win32_teb_destroy(teb) != SL_OK) {
        passed = false;
    }
    if (process != NULL && sl_win32_process_destroy(process) != SL_OK) {
        passed = false;
    }
    sl_module_space_destroy(space);
    return passed;
}

static bool test_raise_exception_handler_initiated_unwind(void) {
    static const uint16_t image_path[] = {
        'C', ':', '\\', 'S', 'a', 'd', 'L', 'a', 'y', 'e', 'r', '\\',
        'C', 'a', 't', 'c', 'h', '.', 'e', 'x', 'e',
    };
    uint8_t fixture[RTL_UNWIND_FIXTURE_SIZE];
    sl_module_space *space = NULL;
    sl_win32_process *process = NULL;
    sl_win32_teb *teb = NULL;
    const sl_loaded_module *main_module = NULL;
    sl_win32_thread_context thread = {0};
    sl_win32_context_scope scope = {0};
    bool attached = false;
    bool entered = false;
    bool passed = false;

    make_raise_unwind_fixture(fixture);
    if (sl_module_space_create(&space) != SL_OK ||
        sl_kernel32_register_space(space) != SL_OK ||
        sl_module_space_add_pe(
            space, "Catch.exe", (sl_byte_view){fixture, sizeof(fixture)},
            &main_module) != SL_OK) {
        goto cleanup;
    }
    size_t bound_count = 0U;
    if (sl_module_space_bind_imports(space, main_module, &bound_count) !=
            SL_OK ||
        bound_count != 1U ||
        sl_module_space_finalize(space, main_module) != SL_OK ||
        sl_win32_process_create(&process) != SL_OK ||
        sl_win32_process_adopt_module_space(
            process, &space, main_module, image_path,
            sizeof(image_path) / sizeof(image_path[0])) != SL_OK) {
        goto cleanup;
    }

    thread.process = process;
    thread.thread_id = UINT32_C(0x4244);
    uintptr_t rsp = native_stack_pointer();
    if (rsp < UINT32_C(0x100000) ||
        rsp > UINTPTR_MAX - UINT32_C(0x100000) ||
        sl_win32_teb_create(&thread, rsp - UINT32_C(0x100000),
                            rsp + UINT32_C(0x100000), &teb) != SL_OK ||
        sl_win32_thread_attach_teb(&thread, teb) != SL_OK) {
        goto cleanup;
    }
    attached = true;
    if (sl_win32_context_enter(&thread, &scope) != SL_OK) {
        goto cleanup;
    }
    entered = true;

    protected_handler_call_count = 0U;
    protected_unwind_handler_flags = 0U;
    protected_handler_establisher = 0U;
    protected_handler_context_address = 0U;
    protected_dispatcher_context_address = 0U;
    memset(&protected_handler_record, 0, sizeof(protected_handler_record));
    memset(&protected_handler_original_context, 0,
           sizeof(protected_handler_original_context));
    memset(&protected_handler_caller_context, 0,
           sizeof(protected_handler_caller_context));
    memset(&protected_handler_dispatcher, 0,
           sizeof(protected_handler_dispatcher));

    typedef uint64_t(SL_WINAPI *raise_entry)(void);
    raise_entry entry = NULL;
    uintptr_t entry_address =
        (uintptr_t)(main_module->mapped->bytes + 0x1000U);
    _Static_assert(sizeof(entry) <= sizeof(entry_address),
                   "entry pointer does not fit uintptr_t");
    memcpy(&entry, &entry_address, sizeof(entry));
    uint64_t result = entry();
    uint64_t base = main_module->mapped->load_base;
    passed =
        result == RTL_UNWIND_RESULT && protected_handler_call_count == 2U &&
        protected_unwind_handler_flags ==
            (SL_WIN64_EXCEPTION_UNWINDING |
             SL_WIN64_EXCEPTION_TARGET_UNWIND) &&
        protected_handler_record.exception_code == UINT32_C(0xe0424242) &&
        protected_handler_record.exception_flags == 0U &&
        protected_handler_record.number_parameters == 2U &&
        protected_handler_record.exception_information[0] ==
            UINT64_C(0x1111222233334444) &&
        protected_handler_record.exception_information[1] ==
            UINT64_C(0x5555666677778888) &&
        protected_handler_record.exception_address ==
            (void *)(uintptr_t)(base + 0x101eU) &&
        protected_handler_original_context.rip == base + 0x101eU &&
        protected_handler_establisher ==
            protected_handler_original_context.rsp &&
        protected_handler_context_address !=
            protected_dispatcher_context_address &&
        protected_handler_caller_context.rsp >
            protected_handler_original_context.rsp &&
        protected_handler_dispatcher.control_pc == base + 0x101eU &&
        protected_handler_dispatcher.image_base == base &&
        protected_handler_dispatcher.function_entry ==
            (const sl_win64_runtime_function *)(const void *)(
                main_module->mapped->bytes + 0x3000U) &&
        protected_handler_dispatcher.establisher_frame ==
            protected_handler_establisher &&
        protected_handler_dispatcher.handler_data ==
            main_module->mapped->bytes + 0x301cU;

cleanup:
    if (entered && sl_win32_context_leave(&scope) != SL_OK) {
        passed = false;
    }
    if (attached && sl_win32_thread_detach_teb(&thread, teb) != SL_OK) {
        passed = false;
    }
    if (teb != NULL && sl_win32_teb_destroy(teb) != SL_OK) {
        passed = false;
    }
    if (process != NULL && sl_win32_process_destroy(process) != SL_OK) {
        passed = false;
    }
    sl_module_space_destroy(space);
    return passed;
}

static bool test_rtl_unwind_ex_thunk_and_restore(void) {
    static const uint16_t image_path[] = {
        'C', ':', '\\', 'S', 'a', 'd', 'L', 'a', 'y', 'e', 'r', '\\',
        'U', 'n', 'w', 'i', 'n', 'd', '.', 'e', 'x', 'e',
    };
    uint8_t fixture[RTL_UNWIND_FIXTURE_SIZE];
    sl_module_space *space = NULL;
    sl_win32_process *process = NULL;
    sl_win32_teb *teb = NULL;
    const sl_loaded_module *main_module = NULL;
    sl_win32_thread_context thread = {0};
    sl_win32_context_scope scope = {0};
    bool attached = false;
    bool entered = false;
    bool passed = false;

    make_rtl_unwind_fixture(fixture);
    if (sl_module_space_create(&space) != SL_OK ||
        sl_kernel32_register_space(space) != SL_OK ||
        sl_module_space_add_pe(
            space, "Unwind.exe",
            (sl_byte_view){fixture, sizeof(fixture)}, &main_module) != SL_OK) {
        goto cleanup;
    }
    size_t bound_count = 0U;
    if (sl_module_space_bind_imports(space, main_module, &bound_count) !=
            SL_OK ||
        bound_count != 1U ||
        sl_module_space_finalize(space, main_module) != SL_OK ||
        sl_win32_process_create(&process) != SL_OK ||
        sl_win32_process_adopt_module_space(
            process, &space, main_module, image_path,
            sizeof(image_path) / sizeof(image_path[0])) != SL_OK) {
        goto cleanup;
    }

    thread.process = process;
    thread.thread_id = UINT32_C(0x4242);
    uintptr_t rsp = native_stack_pointer();
    if (rsp < UINT32_C(0x100000) ||
        rsp > UINTPTR_MAX - UINT32_C(0x100000) ||
        sl_win32_teb_create(&thread, rsp - UINT32_C(0x100000),
                            rsp + UINT32_C(0x100000), &teb) != SL_OK ||
        sl_win32_thread_attach_teb(&thread, teb) != SL_OK) {
        goto cleanup;
    }
    attached = true;
    if (sl_win32_context_enter(&thread, &scope) != SL_OK) {
        goto cleanup;
    }
    entered = true;

    typedef uint64_t(SL_WINAPI *unwind_entry)(void);
    unwind_entry entry = NULL;
    uintptr_t entry_address =
        (uintptr_t)(main_module->mapped->bytes + 0x1000U);
    _Static_assert(sizeof(entry) <= sizeof(entry_address),
                   "entry pointer does not fit uintptr_t");
    memcpy(&entry, &entry_address, sizeof(entry));
    uint64_t result = entry();
    const sl_win64_context *restored =
        (const sl_win64_context *)(const void *)(
            main_module->mapped->bytes + RTL_UNWIND_CONTEXT_RVA);
    passed = result == RTL_UNWIND_RESULT &&
             main_module->mapped->bytes[RTL_UNWIND_HANDLER_FLAG_RVA] == 1U &&
             restored->rax == RTL_UNWIND_RESULT &&
             restored->rip ==
                 main_module->mapped->load_base + RTL_UNWIND_TARGET_RVA &&
             restored->rsp >= rsp - UINT32_C(0x100000) &&
             restored->rsp < rsp + UINT32_C(0x100000);

cleanup:
    if (entered && sl_win32_context_leave(&scope) != SL_OK) {
        passed = false;
    }
    if (attached && sl_win32_thread_detach_teb(&thread, teb) != SL_OK) {
        passed = false;
    }
    if (teb != NULL && sl_win32_teb_destroy(teb) != SL_OK) {
        passed = false;
    }
    if (process != NULL && sl_win32_process_destroy(process) != SL_OK) {
        passed = false;
    }
    sl_module_space_destroy(space);
    return passed;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"Windows exception layouts", test_windows_layouts},
        {"process top-level exception filter", test_process_top_level_filter},
        {"capture AMD64 context", test_capture_context_amd64},
        {"RaiseException top-level dispatch",
         test_raise_exception_top_level_dispatch},
        {"lookup static function entries", test_lookup_static_function_entries},
        {"virtual unwind basic/prologue/epilogue",
         test_virtual_unwind_basic_prologue_and_epilogue},
        {"virtual unwind frame register and saves",
         test_virtual_unwind_frame_register_and_saves},
        {"virtual unwind machine frame and handler",
         test_virtual_unwind_machine_frame_and_handler},
        {"virtual unwind large/far/chained",
         test_virtual_unwind_large_far_and_chain},
        {"virtual unwind v2 epilog descriptors",
         test_virtual_unwind_v2_epilogue_descriptors},
        {"virtual unwind v2 chain and machine frame",
         test_virtual_unwind_v2_chain_and_machine_frame},
        {"epilogue uses declared frame register",
         test_epilogue_uses_declared_frame_register},
        {"unwind second-pass handlers", test_unwind_second_pass_handlers},
        {"RaiseException guest EHANDLER and context restore",
         test_raise_exception_guest_ehandler_and_restore},
        {"RaiseException handler-initiated unwind",
         test_raise_exception_handler_initiated_unwind},
        {"RtlUnwindEx thunk and context restore",
         test_rtl_unwind_ex_thunk_and_restore},
    };
    size_t passed = 0U;
    for (size_t index = 0U; index < sizeof(tests) / sizeof(tests[0]); ++index) {
        if (!tests[index].run()) {
            fprintf(stderr, "FAIL %s\n", tests[index].name);
            return 1;
        }
        printf("PASS %s\n", tests[index].name);
        ++passed;
    }
    printf("%zu Win64 exception/unwind tests passed\n", passed);
    return 0;
}
