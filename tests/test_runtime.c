#define _GNU_SOURCE

#include "sadlayer/kernel32.h"
#include "sadlayer/loader.h"
#include "sadlayer/module.h"
#include "sadlayer/module_space.h"
#include "sadlayer/pe.h"
#include "sadlayer/process.h"
#include "sadlayer/runtime.h"

#include <asm/prctl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FIXTURE_SIZE 2048U
#define FIXTURE_RESULT UINT32_C(0x12345678)
#define FIXTURE_EXIT_CODE 139
#define FIXTURE_TERMINATE_CODE 197
#define FIXTURE_RELOCATED_RVA 0x2140U
#define FIXTURE_RELOCATED_OFFSET UINT64_C(0x1234)
/* Linux/glibc may add this private trampoline flag when restoring an action. */
#define SL_TEST_SA_RESTORER 0x04000000
#define EXPECTED_CRASH_FLAGS                                                \
    (SL_RUNTIME_REPORT_HAS_CRASH_CONTEXT |                                  \
     SL_RUNTIME_REPORT_HAS_SIGNAL_CODE |                                    \
     SL_RUNTIME_REPORT_HAS_FAULT_ADDRESS |                                  \
     SL_RUNTIME_REPORT_HANDLER_ON_ALTSTACK)

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            return false;                                                       \
        }                                                                      \
    } while (false)

static void put_u16(uint8_t *data, size_t offset, uint16_t value) {
    data[offset] = (uint8_t)(value & 0xffU);
    data[offset + 1U] = (uint8_t)(value >> 8U);
}

static void put_u32(uint8_t *data, size_t offset, uint32_t value) {
    data[offset] = (uint8_t)(value & 0xffU);
    data[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
    data[offset + 2U] = (uint8_t)((value >> 16U) & 0xffU);
    data[offset + 3U] = (uint8_t)(value >> 24U);
}

static void put_u64(uint8_t *data, size_t offset, uint64_t value) {
    put_u32(data, offset, (uint32_t)(value & UINT32_MAX));
    put_u32(data, offset + 4U, (uint32_t)(value >> 32U));
}

static uint64_t load_u64(const uint8_t *data) {
    uint64_t value = 0U;
    memcpy(&value, data, sizeof(value));
    return value;
}

static void put_section(uint8_t *data, size_t offset, const char *name,
                        uint32_t virtual_size, uint32_t virtual_address,
                        uint32_t raw_size, uint32_t raw_offset,
                        uint32_t characteristics) {
    size_t name_length = strlen(name);
    if (name_length > 8U) {
        name_length = 8U;
    }
    memcpy(data + offset, name, name_length);
    put_u32(data, offset + 8U, virtual_size);
    put_u32(data, offset + 12U, virtual_address);
    put_u32(data, offset + 16U, raw_size);
    put_u32(data, offset + 20U, raw_offset);
    put_u32(data, offset + 36U, characteristics);
}

static void make_runtime_fixture(uint8_t data[FIXTURE_SIZE]) {
    const size_t pe = 0x80U;
    const size_t coff = pe + 4U;
    const size_t optional = coff + 20U;
    const size_t sections = optional + 0xf0U;
    static const uint8_t entry_code[] = {
        0x48U, 0x83U, 0xecU, 0x28U,             /* sub rsp, 0x28 */
        0xb9U, 0x78U, 0x56U, 0x34U, 0x12U,      /* mov ecx, value */
        0xffU, 0x15U, 0xf1U, 0x0fU, 0x00U, 0x00U, /* call IAT[0] */
        0xffU, 0x15U, 0xf3U, 0x0fU, 0x00U, 0x00U, /* call IAT[1] */
        0x48U, 0x83U, 0xc4U, 0x28U,             /* add rsp, 0x28 */
        0xc3U,                                   /* ret */
    };

    memset(data, 0, FIXTURE_SIZE);
    data[0] = 'M';
    data[1] = 'Z';
    put_u32(data, 0x3cU, (uint32_t)pe);
    memcpy(data + pe, "PE\0\0", 4U);
    put_u16(data, coff, SL_PE_MACHINE_AMD64);
    put_u16(data, coff + 2U, 3U);
    put_u16(data, coff + 16U, 0xf0U);

    put_u16(data, optional, 0x020bU);
    put_u32(data, optional + 16U, 0x1000U);
    put_u64(data, optional + 24U, UINT64_C(0x140000000));
    put_u32(data, optional + 32U, 0x1000U);
    put_u32(data, optional + 36U, 0x200U);
    put_u32(data, optional + 56U, 0x5000U);
    put_u32(data, optional + 60U, 0x200U);
    put_u16(data, optional + 68U, 3U);
    put_u32(data, optional + 108U, 16U);
    put_u32(data, optional + 120U, 0x2080U);
    put_u32(data, optional + 124U, 40U);
    put_u32(data, optional + 152U, 0x4000U);
    put_u32(data, optional + 156U, 12U);

    put_section(data, sections, ".text", 0x200U, 0x1000U, 0x200U, 0x200U,
                UINT32_C(0x60000020));
    put_section(data, sections + 40U, ".idata", 0x200U, 0x2000U, 0x200U,
                0x400U, UINT32_C(0xc0000040));
    put_section(data, sections + 80U, ".reloc", 0x200U, 0x4000U, 0x200U,
                0x600U, UINT32_C(0x42000040));

    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
    put_u64(data, 0x400U, 0x2100U);
    put_u64(data, 0x408U, 0x2120U);
    put_u64(data, 0x410U, 0U);
    put_u32(data, 0x480U, 0x20e0U);
    put_u32(data, 0x48cU, 0x20c0U);
    put_u32(data, 0x490U, 0x2000U);
    memcpy(data + 0x4c0U, "KERNEL32.dll", 13U);
    put_u64(data, 0x4e0U, 0x2100U);
    put_u64(data, 0x4e8U, 0x2120U);
    put_u64(data, 0x4f0U, 0U);
    put_u16(data, 0x500U, 0U);
    memcpy(data + 0x502U, "SetLastError", 13U);
    put_u16(data, 0x520U, 0U);
    memcpy(data + 0x522U, "GetLastError", 13U);
    put_u64(data, 0x540U,
            UINT64_C(0x140000000) + FIXTURE_RELOCATED_OFFSET);
    put_u32(data, 0x600U, 0x2000U);
    put_u32(data, 0x604U, 12U);
    put_u16(data, 0x608U, 0xa140U);
    put_u16(data, 0x60aU, 0U);
}

static void make_worker_runtime_fixture(uint8_t data[FIXTURE_SIZE]) {
    /*
     * Validate Win64 stack alignment, TEB self/PEB/stack fields, relocated
     * PEB.ImageBase, and TEB LastError around two real IAT calls. Each E001xxxx
     * return identifies the failed invariant; success returns FIXTURE_RESULT.
     */
    static const uint8_t entry_code[] = {
        0x48U, 0x83U, 0xecU, 0x28U, 0x40U, 0xf6U, 0xc4U, 0x0fU,
        0x0fU, 0x85U, 0xb9U, 0x00U, 0x00U, 0x00U, 0x65U, 0x48U,
        0x8bU, 0x04U, 0x25U, 0x30U, 0x00U, 0x00U, 0x00U, 0x48U,
        0x85U, 0xc0U, 0x0fU, 0x84U, 0x84U, 0x00U, 0x00U, 0x00U,
        0x48U, 0x39U, 0x40U, 0x30U, 0x75U, 0x7eU, 0x65U, 0x48U,
        0x8bU, 0x14U, 0x25U, 0x60U, 0x00U, 0x00U, 0x00U, 0x48U,
        0x85U, 0xd2U, 0x74U, 0x77U, 0x48U, 0x39U, 0x50U, 0x60U,
        0x75U, 0x71U, 0x4cU, 0x8bU, 0x42U, 0x10U, 0x4cU, 0x8bU,
        0x0dU, 0xfbU, 0x10U, 0x00U, 0x00U, 0x49U, 0x81U, 0xe9U,
        0x34U, 0x12U, 0x00U, 0x00U, 0x4dU, 0x39U, 0xc8U, 0x75U,
        0x5aU, 0x65U, 0x48U, 0x8bU, 0x14U, 0x25U, 0x10U, 0x00U,
        0x00U, 0x00U, 0x65U, 0x48U, 0x8bU, 0x0cU, 0x25U, 0x08U,
        0x00U, 0x00U, 0x00U, 0x48U, 0x39U, 0xcaU, 0x73U, 0x4aU,
        0x48U, 0x39U, 0xd4U, 0x72U, 0x4cU, 0x48U, 0x39U, 0xccU,
        0x73U, 0x47U, 0x4cU, 0x8dU, 0x44U, 0x24U, 0x50U, 0x49U,
        0x39U, 0xc8U, 0x77U, 0x36U, 0xb9U, 0x78U, 0x56U, 0x34U,
        0x12U, 0xffU, 0x15U, 0x79U, 0x0fU, 0x00U, 0x00U, 0x65U,
        0x81U, 0x3cU, 0x25U, 0x68U, 0x00U, 0x00U, 0x00U, 0x78U,
        0x56U, 0x34U, 0x12U, 0x75U, 0x2bU, 0xffU, 0x15U, 0x6dU,
        0x0fU, 0x00U, 0x00U, 0x3dU, 0x78U, 0x56U, 0x34U, 0x12U,
        0x75U, 0x1eU, 0xebU, 0x28U, 0xb8U, 0x01U, 0x00U, 0x01U,
        0xe0U, 0xebU, 0x21U, 0xb8U, 0x02U, 0x00U, 0x01U, 0xe0U,
        0xebU, 0x1aU, 0xb8U, 0x03U, 0x00U, 0x01U, 0xe0U, 0xebU,
        0x13U, 0xb8U, 0x04U, 0x00U, 0x01U, 0xe0U, 0xebU, 0x0cU,
        0xb8U, 0x05U, 0x00U, 0x01U, 0xe0U, 0xebU, 0x05U, 0xb8U,
        0x06U, 0x00U, 0x01U, 0xe0U, 0x48U, 0x83U, 0xc4U, 0x28U,
        0xc3U,
    };
    _Static_assert(sizeof(entry_code) <= 0x200U,
                   "worker entry must fit in .text");

    make_runtime_fixture(data);
    memset(data + 0x200U, 0, 0x200U);
    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
}

static void make_guard_fault_fixture(uint8_t data[FIXTURE_SIZE]) {
    /* Read StackLimit through GS and deliberately touch its lower guard page. */
    static const uint8_t entry_code[] = {
        0x65U, 0x48U, 0x8bU, 0x04U, 0x25U, 0x10U, 0x00U,
        0x00U, 0x00U, 0xc6U, 0x40U, 0xffU, 0x5aU, 0xc3U,
    };
    _Static_assert(sizeof(entry_code) <= 0x200U,
                   "guard fault entry must fit in .text");

    make_runtime_fixture(data);
    memset(data + 0x200U, 0, 0x200U);
    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
}

static void make_destroyed_stack_fault_fixture(uint8_t data[FIXTURE_SIZE]) {
    /* Set RSP to zero, then fault on StackLimit-1 through a preserved RAX. */
    static const uint8_t entry_code[] = {
        0x65U, 0x48U, 0x8bU, 0x04U, 0x25U, 0x10U, 0x00U, 0x00U,
        0x00U, 0x31U, 0xe4U, 0xc6U, 0x40U, 0xffU, 0x5aU, 0x0fU,
        0x0bU,
    };
    _Static_assert(sizeof(entry_code) <= 0x200U,
                   "destroyed-stack entry must fit in .text");

    make_runtime_fixture(data);
    memset(data + 0x200U, 0, 0x200U);
    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
}

static void make_unhandled_signal_fixture(uint8_t data[FIXTURE_SIZE]) {
    /* SIGTERM must terminate even when the parent blocked or ignored it. */
    static const uint8_t entry_code[] = {
        0xb8U, 0x27U, 0x00U, 0x00U, 0x00U, /* mov eax, SYS_getpid */
        0x0fU, 0x05U,                     /* syscall */
        0x89U, 0xc7U,                     /* mov edi, eax */
        0xbeU, 0x0fU, 0x00U, 0x00U, 0x00U, /* mov esi, SIGTERM */
        0xb8U, 0x3eU, 0x00U, 0x00U, 0x00U, /* mov eax, SYS_kill */
        0x0fU, 0x05U,                     /* syscall */
        0x0fU, 0x0bU,                     /* ud2 if SIGTERM survives */
    };
    _Static_assert(sizeof(entry_code) <= 0x200U,
                   "unhandled-signal entry must fit in .text");

    make_runtime_fixture(data);
    memset(data + 0x200U, 0, 0x200U);
    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
}

static void make_exit_runtime_fixture(uint8_t data[FIXTURE_SIZE]) {
    static const uint8_t entry_code[] = {
        0x48U, 0x83U, 0xecU, 0x28U,             /* sub rsp, 0x28 */
        0xb9U, 0x8bU, 0x00U, 0x00U, 0x00U,      /* mov ecx, 139 */
        0xffU, 0x15U, 0xf9U, 0x0fU, 0x00U, 0x00U, /* call IAT[1] */
        0x0fU, 0x0bU,                            /* ud2 if it returns */
    };

    make_runtime_fixture(data);
    memset(data + 0x200U, 0, 0x200U);
    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
    memset(data + 0x522U, 0, 32U);
    memcpy(data + 0x522U, "ExitProcess", 12U);
}

static void make_terminate_runtime_fixture(uint8_t data[FIXTURE_SIZE]) {
    static const uint8_t entry_code[] = {
        0x48U, 0x83U, 0xecU, 0x28U,             /* sub rsp, 0x28 */
        0xffU, 0x15U, 0xf6U, 0x0fU, 0x00U, 0x00U, /* GetCurrentProcess */
        0x48U, 0x89U, 0xc1U,                    /* mov rcx, rax */
        0xbaU, 0xc5U, 0x00U, 0x00U, 0x00U,      /* mov edx, 197 */
        0xffU, 0x15U, 0xf0U, 0x0fU, 0x00U, 0x00U, /* TerminateProcess */
        0x0fU, 0x0bU,                            /* ud2 if it returns */
    };
    _Static_assert(sizeof(entry_code) <= 0x200U,
                   "terminate entry must fit in .text");

    make_runtime_fixture(data);
    memset(data + 0x200U, 0, 0x200U);
    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
    memset(data + 0x502U, 0, 30U);
    memcpy(data + 0x502U, "GetCurrentProcess", sizeof("GetCurrentProcess"));
    memset(data + 0x522U, 0, 32U);
    memcpy(data + 0x522U, "TerminateProcess", sizeof("TerminateProcess"));
}

static bool current_gs_base(uintptr_t *base) {
    unsigned long value = 0UL;
    if (syscall(SYS_arch_prctl, ARCH_GET_GS, &value) != 0) {
        return false;
    }
    *base = (uintptr_t)value;
    return true;
}

static bool crash_fields_are_zero(const sl_runtime_report *report) {
    return report->signal_number == 0 && report->report_flags == 0U &&
           report->signal_code == 0 && report->fault_address == 0U &&
           report->instruction_pointer == 0U && report->stack_pointer == 0U;
}

static bool runtime_report_is_zero(const sl_runtime_report *report) {
    return report->outcome == SL_RUNTIME_OUTCOME_NONE &&
           report->worker_status == SL_OK && report->return_value == 0U &&
           report->last_error == 0U && report->worker_process_id == 0U &&
           report->exit_code == 0 && crash_fields_are_zero(report);
}

static bool rejected_worker_report_is_clean(const sl_pe_image *image,
                                            const sl_mapped_image *mapped,
                                            sl_win32_process *process,
                                            sl_status expected_status) {
    sl_runtime_report report;
    memset(&report, 0xa5, sizeof(report));
    sl_status status =
        sl_runtime_run_trusted_worker(image, mapped, process, &report);
    return status == expected_status && runtime_report_is_zero(&report);
}

static bool unhandled_signal_report_is_valid(
    const sl_runtime_report *report, int signal_number) {
    return report->outcome == SL_RUNTIME_OUTCOME_SIGNALLED &&
           report->signal_number == signal_number &&
           report->worker_status == SL_OK && report->return_value == 0U &&
           report->last_error == 0U && report->report_flags == 0U &&
           report->signal_code == 0 && report->fault_address == 0U &&
           report->instruction_pointer == 0U &&
           report->stack_pointer == 0U && report->worker_process_id != 0U &&
           report->worker_process_id != (uint32_t)getpid();
}

static bool signal_sets_are_equal(const sigset_t *left,
                                  const sigset_t *right) {
    for (int signal_number = 1; signal_number < NSIG; ++signal_number) {
        int left_member = sigismember(left, signal_number);
        int right_member = sigismember(right, signal_number);
        if (left_member < 0 || right_member < 0 ||
            left_member != right_member) {
            return false;
        }
    }
    return true;
}

static bool signal_actions_are_equal(const struct sigaction *left,
                                     const struct sigaction *right) {
    return left->sa_handler == right->sa_handler &&
           (left->sa_flags & ~SL_TEST_SA_RESTORER) ==
               (right->sa_flags & ~SL_TEST_SA_RESTORER) &&
           signal_sets_are_equal(&left->sa_mask, &right->sa_mask);
}

static bool run_worker_with_parent_sigterm_state(
    const sl_pe_image *image, const sl_mapped_image *mapped,
    sl_win32_process *process, bool blocked, bool ignored,
    sl_status *worker_status, sl_runtime_report *report) {
    struct sigaction original_action;
    sigset_t original_mask;
    if (sigaction(SIGTERM, NULL, &original_action) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &original_mask) != 0) {
        return false;
    }

    struct sigaction configured_action;
    memset(&configured_action, 0, sizeof(configured_action));
    configured_action.sa_handler = ignored ? SIG_IGN : SIG_DFL;
    if (sigemptyset(&configured_action.sa_mask) != 0) {
        return false;
    }
    sigset_t configured_mask = original_mask;
    int mask_edit_result = blocked ? sigaddset(&configured_mask, SIGTERM)
                                   : sigdelset(&configured_mask, SIGTERM);
    if (mask_edit_result != 0) {
        return false;
    }
    if (sigaction(SIGTERM, &configured_action, NULL) != 0) {
        return false;
    }
    if (sigprocmask(SIG_SETMASK, &configured_mask, NULL) != 0) {
        (void)sigaction(SIGTERM, &original_action, NULL);
        return false;
    }

    struct sigaction configured_snapshot;
    sigset_t configured_mask_snapshot;
    if (sigaction(SIGTERM, NULL, &configured_snapshot) != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &configured_mask_snapshot) != 0) {
        (void)sigaction(SIGTERM, &original_action, NULL);
        (void)sigprocmask(SIG_SETMASK, &original_mask, NULL);
        return false;
    }

    *worker_status =
        sl_runtime_run_trusted_worker(image, mapped, process, report);

    struct sigaction observed_action;
    sigset_t observed_mask;
    int action_query_result = sigaction(SIGTERM, NULL, &observed_action);
    int mask_query_result =
        sigprocmask(SIG_SETMASK, NULL, &observed_mask);
    bool parent_state_preserved =
        action_query_result == 0 && mask_query_result == 0 &&
        signal_actions_are_equal(&observed_action, &configured_snapshot) &&
        signal_sets_are_equal(&observed_mask, &configured_mask_snapshot);

    int action_restore_result =
        sigaction(SIGTERM, &original_action, NULL);
    int mask_restore_result =
        sigprocmask(SIG_SETMASK, &original_mask, NULL);
    struct sigaction restored_action;
    sigset_t restored_mask;
    int restored_action_result =
        sigaction(SIGTERM, NULL, &restored_action);
    int restored_mask_result =
        sigprocmask(SIG_SETMASK, NULL, &restored_mask);
    bool original_state_restored =
        action_restore_result == 0 && mask_restore_result == 0 &&
        restored_action_result == 0 && restored_mask_result == 0 &&
        signal_actions_are_equal(&restored_action, &original_action) &&
        signal_sets_are_equal(&restored_mask, &original_mask);
    return parent_state_preserved && original_state_restored;
}

static bool prepare_runtime_image(const uint8_t fixture[FIXTURE_SIZE],
                                  sl_pe_image *image,
                                  sl_mapped_image *mapped) {
    sl_module_registry registry;
    size_t bound_count = 0U;

    if (sl_pe_parse((sl_byte_view){fixture, FIXTURE_SIZE}, image) != SL_OK ||
        sl_loader_map_image_for_execution(image, mapped) != SL_OK) {
        return false;
    }
    sl_module_registry_init(&registry);
    if (sl_kernel32_register(&registry) != SL_OK ||
        sl_loader_bind_imports(image, mapped,
                               sl_module_registry_import_resolver, &registry,
                               &bound_count) != SL_OK ||
        bound_count != 2U || sl_loader_finalize_image(image, mapped) != SL_OK) {
        sl_loader_unmap_image(mapped);
        return false;
    }
    return true;
}

static bool read_mapping_permissions(const void *address,
                                     char permissions[5]) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        return false;
    }
    uintptr_t target = (uintptr_t)address;
    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), maps) != NULL) {
        unsigned long start = 0UL;
        unsigned long end = 0UL;
        char current[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, current) == 3 &&
            target >= (uintptr_t)start && target < (uintptr_t)end) {
            memcpy(permissions, current, sizeof(current));
            found = true;
            break;
        }
    }
    (void)fclose(maps);
    return found;
}

static bool test_address_stable_mapping(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image first;
    sl_mapped_image second = {0};
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image_for_execution(&image, &first) == SL_OK);
    CHECK(first.storage == SL_IMAGE_STORAGE_VIRTUAL);
    CHECK(first.load_base == (uint64_t)(uintptr_t)first.bytes);
    CHECK((uintptr_t)first.bytes % (64U * 1024U) == 0U);
    CHECK(load_u64(first.bytes + FIXTURE_RELOCATED_RVA) ==
          first.load_base + FIXTURE_RELOCATED_OFFSET);
    first.bytes[0x3000U] = 0x5aU;

    CHECK(sl_loader_map_image_for_execution(&image, &second) == SL_OK);
    CHECK(second.bytes != first.bytes);
    CHECK(second.load_base == (uint64_t)(uintptr_t)second.bytes);
    CHECK((uintptr_t)second.bytes % (64U * 1024U) == 0U);
    CHECK(load_u64(second.bytes + FIXTURE_RELOCATED_RVA) ==
          second.load_base + FIXTURE_RELOCATED_OFFSET);
    CHECK(first.bytes[0x3000U] == 0x5aU);

    sl_loader_unmap_image(&second);
    sl_loader_unmap_image(&first);
    CHECK(first.bytes == NULL && first.storage == SL_IMAGE_STORAGE_NONE);
    sl_loader_unmap_image(&first);
    return true;
}

static bool test_final_protections_and_handoff(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_module_registry registry;
    sl_win32_process *process = NULL;
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image_for_execution(&image, &mapped) == SL_OK);

    sl_module_registry_init(&registry);
    CHECK(sl_kernel32_register(&registry) == SL_OK);
    size_t bound_count = 0U;
    CHECK(sl_loader_bind_imports(&image, &mapped,
                                 sl_module_registry_import_resolver, &registry,
                                 &bound_count) == SL_OK);
    CHECK(bound_count == 2U);
    CHECK(sl_loader_finalize_image(&image, &mapped) == SL_OK);
    CHECK(mapped.protections_finalized);

    char permissions[5] = {0};
    CHECK(read_mapping_permissions(mapped.bytes, permissions));
    CHECK(memcmp(permissions, "r--", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x1000U, permissions));
    CHECK(memcmp(permissions, "r-x", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x2000U, permissions));
    CHECK(memcmp(permissions, "rw-", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x3000U, permissions));
    CHECK(memcmp(permissions, "---", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x4000U, permissions));
    CHECK(memcmp(permissions, "r--", 3U) == 0);

    CHECK(sl_win32_process_create(&process) == SL_OK);
    sl_win32_thread_context thread = {
        .process = process,
        .last_error = 7U,
        .thread_id = 0U,
    };
    uint32_t result = 0U;
    CHECK(sl_runtime_call_trusted_entry(&image, &mapped, &thread, &result) ==
          SL_OK);
    CHECK(result == FIXTURE_RESULT);
    CHECK(thread.last_error == FIXTURE_RESULT);
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_loader_bind_imports(&image, &mapped,
                                 sl_module_registry_import_resolver, &registry,
                                 &bound_count) == SL_ERROR_INVALID_STATE);
    CHECK(sl_loader_apply_relocations(&image, &mapped, mapped.load_base) ==
          SL_ERROR_INVALID_STATE);
    mapped.entry_rva = 0x2000U;
    CHECK(sl_runtime_call_trusted_entry(&image, &mapped, &thread, &result) ==
          SL_ERROR_INVALID_STATE);
    mapped.entry_rva = image.entry_rva;
    sl_pe_image malformed = image;
    malformed.section_count = SL_PE_MAX_SECTIONS + 1U;
    CHECK(sl_runtime_call_trusted_entry(&malformed, &mapped, &thread,
                                        &result) == SL_ERROR_INVALID_STATE);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_worker_validates_arguments_image_and_state(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_worker_runtime_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, NULL) ==
          SL_ERROR_INVALID_ARGUMENT);
    CHECK(rejected_worker_report_is_clean(NULL, &mapped, process,
                                          SL_ERROR_INVALID_STATE));
    CHECK(rejected_worker_report_is_clean(&image, NULL, process,
                                          SL_ERROR_INVALID_STATE));
    CHECK(rejected_worker_report_is_clean(&image, &mapped, NULL,
                                          SL_ERROR_INVALID_STATE));

    sl_pe_image invalid_image = image;
    invalid_image.machine = SL_PE_MACHINE_I386;
    CHECK(rejected_worker_report_is_clean(&invalid_image, &mapped, process,
                                          SL_ERROR_INVALID_STATE));
    invalid_image = image;
    invalid_image.section_count = SL_PE_MAX_SECTIONS + 1U;
    CHECK(rejected_worker_report_is_clean(&invalid_image, &mapped, process,
                                          SL_ERROR_INVALID_STATE));
    invalid_image = image;
    invalid_image.sections[0].characteristics &= ~UINT32_C(0x20000000);
    CHECK(rejected_worker_report_is_clean(&invalid_image, &mapped, process,
                                          SL_ERROR_INVALID_STATE));

    sl_mapped_image invalid_mapped = mapped;
    invalid_mapped.protections_finalized = false;
    CHECK(rejected_worker_report_is_clean(&image, &invalid_mapped, process,
                                          SL_ERROR_INVALID_STATE));
    invalid_mapped = mapped;
    invalid_mapped.storage = SL_IMAGE_STORAGE_VIRTUAL_TAINTED;
    CHECK(rejected_worker_report_is_clean(&image, &invalid_mapped, process,
                                          SL_ERROR_INVALID_STATE));
    invalid_mapped = mapped;
    invalid_mapped.entry_rva = 0U;
    CHECK(rejected_worker_report_is_clean(&image, &invalid_mapped, process,
                                          SL_ERROR_INVALID_STATE));
    invalid_mapped = mapped;
    invalid_mapped.size = (size_t)image.image_size - 1U;
    CHECK(rejected_worker_report_is_clean(&image, &invalid_mapped, process,
                                          SL_ERROR_INVALID_STATE));

    sl_win32_thread_context thread = {.process = process};
    sl_win32_context_scope scope = {0};
    CHECK(sl_win32_context_enter(&thread, &scope) == SL_OK);
    bool rejected_active_context = rejected_worker_report_is_clean(
        &image, &mapped, process, SL_ERROR_INVALID_STATE);
    sl_status leave_status = sl_win32_context_leave(&scope);
    CHECK(leave_status == SL_OK);
    CHECK(rejected_active_context);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_process_main_worker_and_legacy_identity(void) {
    static const uint16_t image_path[] = {
        'C', ':', '\\', 'G', 'a', 'm', 'e', 's', '\\', 'R', 'u', 'n',
        't', 'i', 'm', 'e', '.', 'e', 'x', 'e',
    };
    uint8_t fixture[FIXTURE_SIZE];
    uint8_t foreign_fixture[FIXTURE_SIZE];
    sl_win32_process *process = NULL;
    sl_win32_process *empty_process = NULL;
    sl_module_space *space = NULL;
    const sl_loaded_module *main_module = NULL;
    sl_runtime_report report;

    make_worker_runtime_fixture(fixture);
    CHECK(sl_win32_process_create(&process) == SL_OK);
    CHECK(sl_module_space_create(&space) == SL_OK);
    CHECK(sl_module_space_add_pe(
              space, "Runtime.exe",
              (sl_byte_view){fixture, sizeof(fixture)}, &main_module) == SL_OK);
    CHECK(sl_kernel32_register_space(space) == SL_OK);
    size_t bound_count = 99U;
    CHECK(sl_module_space_bind_imports(space, main_module, &bound_count) ==
          SL_OK);
    CHECK(bound_count == 2U);
    CHECK(sl_module_space_finalize(space, main_module) == SL_OK);
    CHECK(main_module->mapped->protections_finalized);
    CHECK(sl_win32_process_adopt_module_space(
              process, &space, main_module, image_path,
              sizeof(image_path) / sizeof(image_path[0])) == SL_OK);
    CHECK(space == NULL);
    CHECK(sl_win32_process_main_module(process) == main_module);
    CHECK(load_u64((const uint8_t *)sl_win32_process_peb(process) +
                   SL_WIN32_PEB_IMAGE_BASE_OFFSET) ==
          main_module->mapped->load_base);

    CHECK(sl_runtime_run_process_main(process, NULL) ==
          SL_ERROR_INVALID_ARGUMENT);
    memset(&report, 0xa5, sizeof(report));
    CHECK(sl_runtime_run_process_main(NULL, &report) ==
          SL_ERROR_INVALID_STATE);
    CHECK(runtime_report_is_zero(&report));
    CHECK(sl_win32_process_create(&empty_process) == SL_OK);
    memset(&report, 0xa5, sizeof(report));
    CHECK(sl_runtime_run_process_main(empty_process, &report) ==
          SL_ERROR_INVALID_STATE);
    CHECK(runtime_report_is_zero(&report));
    CHECK(sl_win32_process_destroy(empty_process) == SL_OK);

    CHECK(sl_runtime_run_process_main(process, &report) == SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_RETURNED);
    CHECK(report.worker_status == SL_OK);
    CHECK(report.return_value == FIXTURE_RESULT);
    CHECK(report.last_error == FIXTURE_RESULT);
    CHECK(crash_fields_are_zero(&report));
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != (uint32_t)getpid());
    CHECK(sl_win32_context_current() == NULL);
    CHECK(load_u64((const uint8_t *)sl_win32_process_peb(process) +
                   SL_WIN32_PEB_IMAGE_BASE_OFFSET) ==
          main_module->mapped->load_base);

    CHECK(sl_runtime_run_trusted_worker(main_module->image,
                                        main_module->mapped, process,
                                        &report) == SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_RETURNED);
    CHECK(report.worker_status == SL_OK);
    CHECK(report.return_value == FIXTURE_RESULT);

    sl_pe_image foreign_image;
    sl_mapped_image foreign_mapped = {0};
    make_worker_runtime_fixture(foreign_fixture);
    CHECK(prepare_runtime_image(foreign_fixture, &foreign_image,
                                &foreign_mapped));
    CHECK(rejected_worker_report_is_clean(&foreign_image, &foreign_mapped,
                                          process,
                                          SL_ERROR_INVALID_STATE));
    sl_pe_image copied_image = *main_module->image;
    sl_mapped_image copied_mapping = *main_module->mapped;
    CHECK(rejected_worker_report_is_clean(&copied_image, &copied_mapping,
                                          process,
                                          SL_ERROR_INVALID_STATE));

    sl_loader_unmap_image(&foreign_mapped);
    CHECK(sl_win32_process_destroy(process) == SL_OK);
    return true;
}

typedef struct {
    sl_win32_process *process;
    const sl_loaded_module *main_module;
    const sl_loaded_module *secondary_module;
} module_query_process;

static bool prepare_module_query_process(
    const char *main_name, const char *alias_name, const uint16_t *image_path,
    size_t image_path_length, module_query_process *result) {
    uint8_t fixture[FIXTURE_SIZE];
    uint8_t secondary_fixture[FIXTURE_SIZE];
    sl_module_space *space = NULL;
    sl_win32_process *process = NULL;
    const sl_loaded_module *main_module = NULL;
    const sl_loaded_module *secondary_module = NULL;
    size_t bound_count = 99U;

    *result = (module_query_process){0};
    make_worker_runtime_fixture(fixture);
    make_worker_runtime_fixture(secondary_fixture);
    if (sl_win32_process_create(&process) != SL_OK ||
        sl_module_space_create(&space) != SL_OK ||
        sl_module_space_add_pe(
            space, main_name,
            (sl_byte_view){fixture, sizeof(fixture)}, &main_module) != SL_OK ||
        sl_module_space_add_pe(
            space, "Utility.dll",
            (sl_byte_view){secondary_fixture, sizeof(secondary_fixture)},
            &secondary_module) != SL_OK ||
        sl_kernel32_register_space(space) != SL_OK ||
        sl_module_space_add_alias(space, alias_name, main_name) != SL_OK ||
        sl_module_space_add_alias(space, "UtilityNoExtension",
                                  "Utility.dll") != SL_OK ||
        sl_module_space_bind_imports(space, main_module, &bound_count) !=
            SL_OK ||
        bound_count != 2U ||
        sl_module_space_finalize(space, main_module) != SL_OK ||
        !main_module->mapped->protections_finalized ||
        sl_module_space_bind_imports(space, secondary_module, &bound_count) !=
            SL_OK ||
        bound_count != 2U ||
        sl_module_space_finalize(space, secondary_module) != SL_OK ||
        !secondary_module->mapped->protections_finalized ||
        sl_win32_process_adopt_module_space(
            process, &space, main_module, image_path, image_path_length) !=
            SL_OK) {
        sl_module_space_destroy(space);
        if (process != NULL) {
            (void)sl_win32_process_destroy(process);
        }
        return false;
    }

    result->process = process;
    result->main_module = main_module;
    result->secondary_module = secondary_module;
    return true;
}

static void fill_wide_buffer(uint16_t *buffer, size_t count, uint16_t value) {
    for (size_t index = 0U; index < count; ++index) {
        buffer[index] = value;
    }
}

static bool test_module_queries_follow_process_context(void) {
    static const uint16_t first_path[] = {
        'C', ':', '\\', 'G', 'a', 'm', 'e', 's', '\\', 'F', 'i', 'r',
        's', 't', '\\', 'R', 'u', 'n', 't', 'i', 'm', 'e', 'A', '.', 'e',
        'x', 'e',
    };
    static const uint16_t second_path[] = {
        'D', ':', '\\', 'G', 'a', 'm', 'e', 's', '\\', 0xd83dU, 0xdc1bU,
        '\\', 'R', 'u', 'n', 't', 'i', 'm', 'e', 'B', '.', 'e', 'x', 'e',
    };
    static const uint16_t first_exact[] = {
        'R', 'u', 'n', 't', 'i', 'm', 'e', 'A', '.', 'e', 'x', 'e', 0U,
    };
    static const uint16_t first_mixed_case[] = {
        'r', 'U', 'n', 'T', 'i', 'M', 'e', 'A', '.', 'E', 'x', 'E', 0U,
    };
    static const uint16_t first_alias_without_extension[] = {
        'r', 'U', 'n', 'T', 'i', 'M', 'e', 'A', 'l', 'I', 'a', 'S', 'a', 0U,
    };
    static const uint16_t second_exact[] = {
        'R', 'u', 'n', 't', 'i', 'm', 'e', 'B', '.', 'e', 'x', 'e', 0U,
    };
    static const uint16_t secondary_exact[] = {
        'U', 't', 'i', 'l', 'i', 't', 'y', '.', 'd', 'l', 'l', 0U,
    };
    static const uint16_t secondary_mixed_without_extension[] = {
        'u', 'T', 'i', 'L', 'i', 'T', 'y', 0U,
    };
    static const uint16_t secondary_path_with_dotted_directory[] = {
        'C', ':', '\\', 'd', 'i', 'r', '.', 'v', '1', '\\',
        'U', 't', 'i', 'l', 'i', 't', 'y', 0U,
    };
    static const uint16_t secondary_trailing_period[] = {
        'U', 't', 'i', 'l', 'i', 't', 'y', 'N', 'o', 'E', 'x', 't',
        'e', 'n', 's', 'i', 'o', 'n', '.', 0U,
    };
    static const uint16_t kernel32_name[] = {
        'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'd', 'l', 'l', 0U,
    };
    static const uint16_t absent_name[] = {
        'M', 'i', 's', 's', 'i', 'n', 'g', '.', 'd', 'l', 'l', 0U,
    };
    const size_t first_path_length =
        sizeof(first_path) / sizeof(first_path[0]);
    const size_t second_path_length =
        sizeof(second_path) / sizeof(second_path[0]);
    module_query_process first;
    module_query_process second;
    CHECK(prepare_module_query_process(
        "RuntimeA.exe", "RuntimeAliasA.dll", first_path, first_path_length,
        &first));
    CHECK(prepare_module_query_process(
        "RuntimeB.exe", "RuntimeAliasB.dll", second_path, second_path_length,
        &second));
    CHECK(first.main_module->mapped->load_base !=
          second.main_module->mapped->load_base);

    sl_win32_thread_context first_thread = {
        .process = first.process,
        .last_error = UINT32_C(0x11112222),
    };
    sl_win32_thread_context second_thread = {
        .process = second.process,
        .last_error = UINT32_C(0x33334444),
    };
    sl_win32_context_scope first_scope = {0};
    sl_win32_context_scope second_scope = {0};
    CHECK(sl_win32_context_enter(&first_thread, &first_scope) == SL_OK);

    void *first_handle =
        (void *)(uintptr_t)first.main_module->mapped->load_base;
    void *first_secondary_handle =
        (void *)(uintptr_t)first.secondary_module->mapped->load_base;
    sl_kernel32_set_last_error(UINT32_C(0xa1a2a3a4));
    CHECK(sl_kernel32_get_module_handle_w(NULL) == first_handle);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xa1a2a3a4));
    CHECK(sl_kernel32_get_module_handle_w(first_exact) == first_handle);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xa1a2a3a4));
    CHECK(sl_kernel32_get_module_handle_w(first_mixed_case) == first_handle);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xa1a2a3a4));
    CHECK(sl_kernel32_get_module_handle_w(first_alias_without_extension) ==
          first_handle);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xa1a2a3a4));
    CHECK(sl_kernel32_get_module_handle_w(secondary_exact) ==
          first_secondary_handle);
    CHECK(sl_kernel32_get_module_handle_w(
              secondary_mixed_without_extension) == first_secondary_handle);
    CHECK(sl_kernel32_get_module_handle_w(
              secondary_path_with_dotted_directory) == NULL);
    CHECK(sl_kernel32_get_last_error() == 126U);
    sl_kernel32_set_last_error(UINT32_C(0xa1a2a3a4));
    CHECK(sl_kernel32_get_module_handle_w(secondary_trailing_period) ==
          first_secondary_handle);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xa1a2a3a4));

    CHECK(sl_kernel32_get_module_handle_w(kernel32_name) == NULL);
    CHECK(sl_kernel32_get_last_error() == 126U);
    CHECK(sl_kernel32_get_module_handle_w(absent_name) == NULL);
    CHECK(sl_kernel32_get_last_error() == 126U);

    uint16_t filename[64];
    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    sl_kernel32_set_last_error(UINT32_C(0xb1b2b3b4));
    CHECK(sl_kernel32_get_module_file_name_w(
              NULL, filename, (uint32_t)(first_path_length + 1U)) ==
          (uint32_t)first_path_length);
    CHECK(memcmp(filename, first_path,
                 first_path_length * sizeof(first_path[0])) == 0);
    CHECK(filename[first_path_length] == 0U);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xb1b2b3b4));

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    sl_kernel32_set_last_error(UINT32_C(0xc1c2c3c4));
    CHECK(sl_kernel32_get_module_file_name_w(
              first_handle, filename,
              (uint32_t)(first_path_length + 1U)) ==
          (uint32_t)first_path_length);
    CHECK(memcmp(filename, first_path,
                 first_path_length * sizeof(first_path[0])) == 0);
    CHECK(filename[first_path_length] == 0U);
    CHECK(filename[first_path_length + 1U] == 0xa5a5U);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0xc1c2c3c4));

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    sl_kernel32_set_last_error(0U);
    CHECK(sl_kernel32_get_module_file_name_w(
              first_handle, filename, (uint32_t)first_path_length) ==
          (uint32_t)first_path_length);
    CHECK(memcmp(filename, first_path,
                 (first_path_length - 1U) * sizeof(first_path[0])) == 0);
    CHECK(filename[first_path_length - 1U] == 0U);
    CHECK(filename[first_path_length] == 0xa5a5U);
    CHECK(sl_kernel32_get_last_error() == 122U);

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    CHECK(sl_kernel32_get_module_file_name_w(first_handle, filename, 4U) ==
          4U);
    CHECK(memcmp(filename, first_path, 3U * sizeof(first_path[0])) == 0);
    CHECK(filename[3] == 0U && filename[4] == 0xa5a5U);
    CHECK(sl_kernel32_get_last_error() == 122U);

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    CHECK(sl_kernel32_get_module_file_name_w(first_handle, filename, 1U) ==
          1U);
    CHECK(filename[0] == 0U && filename[1] == 0xa5a5U);
    CHECK(sl_kernel32_get_last_error() == 122U);

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    uint16_t unchanged[64];
    memcpy(unchanged, filename, sizeof(filename));
    CHECK(sl_kernel32_get_module_file_name_w(first_handle, filename, 0U) ==
          0U);
    CHECK(sl_kernel32_get_last_error() == 122U);
    CHECK(memcmp(filename, unchanged, sizeof(filename)) == 0);
    CHECK(sl_kernel32_get_module_file_name_w(
              first_handle, NULL, (uint32_t)(first_path_length + 1U)) == 0U);
    CHECK(sl_kernel32_get_last_error() == 87U);

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    memcpy(unchanged, filename, sizeof(filename));
    CHECK(sl_kernel32_get_module_file_name_w(
              (void *)(uintptr_t)UINT64_C(0x12345000), filename,
              (uint32_t)(first_path_length + 1U)) == 0U);
    CHECK(sl_kernel32_get_last_error() == 126U);
    CHECK(memcmp(filename, unchanged, sizeof(filename)) == 0);
    CHECK(sl_kernel32_get_module_file_name_w(
              first_secondary_handle, filename,
              (uint32_t)(first_path_length + 1U)) == 0U);
    CHECK(sl_kernel32_get_last_error() == 126U);
    CHECK(memcmp(filename, unchanged, sizeof(filename)) == 0);

    sl_kernel32_set_last_error(UINT32_C(0x51525354));
    CHECK(sl_win32_context_enter(&second_thread, &second_scope) == SL_OK);
    void *second_handle =
        (void *)(uintptr_t)second.main_module->mapped->load_base;
    void *second_secondary_handle =
        (void *)(uintptr_t)second.secondary_module->mapped->load_base;
    CHECK(sl_kernel32_get_module_handle_w(NULL) == second_handle);
    CHECK(sl_kernel32_get_module_handle_w(second_exact) == second_handle);
    CHECK(sl_kernel32_get_module_handle_w(secondary_exact) ==
          second_secondary_handle);
    CHECK(second_secondary_handle != first_secondary_handle);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x33334444));

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    CHECK(sl_kernel32_get_module_file_name_w(
              second_handle, filename,
              (uint32_t)(second_path_length + 1U)) ==
          (uint32_t)second_path_length);
    CHECK(memcmp(filename, second_path,
                 second_path_length * sizeof(second_path[0])) == 0);
    CHECK(filename[second_path_length] == 0U);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x33334444));

    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    memcpy(unchanged, filename, sizeof(filename));
    CHECK(sl_kernel32_get_module_file_name_w(
              first_handle, filename,
              (uint32_t)(first_path_length + 1U)) == 0U);
    CHECK(sl_kernel32_get_last_error() == 126U);
    CHECK(memcmp(filename, unchanged, sizeof(filename)) == 0);
    CHECK(sl_kernel32_get_module_file_name_w(
              first_secondary_handle, filename,
              (uint32_t)(first_path_length + 1U)) == 0U);
    CHECK(sl_kernel32_get_last_error() == 126U);
    CHECK(memcmp(filename, unchanged, sizeof(filename)) == 0);
    CHECK(sl_kernel32_get_module_handle_w(first_exact) == NULL);
    CHECK(sl_kernel32_get_last_error() == 126U);
    CHECK(sl_kernel32_get_module_handle_w(kernel32_name) == NULL);
    CHECK(sl_kernel32_get_last_error() == 126U);

    sl_kernel32_set_last_error(UINT32_C(0x61626364));
    CHECK(sl_win32_context_leave(&second_scope) == SL_OK);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x51525354));
    CHECK(sl_kernel32_get_module_handle_w(NULL) == first_handle);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x51525354));
    fill_wide_buffer(filename, sizeof(filename) / sizeof(filename[0]),
                     0xa5a5U);
    CHECK(sl_kernel32_get_module_file_name_w(
              NULL, filename, (uint32_t)(first_path_length + 1U)) ==
          (uint32_t)first_path_length);
    CHECK(memcmp(filename, first_path,
                 first_path_length * sizeof(first_path[0])) == 0);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x51525354));

    CHECK(sl_win32_context_leave(&first_scope) == SL_OK);
    CHECK(sl_win32_context_current() == NULL);
    CHECK(sl_win32_process_destroy(second.process) == SL_OK);
    CHECK(sl_win32_process_destroy(first.process) == SL_OK);
    return true;
}

static bool test_guarded_worker_installs_teb_in_gs(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    uintptr_t parent_gs_before = 0U;
    uintptr_t parent_gs_after = 0U;
    make_worker_runtime_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);
    const uint8_t *parent_peb = sl_win32_process_peb(process);
    CHECK(load_u64(parent_peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET) == 0U);
    CHECK(current_gs_base(&parent_gs_before));

    sl_runtime_report report;
    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, &report) ==
          SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_RETURNED);
    CHECK(report.worker_status == SL_OK);
    CHECK(report.return_value == FIXTURE_RESULT);
    CHECK(report.last_error == FIXTURE_RESULT);
    CHECK(crash_fields_are_zero(&report));
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != (uint32_t)getpid());
    CHECK(current_gs_base(&parent_gs_after));
    CHECK(parent_gs_after == parent_gs_before);
    CHECK(sl_win32_context_current() == NULL);
    CHECK(load_u64(parent_peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET) == 0U);

    uint32_t first_worker_process_id = report.worker_process_id;
    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, &report) ==
          SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_RETURNED);
    CHECK(report.worker_status == SL_OK);
    CHECK(report.return_value == FIXTURE_RESULT);
    CHECK(report.last_error == FIXTURE_RESULT);
    CHECK(crash_fields_are_zero(&report));
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != first_worker_process_id);
    CHECK(current_gs_base(&parent_gs_after));
    CHECK(parent_gs_after == parent_gs_before);
    CHECK(load_u64(parent_peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET) == 0U);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_worker_rejects_non_waitable_sigchld(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_worker_runtime_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    struct sigaction original;
    struct sigaction ignored;
    memset(&ignored, 0, sizeof(ignored));
    ignored.sa_handler = SIG_IGN;
    CHECK(sigemptyset(&ignored.sa_mask) == 0);
    CHECK(sigaction(SIGCHLD, NULL, &original) == 0);
    CHECK(sigaction(SIGCHLD, &ignored, NULL) == 0);

    sl_runtime_report report;
    sl_status status =
        sl_runtime_run_trusted_worker(&image, &mapped, process, &report);
    int restore_result = sigaction(SIGCHLD, &original, NULL);
    CHECK(restore_result == 0);
    CHECK(status == SL_ERROR_THREAD_ENVIRONMENT);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_NONE);
    CHECK(report.worker_process_id == 0U);

    struct sigaction no_child_wait;
    memset(&no_child_wait, 0, sizeof(no_child_wait));
    no_child_wait.sa_handler = SIG_DFL;
    no_child_wait.sa_flags = SA_NOCLDWAIT;
    CHECK(sigemptyset(&no_child_wait.sa_mask) == 0);
    CHECK(sigaction(SIGCHLD, &no_child_wait, NULL) == 0);
    status = sl_runtime_run_trusted_worker(&image, &mapped, process, &report);
    restore_result = sigaction(SIGCHLD, &original, NULL);
    CHECK(restore_result == 0);
    CHECK(status == SL_ERROR_THREAD_ENVIRONMENT);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_NONE);
    CHECK(report.worker_process_id == 0U);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_worker_observes_exit_process(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_exit_runtime_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    sl_runtime_report report;
    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, &report) ==
          SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_EXITED);
    CHECK(report.exit_code == FIXTURE_EXIT_CODE);
    CHECK(report.return_value == 0U);
    CHECK(report.last_error == 0U);
    CHECK(crash_fields_are_zero(&report));
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != (uint32_t)getpid());
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_worker_observes_terminate_process(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_terminate_runtime_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    sl_runtime_report report;
    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, &report) ==
          SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_EXITED);
    CHECK(report.exit_code == FIXTURE_TERMINATE_CODE);
    CHECK(report.return_value == 0U);
    CHECK(report.last_error == 0U);
    CHECK(crash_fields_are_zero(&report));
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != (uint32_t)getpid());
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_unhandled_signal_uses_wait_status_fallback(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_unhandled_signal_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    sl_runtime_report report;
    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, &report) ==
          SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_SIGNALLED);
    CHECK(report.signal_number == SIGTERM);
    CHECK(report.worker_status == SL_OK);
    CHECK(report.return_value == 0U);
    CHECK(report.last_error == 0U);
    CHECK(report.report_flags == 0U);
    CHECK(report.signal_code == 0);
    CHECK(report.fault_address == 0U);
    CHECK(report.instruction_pointer == 0U);
    CHECK(report.stack_pointer == 0U);
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != (uint32_t)getpid());
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_worker_unblocks_inherited_sigterm(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_unhandled_signal_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    sl_status status = SL_ERROR_THREAD_ENVIRONMENT;
    sl_runtime_report report;
    CHECK(run_worker_with_parent_sigterm_state(
        &image, &mapped, process, true, false, &status, &report));
    CHECK(status == SL_OK);
    CHECK(unhandled_signal_report_is_valid(&report, SIGTERM));
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_worker_resets_inherited_ignored_sigterm(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_unhandled_signal_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    sl_status status = SL_ERROR_THREAD_ENVIRONMENT;
    sl_runtime_report report;
    CHECK(run_worker_with_parent_sigterm_state(
        &image, &mapped, process, false, true, &status, &report));
    CHECK(status == SL_OK);
    CHECK(unhandled_signal_report_is_valid(&report, SIGTERM));
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_guard_fault_is_contained(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_guard_fault_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    sl_runtime_report report;
    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, &report) ==
          SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_SIGNALLED);
    CHECK(report.worker_status == SL_OK);
    CHECK(report.signal_number == SIGSEGV);
    CHECK(report.report_flags == EXPECTED_CRASH_FLAGS);
    CHECK(report.signal_code == SEGV_ACCERR);
    CHECK(report.instruction_pointer ==
          mapped.load_base + (uint64_t)mapped.entry_rva + 9U);
    CHECK(report.stack_pointer != 0U);
    CHECK(report.fault_address < UINT64_MAX);
    long page_size = sysconf(_SC_PAGESIZE);
    CHECK(page_size > 0L);
    CHECK((report.fault_address + 1U) % (uint64_t)page_size == 0U);
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != (uint32_t)getpid());
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_crash_report_survives_destroyed_guest_stack(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_win32_process *process = NULL;
    make_destroyed_stack_fault_fixture(fixture);
    CHECK(prepare_runtime_image(fixture, &image, &mapped));
    CHECK(sl_win32_process_create(&process) == SL_OK);

    sl_runtime_report report;
    CHECK(sl_runtime_run_trusted_worker(&image, &mapped, process, &report) ==
          SL_OK);
    CHECK(report.outcome == SL_RUNTIME_OUTCOME_SIGNALLED);
    CHECK(report.worker_status == SL_OK);
    CHECK(report.signal_number == SIGSEGV);
    CHECK(report.report_flags == EXPECTED_CRASH_FLAGS);
    CHECK(report.signal_code == SEGV_ACCERR);
    CHECK(report.instruction_pointer ==
          mapped.load_base + (uint64_t)mapped.entry_rva + 11U);
    CHECK(report.stack_pointer == 0U);
    CHECK(report.fault_address < UINT64_MAX);
    long page_size = sysconf(_SC_PAGESIZE);
    CHECK(page_size > 0L);
    CHECK((report.fault_address + 1U) % (uint64_t)page_size == 0U);
    CHECK(report.worker_process_id != 0U);
    CHECK(report.worker_process_id != (uint32_t)getpid());
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_rejects_writable_executable_page(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    image.sections[0].characteristics |= UINT32_C(0x80000000);
    CHECK(sl_loader_map_image_for_execution(&image, &mapped) == SL_OK);
    CHECK(sl_loader_finalize_image(&image, &mapped) ==
          SL_ERROR_WX_CONFLICT);
    CHECK(!mapped.protections_finalized);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_failed_protection_rollback_taints_mapping(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image_for_execution(&image, &mapped) == SL_OK);

    long page_size = sysconf(_SC_PAGESIZE);
    CHECK(page_size > 0L);
    CHECK((size_t)page_size <= SIZE_MAX / 3U);
    size_t hole_offset = (size_t)page_size * 3U;
    CHECK(hole_offset <= mapped.allocation_size);
    CHECK((size_t)page_size <= mapped.allocation_size - hole_offset);
    CHECK(munmap(mapped.bytes + hole_offset, (size_t)page_size) == 0);
    CHECK(sl_loader_finalize_image(&image, &mapped) ==
          SL_ERROR_MEMORY_PROTECTION);
    CHECK(mapped.storage == SL_IMAGE_STORAGE_VIRTUAL_TAINTED);
    CHECK(!mapped.protections_finalized);
    CHECK(sl_loader_finalize_image(&image, &mapped) == SL_ERROR_INVALID_STATE);
    CHECK(sl_loader_apply_relocations(&image, &mapped, mapped.load_base) ==
          SL_ERROR_INVALID_STATE);
    sl_module_registry registry;
    sl_module_registry_init(&registry);
    CHECK(sl_kernel32_register(&registry) == SL_OK);
    size_t bound_count = 0U;
    CHECK(sl_loader_bind_imports(&image, &mapped,
                                 sl_module_registry_import_resolver, &registry,
                                 &bound_count) == SL_ERROR_INVALID_STATE);
    CHECK(bound_count == 0U);

    sl_loader_unmap_image(&mapped);
    CHECK(mapped.bytes == NULL && mapped.storage == SL_IMAGE_STORAGE_NONE);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"address-stable executable mapping", test_address_stable_mapping},
        {"final protections and PE handoff",
         test_final_protections_and_handoff},
        {"worker validates arguments, image, and state",
         test_worker_validates_arguments_image_and_state},
        {"process main worker and legacy identity",
         test_process_main_worker_and_legacy_identity},
        {"module queries follow process context",
         test_module_queries_follow_process_context},
        {"guard-page fault is contained", test_guard_fault_is_contained},
        {"crash report survives destroyed guest stack",
         test_crash_report_survives_destroyed_guest_stack},
        {"guarded worker installs TEB in GS",
         test_guarded_worker_installs_teb_in_gs},
        {"worker rejects non-waitable SIGCHLD",
         test_worker_rejects_non_waitable_sigchld},
        {"worker observes ExitProcess", test_worker_observes_exit_process},
        {"worker observes TerminateProcess",
         test_worker_observes_terminate_process},
        {"unhandled signal uses wait-status fallback",
         test_unhandled_signal_uses_wait_status_fallback},
        {"worker unblocks inherited SIGTERM",
         test_worker_unblocks_inherited_sigterm},
        {"worker resets inherited ignored SIGTERM",
         test_worker_resets_inherited_ignored_sigterm},
        {"reject writable executable pages",
         test_rejects_writable_executable_page},
        {"taint mapping after failed protection rollback",
         test_failed_protection_rollback_taints_mapping},
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
    printf("%zu runtime tests passed\n", passed);
    return 0;
}
