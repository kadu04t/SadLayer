#include "sadlayer/context.h"
#include "sadlayer/kernel32.h"
#include "sadlayer/module.h"
#include "sadlayer/pe.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <threads.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            return false;                                                       \
        }                                                                      \
    } while (false)

static sl_status resolve_name(const sl_module_registry *registry,
                              const char *name, sl_resolved_symbol *resolved) {
    sl_pe_import_symbol import = {
        .module_name = "kErNeL32.DlL",
        .symbol_name = name,
        .iat_rva = 0U,
        .hint = 0U,
        .ordinal = 0U,
        .by_ordinal = false,
    };
    return sl_module_registry_resolve(registry, &import, resolved);
}

typedef struct {
    bool passed;
} register_context;

static int register_kernel32_on_thread(void *opaque) {
    register_context *context = opaque;
    sl_module_registry registry;
    sl_resolved_symbol resolved;
    sl_module_registry_init(&registry);
    context->passed = sl_kernel32_register(&registry) == SL_OK &&
                      resolve_name(&registry, "GetLastError", &resolved) ==
                          SL_OK &&
                      resolved.is_native && resolved.guest_address != 0U;
    return context->passed ? 0 : 1;
}

static bool test_export_surface_and_abi(void) {
    static const char *const implemented[] = {
        "GetLastError",          "SetLastError",
        "GetCurrentProcessId",   "GetCurrentThreadId",
        "GetCurrentProcess",     "IsDebuggerPresent",
        "QueryPerformanceCounter", "QueryPerformanceFrequency",
        "GetSystemTimeAsFileTime", "GetProcessHeap",
        "HeapAlloc",             "HeapFree",
        "HeapReAlloc",           "HeapSize",
        "TlsAlloc",              "TlsFree",
        "TlsGetValue",           "TlsSetValue",
        "FlsAlloc",              "FlsFree",
        "FlsGetValue",           "FlsSetValue",
        "EnterCriticalSection",  "LeaveCriticalSection",
        "DeleteCriticalSection", "InitializeCriticalSectionAndSpinCount",
        "IsProcessorFeaturePresent",
        "InitializeSListHead",   "EncodePointer",
        "DecodePointer",
        "GetACP",                "GetOEMCP",
        "GetConsoleOutputCP",    "IsValidCodePage",
        "GetCPInfo",             "MultiByteToWideChar",
        "WideCharToMultiByte",   "GetCommandLineA",
        "GetCommandLineW",       "GetEnvironmentStringsW",
        "FreeEnvironmentStringsW", "GetStringTypeW",
        "LCMapStringW",          "GetFileType",
        "GetStdHandle",          "SetStdHandle",
        "WriteFile",             "WriteConsoleW",
        "GetConsoleMode",        "FlushFileBuffers",
        "GetStartupInfoW",       "CloseHandle",
        "ExitProcess",           "TerminateProcess",
    };
    register_context contexts[4] = {{false}, {false}, {false}, {false}};
    thrd_t threads[4];
    for (size_t index = 0U; index < 4U; ++index) {
        CHECK(thrd_create(&threads[index], register_kernel32_on_thread,
                          &contexts[index]) == thrd_success);
    }
    for (size_t index = 0U; index < 4U; ++index) {
        int result = 1;
        CHECK(thrd_join(threads[index], &result) == thrd_success);
        CHECK(result == 0 && contexts[index].passed);
    }

    sl_module_registry registry;
    sl_module_registry_init(&registry);
    CHECK(sl_kernel32_register(&registry) == SL_OK);
    for (size_t index = 0U;
         index < sizeof(implemented) / sizeof(implemented[0]); ++index) {
        sl_resolved_symbol resolved;
        CHECK(resolve_name(&registry, implemented[index], &resolved) == SL_OK);
        CHECK(resolved.is_native);
        CHECK(resolved.guest_address != 0U);
    }

    sl_resolved_symbol resolved;
    CHECK(resolve_name(&registry, "getlasterror", &resolved) ==
          SL_ERROR_EXPORT_NOT_FOUND);
    CHECK(resolve_name(&registry, "GetLastError", &resolved) == SL_OK);
    typedef uint32_t(SL_WINAPI *get_last_error_function)(void);
    get_last_error_function function = NULL;
    uintptr_t address = (uintptr_t)resolved.guest_address;
    _Static_assert(sizeof(function) <= sizeof(address),
                   "native function pointer does not fit uintptr_t");
    memcpy(&function, &address, sizeof(function));
    sl_kernel32_set_last_error(UINT32_C(0x12345678));
    CHECK(function() == UINT32_C(0x12345678));

    CHECK(resolve_name(&registry, "WideCharToMultiByte", &resolved) == SL_OK);
    typedef int32_t(SL_WINAPI *wide_to_multi_function)(
        uint32_t, uint32_t, const uint16_t *, int32_t, char *, int32_t,
        const char *, sl_win32_bool *);
    wide_to_multi_function convert = NULL;
    address = (uintptr_t)resolved.guest_address;
    _Static_assert(sizeof(convert) <= sizeof(address),
                   "native function pointer does not fit uintptr_t");
    memcpy(&convert, &address, sizeof(convert));
    const uint16_t wide[] = {'O', 'K', 0U};
    char narrow[3] = {0};
    CHECK(convert(SL_WIN32_CP_UTF8, SL_WIN32_WC_ERR_INVALID_CHARS, wide, -1,
                  narrow, (int32_t)sizeof(narrow), NULL, NULL) == 3);
    CHECK(memcmp(narrow, "OK", sizeof(narrow)) == 0);

    CHECK(resolve_name(&registry, "WriteFile", &resolved) == SL_OK);
    typedef sl_win32_bool(SL_WINAPI *write_file_function)(
        void *, const void *, uint32_t, uint32_t *, void *);
    write_file_function write_file = NULL;
    address = (uintptr_t)resolved.guest_address;
    _Static_assert(sizeof(write_file) <= sizeof(address),
                   "native function pointer does not fit uintptr_t");
    memcpy(&write_file, &address, sizeof(write_file));
    uint32_t bytes_written = 99U;
    CHECK(write_file(NULL, "x", 1U, &bytes_written, NULL) == SL_WIN32_FALSE);
    CHECK(bytes_written == 0U);
    CHECK(sl_kernel32_get_last_error() == 6U);
    return true;
}

typedef struct {
    uint32_t tls_index;
    uint32_t error_value;
    uintptr_t tls_value;
    bool passed;
} thread_context;

static int test_thread_state(void *opaque) {
    thread_context *context = opaque;
    sl_kernel32_set_last_error(context->error_value);
    context->passed = sl_kernel32_tls_set_value(
                          context->tls_index, (void *)context->tls_value) ==
                          SL_WIN32_TRUE &&
                      (uintptr_t)sl_kernel32_tls_get_value(context->tls_index) ==
                          context->tls_value &&
                      sl_kernel32_get_last_error() == 0U;
    sl_kernel32_set_last_error(context->error_value);
    context->passed = context->passed &&
                      sl_kernel32_get_last_error() == context->error_value;
    return context->passed ? 0 : 1;
}

static bool test_last_error_and_tls(void) {
    uint32_t index = sl_kernel32_tls_alloc();
    CHECK(index != SL_WIN32_TLS_OUT_OF_INDEXES);
    sl_kernel32_set_last_error(99U);
    CHECK(sl_kernel32_tls_get_value(index) == NULL);
    CHECK(sl_kernel32_get_last_error() == 0U);
    CHECK(sl_kernel32_tls_set_value(index, (void *)(uintptr_t)0x1111U) ==
          SL_WIN32_TRUE);

    thread_context context = {index, 77U, (uintptr_t)0x2222U, false};
    thrd_t thread;
    CHECK(thrd_create(&thread, test_thread_state, &context) == thrd_success);
    int result = 1;
    CHECK(thrd_join(thread, &result) == thrd_success);
    CHECK(result == 0);
    CHECK(context.passed);
    CHECK((uintptr_t)sl_kernel32_tls_get_value(index) == (uintptr_t)0x1111U);
    CHECK(sl_kernel32_tls_free(index) == SL_WIN32_TRUE);
    CHECK(sl_kernel32_tls_get_value(index) == NULL);
    CHECK(sl_kernel32_get_last_error() == 87U);

    uint32_t reused = sl_kernel32_tls_alloc();
    CHECK(reused == index);
    CHECK(sl_kernel32_tls_get_value(reused) == NULL);
    CHECK(sl_kernel32_tls_free(reused) == SL_WIN32_TRUE);
    return true;
}

typedef struct {
    uint32_t index;
    atomic_bool at_commit;
    atomic_bool may_commit;
    sl_win32_bool set_result;
    uint32_t set_error;
    void *value_after_reuse;
} tls_aba_context;

static void pause_local_set_before_commit(void *opaque) {
    tls_aba_context *context = opaque;
    atomic_store_explicit(&context->at_commit, true, memory_order_release);
    while (!atomic_load_explicit(&context->may_commit, memory_order_acquire)) {
        thrd_yield();
    }
}

static int set_tls_during_reuse(void *opaque) {
    tls_aba_context *context = opaque;
    context->set_result = sl_kernel32_tls_set_value(
        context->index, (void *)(uintptr_t)0xabcdefU);
    context->set_error = sl_kernel32_get_last_error();
    context->value_after_reuse =
        sl_kernel32_tls_get_value(context->index);
    return 0;
}

static bool test_tls_concurrent_reuse(void) {
    uint32_t index = sl_kernel32_tls_alloc();
    CHECK(index != SL_WIN32_TLS_OUT_OF_INDEXES);
    tls_aba_context context = {
        .index = index,
        .at_commit = ATOMIC_VAR_INIT(false),
        .may_commit = ATOMIC_VAR_INIT(false),
        .set_result = SL_WIN32_TRUE,
        .set_error = 0U,
        .value_after_reuse = (void *)(uintptr_t)1U,
    };
    sl_kernel32_test_set_local_set_hook(pause_local_set_before_commit,
                                       &context);
    thrd_t setter;
    CHECK(thrd_create(&setter, set_tls_during_reuse, &context) ==
          thrd_success);
    while (!atomic_load_explicit(&context.at_commit, memory_order_acquire)) {
        thrd_yield();
    }

    CHECK(sl_kernel32_tls_free(index) == SL_WIN32_TRUE);
    uint32_t reused = sl_kernel32_tls_alloc();
    CHECK(reused == index);
    atomic_store_explicit(&context.may_commit, true, memory_order_release);
    int result = 1;
    CHECK(thrd_join(setter, &result) == thrd_success);
    sl_kernel32_test_set_local_set_hook(NULL, NULL);

    CHECK(result == 0);
    CHECK(context.set_result == SL_WIN32_FALSE);
    CHECK(context.set_error == 87U);
    CHECK(context.value_after_reuse == NULL);
    CHECK(sl_kernel32_tls_get_value(reused) == NULL);
    CHECK(sl_kernel32_tls_free(reused) == SL_WIN32_TRUE);
    return true;
}

static bool test_context_scopes(void) {
    sl_kernel32_set_last_error(11U);
    sl_win32_thread_context first = {
        .process = NULL,
        .last_error = 22U,
        .thread_id = 0U,
    };
    sl_win32_thread_context second = {
        .process = NULL,
        .last_error = 44U,
        .thread_id = 0U,
    };
    sl_win32_context_scope first_scope;
    sl_win32_context_scope second_scope;

    CHECK(sl_win32_context_current() == NULL);
    CHECK(sl_win32_context_enter(&first, &first_scope) == SL_OK);
    CHECK(sl_win32_context_current() == &first);
    CHECK(sl_kernel32_get_last_error() == 22U);
    sl_kernel32_set_last_error(33U);
    uint32_t first_id = sl_kernel32_get_current_thread_id();
    CHECK(first_id != 0U && first.thread_id == first_id);

    CHECK(sl_win32_context_enter(&second, &second_scope) == SL_OK);
    CHECK(sl_kernel32_get_last_error() == 44U);
    uint32_t second_id = sl_kernel32_get_current_thread_id();
    CHECK(second_id != 0U && second_id != first_id);
    CHECK(sl_win32_context_leave(&first_scope) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(sl_win32_context_current() == &second);
    CHECK(sl_win32_context_leave(&second_scope) == SL_OK);
    CHECK(sl_win32_context_current() == &first);
    CHECK(sl_kernel32_get_last_error() == 33U);
    CHECK(sl_kernel32_get_current_thread_id() == first_id);
    CHECK(sl_win32_context_leave(&first_scope) == SL_OK);
    CHECK(sl_win32_context_current() == NULL);
    CHECK(sl_kernel32_get_last_error() == 11U);
    CHECK(sl_win32_context_leave(&first_scope) == SL_ERROR_INVALID_ARGUMENT);
    return true;
}

static bool test_process_pointer_cookie(void) {
    sl_win32_process *first_process = NULL;
    sl_win32_process *second_process = NULL;
    CHECK(sl_win32_process_create(NULL) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(sl_win32_process_create(&first_process) == SL_OK);
    CHECK(sl_win32_process_create(&second_process) == SL_OK);

    sl_module_registry registry;
    sl_module_registry_init(&registry);
    CHECK(sl_kernel32_register(&registry) == SL_OK);
    sl_resolved_symbol resolved;
    typedef void *(SL_WINAPI *pointer_function)(void *);
    pointer_function encode = NULL;
    pointer_function decode = NULL;
    uintptr_t address = 0U;

    CHECK(resolve_name(&registry, "EncodePointer", &resolved) == SL_OK);
    address = (uintptr_t)resolved.guest_address;
    _Static_assert(sizeof(encode) <= sizeof(address),
                   "native function pointer does not fit uintptr_t");
    memcpy(&encode, &address, sizeof(encode));
    CHECK(resolve_name(&registry, "DecodePointer", &resolved) == SL_OK);
    address = (uintptr_t)resolved.guest_address;
    _Static_assert(sizeof(decode) <= sizeof(address),
                   "native function pointer does not fit uintptr_t");
    memcpy(&decode, &address, sizeof(decode));

    sl_win32_thread_context first_thread = {
        .process = first_process,
        .last_error = UINT32_C(0x13572468),
        .thread_id = 0U,
    };
    sl_win32_thread_context second_thread = {
        .process = second_process,
        .last_error = UINT32_C(0x24681357),
        .thread_id = 0U,
    };
    sl_win32_context_scope first_scope;
    sl_win32_context_scope second_scope;
    CHECK(sl_win32_context_enter(&first_thread, &first_scope) == SL_OK);

    void *encoded_null = encode(NULL);
    CHECK(encoded_null != NULL);
    CHECK(decode(encoded_null) == NULL);
    int object = 0;
    void *encoded_object = encode(&object);
    CHECK(decode(encoded_object) == &object);
    CHECK(encode(&object) == encoded_object);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x13572468));

    CHECK(sl_win32_context_enter(&second_thread, &second_scope) == SL_OK);
    void *second_encoded_null = encode(NULL);
    CHECK(second_encoded_null != NULL);
    CHECK(decode(second_encoded_null) == NULL);
    CHECK(decode(encode(&object)) == &object);
    CHECK(sl_kernel32_get_last_error() == UINT32_C(0x24681357));
    CHECK(sl_win32_context_leave(&second_scope) == SL_OK);
    CHECK(encode(NULL) == encoded_null);
    CHECK(sl_win32_context_leave(&first_scope) == SL_OK);

    sl_win32_process_destroy(second_process);
    sl_win32_process_destroy(first_process);
    return true;
}

static atomic_uintptr_t fls_callback_value;

static void SL_WINAPI capture_fls_value(void *value) {
    atomic_store_explicit(&fls_callback_value, (uintptr_t)value,
                          memory_order_relaxed);
}

static uintptr_t fls_callback_address(void) {
    typedef void(SL_WINAPI *callback_function)(void *);
    callback_function callback = capture_fls_value;
    uintptr_t address = 0U;
    _Static_assert(sizeof(callback) <= sizeof(address),
                   "FLS callback pointer does not fit uintptr_t");
    memcpy(&address, &callback, sizeof(callback));
    return address;
}

static bool test_fls_lifecycle(void) {
    atomic_store_explicit(&fls_callback_value, 0U, memory_order_relaxed);
    uint32_t index = sl_kernel32_fls_alloc(fls_callback_address());
    CHECK(index != SL_WIN32_TLS_OUT_OF_INDEXES);
    CHECK(sl_kernel32_fls_set_value(index, (void *)(uintptr_t)0x4455U) ==
          SL_WIN32_TRUE);
    CHECK((uintptr_t)sl_kernel32_fls_get_value(index) == (uintptr_t)0x4455U);
    CHECK(sl_kernel32_fls_free(index) == SL_WIN32_TRUE);
    CHECK(atomic_load_explicit(&fls_callback_value, memory_order_relaxed) ==
          (uintptr_t)0x4455U);
    return true;
}

static bool test_heap_contract(void) {
    void *heap = sl_kernel32_get_process_heap();
    CHECK(heap != NULL);
    sl_kernel32_set_last_error(123U);
    uint8_t *memory = sl_kernel32_heap_alloc(heap, 0x8U, 32U);
    CHECK(memory != NULL);
    CHECK((uintptr_t)memory % alignof(max_align_t) == 0U);
    for (size_t index = 0U; index < 32U; ++index) {
        CHECK(memory[index] == 0U);
    }
    CHECK(sl_kernel32_get_last_error() == 123U);
    memset(memory, 0x5a, 16U);
    memory = sl_kernel32_heap_realloc(heap, 0x8U, memory, 64U);
    CHECK(memory != NULL);
    for (size_t index = 0U; index < 16U; ++index) {
        CHECK(memory[index] == 0x5aU);
    }
    for (size_t index = 32U; index < 64U; ++index) {
        CHECK(memory[index] == 0U);
    }
    CHECK(sl_kernel32_heap_size(heap, 0U, memory) == 64U);
    uint8_t *same = sl_kernel32_heap_realloc(heap, 0x10U, memory, 48U);
    CHECK(same == memory);
    CHECK(sl_kernel32_heap_size(heap, 0U, memory) == 48U);
    CHECK(sl_kernel32_heap_realloc(heap, 0x10U, memory, 96U) == NULL);
    CHECK(sl_kernel32_heap_free(heap, 0U, memory) == SL_WIN32_TRUE);
    CHECK(sl_kernel32_heap_alloc(NULL, 0U, 4U) == NULL);
    CHECK(sl_kernel32_get_last_error() == 123U);
    return true;
}

static bool test_character_conversion(void) {
    static const char utf8[] = "A\xf0\x9f\x90\x9b";
    uint16_t wide[4] = {0U, 0U, 0U, 0U};
    sl_kernel32_set_last_error(0x1234U);
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_UTF8, SL_WIN32_MB_ERR_INVALID_CHARS, utf8, -1, NULL,
              0) == 4);
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_UTF8, SL_WIN32_MB_ERR_INVALID_CHARS, utf8, -1, wide,
              4) == 4);
    CHECK(wide[0] == (uint16_t)'A');
    CHECK(wide[1] == 0xd83dU);
    CHECK(wide[2] == 0xdc1bU);
    CHECK(wide[3] == 0U);
    CHECK(sl_kernel32_get_last_error() == 0x1234U);

    char roundtrip[6] = {0};
    CHECK(sl_kernel32_wide_char_to_multi_byte(
              SL_WIN32_CP_UTF8, SL_WIN32_WC_ERR_INVALID_CHARS, wide, -1,
              roundtrip, (int32_t)sizeof(roundtrip), NULL, NULL) == 6);
    CHECK(memcmp(roundtrip, utf8, sizeof(utf8)) == 0);

    const char embedded[] = {'A', '\0', 'B'};
    uint16_t embedded_wide[3] = {0U, 0U, 0U};
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_UTF8, SL_WIN32_MB_ERR_INVALID_CHARS, embedded, 3,
              embedded_wide, 3) == 3);
    CHECK(embedded_wide[0] == (uint16_t)'A');
    CHECK(embedded_wide[1] == 0U);
    CHECK(embedded_wide[2] == (uint16_t)'B');

    const char invalid[] = {(char)0xff};
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_UTF8, SL_WIN32_MB_ERR_INVALID_CHARS, invalid, 1,
              wide, 4) == 0);
    CHECK(sl_kernel32_get_last_error() == 1113U);
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_UTF8, 0U, invalid, 1, wide, 4) == 1);
    CHECK(wide[0] == 0xfffdU);

    const uint16_t invalid_wide[] = {0xd800U};
    CHECK(sl_kernel32_wide_char_to_multi_byte(
              SL_WIN32_CP_UTF8, SL_WIN32_WC_ERR_INVALID_CHARS, invalid_wide, 1,
              roundtrip, (int32_t)sizeof(roundtrip), NULL, NULL) == 0);
    CHECK(sl_kernel32_get_last_error() == 1113U);
    CHECK(sl_kernel32_wide_char_to_multi_byte(
              SL_WIN32_CP_UTF8, 0U, invalid_wide, 1, roundtrip,
              (int32_t)sizeof(roundtrip), NULL, NULL) == 3);
    CHECK(memcmp(roundtrip, "\xef\xbf\xbd", 3U) == 0);

    const char cp1252_euro[] = {(char)0x80};
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_ACP, 0U, cp1252_euro, 1, wide, 4) == 1);
    CHECK(wide[0] == 0x20acU);
    const char cp437_e_acute[] = {(char)0x82};
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_OEMCP, 0U, cp437_e_acute, 1, wide, 4) == 1);
    CHECK(wide[0] == 0x00e9U);

    const char undefined_cp1252[] = {(char)0x81};
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              1252U, SL_WIN32_MB_ERR_INVALID_CHARS, undefined_cp1252, 1, wide,
              4) == 0);
    CHECK(sl_kernel32_get_last_error() == 1113U);
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              1252U, 0U, undefined_cp1252, 1, wide, 4) == 1);
    CHECK(wide[0] == 0xfffdU);

    const uint16_t unrepresentable[] = {0x0100U};
    sl_win32_bool used_default = SL_WIN32_FALSE;
    char replacement = '!';
    CHECK(sl_kernel32_wide_char_to_multi_byte(
              1252U, 0U, unrepresentable, 1, roundtrip,
              (int32_t)sizeof(roundtrip), &replacement, &used_default) == 1);
    CHECK(roundtrip[0] == '!');
    CHECK(used_default == SL_WIN32_TRUE);

    uint16_t unchanged[2] = {0xaaaaU, 0xbbbbU};
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_UTF8, SL_WIN32_MB_ERR_INVALID_CHARS, "AB", 2,
              unchanged, 1) == 0);
    CHECK(sl_kernel32_get_last_error() == 122U);
    CHECK(unchanged[0] == 0xaaaaU && unchanged[1] == 0xbbbbU);
    CHECK(sl_kernel32_multi_byte_to_wide_char(
              SL_WIN32_CP_UTF8, 1U, "A", 1, wide, 4) == 0);
    CHECK(sl_kernel32_get_last_error() == 1004U);
    return true;
}

static bool test_process_strings(void) {
    static const char command[] =
        "\"C:\\Games\\Hollow Knight\\hollow_knight.exe\" \xf0\x9f\x90\x9b";
    CHECK(sl_kernel32_set_command_line_utf8(command) == SL_OK);
    CHECK(sl_kernel32_get_command_line_a() == sl_kernel32_get_command_line_a());
    CHECK(sl_kernel32_get_command_line_w() == sl_kernel32_get_command_line_w());
    CHECK(strstr(sl_kernel32_get_command_line_a(), "hollow_knight.exe") != NULL);
    size_t command_units = 0U;
    while (sl_kernel32_get_command_line_w()[command_units] != 0U) {
        ++command_units;
    }
    CHECK(command_units >= 2U);
    CHECK(sl_kernel32_get_command_line_w()[command_units - 2U] == 0xd83dU);
    CHECK(sl_kernel32_get_command_line_w()[command_units - 1U] == 0xdc1bU);
    size_t ansi_length = strlen(sl_kernel32_get_command_line_a());
    CHECK(ansi_length != 0U);
    CHECK(sl_kernel32_get_command_line_a()[ansi_length - 1U] == '?');

    uint16_t *first = sl_kernel32_get_environment_strings_w();
    uint16_t *second = sl_kernel32_get_environment_strings_w();
    CHECK(first != NULL && second != NULL && first != second);
    size_t offset = 0U;
    bool previous_was_zero = false;
    for (size_t limit = 0U; limit < 1024U * 1024U; ++limit) {
        bool is_zero = first[offset] == 0U;
        ++offset;
        if (is_zero && previous_was_zero) {
            break;
        }
        previous_was_zero = is_zero;
    }
    CHECK(offset >= 2U);
    CHECK(first[offset - 1U] == 0U && first[offset - 2U] == 0U);
    CHECK(sl_kernel32_free_environment_strings_w(first) == SL_WIN32_TRUE);
    CHECK(sl_kernel32_free_environment_strings_w(first) == SL_WIN32_FALSE);
    CHECK(sl_kernel32_get_last_error() == 87U);
    CHECK(sl_kernel32_free_environment_strings_w(second) == SL_WIN32_TRUE);
    return true;
}

static bool test_locale_primitives(void) {
    static const uint16_t text[] = {'A', 'f', '0', ' ', '\t', '\n', '!', 0U};
    uint16_t types[sizeof(text) / sizeof(text[0])] = {0U};
    sl_kernel32_set_last_error(0x4455U);
    CHECK(sl_kernel32_get_string_type_w(SL_WIN32_CT_CTYPE1, text, -1,
                                        types) == SL_WIN32_TRUE);
    CHECK(types[0] == (SL_WIN32_C1_UPPER | SL_WIN32_C1_ALPHA |
                       SL_WIN32_C1_XDIGIT));
    CHECK(types[1] == (SL_WIN32_C1_LOWER | SL_WIN32_C1_ALPHA |
                       SL_WIN32_C1_XDIGIT));
    CHECK(types[2] == (SL_WIN32_C1_DIGIT | SL_WIN32_C1_XDIGIT));
    CHECK(types[3] == (SL_WIN32_C1_SPACE | SL_WIN32_C1_BLANK));
    CHECK(types[4] == (SL_WIN32_C1_SPACE | SL_WIN32_C1_CNTRL |
                       SL_WIN32_C1_BLANK));
    CHECK(types[5] == (SL_WIN32_C1_SPACE | SL_WIN32_C1_CNTRL));
    CHECK(types[6] == SL_WIN32_C1_PUNCT);
    CHECK(types[7] == SL_WIN32_C1_CNTRL);
    CHECK(sl_kernel32_get_last_error() == 0x4455U);

    static const uint16_t latin[] = {0x00c7U, 0x00e9U, 0x00dfU};
    uint16_t latin_types[3] = {0U, 0U, 0U};
    CHECK(sl_kernel32_get_string_type_w(SL_WIN32_CT_CTYPE1, latin, 3,
                                        latin_types) == SL_WIN32_TRUE);
    CHECK(latin_types[0] == (SL_WIN32_C1_UPPER | SL_WIN32_C1_ALPHA));
    CHECK(latin_types[1] == (SL_WIN32_C1_LOWER | SL_WIN32_C1_ALPHA));
    CHECK(latin_types[2] == (SL_WIN32_C1_LOWER | SL_WIN32_C1_ALPHA));

    static const uint16_t mixed[] = {'A', 'b', 0x00c7U, 0U};
    CHECK(sl_kernel32_lc_map_string_w(
              0x007fU, SL_WIN32_LCMAP_LOWERCASE, mixed, -1, NULL, 0) == 4);
    uint16_t lowered[4] = {0xffffU, 0xffffU, 0xffffU, 0xffffU};
    CHECK(sl_kernel32_lc_map_string_w(
              0x007fU, SL_WIN32_LCMAP_LOWERCASE, mixed, -1, lowered, 4) == 4);
    CHECK(lowered[0] == (uint16_t)'a' && lowered[1] == (uint16_t)'b');
    CHECK(lowered[2] == 0x00e7U && lowered[3] == 0U);

    uint16_t upper[] = {'a', 'z', 0x00e9U, 0x00ffU, 0x00dfU};
    CHECK(sl_kernel32_lc_map_string_w(
              0x0416U, SL_WIN32_LCMAP_UPPERCASE, upper, 5, upper, 5) == 5);
    CHECK(upper[0] == (uint16_t)'A' && upper[1] == (uint16_t)'Z');
    CHECK(upper[2] == 0x00c9U && upper[3] == 0x0178U);
    CHECK(upper[4] == 0x00dfU);

    uint16_t unchanged[2] = {0xaaaaU, 0xbbbbU};
    CHECK(sl_kernel32_lc_map_string_w(
              0x007fU, SL_WIN32_LCMAP_LOWERCASE, mixed, 2, unchanged, 1) == 0);
    CHECK(sl_kernel32_get_last_error() == 122U);
    CHECK(unchanged[0] == 0xaaaaU && unchanged[1] == 0xbbbbU);
    CHECK(sl_kernel32_lc_map_string_w(0x007fU, 0x300U, mixed, 2, unchanged,
                                      2) == 0);
    CHECK(sl_kernel32_get_last_error() == 1004U);
    CHECK(sl_kernel32_lc_map_string_w(
              0x007fU,
              SL_WIN32_LCMAP_LOWERCASE | SL_WIN32_LCMAP_LINGUISTIC_CASING,
              mixed, 2, unchanged, 2) == 0);
    CHECK(sl_kernel32_get_last_error() == 1004U);
    CHECK(sl_kernel32_lc_map_string_w(
              0U, SL_WIN32_LCMAP_LOWERCASE, mixed, 2, unchanged, 2) == 0);
    CHECK(sl_kernel32_get_last_error() == 87U);
    return true;
}

static bool test_time_and_identity(void) {
    CHECK(sl_kernel32_get_current_process_id() != 0U);
    uint32_t thread_id = sl_kernel32_get_current_thread_id();
    CHECK(thread_id != 0U);
    CHECK(sl_kernel32_get_current_thread_id() == thread_id);
    CHECK(sl_kernel32_get_current_process() != NULL);
    CHECK(sl_kernel32_is_debugger_present() == SL_WIN32_FALSE);

    int64_t frequency = 0;
    int64_t before = 0;
    int64_t after = 0;
    CHECK(sl_kernel32_query_performance_frequency(&frequency) == SL_WIN32_TRUE);
    CHECK(frequency == INT64_C(1000000000));
    CHECK(sl_kernel32_query_performance_counter(&before) == SL_WIN32_TRUE);
    CHECK(sl_kernel32_query_performance_counter(&after) == SL_WIN32_TRUE);
    CHECK(after >= before);

    sl_win32_filetime filetime = {0U, 0U};
    sl_kernel32_get_system_time_as_file_time(&filetime);
    uint64_t ticks = (uint64_t)filetime.low_date_time |
                     ((uint64_t)filetime.high_date_time << 32U);
    CHECK(ticks > UINT64_C(11644473600) * UINT64_C(10000000));
    return true;
}

static bool test_critical_section_and_cpu(void) {
    _Alignas(16) uint8_t critical_section[40] = {0};
    CHECK(sl_kernel32_initialize_critical_section_and_spin_count(
              critical_section, 4000U) == SL_WIN32_TRUE);
    sl_kernel32_set_last_error(0U);
    sl_kernel32_enter_critical_section(critical_section);
    sl_kernel32_enter_critical_section(critical_section);
    sl_kernel32_leave_critical_section(critical_section);
    sl_kernel32_leave_critical_section(critical_section);
    CHECK(sl_kernel32_get_last_error() == 0U);
    sl_kernel32_delete_critical_section(critical_section);
    for (size_t index = 0U; index < sizeof(critical_section); ++index) {
        CHECK(critical_section[index] == 0U);
    }
    CHECK(sl_kernel32_is_processor_feature_present(10U) == SL_WIN32_TRUE);
    CHECK(sl_kernel32_is_processor_feature_present(UINT32_MAX) ==
          SL_WIN32_FALSE);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"export surface and ms ABI", test_export_surface_and_abi},
        {"last-error and TLS", test_last_error_and_tls},
        {"TLS concurrent index reuse", test_tls_concurrent_reuse},
        {"nested thread contexts", test_context_scopes},
        {"process pointer cookie", test_process_pointer_cookie},
        {"FLS lifecycle", test_fls_lifecycle},
        {"heap contract", test_heap_contract},
        {"time and identity", test_time_and_identity},
        {"critical section and CPU", test_critical_section_and_cpu},
        {"character conversion", test_character_conversion},
        {"process strings", test_process_strings},
        {"locale primitives", test_locale_primitives},
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
    printf("%zu kernel32 tests passed\n", passed);
    return 0;
}
