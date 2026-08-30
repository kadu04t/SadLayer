#include "sadlayer/context.h"
#include "sadlayer/kernel32.h"
#include "sadlayer/process.h"
#include "sadlayer/teb.h"

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            return false;                                                       \
        }                                                                      \
    } while (false)

static uintptr_t load_uintptr(const uint8_t *source) {
    uintptr_t value = 0U;
    memcpy(&value, source, sizeof(value));
    return value;
}

static uint32_t load_u32(const uint8_t *source) {
    uint32_t value = 0U;
    memcpy(&value, source, sizeof(value));
    return value;
}

typedef struct {
    sl_win32_thread_context *thread;
    atomic_bool entered;
    atomic_bool may_leave;
    sl_status enter_status;
    sl_status leave_status;
} active_context_probe;

static int hold_context_on_worker(void *opaque) {
    active_context_probe *probe = opaque;
    sl_win32_context_scope scope;
    probe->enter_status = sl_win32_context_enter(probe->thread, &scope);
    atomic_store_explicit(&probe->entered, true, memory_order_release);
    if (probe->enter_status != SL_OK) {
        return 0;
    }
    while (!atomic_load_explicit(&probe->may_leave, memory_order_acquire)) {
        thrd_yield();
    }
    probe->leave_status = sl_win32_context_leave(&scope);
    return 0;
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

static bool test_process_bootstrap_layout(void) {
    sl_win32_process *process = NULL;
    CHECK(sl_win32_process_create(&process) == SL_OK);
    CHECK(sl_win32_process_set_image_base(process, UINT64_C(0x140000000)) ==
          SL_OK);
    uint8_t *peb = sl_win32_process_peb(process);
    uint8_t *parameters = sl_win32_process_parameters(process);
    CHECK(peb != NULL && parameters != NULL);
    CHECK(load_uintptr(peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET) ==
          (uintptr_t)UINT64_C(0x140000000));
    CHECK(load_uintptr(peb + SL_WIN32_PEB_PROCESS_PARAMETERS_OFFSET) ==
          (uintptr_t)parameters);
    CHECK(load_uintptr(peb + SL_WIN32_PEB_PROCESS_HEAP_OFFSET) == 4U);
    CHECK(load_u32(peb + SL_WIN32_PEB_NT_GLOBAL_FLAG_OFFSET) == 0U);
    CHECK(load_u32(parameters + SL_WIN32_PROCESS_PARAMETERS_FLAGS_OFFSET) ==
          SL_WIN32_PROCESS_PARAMETERS_NORMALIZED);
    CHECK(sl_win32_process_destroy(process) == SL_OK);
    return true;
}

static bool test_teb_layout_and_last_error_alias(void) {
    const uintptr_t stack_limit = UINT64_C(0x70000000);
    const uintptr_t stack_base = UINT64_C(0x70100000);
    sl_win32_process *process = NULL;
    sl_win32_teb *teb = NULL;
    CHECK(sl_win32_process_create(&process) == SL_OK);
    sl_win32_thread_context thread = {
        .process = process,
        .last_error = 30U,
        .thread_id = 20U,
        .teb = NULL,
        .last_error_address = NULL,
    };
    CHECK(sl_win32_teb_create(&thread, stack_base, stack_limit, &teb) ==
          SL_ERROR_INVALID_ARGUMENT);
    CHECK(teb == NULL);
    CHECK(sl_win32_teb_create(&thread, stack_limit, stack_base, &teb) == SL_OK);
    sl_win32_teb *duplicate = (sl_win32_teb *)(uintptr_t)1U;
    CHECK(sl_win32_teb_create(&thread, stack_limit, stack_base, &duplicate) ==
          SL_ERROR_INVALID_STATE);
    CHECK(duplicate == NULL);
    uint8_t *base = sl_win32_teb_base(teb);
    CHECK(base != NULL);
    CHECK(load_uintptr(base + SL_WIN32_TEB_STACK_BASE_OFFSET) == stack_base);
    CHECK(load_uintptr(base + SL_WIN32_TEB_STACK_LIMIT_OFFSET) == stack_limit);
    CHECK(load_uintptr(base + SL_WIN32_TEB_SELF_OFFSET) == (uintptr_t)base);
    CHECK(load_uintptr(base + SL_WIN32_TEB_PROCESS_ID_OFFSET) ==
          (uintptr_t)(uint32_t)getpid());
    CHECK(load_uintptr(base + SL_WIN32_TEB_THREAD_ID_OFFSET) == 20U);
    CHECK(load_uintptr(base + SL_WIN32_TEB_TLS_POINTER_OFFSET) == 0U);
    CHECK(load_uintptr(base + SL_WIN32_TEB_PEB_OFFSET) ==
          (uintptr_t)sl_win32_process_peb(process));
    CHECK(*sl_win32_teb_last_error(teb) == 30U);

    long page_value = sysconf(_SC_PAGESIZE);
    CHECK(page_value > 0L);
    size_t page_size = (size_t)page_value;
    char permissions[5] = {0};
    CHECK(read_mapping_permissions(base - page_size, permissions));
    CHECK(memcmp(permissions, "---", 3U) == 0);
    CHECK(read_mapping_permissions(base, permissions));
    CHECK(memcmp(permissions, "rw-", 3U) == 0);
    CHECK(read_mapping_permissions(base + 2U * page_size, permissions));
    CHECK(memcmp(permissions, "---", 3U) == 0);

    thread.last_error = 35U;
    CHECK(sl_win32_thread_attach_teb(&thread, teb) == SL_OK);
    CHECK(sl_win32_teb_destroy(teb) == SL_ERROR_INVALID_STATE);
    CHECK(sl_win32_process_destroy(process) == SL_ERROR_INVALID_STATE);
    CHECK(thread.teb == base);
    CHECK(thread.last_error_address == sl_win32_teb_last_error(teb));
    sl_win32_context_scope scope;
    CHECK(sl_win32_context_enter(&thread, &scope) == SL_OK);
    CHECK(sl_kernel32_get_last_error() == 35U);
    CHECK(sl_kernel32_get_current_thread_id() == 20U);
    sl_win32_thread_context nested = {
        .process = process,
        .last_error = 60U,
        .thread_id = 21U,
    };
    sl_win32_context_scope nested_scope;
    CHECK(sl_win32_context_enter(&nested, &nested_scope) == SL_OK);
    CHECK(sl_win32_thread_detach_teb(&thread, teb) ==
          SL_ERROR_INVALID_STATE);
    CHECK(sl_win32_context_leave(&nested_scope) == SL_OK);
    sl_kernel32_set_last_error(40U);
    CHECK(*sl_win32_teb_last_error(teb) == 40U);
    *sl_win32_teb_last_error(teb) = 50U;
    CHECK(sl_kernel32_get_last_error() == 50U);
    CHECK(sl_win32_thread_detach_teb(&thread, teb) == SL_ERROR_INVALID_STATE);
    CHECK(sl_win32_context_leave(&scope) == SL_OK);
    active_context_probe probe = {
        .thread = &thread,
        .enter_status = SL_ERROR_INVALID_STATE,
        .leave_status = SL_ERROR_INVALID_STATE,
    };
    atomic_init(&probe.entered, false);
    atomic_init(&probe.may_leave, false);
    thrd_t worker;
    CHECK(thrd_create(&worker, hold_context_on_worker, &probe) ==
          thrd_success);
    while (!atomic_load_explicit(&probe.entered, memory_order_acquire)) {
        thrd_yield();
    }
    sl_status cross_thread_detach =
        sl_win32_thread_detach_teb(&thread, teb);
    atomic_store_explicit(&probe.may_leave, true, memory_order_release);
    int worker_result = 1;
    CHECK(thrd_join(worker, &worker_result) == thrd_success);
    CHECK(worker_result == 0 && probe.enter_status == SL_OK &&
          probe.leave_status == SL_OK);
    CHECK(cross_thread_detach == SL_ERROR_INVALID_STATE);
    CHECK(sl_win32_thread_detach_teb(&thread, teb) == SL_OK);
    CHECK(thread.last_error == 50U && thread.last_error_address == NULL &&
          thread.teb == NULL);

    CHECK(sl_win32_teb_destroy(teb) == SL_OK);
    CHECK(sl_win32_process_destroy(process) == SL_OK);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"PEB and process parameters layout", test_process_bootstrap_layout},
        {"guarded TEB and last-error alias",
         test_teb_layout_and_last_error_alias},
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
    printf("%zu TEB/PEB tests passed\n", passed);
    return 0;
}
