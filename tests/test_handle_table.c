#include "sadlayer/handle_table.h"
#include "sadlayer/process.h"

#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
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

typedef struct {
    atomic_uint *destroyed;
    uint32_t value;
} test_handle_object;

static void count_destruction(void *opaque) {
    test_handle_object *object = opaque;
    (void)atomic_fetch_add_explicit(object->destroyed, 1U,
                                    memory_order_relaxed);
}

static bool lease_is_empty(const sl_handle_lease *lease) {
    return lease->object == NULL && lease->internal == NULL;
}

static bool test_arguments_and_clean_outputs(void) {
    sl_handle_table *table = (sl_handle_table *)(uintptr_t)1U;
    CHECK(sl_handle_table_create(NULL) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(sl_handle_table_create(&table) == SL_OK);
    CHECK(table != NULL);

    atomic_uint destroyed;
    atomic_init(&destroyed, 0U);
    test_handle_object object = {
        .destroyed = &destroyed,
        .value = 7U,
    };
    sl_handle handle = UINT64_MAX;
    CHECK(sl_handle_table_insert(NULL, SL_HANDLE_KIND_FILE, &object,
                                 count_destruction,
                                 &handle) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(handle == 0U);

    handle = UINT64_MAX;
    CHECK(sl_handle_table_insert(table, (sl_handle_kind)0, &object,
                                 count_destruction,
                                 &handle) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(handle == 0U);
    handle = UINT64_MAX;
    CHECK(sl_handle_table_insert(table, (sl_handle_kind)3, &object,
                                 count_destruction,
                                 &handle) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(handle == 0U);
    handle = UINT64_MAX;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, NULL,
                                 count_destruction,
                                 &handle) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(handle == 0U);
    handle = UINT64_MAX;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &object, NULL,
                                 &handle) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(handle == 0U);
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &object,
                                 count_destruction,
                                 NULL) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 0U);

    sl_handle_lease lease = {
        .object = (void *)(uintptr_t)1U,
        .internal = (void *)(uintptr_t)1U,
    };
    CHECK(sl_handle_table_acquire(NULL, 1U, SL_HANDLE_KIND_FILE, &lease) ==
          SL_ERROR_INVALID_ARGUMENT);
    CHECK(lease_is_empty(&lease));
    lease.object = (void *)(uintptr_t)1U;
    lease.internal = (void *)(uintptr_t)1U;
    CHECK(sl_handle_table_acquire(table, 1U, (sl_handle_kind)0, &lease) ==
          SL_ERROR_INVALID_ARGUMENT);
    CHECK(lease_is_empty(&lease));
    CHECK(sl_handle_table_acquire(table, 1U, SL_HANDLE_KIND_FILE, NULL) ==
          SL_ERROR_INVALID_ARGUMENT);

    CHECK(sl_handle_table_close(NULL, 1U, SL_HANDLE_KIND_FILE) ==
          SL_ERROR_INVALID_ARGUMENT);
    CHECK(sl_handle_table_close(table, 1U, (sl_handle_kind)0) ==
          SL_ERROR_INVALID_ARGUMENT);
    CHECK(sl_handle_table_prepare_clone(NULL) == SL_ERROR_INVALID_ARGUMENT);

    sl_handle_lease empty = {0};
    sl_handle_lease_release(&empty);
    CHECK(lease_is_empty(&empty));
    sl_handle_lease_release(NULL);

    sl_handle_table_destroy(table);
    sl_handle_table_destroy(NULL);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 0U);
    return true;
}

static bool test_lifecycle_kind_and_malformed_handles(void) {
    sl_handle_table *table = NULL;
    atomic_uint destroyed;
    atomic_init(&destroyed, 0U);
    test_handle_object object = {
        .destroyed = &destroyed,
        .value = UINT32_C(0x12345678),
    };
    CHECK(sl_handle_table_create(&table) == SL_OK);

    sl_handle handle = 0U;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &object,
                                 count_destruction, &handle) == SL_OK);
    CHECK(handle != 0U && handle != UINT64_MAX);

    sl_handle_lease lease = {
        .object = (void *)(uintptr_t)1U,
        .internal = (void *)(uintptr_t)1U,
    };
    CHECK(sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_SEARCH,
                                  &lease) ==
          SL_ERROR_HANDLE_TYPE_MISMATCH);
    CHECK(lease_is_empty(&lease));
    CHECK(sl_handle_table_close(table, handle, SL_HANDLE_KIND_SEARCH) ==
          SL_ERROR_HANDLE_TYPE_MISMATCH);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 0U);

    CHECK(sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_FILE,
                                  &lease) == SL_OK);
    CHECK(lease.object == &object && lease.internal != NULL);
    CHECK(((test_handle_object *)lease.object)->value ==
          UINT32_C(0x12345678));
    sl_handle_lease_release(&lease);
    CHECK(lease_is_empty(&lease));
    sl_handle_lease_release(&lease);

    const sl_handle malformed[] = {
        0U,
        1U,
        UINT64_C(0x12345678),
        UINT64_MAX,
        handle ^ (UINT64_C(1) << 63U),
    };
    for (size_t index = 0U;
         index < sizeof(malformed) / sizeof(malformed[0]); ++index) {
        lease.object = (void *)(uintptr_t)1U;
        lease.internal = (void *)(uintptr_t)1U;
        CHECK(sl_handle_table_acquire(table, malformed[index],
                                      SL_HANDLE_KIND_FILE, &lease) ==
              SL_ERROR_HANDLE_NOT_FOUND);
        CHECK(lease_is_empty(&lease));
        CHECK(sl_handle_table_close(table, malformed[index],
                                    SL_HANDLE_KIND_FILE) ==
              SL_ERROR_HANDLE_NOT_FOUND);
    }

    CHECK(sl_handle_table_close(table, handle, SL_HANDLE_KIND_FILE) == SL_OK);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 1U);
    CHECK(sl_handle_table_close(table, handle, SL_HANDLE_KIND_FILE) ==
          SL_ERROR_HANDLE_NOT_FOUND);
    CHECK(sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_FILE, &lease) ==
          SL_ERROR_HANDLE_NOT_FOUND);
    CHECK(lease_is_empty(&lease));

    sl_handle_table_destroy(table);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 1U);
    return true;
}

static bool test_close_defers_destruction_until_release(void) {
    sl_handle_table *table = NULL;
    atomic_uint first_destroyed;
    atomic_uint second_destroyed;
    atomic_init(&first_destroyed, 0U);
    atomic_init(&second_destroyed, 0U);
    test_handle_object first = {
        .destroyed = &first_destroyed,
        .value = 1U,
    };
    test_handle_object second = {
        .destroyed = &second_destroyed,
        .value = 2U,
    };
    CHECK(sl_handle_table_create(&table) == SL_OK);

    sl_handle stale_handle = 0U;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &first,
                                 count_destruction, &stale_handle) == SL_OK);
    sl_handle_lease lease = {0};
    CHECK(sl_handle_table_acquire(table, stale_handle, SL_HANDLE_KIND_FILE,
                                  &lease) == SL_OK);
    CHECK(sl_handle_table_close(table, stale_handle, SL_HANDLE_KIND_FILE) ==
          SL_OK);
    CHECK(atomic_load_explicit(&first_destroyed, memory_order_relaxed) == 0U);

    sl_handle_lease rejected = {
        .object = (void *)(uintptr_t)1U,
        .internal = (void *)(uintptr_t)1U,
    };
    CHECK(sl_handle_table_acquire(table, stale_handle, SL_HANDLE_KIND_FILE,
                                  &rejected) ==
          SL_ERROR_HANDLE_NOT_FOUND);
    CHECK(lease_is_empty(&rejected));

    sl_handle replacement_handle = 0U;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &second,
                                 count_destruction,
                                 &replacement_handle) == SL_OK);
    CHECK(replacement_handle != stale_handle);
    CHECK(lease.object == &first);

    sl_handle_lease_release(&lease);
    CHECK(lease_is_empty(&lease));
    CHECK(atomic_load_explicit(&first_destroyed, memory_order_relaxed) == 1U);
    CHECK(sl_handle_table_close(table, replacement_handle,
                                SL_HANDLE_KIND_FILE) == SL_OK);
    CHECK(atomic_load_explicit(&second_destroyed, memory_order_relaxed) == 1U);

    sl_handle_table_destroy(table);
    return true;
}

static bool test_capacity_failure_preserves_ownership(void) {
    sl_handle_table *table = NULL;
    atomic_uint destroyed;
    atomic_init(&destroyed, 0U);
    test_handle_object objects[SL_HANDLE_TABLE_CAPACITY + 1U];
    sl_handle handles[SL_HANDLE_TABLE_CAPACITY];
    CHECK(sl_handle_table_create(&table) == SL_OK);

    for (size_t index = 0U; index < SL_HANDLE_TABLE_CAPACITY + 1U; ++index) {
        objects[index].destroyed = &destroyed;
        objects[index].value = (uint32_t)index;
    }
    for (size_t index = 0U; index < SL_HANDLE_TABLE_CAPACITY; ++index) {
        handles[index] = 0U;
        CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE,
                                     &objects[index], count_destruction,
                                     &handles[index]) == SL_OK);
        CHECK(handles[index] != 0U);
    }

    sl_handle rejected = UINT64_MAX;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE,
                                 &objects[SL_HANDLE_TABLE_CAPACITY],
                                 count_destruction,
                                 &rejected) == SL_ERROR_HANDLE_TABLE_FULL);
    CHECK(rejected == 0U);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 0U);

    const size_t released_index = SL_HANDLE_TABLE_CAPACITY / 2U;
    sl_handle stale = handles[released_index];
    CHECK(sl_handle_table_close(table, stale, SL_HANDLE_KIND_FILE) == SL_OK);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 1U);

    sl_handle replacement = 0U;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE,
                                 &objects[SL_HANDLE_TABLE_CAPACITY],
                                 count_destruction, &replacement) == SL_OK);
    CHECK(replacement != 0U && replacement != stale);
    sl_handle_lease lease = {0};
    CHECK(sl_handle_table_acquire(table, stale, SL_HANDLE_KIND_FILE, &lease) ==
          SL_ERROR_HANDLE_NOT_FOUND);
    CHECK(lease_is_empty(&lease));

    sl_handle_table_destroy(table);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) ==
          SL_HANDLE_TABLE_CAPACITY + 1U);
    return true;
}

static bool test_destroy_drains_open_handles_and_leases(void) {
    sl_handle_table *table = NULL;
    atomic_uint destroyed;
    atomic_init(&destroyed, 0U);
    test_handle_object objects[3] = {
        {.destroyed = &destroyed, .value = 1U},
        {.destroyed = &destroyed, .value = 2U},
        {.destroyed = &destroyed, .value = 3U},
    };
    sl_handle handles[3] = {0U, 0U, 0U};
    CHECK(sl_handle_table_create(&table) == SL_OK);
    for (size_t index = 0U; index < 3U; ++index) {
        CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_SEARCH,
                                     &objects[index], count_destruction,
                                     &handles[index]) == SL_OK);
    }

    sl_handle_lease lease = {0};
    CHECK(sl_handle_table_acquire(table, handles[1], SL_HANDLE_KIND_SEARCH,
                                  &lease) == SL_OK);
    sl_handle_table_destroy(table);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 2U);
    CHECK(lease.object == &objects[1]);
    sl_handle_lease_release(&lease);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 3U);
    return true;
}

static bool test_process_ownership_and_isolation(void) {
    sl_win32_process *first_process = NULL;
    sl_win32_process *second_process = NULL;
    atomic_uint first_destroyed;
    atomic_uint second_destroyed;
    atomic_init(&first_destroyed, 0U);
    atomic_init(&second_destroyed, 0U);
    test_handle_object first_object = {
        .destroyed = &first_destroyed,
        .value = 1U,
    };
    test_handle_object second_object = {
        .destroyed = &second_destroyed,
        .value = 2U,
    };
    CHECK(sl_win32_process_handle_table(NULL) == NULL);
    CHECK(sl_win32_process_create(&first_process) == SL_OK);
    CHECK(sl_win32_process_create(&second_process) == SL_OK);

    sl_handle_table *first_table =
        sl_win32_process_handle_table(first_process);
    sl_handle_table *second_table =
        sl_win32_process_handle_table(second_process);
    CHECK(first_table != NULL && second_table != NULL);
    CHECK(first_table != second_table);

    sl_handle first_handle = 0U;
    CHECK(sl_handle_table_insert(first_table, SL_HANDLE_KIND_FILE,
                                 &first_object, count_destruction,
                                 &first_handle) == SL_OK);
    sl_handle_lease lease = {
        .object = (void *)(uintptr_t)1U,
        .internal = (void *)(uintptr_t)1U,
    };
    CHECK(sl_handle_table_acquire(second_table, first_handle,
                                  SL_HANDLE_KIND_FILE, &lease) ==
          SL_ERROR_HANDLE_NOT_FOUND);
    CHECK(lease_is_empty(&lease));

    sl_handle second_handle = 0U;
    CHECK(sl_handle_table_insert(second_table, SL_HANDLE_KIND_FILE,
                                 &second_object, count_destruction,
                                 &second_handle) == SL_OK);
    CHECK(sl_win32_process_destroy(first_process) == SL_OK);
    CHECK(atomic_load_explicit(&first_destroyed, memory_order_relaxed) == 1U);
    CHECK(atomic_load_explicit(&second_destroyed, memory_order_relaxed) == 0U);

    CHECK(sl_handle_table_acquire(second_table, second_handle,
                                  SL_HANDLE_KIND_FILE, &lease) == SL_OK);
    CHECK(lease.object == &second_object);
    sl_handle_lease_release(&lease);
    CHECK(sl_win32_process_destroy(second_process) == SL_OK);
    CHECK(atomic_load_explicit(&second_destroyed, memory_order_relaxed) == 1U);
    return true;
}

typedef struct {
    sl_handle_table *table;
    sl_handle handle;
    atomic_bool begin;
    sl_status status;
} close_thread_probe;

static int close_on_worker(void *opaque) {
    close_thread_probe *probe = opaque;
    while (!atomic_load_explicit(&probe->begin, memory_order_acquire)) {
        thrd_yield();
    }
    probe->status = sl_handle_table_close(
        probe->table, probe->handle, SL_HANDLE_KIND_FILE);
    return 0;
}

static bool test_concurrent_close_with_active_lease(void) {
    sl_handle_table *table = NULL;
    atomic_uint destroyed;
    atomic_init(&destroyed, 0U);
    test_handle_object object = {
        .destroyed = &destroyed,
        .value = 99U,
    };
    CHECK(sl_handle_table_create(&table) == SL_OK);
    sl_handle handle = 0U;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &object,
                                 count_destruction, &handle) == SL_OK);
    CHECK(sl_handle_table_prepare_clone(table) == SL_OK);
    sl_handle_table_complete_clone(table);
    sl_handle_lease lease = {0};
    CHECK(sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_FILE,
                                  &lease) == SL_OK);
    sl_handle_lease second_lease = {0};
    CHECK(sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_FILE,
                                  &second_lease) == SL_OK);
    CHECK(sl_handle_table_prepare_clone(table) == SL_ERROR_INVALID_STATE);

    close_thread_probe probe = {
        .table = table,
        .handle = handle,
        .begin = ATOMIC_VAR_INIT(false),
        .status = SL_ERROR_INVALID_STATE,
    };
    thrd_t worker;
    CHECK(thrd_create(&worker, close_on_worker, &probe) == thrd_success);
    atomic_store_explicit(&probe.begin, true, memory_order_release);
    int worker_result = -1;
    CHECK(thrd_join(worker, &worker_result) == thrd_success);
    CHECK(worker_result == 0);
    CHECK(probe.status == SL_OK);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 0U);
    CHECK(sl_handle_table_prepare_clone(table) == SL_ERROR_INVALID_STATE);

    sl_handle_lease rejected = {0};
    CHECK(sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_FILE,
                                  &rejected) ==
          SL_ERROR_HANDLE_NOT_FOUND);
    CHECK(lease.object == &object);
    sl_handle_lease_release(&lease);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 0U);
    CHECK(sl_handle_table_prepare_clone(table) == SL_ERROR_INVALID_STATE);
    CHECK(second_lease.object == &object);
    sl_handle_lease_release(&second_lease);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 1U);

    CHECK(sl_handle_table_prepare_clone(table) == SL_OK);
    sl_handle_table_complete_clone(table);

    sl_handle_table_destroy(table);
    return true;
}

typedef struct {
    atomic_bool entered;
    atomic_bool may_return;
    atomic_uint destroyed;
} blocking_object;

static void block_destruction(void *opaque) {
    blocking_object *object = opaque;
    atomic_store_explicit(&object->entered, true, memory_order_release);
    while (!atomic_load_explicit(&object->may_return, memory_order_acquire)) {
        thrd_yield();
    }
    (void)atomic_fetch_add_explicit(&object->destroyed, 1U,
                                    memory_order_relaxed);
}

static bool test_clone_rejects_destructor_in_flight(void) {
    sl_handle_table *table = NULL;
    blocking_object object = {
        .entered = ATOMIC_VAR_INIT(false),
        .may_return = ATOMIC_VAR_INIT(false),
        .destroyed = ATOMIC_VAR_INIT(0U),
    };
    CHECK(sl_handle_table_create(&table) == SL_OK);
    sl_handle handle = 0U;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &object,
                                 block_destruction, &handle) == SL_OK);

    close_thread_probe probe = {
        .table = table,
        .handle = handle,
        .begin = ATOMIC_VAR_INIT(false),
        .status = SL_ERROR_INVALID_STATE,
    };
    thrd_t worker;
    CHECK(thrd_create(&worker, close_on_worker, &probe) == thrd_success);
    atomic_store_explicit(&probe.begin, true, memory_order_release);
    while (!atomic_load_explicit(&object.entered, memory_order_acquire)) {
        thrd_yield();
    }

    CHECK(sl_handle_table_prepare_clone(table) == SL_ERROR_INVALID_STATE);
    atomic_store_explicit(&object.may_return, true, memory_order_release);
    int worker_result = -1;
    CHECK(thrd_join(worker, &worker_result) == thrd_success);
    CHECK(worker_result == 0);
    CHECK(probe.status == SL_OK);
    CHECK(atomic_load_explicit(&object.destroyed, memory_order_relaxed) == 1U);
    CHECK(sl_handle_table_prepare_clone(table) == SL_OK);
    sl_handle_table_complete_clone(table);

    sl_handle_table_destroy(table);
    return true;
}

static int exercise_child_table(sl_handle_table *table, sl_handle handle,
                                atomic_uint *destroyed) {
    sl_handle_table_complete_clone(table);
    sl_handle_lease lease = {0};
    if (sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_FILE, &lease) !=
            SL_OK ||
        lease.object == NULL) {
        return 1;
    }
    sl_handle_lease_release(&lease);
    if (sl_handle_table_close(table, handle, SL_HANDLE_KIND_FILE) != SL_OK ||
        atomic_load_explicit(destroyed, memory_order_relaxed) != 1U) {
        return 2;
    }
    sl_handle_table_destroy(table);
    return 0;
}

static bool test_clone_unlocks_independent_child_copy(void) {
    sl_handle_table *table = NULL;
    atomic_uint destroyed;
    atomic_init(&destroyed, 0U);
    test_handle_object object = {
        .destroyed = &destroyed,
        .value = 55U,
    };
    CHECK(sl_handle_table_create(&table) == SL_OK);
    sl_handle handle = 0U;
    CHECK(sl_handle_table_insert(table, SL_HANDLE_KIND_FILE, &object,
                                 count_destruction, &handle) == SL_OK);
    CHECK(sl_handle_table_prepare_clone(table) == SL_OK);

    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        _exit(exercise_child_table(table, handle, &destroyed));
    }

    sl_handle_table_complete_clone(table);
    int child_status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &child_status, 0);
    } while (waited < 0 && errno == EINTR);
    CHECK(waited == child);
    CHECK(WIFEXITED(child_status));
    CHECK(WEXITSTATUS(child_status) == 0);

    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 0U);
    sl_handle_lease lease = {0};
    CHECK(sl_handle_table_acquire(table, handle, SL_HANDLE_KIND_FILE,
                                  &lease) == SL_OK);
    CHECK(lease.object == &object);
    sl_handle_lease_release(&lease);
    CHECK(sl_handle_table_close(table, handle, SL_HANDLE_KIND_FILE) == SL_OK);
    CHECK(atomic_load_explicit(&destroyed, memory_order_relaxed) == 1U);
    sl_handle_table_destroy(table);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"arguments and clean outputs", test_arguments_and_clean_outputs},
        {"lifecycle, kind, and malformed handles",
         test_lifecycle_kind_and_malformed_handles},
        {"close defers destruction until release",
         test_close_defers_destruction_until_release},
        {"capacity failure preserves ownership",
         test_capacity_failure_preserves_ownership},
        {"destroy drains open handles and leases",
         test_destroy_drains_open_handles_and_leases},
        {"process ownership and isolation",
         test_process_ownership_and_isolation},
        {"concurrent close with active lease",
         test_concurrent_close_with_active_lease},
        {"clone rejects destructor in flight",
         test_clone_rejects_destructor_in_flight},
        {"clone unlocks independent child copy",
         test_clone_unlocks_independent_child_copy},
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
    printf("%zu handle-table tests passed\n", passed);
    return 0;
}
