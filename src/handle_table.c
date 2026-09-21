#include "sadlayer/handle_table.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#define SL_HANDLE_TAG UINT64_C(0x534c000000000000)
#define SL_HANDLE_TAG_MASK UINT64_C(0xffff000000000000)
#define SL_HANDLE_GENERATION_MASK UINT64_C(0x0000ffffffff0000)
#define SL_HANDLE_SLOT_MASK UINT64_C(0x000000000000ffff)
#define SL_TRACKER_REFERENCE_ONE UINT64_C(1)
#define SL_TRACKER_ACTIVITY_ONE (UINT64_C(1) << 32U)

typedef struct {
    /* Low 32 bits are references; high 32 bits are external activities. */
    atomic_ullong state;
} sl_handle_tracker;

typedef struct {
    atomic_uint references;
    sl_handle_kind kind;
    void *object;
    sl_handle_destroy_fn destroy;
    sl_handle_tracker *tracker;
} sl_handle_record;

typedef struct {
    sl_handle_record *record;
    uint32_t generation;
    bool retired;
} sl_handle_slot;

struct sl_handle_table {
    atomic_bool locked;
    bool destroying;
    sl_handle_tracker *tracker;
    sl_handle_slot slots[SL_HANDLE_TABLE_CAPACITY];
};

_Static_assert(SL_HANDLE_TABLE_CAPACITY <= UINT16_MAX,
               "handle slot ordinal must fit the token");
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2,
               "clone-safe handle locking requires lock-free atomic bool");
_Static_assert(sizeof(unsigned long long) == sizeof(uint64_t),
               "handle tracking requires a 64-bit unsigned long long");
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2,
               "clone-safe handle tracking requires lock-free atomic state");

static bool handle_kind_is_valid(sl_handle_kind kind) {
    return kind == SL_HANDLE_KIND_FILE || kind == SL_HANDLE_KIND_SEARCH;
}

static sl_handle encode_handle(size_t slot_index, uint32_t generation) {
    return SL_HANDLE_TAG | ((uint64_t)generation << 16U) |
           (uint64_t)(slot_index + 1U);
}

static bool decode_handle(sl_handle handle, size_t *slot_index,
                          uint32_t *generation) {
    if ((handle & SL_HANDLE_TAG_MASK) != SL_HANDLE_TAG ||
        (handle & SL_HANDLE_SLOT_MASK) == 0U) {
        return false;
    }
    uint64_t ordinal = handle & SL_HANDLE_SLOT_MASK;
    uint64_t encoded_generation =
        (handle & SL_HANDLE_GENERATION_MASK) >> 16U;
    if (ordinal > SL_HANDLE_TABLE_CAPACITY || encoded_generation == 0U) {
        return false;
    }
    *slot_index = (size_t)(ordinal - 1U);
    *generation = (uint32_t)encoded_generation;
    return true;
}

static void table_lock(sl_handle_table *table) {
    while (atomic_exchange_explicit(&table->locked, true,
                                    memory_order_acquire)) {
        thrd_yield();
    }
}

static void table_unlock(sl_handle_table *table) {
    atomic_store_explicit(&table->locked, false, memory_order_release);
}

static uint32_t tracker_reference_count(unsigned long long state) {
    return (uint32_t)(state & UINT64_C(0xffffffff));
}

static uint32_t tracker_activity_count(unsigned long long state) {
    return (uint32_t)(state >> 32U);
}

static void tracker_drop(sl_handle_tracker *tracker,
                         unsigned long long decrement,
                         uint32_t activity_decrement) {
    unsigned long long previous = atomic_fetch_sub_explicit(
        &tracker->state, decrement, memory_order_acq_rel);
    uint32_t references = tracker_reference_count(previous);
    uint32_t activities = tracker_activity_count(previous);
    if (references == 0U || activities < activity_decrement) {
        abort();
    }
    --references;
    activities -= activity_decrement;
    if (references == 0U) {
        if (activities != 0U) {
            abort();
        }
        memset(tracker, 0, sizeof(*tracker));
        free(tracker);
    }
}

/* All increments happen while the table lock is held. */
static bool tracker_retain(sl_handle_tracker *tracker) {
    unsigned long long state =
        atomic_load_explicit(&tracker->state, memory_order_relaxed);
    if (tracker_reference_count(state) == UINT32_MAX) {
        return false;
    }
    (void)atomic_fetch_add_explicit(&tracker->state,
                                    SL_TRACKER_REFERENCE_ONE,
                                    memory_order_relaxed);
    return true;
}

static void tracker_release(sl_handle_tracker *tracker) {
    tracker_drop(tracker, SL_TRACKER_REFERENCE_ONE, 0U);
}

/*
 * Activity begins under the table lock and ends only after any destructor has
 * returned. Its own tracker reference lets a lease safely outlive the table.
 */
static bool tracker_activity_begin(sl_handle_tracker *tracker) {
    unsigned long long state =
        atomic_load_explicit(&tracker->state, memory_order_relaxed);
    if (tracker_reference_count(state) == UINT32_MAX ||
        tracker_activity_count(state) == UINT32_MAX) {
        return false;
    }
    (void)atomic_fetch_add_explicit(
        &tracker->state, SL_TRACKER_REFERENCE_ONE + SL_TRACKER_ACTIVITY_ONE,
        memory_order_relaxed);
    return true;
}

static void tracker_activity_end(sl_handle_tracker *tracker) {
    tracker_drop(tracker,
                 SL_TRACKER_REFERENCE_ONE + SL_TRACKER_ACTIVITY_ONE, 1U);
}

static void record_release(sl_handle_record *record) {
    unsigned int previous = atomic_fetch_sub_explicit(
        &record->references, 1U, memory_order_acq_rel);
    if (previous == 0U) {
        abort();
    }
    if (previous == 1U) {
        sl_handle_destroy_fn destroy = record->destroy;
        void *object = record->object;
        sl_handle_tracker *tracker = record->tracker;
        memset(record, 0, sizeof(*record));
        free(record);
        destroy(object);
        tracker_release(tracker);
    }
}

static void invalidate_slot(sl_handle_slot *slot) {
    slot->record = NULL;
    if (slot->generation == UINT32_MAX) {
        slot->generation = 0U;
        slot->retired = true;
    } else {
        ++slot->generation;
    }
}

sl_status sl_handle_table_create(sl_handle_table **out_table) {
    if (out_table == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    *out_table = NULL;
    sl_handle_table *table = calloc(1U, sizeof(*table));
    if (table == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    sl_handle_tracker *tracker = calloc(1U, sizeof(*tracker));
    if (tracker == NULL) {
        free(table);
        return SL_ERROR_OUT_OF_MEMORY;
    }
    atomic_init(&tracker->state, SL_TRACKER_REFERENCE_ONE);
    atomic_init(&table->locked, false);
    table->tracker = tracker;
    for (size_t index = 0U; index < SL_HANDLE_TABLE_CAPACITY; ++index) {
        table->slots[index].generation = 1U;
    }
    *out_table = table;
    return SL_OK;
}

void sl_handle_table_destroy(sl_handle_table *table) {
    if (table == NULL) {
        return;
    }
    sl_handle_record *records[SL_HANDLE_TABLE_CAPACITY] = {0};
    table_lock(table);
    table->destroying = true;
    for (size_t index = 0U; index < SL_HANDLE_TABLE_CAPACITY; ++index) {
        records[index] = table->slots[index].record;
        if (records[index] != NULL) {
            invalidate_slot(&table->slots[index]);
        }
    }
    table_unlock(table);

    for (size_t index = 0U; index < SL_HANDLE_TABLE_CAPACITY; ++index) {
        if (records[index] != NULL) {
            record_release(records[index]);
        }
    }
    sl_handle_tracker *tracker = table->tracker;
    memset(table, 0, sizeof(*table));
    free(table);
    tracker_release(tracker);
}

sl_status sl_handle_table_insert(sl_handle_table *table, sl_handle_kind kind,
                                 void *object,
                                 sl_handle_destroy_fn destroy,
                                 sl_handle *out_handle) {
    if (out_handle != NULL) {
        *out_handle = 0U;
    }
    if (table == NULL || !handle_kind_is_valid(kind) || object == NULL ||
        destroy == NULL || out_handle == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }

    sl_handle_record *record = calloc(1U, sizeof(*record));
    if (record == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    atomic_init(&record->references, 1U);
    record->kind = kind;
    record->object = object;
    record->destroy = destroy;

    table_lock(table);
    sl_status status;
    if (table->destroying) {
        status = SL_ERROR_INVALID_STATE;
    } else {
        status = SL_ERROR_HANDLE_TABLE_FULL;
        for (size_t index = 0U; index < SL_HANDLE_TABLE_CAPACITY; ++index) {
            sl_handle_slot *slot = &table->slots[index];
            if (slot->record == NULL && !slot->retired) {
                if (!tracker_retain(table->tracker)) {
                    status = SL_ERROR_INVALID_STATE;
                    break;
                }
                record->tracker = table->tracker;
                slot->record = record;
                *out_handle = encode_handle(index, slot->generation);
                status = SL_OK;
                break;
            }
        }
    }
    table_unlock(table);
    if (status != SL_OK) {
        free(record);
    }
    return status;
}

sl_status sl_handle_table_acquire(sl_handle_table *table, sl_handle handle,
                                  sl_handle_kind expected_kind,
                                  sl_handle_lease *out_lease) {
    if (out_lease != NULL) {
        *out_lease = (sl_handle_lease){0};
    }
    if (table == NULL || !handle_kind_is_valid(expected_kind) ||
        out_lease == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    size_t slot_index = 0U;
    uint32_t generation = 0U;
    if (!decode_handle(handle, &slot_index, &generation)) {
        return SL_ERROR_HANDLE_NOT_FOUND;
    }

    table_lock(table);
    sl_status status;
    sl_handle_slot *slot = &table->slots[slot_index];
    sl_handle_record *record = slot->record;
    if (table->destroying || record == NULL || slot->retired ||
        slot->generation != generation) {
        status = SL_ERROR_HANDLE_NOT_FOUND;
    } else if (record->kind != expected_kind) {
        status = SL_ERROR_HANDLE_TYPE_MISMATCH;
    } else {
        unsigned int references =
            atomic_load_explicit(&record->references, memory_order_relaxed);
        if (references == UINT_MAX) {
            status = SL_ERROR_INVALID_STATE;
        } else if (!tracker_activity_begin(record->tracker)) {
            status = SL_ERROR_INVALID_STATE;
        } else {
            (void)atomic_fetch_add_explicit(&record->references, 1U,
                                            memory_order_relaxed);
            out_lease->object = record->object;
            out_lease->internal = record;
            status = SL_OK;
        }
    }
    table_unlock(table);
    return status;
}

void sl_handle_lease_release(sl_handle_lease *lease) {
    if (lease == NULL) {
        return;
    }
    sl_handle_record *record = lease->internal;
    *lease = (sl_handle_lease){0};
    if (record != NULL) {
        sl_handle_tracker *tracker = record->tracker;
        record_release(record);
        tracker_activity_end(tracker);
    }
}

sl_status sl_handle_table_close(sl_handle_table *table, sl_handle handle,
                                sl_handle_kind expected_kind) {
    if (table == NULL || !handle_kind_is_valid(expected_kind)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    size_t slot_index = 0U;
    uint32_t generation = 0U;
    if (!decode_handle(handle, &slot_index, &generation)) {
        return SL_ERROR_HANDLE_NOT_FOUND;
    }

    table_lock(table);
    sl_status status;
    sl_handle_slot *slot = &table->slots[slot_index];
    sl_handle_record *record = slot->record;
    if (table->destroying || record == NULL || slot->retired ||
        slot->generation != generation) {
        status = SL_ERROR_HANDLE_NOT_FOUND;
        record = NULL;
    } else if (record->kind != expected_kind) {
        status = SL_ERROR_HANDLE_TYPE_MISMATCH;
        record = NULL;
    } else {
        if (!tracker_activity_begin(record->tracker)) {
            table_unlock(table);
            return SL_ERROR_INVALID_STATE;
        }
        invalidate_slot(slot);
        status = SL_OK;
    }
    table_unlock(table);
    if (record != NULL) {
        sl_handle_tracker *tracker = record->tracker;
        record_release(record);
        tracker_activity_end(tracker);
    }
    return status;
}

sl_status sl_handle_table_prepare_clone(sl_handle_table *table) {
    if (table == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    table_lock(table);
    if (table->destroying) {
        table_unlock(table);
        return SL_ERROR_INVALID_STATE;
    }
    unsigned long long tracker_state = atomic_load_explicit(
        &table->tracker->state, memory_order_acquire);
    if (tracker_activity_count(tracker_state) != 0U) {
        table_unlock(table);
        return SL_ERROR_INVALID_STATE;
    }
    return SL_OK;
}

void sl_handle_table_complete_clone(sl_handle_table *table) {
    if (table == NULL) {
        abort();
    }
    table_unlock(table);
}
