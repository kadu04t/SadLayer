#ifndef SADLAYER_HANDLE_TABLE_H
#define SADLAYER_HANDLE_TABLE_H

#include <stdint.h>

#include "sadlayer/error.h"

#define SL_HANDLE_TABLE_CAPACITY 256U

typedef struct sl_handle_table sl_handle_table;
typedef uint64_t sl_handle;

typedef enum {
    SL_HANDLE_KIND_FILE = 1,
    SL_HANDLE_KIND_SEARCH = 2,
} sl_handle_kind;

typedef void (*sl_handle_destroy_fn)(void *object);

/*
 * A lease keeps one handle object alive without holding the table lock. It is
 * move-only: do not copy an active lease, and release it exactly once.
 */
typedef struct {
    void *object;
    void *internal;
} sl_handle_lease;

sl_status sl_handle_table_create(sl_handle_table **out_table);
/* No operation may begin or be waiting on table while it is destroyed. */
void sl_handle_table_destroy(sl_handle_table *table);

/* Ownership of object transfers to the table only when this succeeds. */
sl_status sl_handle_table_insert(sl_handle_table *table, sl_handle_kind kind,
                                 void *object,
                                 sl_handle_destroy_fn destroy,
                                 sl_handle *out_handle);

/* The borrowed object remains valid until the returned lease is released. */
sl_status sl_handle_table_acquire(sl_handle_table *table, sl_handle handle,
                                  sl_handle_kind expected_kind,
                                  sl_handle_lease *out_lease);
void sl_handle_lease_release(sl_handle_lease *lease);

/* Invalidates handle atomically; destruction waits for outstanding leases. */
sl_status sl_handle_table_close(sl_handle_table *table, sl_handle handle,
                                sl_handle_kind expected_kind);

/*
 * Freeze an externally quiescent table around clone(). Preparation rejects
 * active leases and close/destructor work. A successful prepare leaves the
 * table locked; the caller must complete once in each resulting process (or
 * once in the parent if clone fails).
 */
sl_status sl_handle_table_prepare_clone(sl_handle_table *table);
void sl_handle_table_complete_clone(sl_handle_table *table);

#endif
