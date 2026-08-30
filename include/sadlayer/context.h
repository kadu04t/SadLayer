#ifndef SADLAYER_CONTEXT_H
#define SADLAYER_CONTEXT_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#include "sadlayer/error.h"
#include "sadlayer/process.h"

#define SL_WIN32_LOCAL_SLOT_COUNT 256U

typedef struct {
    void *value;
    uint64_t generation;
} sl_win32_local_value;

typedef struct {
    sl_win32_process *process;
    uint32_t last_error;
    uint32_t thread_id;
    void *teb;
    uint32_t *last_error_address;
    sl_win32_local_value tls_values[SL_WIN32_LOCAL_SLOT_COUNT];
    sl_win32_local_value fls_values[SL_WIN32_LOCAL_SLOT_COUNT];
    atomic_uintptr_t host_thread_token;
    atomic_uint active_scope_count;
    atomic_uintptr_t teb_owner_token;
} sl_win32_thread_context;

typedef struct sl_win32_context_scope sl_win32_context_scope;

struct sl_win32_context_scope {
    sl_win32_thread_context *previous;
    sl_win32_thread_context *installed;
    sl_win32_process *retained_process;
    sl_win32_context_scope *previous_scope;
};

/*
 * Contexts and their process pointers are borrowed and must be left in strict
 * LIFO order. A context may be nested on one host thread but cannot be active
 * on two host threads at once; it may migrate only after every scope has left.
 * A scope token may be uninitialized on first entry, but cannot be reused while
 * active. Context owners outlive all scopes, and the complete context must be
 * zero-initialized before identity fields are configured.
 */
sl_status sl_win32_context_enter(sl_win32_thread_context *thread,
                                 sl_win32_context_scope *scope);
sl_status sl_win32_context_leave(sl_win32_context_scope *scope);
sl_win32_thread_context *sl_win32_context_current(void);
bool sl_win32_context_is_active(const sl_win32_thread_context *thread);

/* Internal serialization used while attaching or destroying thread state. */
sl_status sl_win32_context_claim_inactive(sl_win32_thread_context *thread);
void sl_win32_context_release_inactive(sl_win32_thread_context *thread);

#endif
