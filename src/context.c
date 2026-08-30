#include "sadlayer/context.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static _Thread_local sl_win32_thread_context *sl_current_thread;
static _Thread_local sl_win32_context_scope *sl_current_scope;
static _Thread_local unsigned char sl_host_thread_marker;

static uintptr_t current_host_thread_token(void) {
    return (uintptr_t)(void *)&sl_host_thread_marker;
}

static sl_status claim_thread_context(sl_win32_thread_context *thread) {
    uintptr_t token = current_host_thread_token();
    uintptr_t owner = atomic_load_explicit(&thread->host_thread_token,
                                           memory_order_acquire);
    if (owner == 0U) {
        uintptr_t expected = 0U;
        if (!atomic_compare_exchange_strong_explicit(
                &thread->host_thread_token, &expected, token,
                memory_order_acq_rel, memory_order_acquire)) {
            return SL_ERROR_INVALID_STATE;
        }
        atomic_store_explicit(&thread->active_scope_count, 1U,
                              memory_order_relaxed);
        return SL_OK;
    }
    if (owner != token) {
        return SL_ERROR_INVALID_STATE;
    }
    unsigned int count = atomic_load_explicit(&thread->active_scope_count,
                                              memory_order_relaxed);
    if (count == UINT_MAX) {
        return SL_ERROR_INVALID_STATE;
    }
    atomic_store_explicit(&thread->active_scope_count, count + 1U,
                          memory_order_relaxed);
    return SL_OK;
}

static void release_thread_context(sl_win32_thread_context *thread) {
    unsigned int count = atomic_load_explicit(&thread->active_scope_count,
                                              memory_order_relaxed);
    if (count == 0U || atomic_load_explicit(&thread->host_thread_token,
                                            memory_order_relaxed) !=
                           current_host_thread_token()) {
        abort();
    }
    --count;
    atomic_store_explicit(&thread->active_scope_count, count,
                          memory_order_relaxed);
    if (count == 0U) {
        atomic_store_explicit(&thread->host_thread_token, 0U,
                              memory_order_release);
    }
}

sl_status sl_win32_context_enter(sl_win32_thread_context *thread,
                                 sl_win32_context_scope *scope) {
    if (thread == NULL || scope == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    for (sl_win32_context_scope *active = sl_current_scope; active != NULL;
         active = active->previous_scope) {
        if (active == scope) {
            return SL_ERROR_INVALID_STATE;
        }
    }

    sl_status status = claim_thread_context(thread);
    if (status != SL_OK) {
        return status;
    }

    sl_win32_process *process = thread->process;
    if (process != NULL) {
        status = sl_win32_process_retain(process);
        if (status != SL_OK) {
            release_thread_context(thread);
            return status;
        }
    }
    scope->previous = sl_current_thread;
    scope->installed = thread;
    scope->retained_process = process;
    scope->previous_scope = sl_current_scope;
    sl_current_thread = thread;
    sl_current_scope = scope;
    return SL_OK;
}

sl_status sl_win32_context_leave(sl_win32_context_scope *scope) {
    if (scope == NULL || sl_current_scope != scope) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (scope->installed == NULL || sl_current_thread != scope->installed ||
        atomic_load_explicit(&scope->installed->host_thread_token,
                             memory_order_acquire) !=
            current_host_thread_token()) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_win32_thread_context *installed = scope->installed;
    sl_win32_process *process = scope->retained_process;
    sl_current_thread = scope->previous;
    sl_current_scope = scope->previous_scope;
    scope->previous = NULL;
    scope->installed = NULL;
    scope->retained_process = NULL;
    scope->previous_scope = NULL;
    if (process != NULL) {
        sl_win32_process_release(process);
    }
    release_thread_context(installed);
    return SL_OK;
}

sl_win32_thread_context *sl_win32_context_current(void) {
    return sl_current_thread;
}

bool sl_win32_context_is_active(const sl_win32_thread_context *thread) {
    return thread != NULL &&
           atomic_load_explicit(&thread->host_thread_token,
                                memory_order_acquire) != 0U;
}

sl_status sl_win32_context_claim_inactive(sl_win32_thread_context *thread) {
    if (thread == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    uintptr_t expected = 0U;
    if (!atomic_compare_exchange_strong_explicit(
            &thread->host_thread_token, &expected,
            current_host_thread_token(), memory_order_acq_rel,
            memory_order_acquire)) {
        return SL_ERROR_INVALID_STATE;
    }
    if (atomic_load_explicit(&thread->active_scope_count,
                             memory_order_relaxed) != 0U) {
        abort();
    }
    return SL_OK;
}

void sl_win32_context_release_inactive(sl_win32_thread_context *thread) {
    if (thread == NULL ||
        atomic_load_explicit(&thread->host_thread_token,
                             memory_order_relaxed) !=
            current_host_thread_token() ||
        atomic_load_explicit(&thread->active_scope_count,
                             memory_order_relaxed) != 0U) {
        abort();
    }
    atomic_store_explicit(&thread->host_thread_token, 0U,
                          memory_order_release);
}
