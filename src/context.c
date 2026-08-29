#include "sadlayer/context.h"

#include <stddef.h>

static _Thread_local sl_win32_thread_context *sl_current_thread;

sl_status sl_win32_context_enter(sl_win32_thread_context *thread,
                                 sl_win32_context_scope *scope) {
    if (thread == NULL || scope == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    scope->previous = sl_current_thread;
    scope->installed = thread;
    sl_current_thread = thread;
    return SL_OK;
}

sl_status sl_win32_context_leave(sl_win32_context_scope *scope) {
    if (scope == NULL || scope->installed == NULL ||
        sl_current_thread != scope->installed) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_current_thread = scope->previous;
    scope->previous = NULL;
    scope->installed = NULL;
    return SL_OK;
}

sl_win32_thread_context *sl_win32_context_current(void) {
    return sl_current_thread;
}
