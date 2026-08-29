#ifndef SADLAYER_CONTEXT_H
#define SADLAYER_CONTEXT_H

#include <stdint.h>

#include "sadlayer/error.h"
#include "sadlayer/process.h"

typedef struct {
    sl_win32_process *process;
    uint32_t last_error;
    uint32_t thread_id;
} sl_win32_thread_context;

typedef struct {
    sl_win32_thread_context *previous;
    sl_win32_thread_context *installed;
} sl_win32_context_scope;

/*
 * Contexts and their process pointers are borrowed, host-thread-local, and must
 * be left in strict LIFO order. Their owners outlive every active scope.
 */
sl_status sl_win32_context_enter(sl_win32_thread_context *thread,
                                 sl_win32_context_scope *scope);
sl_status sl_win32_context_leave(sl_win32_context_scope *scope);
sl_win32_thread_context *sl_win32_context_current(void);

#endif
