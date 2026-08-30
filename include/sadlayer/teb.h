#ifndef SADLAYER_TEB_H
#define SADLAYER_TEB_H

#include <stdint.h>

#include "sadlayer/context.h"
#include "sadlayer/error.h"
#include "sadlayer/process.h"

#define SL_WIN32_TEB_STACK_BASE_OFFSET 0x08U
#define SL_WIN32_TEB_STACK_LIMIT_OFFSET 0x10U
#define SL_WIN32_TEB_SELF_OFFSET 0x30U
#define SL_WIN32_TEB_PROCESS_ID_OFFSET 0x40U
#define SL_WIN32_TEB_THREAD_ID_OFFSET 0x48U
#define SL_WIN32_TEB_TLS_POINTER_OFFSET 0x58U
#define SL_WIN32_TEB_PEB_OFFSET 0x60U
#define SL_WIN32_TEB_LAST_ERROR_OFFSET 0x68U
#define SL_WIN32_TEB_TLS_SLOTS_OFFSET 0x1480U
#define SL_WIN32_TEB_TLS_SLOT_COUNT 64U

typedef struct sl_win32_teb sl_win32_teb;

/*
 * A thread context owns at most one TEB. The context must be inactive while
 * the TEB is created, attached, detached, or destroyed, and must outlive it.
 */
sl_status sl_win32_teb_create(sl_win32_thread_context *thread,
                              uintptr_t stack_limit, uintptr_t stack_base,
                              sl_win32_teb **out_teb);
sl_status sl_win32_teb_destroy(sl_win32_teb *teb);

void *sl_win32_teb_base(sl_win32_teb *teb);
uint32_t *sl_win32_teb_last_error(sl_win32_teb *teb);
sl_status sl_win32_thread_attach_teb(sl_win32_thread_context *thread,
                                     sl_win32_teb *teb);
sl_status sl_win32_thread_detach_teb(sl_win32_thread_context *thread,
                                     sl_win32_teb *teb);

#endif
