#ifndef SADLAYER_PROCESS_H
#define SADLAYER_PROCESS_H

#include <stdint.h>

#include "sadlayer/error.h"

typedef struct sl_win32_process sl_win32_process;

#define SL_WIN32_PEB_IMAGE_BASE_OFFSET 0x10U
#define SL_WIN32_PEB_PROCESS_PARAMETERS_OFFSET 0x20U
#define SL_WIN32_PEB_PROCESS_HEAP_OFFSET 0x30U
#define SL_WIN32_PEB_NT_GLOBAL_FLAG_OFFSET 0xbcU
#define SL_WIN32_PROCESS_PARAMETERS_FLAGS_OFFSET 0x08U
#define SL_WIN32_PROCESS_PARAMETERS_NORMALIZED 0x00000001U

/* Creates stable per-process storage configured before guest threads exist. */
sl_status sl_win32_process_create(sl_win32_process **out_process);
/*
 * Destroy only after every TEB/scope has released the process and every worker
 * has joined. Destruction must not race a new retain through a borrowed raw
 * pointer.
 */
sl_status sl_win32_process_destroy(sl_win32_process *process);

/* Internal references; callers already need a live owner when acquiring one. */
sl_status sl_win32_process_retain(sl_win32_process *process);
void sl_win32_process_release(sl_win32_process *process);

/* Configure during process setup, before publishing any guest thread. */
sl_status sl_win32_process_set_image_base(sl_win32_process *process,
                                          uint64_t image_base);
void *sl_win32_process_peb(sl_win32_process *process);
void *sl_win32_process_parameters(sl_win32_process *process);

uintptr_t sl_win32_process_encode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer);
uintptr_t sl_win32_process_decode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer);

#endif
