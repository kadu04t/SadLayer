#ifndef SADLAYER_PROCESS_H
#define SADLAYER_PROCESS_H

#include <stdint.h>

#include "sadlayer/error.h"

typedef struct sl_win32_process sl_win32_process;

/* Creates the immutable per-process state needed before guest threads exist. */
sl_status sl_win32_process_create(sl_win32_process **out_process);
/* Destroy only after every thread context borrowing this process has left. */
void sl_win32_process_destroy(sl_win32_process *process);

uintptr_t sl_win32_process_encode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer);
uintptr_t sl_win32_process_decode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer);

#endif
