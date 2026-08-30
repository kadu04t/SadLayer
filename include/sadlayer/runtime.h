#ifndef SADLAYER_RUNTIME_H
#define SADLAYER_RUNTIME_H

#include <stdint.h>

#include "sadlayer/context.h"
#include "sadlayer/loader.h"
#include "sadlayer/pe.h"

/*
 * Directly calls an AMD64 entry point trusted by the caller. This is not a
 * sandbox: only repository fixtures may use it until the guarded worker owns
 * signal isolation, a guest stack, and GS-backed TEB installation.
 */
sl_status sl_runtime_call_trusted_entry(const sl_pe_image *image,
                                        const sl_mapped_image *mapped,
                                        sl_win32_thread_context *thread,
                                        uint32_t *result);

#endif
