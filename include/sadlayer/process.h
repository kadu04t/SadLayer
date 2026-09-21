#ifndef SADLAYER_PROCESS_H
#define SADLAYER_PROCESS_H

#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"

typedef struct sl_win32_process sl_win32_process;
struct sl_loaded_module;
struct sl_module_space;
struct sl_handle_table;

typedef enum {
    SL_WIN32_STANDARD_INPUT = 0,
    SL_WIN32_STANDARD_OUTPUT = 1,
    SL_WIN32_STANDARD_ERROR = 2,
} sl_win32_standard_handle;

#define SL_WIN32_PEB_IMAGE_BASE_OFFSET 0x10U
#define SL_WIN32_PEB_PROCESS_PARAMETERS_OFFSET 0x20U
#define SL_WIN32_PEB_PROCESS_HEAP_OFFSET 0x30U
#define SL_WIN32_PEB_NT_GLOBAL_FLAG_OFFSET 0xbcU
#define SL_WIN32_PROCESS_PARAMETERS_FLAGS_OFFSET 0x08U
#define SL_WIN32_PROCESS_PARAMETERS_NORMALIZED 0x00000001U
#define SL_WIN32_IMAGE_PATH_MAX_UNITS 32766U

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

/*
 * Transfers ownership of a fully bound/finalized bootstrap module space into
 * an otherwise unconfigured process. The transfer is one-shot and must happen
 * before any process reference is published. On success, *space_io is NULL;
 * on failure, the caller retains it and the process remains unchanged.
 * image_path_length excludes the terminator.
 */
sl_status sl_win32_process_adopt_module_space(
    sl_win32_process *process, struct sl_module_space **space_io,
    const struct sl_loaded_module *main_module,
    const uint16_t *image_path, size_t image_path_length);

/* Borrowed immutable views, valid while the process remains alive/retained. */
const struct sl_module_space *sl_win32_process_module_space(
    const sl_win32_process *process);
const struct sl_loaded_module *sl_win32_process_main_module(
    const sl_win32_process *process);
/* Borrowed mutable table, valid while the process remains alive/retained. */
struct sl_handle_table *sl_win32_process_handle_table(
    sl_win32_process *process);
/* Standard-handle values are process-local and are not validated or owned. */
sl_status sl_win32_process_get_standard_handle(
    const sl_win32_process *process, sl_win32_standard_handle which,
    uintptr_t *out_handle);
sl_status sl_win32_process_set_standard_handle(
    sl_win32_process *process, sl_win32_standard_handle which,
    uintptr_t handle);
sl_status sl_win32_process_main_image_path(
    const sl_win32_process *process, const uint16_t **path,
    size_t *path_length);

void *sl_win32_process_peb(sl_win32_process *process);
void *sl_win32_process_parameters(sl_win32_process *process);

uintptr_t sl_win32_process_encode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer);
uintptr_t sl_win32_process_decode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer);

/* Process-wide top-level filter shared by every current and future thread. */
uintptr_t sl_win32_process_exchange_unhandled_exception_filter(
    sl_win32_process *process, uintptr_t filter);
uintptr_t sl_win32_process_unhandled_exception_filter(
    const sl_win32_process *process);

#endif
