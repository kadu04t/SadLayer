#include "sadlayer/process.h"

#include "sadlayer/handle_table.h"
#include "sadlayer/module_space.h"
#include "sadlayer/unicode.h"

#include <errno.h>
#include <limits.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define SL_PEB_SIZE 0x1000U
#define SL_PROCESS_PARAMETERS_SIZE 0x1000U
#define SL_BOOTSTRAP_PROCESS_HEAP_HANDLE ((uintptr_t)4U)
#define SL_BOOTSTRAP_STANDARD_INPUT_HANDLE ((uintptr_t)1U)
#define SL_BOOTSTRAP_STANDARD_OUTPUT_HANDLE ((uintptr_t)2U)
#define SL_BOOTSTRAP_STANDARD_ERROR_HANDLE ((uintptr_t)3U)
#define SL_STANDARD_HANDLE_COUNT 3U

struct sl_win32_process {
    atomic_uint active_references;
    atomic_uintptr_t unhandled_exception_filter;
    atomic_uintptr_t standard_handles[SL_STANDARD_HANDLE_COUNT];
    uintptr_t pointer_cookie;
    sl_handle_table *handle_table;
    sl_module_space *module_space;
    const sl_loaded_module *main_module;
    uint16_t *main_image_path;
    size_t main_image_path_length;
    _Alignas(16) uint8_t peb[SL_PEB_SIZE];
    _Alignas(16) uint8_t process_parameters[SL_PROCESS_PARAMETERS_SIZE];
};

_Static_assert(sizeof(uintptr_t) == sizeof(uint64_t),
               "SadLayer currently requires 64-bit process pointers");
_Static_assert(UINTPTR_MAX == ULONG_MAX && ATOMIC_LONG_LOCK_FREE == 2,
               "cloned process handles require lock-free atomic uintptr_t");

static sl_status random_bytes(void *buffer, size_t size) {
    unsigned char *bytes = buffer;
    size_t offset = 0U;
    while (offset < size) {
        ssize_t result = getrandom(bytes + offset, size - offset, 0U);
        if (result > 0) {
            offset += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return SL_ERROR_IO;
    }
    return SL_OK;
}

static void store_u32(uint8_t *destination, uint32_t value) {
    memcpy(destination, &value, sizeof(value));
}

static void store_uintptr(uint8_t *destination, uintptr_t value) {
    memcpy(destination, &value, sizeof(value));
}

static uintptr_t load_uintptr(const uint8_t *source) {
    uintptr_t value = 0U;
    memcpy(&value, source, sizeof(value));
    return value;
}

sl_status sl_win32_process_create(sl_win32_process **out_process) {
    if (out_process == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    *out_process = NULL;

    sl_win32_process *process = calloc(1U, sizeof(*process));
    if (process == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    atomic_init(&process->active_references, 0U);
    atomic_init(&process->unhandled_exception_filter, 0U);
    atomic_init(&process->standard_handles[SL_WIN32_STANDARD_INPUT],
                SL_BOOTSTRAP_STANDARD_INPUT_HANDLE);
    atomic_init(&process->standard_handles[SL_WIN32_STANDARD_OUTPUT],
                SL_BOOTSTRAP_STANDARD_OUTPUT_HANDLE);
    atomic_init(&process->standard_handles[SL_WIN32_STANDARD_ERROR],
                SL_BOOTSTRAP_STANDARD_ERROR_HANDLE);

    sl_status status =
        sl_handle_table_create(&process->handle_table);
    if (status != SL_OK) {
        free(process);
        return status;
    }

    do {
        status = random_bytes(&process->pointer_cookie,
                              sizeof(process->pointer_cookie));
    } while (status == SL_OK && process->pointer_cookie == 0U);
    if (status != SL_OK) {
        sl_handle_table_destroy(process->handle_table);
        free(process);
        return status;
    }

    store_uintptr(process->peb + SL_WIN32_PEB_PROCESS_PARAMETERS_OFFSET,
                  (uintptr_t)process->process_parameters);
    store_uintptr(process->peb + SL_WIN32_PEB_PROCESS_HEAP_OFFSET,
                  SL_BOOTSTRAP_PROCESS_HEAP_HANDLE);
    store_u32(process->process_parameters +
                  SL_WIN32_PROCESS_PARAMETERS_FLAGS_OFFSET,
              SL_WIN32_PROCESS_PARAMETERS_NORMALIZED);

    *out_process = process;
    return SL_OK;
}

sl_status sl_win32_process_destroy(sl_win32_process *process) {
    if (process == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (atomic_load_explicit(&process->active_references,
                             memory_order_acquire) != 0U) {
        return SL_ERROR_INVALID_STATE;
    }
    sl_handle_table_destroy(process->handle_table);
    sl_module_space_destroy(process->module_space);
    free(process->main_image_path);
    memset(process, 0, sizeof(*process));
    free(process);
    return SL_OK;
}

sl_status sl_win32_process_retain(sl_win32_process *process) {
    if (process == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    unsigned int references = atomic_load_explicit(
        &process->active_references, memory_order_relaxed);
    for (;;) {
        if (references == UINT_MAX) {
            return SL_ERROR_INVALID_STATE;
        }
        if (atomic_compare_exchange_weak_explicit(
                &process->active_references, &references, references + 1U,
                memory_order_acquire, memory_order_relaxed)) {
            return SL_OK;
        }
    }
}

void sl_win32_process_release(sl_win32_process *process) {
    unsigned int previous = atomic_fetch_sub_explicit(
        &process->active_references, 1U, memory_order_release);
    if (previous == 0U) {
        abort();
    }
}

sl_status sl_win32_process_set_image_base(sl_win32_process *process,
                                          uint64_t image_base) {
    if (process == NULL || image_base > UINTPTR_MAX) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (process->module_space != NULL) {
        if (process->main_module == NULL ||
            image_base != process->main_module->mapped->load_base) {
            return SL_ERROR_INVALID_STATE;
        }
    }
    store_uintptr(process->peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET,
                  (uintptr_t)image_base);
    return SL_OK;
}

static const sl_loaded_module *find_exact_module(
    const sl_module_space *space, const sl_loaded_module *candidate) {
    const sl_module_registry *registry = sl_module_space_registry(space);
    if (registry == NULL || candidate == NULL) {
        return NULL;
    }
    for (size_t index = 0U; index < registry->count; ++index) {
        if (&registry->modules[index] == candidate) {
            return candidate;
        }
    }
    return NULL;
}

static bool module_space_is_finalized(const sl_module_space *space) {
    const sl_module_registry *registry = sl_module_space_registry(space);
    if (registry == NULL) {
        return false;
    }
    for (size_t index = 0U; index < registry->count; ++index) {
        const sl_loaded_module *module = &registry->modules[index];
        if (module->kind != SL_MODULE_PE) {
            continue;
        }
        if (module->image == NULL || module->mapped == NULL ||
            module->mapped->bytes == NULL ||
            module->mapped->storage != SL_IMAGE_STORAGE_VIRTUAL ||
            !module->mapped->protections_finalized ||
            module->mapped->size != module->image->image_size ||
            module->mapped->load_base !=
                (uint64_t)(uintptr_t)module->mapped->bytes) {
            return false;
        }
    }
    return true;
}

static sl_status validate_image_path(const uint16_t *path,
                                     size_t path_length) {
    if (path == NULL || path_length == 0U ||
        path_length > SL_WIN32_IMAGE_PATH_MAX_UNITS) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    for (size_t index = 0U; index < path_length; ++index) {
        if (path[index] == 0U) {
            return SL_ERROR_INVALID_ARGUMENT;
        }
    }
    size_t utf8_length = 0U;
    return sl_utf16_to_utf8(path, path_length, NULL, 0U, &utf8_length);
}

sl_status sl_win32_process_adopt_module_space(
    sl_win32_process *process, sl_module_space **space_io,
    const sl_loaded_module *main_module, const uint16_t *image_path,
    size_t image_path_length) {
    if (process == NULL || space_io == NULL || *space_io == NULL ||
        main_module == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (process->module_space != NULL || process->main_module != NULL ||
        process->main_image_path != NULL ||
        load_uintptr(process->peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET) != 0U ||
        atomic_load_explicit(&process->active_references,
                             memory_order_acquire) != 0U) {
        return SL_ERROR_INVALID_STATE;
    }

    sl_module_space *space = *space_io;
    const sl_loaded_module *registered =
        find_exact_module(space, main_module);
    if (registered == NULL || registered->kind != SL_MODULE_PE ||
        !module_space_is_finalized(space)) {
        return SL_ERROR_INVALID_STATE;
    }
    sl_status status = validate_image_path(image_path, image_path_length);
    if (status != SL_OK) {
        return status;
    }
    if (registered->mapped->load_base == 0U ||
        registered->mapped->load_base > UINTPTR_MAX) {
        return SL_ERROR_INVALID_STATE;
    }

    size_t allocation_units = image_path_length + 1U;
    uint16_t *path_copy = calloc(allocation_units, sizeof(*path_copy));
    if (path_copy == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    memcpy(path_copy, image_path, image_path_length * sizeof(*path_copy));

    if (atomic_load_explicit(&process->active_references,
                             memory_order_acquire) != 0U) {
        free(path_copy);
        return SL_ERROR_INVALID_STATE;
    }
    process->module_space = space;
    process->main_module = registered;
    process->main_image_path = path_copy;
    process->main_image_path_length = image_path_length;
    store_uintptr(process->peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET,
                  (uintptr_t)registered->mapped->load_base);
    *space_io = NULL;
    return SL_OK;
}

const sl_module_space *sl_win32_process_module_space(
    const sl_win32_process *process) {
    return process == NULL ? NULL : process->module_space;
}

const sl_loaded_module *sl_win32_process_main_module(
    const sl_win32_process *process) {
    return process == NULL ? NULL : process->main_module;
}

sl_handle_table *sl_win32_process_handle_table(sl_win32_process *process) {
    return process == NULL ? NULL : process->handle_table;
}

static bool standard_handle_is_valid(sl_win32_standard_handle which) {
    return which == SL_WIN32_STANDARD_INPUT ||
           which == SL_WIN32_STANDARD_OUTPUT ||
           which == SL_WIN32_STANDARD_ERROR;
}

sl_status sl_win32_process_get_standard_handle(
    const sl_win32_process *process, sl_win32_standard_handle which,
    uintptr_t *out_handle) {
    if (out_handle != NULL) {
        *out_handle = 0U;
    }
    if (process == NULL || !standard_handle_is_valid(which) ||
        out_handle == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    *out_handle = atomic_load_explicit(&process->standard_handles[which],
                                       memory_order_acquire);
    return SL_OK;
}

sl_status sl_win32_process_set_standard_handle(
    sl_win32_process *process, sl_win32_standard_handle which,
    uintptr_t handle) {
    if (process == NULL || !standard_handle_is_valid(which)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    atomic_store_explicit(&process->standard_handles[which], handle,
                          memory_order_release);
    return SL_OK;
}

sl_status sl_win32_process_main_image_path(
    const sl_win32_process *process, const uint16_t **path,
    size_t *path_length) {
    if (path != NULL) {
        *path = NULL;
    }
    if (path_length != NULL) {
        *path_length = 0U;
    }
    if (process == NULL || path == NULL || path_length == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (process->main_image_path == NULL) {
        return SL_ERROR_INVALID_STATE;
    }
    *path = process->main_image_path;
    *path_length = process->main_image_path_length;
    return SL_OK;
}

void *sl_win32_process_peb(sl_win32_process *process) {
    return process == NULL ? NULL : process->peb;
}

void *sl_win32_process_parameters(sl_win32_process *process) {
    return process == NULL ? NULL : process->process_parameters;
}

static uintptr_t rotate_right(uintptr_t value, unsigned int shift) {
    const unsigned int width = (unsigned int)(sizeof(value) * CHAR_BIT);
    if (shift == 0U) {
        return value;
    }
    return (value >> shift) | (value << (width - shift));
}

static uintptr_t rotate_left(uintptr_t value, unsigned int shift) {
    const unsigned int width = (unsigned int)(sizeof(value) * CHAR_BIT);
    if (shift == 0U) {
        return value;
    }
    return (value << shift) | (value >> (width - shift));
}

uintptr_t sl_win32_process_encode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer) {
    const unsigned int width = (unsigned int)(sizeof(pointer) * CHAR_BIT);
    const unsigned int shift =
        (unsigned int)(process->pointer_cookie & (uintptr_t)(width - 1U));
    return rotate_right(pointer ^ process->pointer_cookie, shift);
}

uintptr_t sl_win32_process_decode_pointer(const sl_win32_process *process,
                                          uintptr_t pointer) {
    const unsigned int width = (unsigned int)(sizeof(pointer) * CHAR_BIT);
    const unsigned int shift =
        (unsigned int)(process->pointer_cookie & (uintptr_t)(width - 1U));
    return rotate_left(pointer, shift) ^ process->pointer_cookie;
}

uintptr_t sl_win32_process_exchange_unhandled_exception_filter(
    sl_win32_process *process, uintptr_t filter) {
    if (process == NULL) {
        abort();
    }
    return atomic_exchange_explicit(&process->unhandled_exception_filter,
                                    filter, memory_order_acq_rel);
}

uintptr_t sl_win32_process_unhandled_exception_filter(
    const sl_win32_process *process) {
    if (process == NULL) {
        abort();
    }
    return atomic_load_explicit(&process->unhandled_exception_filter,
                                memory_order_acquire);
}
