#include "sadlayer/process.h"

#include <errno.h>
#include <limits.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define SL_PEB_SIZE 0x1000U
#define SL_PROCESS_PARAMETERS_SIZE 0x1000U
#define SL_BOOTSTRAP_PROCESS_HEAP_HANDLE ((uintptr_t)4U)

struct sl_win32_process {
    atomic_uint active_references;
    uintptr_t pointer_cookie;
    _Alignas(16) uint8_t peb[SL_PEB_SIZE];
    _Alignas(16) uint8_t process_parameters[SL_PROCESS_PARAMETERS_SIZE];
};

_Static_assert(sizeof(uintptr_t) == sizeof(uint64_t),
               "SadLayer currently requires 64-bit process pointers");

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

    sl_status status;
    do {
        status = random_bytes(&process->pointer_cookie,
                              sizeof(process->pointer_cookie));
    } while (status == SL_OK && process->pointer_cookie == 0U);
    if (status != SL_OK) {
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
    store_uintptr(process->peb + SL_WIN32_PEB_IMAGE_BASE_OFFSET,
                  (uintptr_t)image_base);
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
