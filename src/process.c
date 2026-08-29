#include "sadlayer/process.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>

struct sl_win32_process {
    uintptr_t pointer_cookie;
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

sl_status sl_win32_process_create(sl_win32_process **out_process) {
    if (out_process == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    *out_process = NULL;

    sl_win32_process *process = calloc(1U, sizeof(*process));
    if (process == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }

    sl_status status;
    do {
        status = random_bytes(&process->pointer_cookie,
                              sizeof(process->pointer_cookie));
    } while (status == SL_OK && process->pointer_cookie == 0U);
    if (status != SL_OK) {
        free(process);
        return status;
    }

    *out_process = process;
    return SL_OK;
}

void sl_win32_process_destroy(sl_win32_process *process) { free(process); }

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
