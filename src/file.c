#define _GNU_SOURCE

#include "sadlayer/file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct sl_win32_file {
    int fd;
    uint32_t desired_access;
    sl_win32_file_type type;
};

_Static_assert(sizeof(off_t) >= sizeof(int64_t),
               "SadLayer file positions require 64-bit host off_t");

static bool file_type_is_valid(sl_win32_file_type type) {
    return type == SL_WIN32_FILE_TYPE_DISK ||
           type == SL_WIN32_FILE_TYPE_CHAR;
}

static bool access_is_valid(uint32_t desired_access) {
    return (desired_access &
            ~(SL_WIN32_GENERIC_READ | SL_WIN32_GENERIC_WRITE)) == 0U;
}

static void clean_error(int *host_error) {
    if (host_error != NULL) {
        *host_error = 0;
    }
}

static sl_status record_io_error(int *host_error) {
    if (host_error != NULL) {
        *host_error = errno;
    }
    return SL_ERROR_IO;
}

sl_status sl_win32_file_create_owned_fd(int fd, uint32_t desired_access,
                                        sl_win32_file_type type,
                                        sl_win32_file **out_file) {
    if (out_file != NULL) {
        *out_file = NULL;
    }
    if (fd < 0 || !access_is_valid(desired_access) ||
        !file_type_is_valid(type) || out_file == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_win32_file *file = calloc(1U, sizeof(*file));
    if (file == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    file->fd = fd;
    file->desired_access = desired_access;
    file->type = type;
    *out_file = file;
    return SL_OK;
}

sl_status sl_win32_file_open_console_output(sl_win32_file **out_file,
                                            int *host_error) {
    if (out_file != NULL) {
        *out_file = NULL;
    }
    clean_error(host_error);
    if (out_file == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    int fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) {
        return record_io_error(host_error);
    }
    sl_status status = sl_win32_file_create_owned_fd(
        fd, SL_WIN32_GENERIC_WRITE, SL_WIN32_FILE_TYPE_CHAR, out_file);
    if (status != SL_OK) {
        (void)close(fd);
    }
    return status;
}

void sl_win32_file_destroy(void *opaque) {
    sl_win32_file *file = opaque;
    if (file == NULL) {
        return;
    }
    if (file->fd >= 0) {
        (void)close(file->fd);
    }
    memset(file, 0, sizeof(*file));
    file->fd = -1;
    free(file);
}

sl_win32_file_type sl_win32_file_get_type(const sl_win32_file *file) {
    return file == NULL ? (sl_win32_file_type)0 : file->type;
}

bool sl_win32_file_can_read(const sl_win32_file *file) {
    return file != NULL &&
           (file->desired_access & SL_WIN32_GENERIC_READ) != 0U;
}

bool sl_win32_file_can_write(const sl_win32_file *file) {
    return file != NULL &&
           (file->desired_access & SL_WIN32_GENERIC_WRITE) != 0U;
}

sl_status sl_win32_file_write(sl_win32_file *file, const void *buffer,
                              size_t byte_count, size_t *bytes_written,
                              int *host_error) {
    if (bytes_written != NULL) {
        *bytes_written = 0U;
    }
    clean_error(host_error);
    if (file == NULL || bytes_written == NULL ||
        (buffer == NULL && byte_count != 0U)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (!sl_win32_file_can_write(file)) {
        if (host_error != NULL) {
            *host_error = EACCES;
        }
        return SL_ERROR_IO;
    }

    const uint8_t *bytes = buffer;
    while (*bytes_written < byte_count) {
        ssize_t result = write(file->fd, bytes + *bytes_written,
                               byte_count - *bytes_written);
        if (result > 0) {
            *bytes_written += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result == 0) {
            errno = EIO;
        }
        return record_io_error(host_error);
    }
    return SL_OK;
}

sl_status sl_win32_file_seek(sl_win32_file *file, int64_t distance,
                             sl_win32_file_seek_origin origin,
                             uint64_t *new_position, int *host_error) {
    clean_error(host_error);
    if (file == NULL || new_position == NULL ||
        (origin != SL_WIN32_FILE_SEEK_BEGIN &&
         origin != SL_WIN32_FILE_SEEK_CURRENT &&
         origin != SL_WIN32_FILE_SEEK_END)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (!sl_win32_file_can_read(file) && !sl_win32_file_can_write(file)) {
        if (host_error != NULL) {
            *host_error = EACCES;
        }
        return SL_ERROR_IO;
    }
    if (file->type != SL_WIN32_FILE_TYPE_DISK) {
        if (host_error != NULL) {
            *host_error = ESPIPE;
        }
        return SL_ERROR_IO;
    }
    int whence = SEEK_SET;
    if (origin == SL_WIN32_FILE_SEEK_CURRENT) {
        whence = SEEK_CUR;
    } else if (origin == SL_WIN32_FILE_SEEK_END) {
        whence = SEEK_END;
    }
    off_t result = lseek(file->fd, (off_t)distance, whence);
    if (result < 0) {
        return record_io_error(host_error);
    }
    *new_position = (uint64_t)result;
    return SL_OK;
}

sl_status sl_win32_file_flush(sl_win32_file *file, int *host_error) {
    clean_error(host_error);
    if (file == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (!sl_win32_file_can_write(file)) {
        if (host_error != NULL) {
            *host_error = EACCES;
        }
        return SL_ERROR_IO;
    }
    if (file->type != SL_WIN32_FILE_TYPE_DISK) {
        if (host_error != NULL) {
            *host_error = EBADF;
        }
        return SL_ERROR_IO;
    }
    int result;
    do {
        result = fsync(file->fd);
    } while (result != 0 && errno == EINTR);
    return result == 0 ? SL_OK : record_io_error(host_error);
}
