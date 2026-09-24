#ifndef SADLAYER_FILE_H
#define SADLAYER_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"

#define SL_WIN32_GENERIC_READ UINT32_C(0x80000000)
#define SL_WIN32_GENERIC_WRITE UINT32_C(0x40000000)

typedef struct sl_win32_file sl_win32_file;

typedef enum {
    SL_WIN32_FILE_TYPE_DISK = 1,
    SL_WIN32_FILE_TYPE_CHAR = 2,
} sl_win32_file_type;

typedef enum {
    SL_WIN32_FILE_SEEK_BEGIN = 0,
    SL_WIN32_FILE_SEEK_CURRENT = 1,
    SL_WIN32_FILE_SEEK_END = 2,
} sl_win32_file_seek_origin;

/*
 * Takes ownership of fd only on success. The descriptor is never exposed to
 * the guest; callers publish the resulting object through a typed handle.
 */
sl_status sl_win32_file_create_owned_fd(int fd, uint32_t desired_access,
                                        sl_win32_file_type type,
                                        sl_win32_file **out_file);

/* Duplicates the current host console-output descriptor with close-on-exec. */
sl_status sl_win32_file_open_console_output(sl_win32_file **out_file,
                                            int *host_error);

/* Compatible with sl_handle_destroy_fn. */
void sl_win32_file_destroy(void *opaque);

sl_win32_file_type sl_win32_file_get_type(const sl_win32_file *file);
bool sl_win32_file_can_read(const sl_win32_file *file);
bool sl_win32_file_can_write(const sl_win32_file *file);

sl_status sl_win32_file_write(sl_win32_file *file, const void *buffer,
                              size_t byte_count, size_t *bytes_written,
                              int *host_error);
sl_status sl_win32_file_seek(sl_win32_file *file, int64_t distance,
                             sl_win32_file_seek_origin origin,
                             uint64_t *new_position, int *host_error);
sl_status sl_win32_file_flush(sl_win32_file *file, int *host_error);

#endif
