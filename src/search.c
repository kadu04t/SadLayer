#define _GNU_SOURCE

#include "sadlayer/search.h"

#include "sadlayer/unicode.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <threads.h>
#include <unistd.h>

#define SL_SEARCH_BUFFER_SIZE 8192U
#define SL_FILE_ATTRIBUTE_DIRECTORY 0x00000010U
#define SL_FILE_ATTRIBUTE_ARCHIVE 0x00000020U
#define SL_FILE_ATTRIBUTE_REPARSE_POINT 0x00000400U
#define SL_FILETIME_UNIX_EPOCH_DELTA INT64_C(11644473600)
#define SL_FILETIME_TICKS_PER_SECOND UINT64_C(10000000)

typedef struct {
    uint64_t inode;
    int64_t offset;
    uint16_t record_length;
    uint8_t type;
    char name[];
} sl_linux_dirent64;

struct sl_win32_search {
    atomic_bool locked;
    int directory_fd;
    uint16_t *pattern;
    size_t pattern_length;
    bool case_sensitive;
    bool directories_only;
    bool exhausted;
    size_t buffer_offset;
    size_t buffer_size;
    _Alignas(uint64_t) uint8_t buffer[SL_SEARCH_BUFFER_SIZE];
};

_Static_assert(sizeof(sl_win32_find_data_w) == 592U,
               "Windows WIN32_FIND_DATAW layout changed");
_Static_assert(offsetof(sl_win32_find_data_w, creation_time) == 4U,
               "WIN32_FIND_DATAW creation-time offset changed");
_Static_assert(offsetof(sl_win32_find_data_w, last_access_time) == 12U,
               "WIN32_FIND_DATAW access-time offset changed");
_Static_assert(offsetof(sl_win32_find_data_w, last_write_time) == 20U,
               "WIN32_FIND_DATAW write-time offset changed");
_Static_assert(offsetof(sl_win32_find_data_w, file_size_high) == 28U,
               "WIN32_FIND_DATAW size offset changed");
_Static_assert(offsetof(sl_win32_find_data_w, file_name) == 44U,
               "WIN32_FIND_DATAW filename offset changed");
_Static_assert(offsetof(sl_win32_find_data_w, alternate_file_name) == 564U,
               "WIN32_FIND_DATAW alternate-name offset changed");
_Static_assert(offsetof(sl_linux_dirent64, name) == 19U,
               "Linux getdents64 record layout changed");
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2,
               "clone-safe search locking requires lock-free atomic bool");

static void search_lock(sl_win32_search *search) {
    while (atomic_exchange_explicit(&search->locked, true,
                                    memory_order_acquire)) {
        thrd_yield();
    }
}

static void search_unlock(sl_win32_search *search) {
    atomic_store_explicit(&search->locked, false, memory_order_release);
}

static void clean_error(int *host_error) {
    if (host_error != NULL) {
        *host_error = 0;
    }
}

static sl_search_result record_io_error(int *host_error) {
    if (host_error != NULL) {
        *host_error = errno;
    }
    return SL_SEARCH_IO;
}

static bool component_is(const char *component, size_t length,
                         const char *expected) {
    size_t expected_length = strlen(expected);
    return length == expected_length &&
           memcmp(component, expected, length) == 0;
}

static sl_search_result normalize_pattern(
    const uint16_t *path_pattern, size_t path_pattern_length,
    char **out_directory, uint16_t **out_pattern,
    size_t *out_pattern_length) {
    *out_directory = NULL;
    *out_pattern = NULL;
    *out_pattern_length = 0U;
    if (path_pattern == NULL || path_pattern_length == 0U) {
        return SL_SEARCH_INVALID_ARGUMENT;
    }
    for (size_t index = 0U; index < path_pattern_length; ++index) {
        if (path_pattern[index] == 0U) {
            return SL_SEARCH_INVALID_PATH;
        }
    }

    size_t encoded_length = 0U;
    sl_status status = sl_utf16_to_utf8(path_pattern, path_pattern_length,
                                        NULL, 0U, &encoded_length);
    if (status != SL_OK) {
        return status == SL_ERROR_INVALID_ENCODING
                   ? SL_SEARCH_INVALID_ENCODING
                   : SL_SEARCH_INVALID_ARGUMENT;
    }
    if (encoded_length == 0U || encoded_length == SIZE_MAX) {
        return SL_SEARCH_INVALID_PATH;
    }
    char *encoded = malloc(encoded_length + 1U);
    if (encoded == NULL) {
        return SL_SEARCH_OUT_OF_MEMORY;
    }
    size_t converted = 0U;
    status = sl_utf16_to_utf8(path_pattern, path_pattern_length, encoded,
                              encoded_length, &converted);
    if (status != SL_OK || converted != encoded_length) {
        free(encoded);
        return status == SL_ERROR_INVALID_ENCODING
                   ? SL_SEARCH_INVALID_ENCODING
                   : SL_SEARCH_INVALID_ARGUMENT;
    }
    encoded[encoded_length] = '\0';
    for (size_t index = 0U; index < encoded_length; ++index) {
        if (encoded[index] == '\\') {
            encoded[index] = '/';
        } else if (encoded[index] == ':') {
            free(encoded);
            return SL_SEARCH_INVALID_PATH;
        }
    }
    if (encoded[0] == '/' || encoded[encoded_length - 1U] == '/') {
        free(encoded);
        return SL_SEARCH_INVALID_PATH;
    }

    size_t leaf_start = encoded_length;
    while (leaf_start > 0U && encoded[leaf_start - 1U] != '/') {
        --leaf_start;
    }
    const char *leaf = encoded + leaf_start;
    size_t leaf_length = encoded_length - leaf_start;
    if (leaf_length == 0U || component_is(leaf, leaf_length, ".") ||
        component_is(leaf, leaf_length, "..")) {
        free(encoded);
        return SL_SEARCH_INVALID_PATH;
    }

    char *directory = calloc(leaf_start + 1U, 1U);
    if (directory == NULL) {
        free(encoded);
        return SL_SEARCH_OUT_OF_MEMORY;
    }
    size_t input = 0U;
    size_t output = 0U;
    while (input < leaf_start) {
        while (input < leaf_start && encoded[input] == '/') {
            ++input;
        }
        size_t begin = input;
        while (input < leaf_start && encoded[input] != '/') {
            ++input;
        }
        size_t length = input - begin;
        if (length == 0U || component_is(encoded + begin, length, ".")) {
            continue;
        }
        if (component_is(encoded + begin, length, "..")) {
            if (output == 0U) {
                free(directory);
                free(encoded);
                return SL_SEARCH_INVALID_PATH;
            }
            while (output > 0U && directory[output - 1U] != '/') {
                --output;
            }
            if (output > 0U) {
                --output;
            }
            continue;
        }
        if (memchr(encoded + begin, '*', length) != NULL ||
            memchr(encoded + begin, '?', length) != NULL) {
            free(directory);
            free(encoded);
            return SL_SEARCH_INVALID_PATH;
        }
        if (output != 0U) {
            directory[output++] = '/';
        }
        memcpy(directory + output, encoded + begin, length);
        output += length;
    }
    directory[output] = '\0';

    size_t pattern_length = 0U;
    status = sl_utf8_to_utf16(leaf, leaf_length, NULL, 0U, &pattern_length);
    if (status != SL_OK) {
        free(directory);
        free(encoded);
        return SL_SEARCH_INVALID_ENCODING;
    }
    if (pattern_length > (SIZE_MAX / sizeof(uint16_t)) - 1U) {
        free(directory);
        free(encoded);
        return SL_SEARCH_OUT_OF_MEMORY;
    }
    uint16_t *pattern = calloc(pattern_length + 1U, sizeof(*pattern));
    if (pattern == NULL) {
        free(directory);
        free(encoded);
        return SL_SEARCH_OUT_OF_MEMORY;
    }
    size_t pattern_converted = 0U;
    status = sl_utf8_to_utf16(leaf, leaf_length, pattern, pattern_length,
                              &pattern_converted);
    free(encoded);
    if (status != SL_OK || pattern_converted != pattern_length) {
        free(pattern);
        free(directory);
        return SL_SEARCH_INVALID_ENCODING;
    }

    *out_directory = directory;
    *out_pattern = pattern;
    *out_pattern_length = pattern_length;
    return SL_SEARCH_OK;
}

static int open_search_directory(int root_fd, char *directory) {
    int current = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) {
        return -1;
    }
    char *component = directory;
    while (*component != '\0') {
        char *separator = strchr(component, '/');
        if (separator != NULL) {
            *separator = '\0';
        }
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int saved_error = errno;
        (void)close(current);
        if (next < 0) {
            errno = saved_error;
            return -1;
        }
        current = next;
        if (separator == NULL) {
            break;
        }
        component = separator + 1;
    }
    return current;
}

static uint16_t fold_ascii(uint16_t unit) {
    if (unit >= (uint16_t)'A' && unit <= (uint16_t)'Z') {
        return (uint16_t)(unit - (uint16_t)'A' + (uint16_t)'a');
    }
    return unit;
}

static bool units_equal(uint16_t first, uint16_t second,
                        bool case_sensitive) {
    return case_sensitive ? first == second
                          : fold_ascii(first) == fold_ascii(second);
}

static bool wildcard_matches(const uint16_t *pattern, size_t pattern_length,
                             const uint16_t *name, size_t name_length,
                             bool case_sensitive) {
    if (pattern_length == 3U && pattern[0] == (uint16_t)'*' &&
        pattern[1] == (uint16_t)'.' && pattern[2] == (uint16_t)'*') {
        return true;
    }
    size_t pattern_index = 0U;
    size_t name_index = 0U;
    size_t star_index = SIZE_MAX;
    size_t star_name_index = 0U;
    while (name_index < name_length) {
        if (pattern_index < pattern_length &&
            (pattern[pattern_index] == (uint16_t)'?' ||
             units_equal(pattern[pattern_index], name[name_index],
                         case_sensitive))) {
            ++pattern_index;
            ++name_index;
        } else if (pattern_index < pattern_length &&
                   pattern[pattern_index] == (uint16_t)'*') {
            star_index = pattern_index++;
            star_name_index = name_index;
        } else if (star_index != SIZE_MAX) {
            pattern_index = star_index + 1U;
            name_index = ++star_name_index;
        } else {
            return false;
        }
    }
    while (pattern_index < pattern_length &&
           pattern[pattern_index] == (uint16_t)'*') {
        ++pattern_index;
    }
    return pattern_index == pattern_length;
}

static uint64_t timespec_to_filetime(struct timespec value) {
    if (value.tv_sec < -SL_FILETIME_UNIX_EPOCH_DELTA) {
        return 0U;
    }
    uint64_t seconds;
    if (value.tv_sec < 0) {
        seconds = (uint64_t)(value.tv_sec + SL_FILETIME_UNIX_EPOCH_DELTA);
    } else {
        uint64_t unix_seconds = (uint64_t)value.tv_sec;
        if (unix_seconds >
            UINT64_MAX - (uint64_t)SL_FILETIME_UNIX_EPOCH_DELTA) {
            return UINT64_MAX;
        }
        seconds = unix_seconds + (uint64_t)SL_FILETIME_UNIX_EPOCH_DELTA;
    }
    if (seconds > UINT64_MAX / SL_FILETIME_TICKS_PER_SECOND) {
        return UINT64_MAX;
    }
    uint64_t ticks = seconds * SL_FILETIME_TICKS_PER_SECOND;
    uint64_t subsecond = value.tv_nsec <= 0L
                             ? 0U
                             : (uint64_t)value.tv_nsec / UINT64_C(100);
    return ticks > UINT64_MAX - subsecond ? UINT64_MAX : ticks + subsecond;
}

static sl_win32_search_filetime split_filetime(uint64_t value) {
    return (sl_win32_search_filetime){
        .low_date_time = (uint32_t)value,
        .high_date_time = (uint32_t)(value >> 32U),
    };
}

static bool fill_find_data(sl_win32_search *search, const char *name,
                           size_t name_length, const struct stat *metadata,
                           sl_win32_find_data_w *result) {
    size_t wide_length = 0U;
    if (sl_utf8_to_utf16(name, name_length, NULL, 0U, &wide_length) != SL_OK ||
        wide_length >= SL_WIN32_FIND_NAME_CAPACITY) {
        return false;
    }
    uint16_t wide_name[SL_WIN32_FIND_NAME_CAPACITY] = {0};
    size_t converted = 0U;
    if (sl_utf8_to_utf16(name, name_length, wide_name,
                         SL_WIN32_FIND_NAME_CAPACITY - 1U,
                         &converted) != SL_OK ||
        converted != wide_length ||
        !wildcard_matches(search->pattern, search->pattern_length, wide_name,
                          wide_length, search->case_sensitive)) {
        return false;
    }
    if (search->directories_only && !S_ISDIR(metadata->st_mode)) {
        return false;
    }

    sl_win32_find_data_w found = {0};
    if (S_ISDIR(metadata->st_mode)) {
        found.file_attributes = SL_FILE_ATTRIBUTE_DIRECTORY;
    } else if (S_ISLNK(metadata->st_mode)) {
        found.file_attributes = SL_FILE_ATTRIBUTE_REPARSE_POINT;
    } else {
        found.file_attributes = SL_FILE_ATTRIBUTE_ARCHIVE;
    }
    found.last_access_time =
        split_filetime(timespec_to_filetime(metadata->st_atim));
    found.last_write_time =
        split_filetime(timespec_to_filetime(metadata->st_mtim));
    if (!S_ISDIR(metadata->st_mode) && metadata->st_size > 0) {
        uint64_t size = (uint64_t)metadata->st_size;
        found.file_size_low = (uint32_t)size;
        found.file_size_high = (uint32_t)(size >> 32U);
    }
    memcpy(found.file_name, wide_name,
           (wide_length + 1U) * sizeof(*wide_name));
    *result = found;
    return true;
}

static sl_search_result search_next_locked(sl_win32_search *search,
                                           sl_win32_find_data_w *result,
                                           int *host_error) {
    while (!search->exhausted) {
        if (search->buffer_offset == search->buffer_size) {
            ssize_t count;
            do {
                count = syscall(SYS_getdents64, search->directory_fd,
                                search->buffer, sizeof(search->buffer));
            } while (count < 0 && errno == EINTR);
            if (count < 0) {
                return record_io_error(host_error);
            }
            if (count == 0) {
                search->exhausted = true;
                return SL_SEARCH_NO_MATCH;
            }
            search->buffer_offset = 0U;
            search->buffer_size = (size_t)count;
        }

        size_t remaining = search->buffer_size - search->buffer_offset;
        if (remaining < offsetof(sl_linux_dirent64, name) + 1U) {
            errno = EIO;
            return record_io_error(host_error);
        }
        const sl_linux_dirent64 *entry =
            (const sl_linux_dirent64 *)(const void *)(
                search->buffer + search->buffer_offset);
        size_t minimum = offsetof(sl_linux_dirent64, name) + 1U;
        if ((size_t)entry->record_length < minimum ||
            (size_t)entry->record_length > remaining) {
            errno = EIO;
            return record_io_error(host_error);
        }
        search->buffer_offset += (size_t)entry->record_length;

        size_t name_capacity = (size_t)entry->record_length -
                               offsetof(sl_linux_dirent64, name);
        const char *terminator = memchr(entry->name, '\0', name_capacity);
        if (terminator == NULL) {
            errno = EIO;
            return record_io_error(host_error);
        }
        size_t name_length = (size_t)(terminator - entry->name);
        if ((name_length == 1U && entry->name[0] == '.') ||
            (name_length == 2U && entry->name[0] == '.' &&
             entry->name[1] == '.')) {
            continue;
        }

        struct stat metadata;
        if (fstatat(search->directory_fd, entry->name, &metadata,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                continue;
            }
            return record_io_error(host_error);
        }
        if (fill_find_data(search, entry->name, name_length, &metadata,
                           result)) {
            return SL_SEARCH_OK;
        }
    }
    return SL_SEARCH_NO_MATCH;
}

sl_search_result sl_win32_search_open(
    int root_fd, const uint16_t *path_pattern, size_t path_pattern_length,
    sl_win32_search_options options, sl_win32_search **out_search,
    sl_win32_find_data_w *first_result, int *host_error) {
    if (out_search != NULL) {
        *out_search = NULL;
    }
    clean_error(host_error);
    if (root_fd < 0 || path_pattern == NULL || path_pattern_length == 0U ||
        out_search == NULL || first_result == NULL) {
        return SL_SEARCH_INVALID_ARGUMENT;
    }

    char *directory = NULL;
    uint16_t *pattern = NULL;
    size_t pattern_length = 0U;
    sl_search_result result = normalize_pattern(
        path_pattern, path_pattern_length, &directory, &pattern,
        &pattern_length);
    if (result != SL_SEARCH_OK) {
        return result;
    }
    int directory_fd = open_search_directory(root_fd, directory);
    free(directory);
    if (directory_fd < 0) {
        free(pattern);
        return record_io_error(host_error);
    }

    sl_win32_search *search = calloc(1U, sizeof(*search));
    if (search == NULL) {
        (void)close(directory_fd);
        free(pattern);
        return SL_SEARCH_OUT_OF_MEMORY;
    }
    atomic_init(&search->locked, false);
    search->directory_fd = directory_fd;
    search->pattern = pattern;
    search->pattern_length = pattern_length;
    search->case_sensitive = options.case_sensitive;
    search->directories_only = options.directories_only;

    sl_win32_find_data_w found;
    result = search_next_locked(search, &found, host_error);
    if (result != SL_SEARCH_OK) {
        sl_win32_search_destroy(search);
        return result;
    }
    *first_result = found;
    *out_search = search;
    return SL_SEARCH_OK;
}

sl_search_result sl_win32_search_next(sl_win32_search *search,
                                      sl_win32_find_data_w *result,
                                      int *host_error) {
    clean_error(host_error);
    if (search == NULL || result == NULL) {
        return SL_SEARCH_INVALID_ARGUMENT;
    }
    search_lock(search);
    sl_win32_find_data_w found;
    sl_search_result status = search_next_locked(search, &found, host_error);
    if (status == SL_SEARCH_OK) {
        *result = found;
    }
    search_unlock(search);
    return status;
}

void sl_win32_search_destroy(void *opaque) {
    sl_win32_search *search = opaque;
    if (search == NULL) {
        return;
    }
    if (search->directory_fd >= 0) {
        (void)close(search->directory_fd);
    }
    free(search->pattern);
    memset(search, 0, sizeof(*search));
    search->directory_fd = -1;
    free(search);
}
