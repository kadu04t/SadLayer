#ifndef SADLAYER_SEARCH_H
#define SADLAYER_SEARCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SL_WIN32_FIND_NAME_CAPACITY 260U
#define SL_WIN32_FIND_ALTERNATE_NAME_CAPACITY 14U

typedef struct sl_win32_search sl_win32_search;

typedef struct {
    uint32_t low_date_time;
    uint32_t high_date_time;
} sl_win32_search_filetime;

typedef struct {
    uint32_t file_attributes;
    sl_win32_search_filetime creation_time;
    sl_win32_search_filetime last_access_time;
    sl_win32_search_filetime last_write_time;
    uint32_t file_size_high;
    uint32_t file_size_low;
    uint32_t reserved0;
    uint32_t reserved1;
    uint16_t file_name[SL_WIN32_FIND_NAME_CAPACITY];
    uint16_t alternate_file_name[SL_WIN32_FIND_ALTERNATE_NAME_CAPACITY];
} sl_win32_find_data_w;

typedef struct {
    bool case_sensitive;
    bool directories_only;
} sl_win32_search_options;

typedef enum {
    SL_SEARCH_OK = 0,
    SL_SEARCH_INVALID_ARGUMENT,
    SL_SEARCH_INVALID_ENCODING,
    SL_SEARCH_INVALID_PATH,
    SL_SEARCH_NO_MATCH,
    SL_SEARCH_IO,
    SL_SEARCH_OUT_OF_MEMORY,
} sl_search_result;

/*
 * Opens only relative patterns below root_fd. Parent components are resolved
 * without following symlinks; the search receives its own directory open-file
 * description and never advances the root descriptor's directory offset.
 */
sl_search_result sl_win32_search_open(
    int root_fd, const uint16_t *path_pattern, size_t path_pattern_length,
    sl_win32_search_options options, sl_win32_search **out_search,
    sl_win32_find_data_w *first_result, int *host_error);

sl_search_result sl_win32_search_next(sl_win32_search *search,
                                      sl_win32_find_data_w *result,
                                      int *host_error);

/* Compatible with sl_handle_destroy_fn. */
void sl_win32_search_destroy(void *opaque);

#endif
