#define _GNU_SOURCE

#include "sadlayer/search.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            return false;                                                       \
        }                                                                      \
    } while (false)

#define TEST_FILE_ATTRIBUTE_DIRECTORY 0x00000010U
#define TEST_FILE_ATTRIBUTE_ARCHIVE 0x00000020U
#define TEST_FILE_ATTRIBUTE_REPARSE_POINT 0x00000400U

typedef struct {
    char path[64];
    int root_fd;
} search_fixture;

typedef struct {
    char names[16][SL_WIN32_FIND_NAME_CAPACITY];
    uint32_t attributes[16];
    uint64_t sizes[16];
    size_t count;
} search_results;

static bool write_fixture_file(int directory_fd, const char *name,
                               const char *contents) {
    int fd = openat(directory_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    size_t length = strlen(contents);
    size_t offset = 0U;
    while (offset < length) {
        ssize_t written = write(fd, contents + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        (void)close(fd);
        return false;
    }
    return close(fd) == 0;
}

static bool setup_fixture(search_fixture *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    fixture->root_fd = -1;
    memcpy(fixture->path, "/tmp/sadlayer-search-XXXXXX",
           sizeof("/tmp/sadlayer-search-XXXXXX"));
    if (mkdtemp(fixture->path) == NULL) {
        return false;
    }
    fixture->root_fd = open(fixture->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->root_fd < 0 ||
        !write_fixture_file(fixture->root_fd, "alpha.txt", "alpha") ||
        !write_fixture_file(fixture->root_fd, "ALPHA.BIN", "bin") ||
        !write_fixture_file(fixture->root_fd, "plain", "data") ||
        mkdirat(fixture->root_fd, "sub", 0700) != 0) {
        return false;
    }
    int subdirectory = openat(fixture->root_fd, "sub",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (subdirectory < 0 ||
        !write_fixture_file(subdirectory, "nested.dll", "nested")) {
        if (subdirectory >= 0) {
            (void)close(subdirectory);
        }
        return false;
    }
    if (close(subdirectory) != 0 ||
        symlinkat("/tmp", fixture->root_fd, "escape") != 0) {
        return false;
    }
    return true;
}

static bool teardown_fixture(search_fixture *fixture) {
    bool passed = true;
    if (fixture->root_fd >= 0) {
        if (unlinkat(fixture->root_fd, "alpha.txt", 0) != 0 ||
            unlinkat(fixture->root_fd, "ALPHA.BIN", 0) != 0 ||
            unlinkat(fixture->root_fd, "plain", 0) != 0 ||
            unlinkat(fixture->root_fd, "sub/nested.dll", 0) != 0 ||
            unlinkat(fixture->root_fd, "sub", AT_REMOVEDIR) != 0 ||
            unlinkat(fixture->root_fd, "escape", 0) != 0) {
            passed = false;
        }
        if (close(fixture->root_fd) != 0) {
            passed = false;
        }
        fixture->root_fd = -1;
    }
    if (fixture->path[0] != '\0' && rmdir(fixture->path) != 0) {
        passed = false;
    }
    return passed;
}

static size_t ascii_pattern(const char *source, uint16_t *destination,
                            size_t capacity) {
    size_t length = strlen(source);
    if (length > capacity) {
        return 0U;
    }
    for (size_t index = 0U; index < length; ++index) {
        destination[index] = (uint16_t)(unsigned char)source[index];
    }
    return length;
}

static bool find_name_to_ascii(const sl_win32_find_data_w *data,
                               char destination[SL_WIN32_FIND_NAME_CAPACITY]) {
    size_t index = 0U;
    while (index < SL_WIN32_FIND_NAME_CAPACITY &&
           data->file_name[index] != 0U) {
        if (data->file_name[index] > 0x7fU) {
            return false;
        }
        destination[index] = (char)data->file_name[index];
        ++index;
    }
    if (index == SL_WIN32_FIND_NAME_CAPACITY) {
        return false;
    }
    destination[index] = '\0';
    return true;
}

static bool append_result(search_results *results,
                          const sl_win32_find_data_w *data) {
    if (results->count >= 16U ||
        !find_name_to_ascii(data, results->names[results->count])) {
        return false;
    }
    results->attributes[results->count] = data->file_attributes;
    results->sizes[results->count] =
        ((uint64_t)data->file_size_high << 32U) | data->file_size_low;
    ++results->count;
    return true;
}

static bool collect_matches(int root_fd, const char *pattern_text,
                            sl_win32_search_options options,
                            search_results *results) {
    memset(results, 0, sizeof(*results));
    uint16_t pattern[128] = {0};
    size_t pattern_length =
        ascii_pattern(pattern_text, pattern, sizeof(pattern) / sizeof(*pattern));
    if (pattern_length == 0U) {
        return false;
    }
    sl_win32_search *search = NULL;
    sl_win32_find_data_w data;
    memset(&data, 0xa5, sizeof(data));
    int host_error = -1;
    sl_search_result status = sl_win32_search_open(
        root_fd, pattern, pattern_length, options, &search, &data,
        &host_error);
    if (status != SL_SEARCH_OK || search == NULL || host_error != 0 ||
        !append_result(results, &data)) {
        sl_win32_search_destroy(search);
        return false;
    }
    for (;;) {
        memset(&data, 0xa5, sizeof(data));
        status = sl_win32_search_next(search, &data, &host_error);
        if (status == SL_SEARCH_NO_MATCH) {
            break;
        }
        if (status != SL_SEARCH_OK || host_error != 0 ||
            !append_result(results, &data)) {
            sl_win32_search_destroy(search);
            return false;
        }
    }
    if (host_error != 0) {
        sl_win32_search_destroy(search);
        return false;
    }
    memset(&data, 0xa5, sizeof(data));
    if (sl_win32_search_next(search, &data, &host_error) !=
            SL_SEARCH_NO_MATCH ||
        host_error != 0 || ((const uint8_t *)&data)[0] != 0xa5U) {
        sl_win32_search_destroy(search);
        return false;
    }
    sl_win32_search_destroy(search);
    return true;
}

static ptrdiff_t result_index(const search_results *results,
                              const char *name) {
    for (size_t index = 0U; index < results->count; ++index) {
        if (strcmp(results->names[index], name) == 0) {
            return (ptrdiff_t)index;
        }
    }
    return -1;
}

static bool test_layout_and_arguments(void) {
    CHECK(sizeof(sl_win32_find_data_w) == 592U);
    CHECK(offsetof(sl_win32_find_data_w, creation_time) == 4U);
    CHECK(offsetof(sl_win32_find_data_w, last_access_time) == 12U);
    CHECK(offsetof(sl_win32_find_data_w, last_write_time) == 20U);
    CHECK(offsetof(sl_win32_find_data_w, file_size_high) == 28U);
    CHECK(offsetof(sl_win32_find_data_w, file_name) == 44U);
    CHECK(offsetof(sl_win32_find_data_w, alternate_file_name) == 564U);

    search_fixture fixture;
    CHECK(setup_fixture(&fixture));
    const uint16_t star[] = {'*'};
    const uint16_t embedded_nul[] = {'a', 0U, '*'};
    const uint16_t invalid_utf16[] = {0xd800U};
    const uint16_t absolute[] = {'/', '*'};
    const uint16_t escape[] = {'.', '.', '/', '*'};
    sl_win32_search *search = (sl_win32_search *)(uintptr_t)1U;
    sl_win32_find_data_w data;
    memset(&data, 0xa5, sizeof(data));
    int host_error = -1;
    sl_win32_search_options options = {0};

    CHECK(sl_win32_search_open(-1, star, 1U, options, &search, &data,
                               &host_error) == SL_SEARCH_INVALID_ARGUMENT);
    CHECK(search == NULL && host_error == 0);
    search = (sl_win32_search *)(uintptr_t)1U;
    CHECK(sl_win32_search_open(fixture.root_fd, NULL, 1U, options, &search,
                               &data, &host_error) ==
          SL_SEARCH_INVALID_ARGUMENT);
    CHECK(search == NULL);
    CHECK(sl_win32_search_open(fixture.root_fd, star, 1U, options, NULL,
                               &data, &host_error) ==
          SL_SEARCH_INVALID_ARGUMENT);
    CHECK(sl_win32_search_open(fixture.root_fd, star, 1U, options, &search,
                               NULL, &host_error) ==
          SL_SEARCH_INVALID_ARGUMENT);
    CHECK(sl_win32_search_open(fixture.root_fd, embedded_nul, 3U, options,
                               &search, &data, &host_error) ==
          SL_SEARCH_INVALID_PATH);
    CHECK(sl_win32_search_open(fixture.root_fd, invalid_utf16, 1U, options,
                               &search, &data, &host_error) ==
          SL_SEARCH_INVALID_ENCODING);
    CHECK(sl_win32_search_open(fixture.root_fd, absolute, 2U, options,
                               &search, &data, &host_error) ==
          SL_SEARCH_INVALID_PATH);
    CHECK(sl_win32_search_open(fixture.root_fd, escape, 4U, options, &search,
                               &data, &host_error) ==
          SL_SEARCH_INVALID_PATH);
    CHECK(sl_win32_search_next(NULL, &data, &host_error) ==
          SL_SEARCH_INVALID_ARGUMENT);
    CHECK(sl_win32_search_next((sl_win32_search *)(uintptr_t)1U, NULL,
                               &host_error) == SL_SEARCH_INVALID_ARGUMENT);
    sl_win32_search_destroy(NULL);
    CHECK(teardown_fixture(&fixture));
    return true;
}

static bool test_wildcards_and_metadata(void) {
    search_fixture fixture;
    CHECK(setup_fixture(&fixture));
    search_results results;
    sl_win32_search_options options = {0};

    CHECK(collect_matches(fixture.root_fd, "*", options, &results));
    CHECK(results.count == 5U);
    ptrdiff_t alpha = result_index(&results, "alpha.txt");
    ptrdiff_t upper = result_index(&results, "ALPHA.BIN");
    ptrdiff_t plain = result_index(&results, "plain");
    ptrdiff_t sub = result_index(&results, "sub");
    ptrdiff_t symlink = result_index(&results, "escape");
    CHECK(alpha >= 0 && upper >= 0 && plain >= 0 && sub >= 0 && symlink >= 0);
    CHECK(results.attributes[(size_t)alpha] == TEST_FILE_ATTRIBUTE_ARCHIVE);
    CHECK(results.sizes[(size_t)alpha] == 5U);
    CHECK(results.attributes[(size_t)sub] == TEST_FILE_ATTRIBUTE_DIRECTORY);
    CHECK(results.sizes[(size_t)sub] == 0U);
    CHECK(results.attributes[(size_t)symlink] ==
          TEST_FILE_ATTRIBUTE_REPARSE_POINT);

    CHECK(collect_matches(fixture.root_fd, "*.txt", options, &results));
    CHECK(results.count == 1U && result_index(&results, "alpha.txt") >= 0);
    CHECK(collect_matches(fixture.root_fd, "a?pha.*", options, &results));
    CHECK(results.count == 2U && result_index(&results, "alpha.txt") >= 0 &&
          result_index(&results, "ALPHA.BIN") >= 0);
    CHECK(collect_matches(fixture.root_fd, "*.*", options, &results));
    CHECK(result_index(&results, "plain") >= 0);

    options.case_sensitive = true;
    CHECK(collect_matches(fixture.root_fd, "alpha.*", options, &results));
    CHECK(results.count == 1U && result_index(&results, "alpha.txt") >= 0);
    options.case_sensitive = false;
    options.directories_only = true;
    CHECK(collect_matches(fixture.root_fd, "*", options, &results));
    CHECK(results.count == 1U && result_index(&results, "sub") >= 0);
    CHECK(teardown_fixture(&fixture));
    return true;
}

static bool test_paths_isolation_and_no_match(void) {
    search_fixture fixture;
    CHECK(setup_fixture(&fixture));
    search_results results;
    sl_win32_search_options options = {0};
    CHECK(collect_matches(fixture.root_fd, "sub\\*.DLL", options, &results));
    CHECK(results.count == 1U && result_index(&results, "nested.dll") >= 0);
    CHECK(collect_matches(fixture.root_fd, "sub/../*.txt", options,
                          &results));
    CHECK(results.count == 1U && result_index(&results, "alpha.txt") >= 0);

    uint16_t pattern[32] = {0};
    size_t length = ascii_pattern("escape/*", pattern, 32U);
    sl_win32_search *search = NULL;
    sl_win32_find_data_w data;
    int host_error = 0;
    CHECK(sl_win32_search_open(fixture.root_fd, pattern, length, options,
                               &search, &data, &host_error) == SL_SEARCH_IO);
    CHECK(search == NULL && (host_error == ELOOP || host_error == ENOTDIR));

    length = ascii_pattern("missing-*", pattern, 32U);
    memset(&data, 0xa5, sizeof(data));
    host_error = -1;
    CHECK(sl_win32_search_open(fixture.root_fd, pattern, length, options,
                               &search, &data, &host_error) ==
          SL_SEARCH_NO_MATCH);
    CHECK(search == NULL && host_error == 0 &&
          ((const uint8_t *)&data)[0] == 0xa5U);

    uint16_t all[] = {'*'};
    sl_win32_search *first = NULL;
    sl_win32_search *second = NULL;
    sl_win32_find_data_w first_data;
    sl_win32_find_data_w second_data;
    CHECK(sl_win32_search_open(fixture.root_fd, all, 1U, options, &first,
                               &first_data, &host_error) == SL_SEARCH_OK);
    CHECK(sl_win32_search_open(fixture.root_fd, all, 1U, options, &second,
                               &second_data, &host_error) == SL_SEARCH_OK);
    char first_name[SL_WIN32_FIND_NAME_CAPACITY];
    char second_name[SL_WIN32_FIND_NAME_CAPACITY];
    CHECK(find_name_to_ascii(&first_data, first_name));
    CHECK(find_name_to_ascii(&second_data, second_name));
    CHECK(strcmp(first_name, second_name) == 0);
    sl_win32_search_destroy(first);
    sl_win32_search_destroy(second);

    CHECK(teardown_fixture(&fixture));
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"layout and arguments", test_layout_and_arguments},
        {"wildcards and metadata", test_wildcards_and_metadata},
        {"paths, isolation, and no match",
         test_paths_isolation_and_no_match},
    };
    size_t passed = 0U;
    for (size_t index = 0U; index < sizeof(tests) / sizeof(tests[0]); ++index) {
        if (!tests[index].run()) {
            fprintf(stderr, "FAIL %s\n", tests[index].name);
            return 1;
        }
        printf("PASS %s\n", tests[index].name);
        ++passed;
    }
    printf("%zu search tests passed\n", passed);
    return 0;
}
