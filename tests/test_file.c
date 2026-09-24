#define _GNU_SOURCE

#include "sadlayer/file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
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

static bool test_arguments_and_descriptor_ownership(void) {
    int descriptors[2] = {-1, -1};
    CHECK(pipe(descriptors) == 0);
    sl_win32_file *file = (sl_win32_file *)(uintptr_t)1U;

    CHECK(sl_win32_file_create_owned_fd(
              -1, SL_WIN32_GENERIC_WRITE, SL_WIN32_FILE_TYPE_CHAR,
              &file) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(file == NULL);
    file = (sl_win32_file *)(uintptr_t)1U;
    CHECK(sl_win32_file_create_owned_fd(
              descriptors[1], UINT32_C(0x20000000),
              SL_WIN32_FILE_TYPE_CHAR, &file) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(file == NULL);
    CHECK(fcntl(descriptors[1], F_GETFD) >= 0);
    file = (sl_win32_file *)(uintptr_t)1U;
    CHECK(sl_win32_file_create_owned_fd(
              descriptors[1], SL_WIN32_GENERIC_WRITE,
              (sl_win32_file_type)0, &file) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(file == NULL);
    CHECK(fcntl(descriptors[1], F_GETFD) >= 0);
    CHECK(sl_win32_file_create_owned_fd(
              descriptors[1], SL_WIN32_GENERIC_WRITE,
              SL_WIN32_FILE_TYPE_CHAR, NULL) == SL_ERROR_INVALID_ARGUMENT);
    CHECK(fcntl(descriptors[1], F_GETFD) >= 0);

    CHECK(sl_win32_file_create_owned_fd(
              descriptors[1], SL_WIN32_GENERIC_WRITE,
              SL_WIN32_FILE_TYPE_CHAR, &file) == SL_OK);
    CHECK(file != NULL);
    CHECK(sl_win32_file_get_type(file) == SL_WIN32_FILE_TYPE_CHAR);
    CHECK(!sl_win32_file_can_read(file));
    CHECK(sl_win32_file_can_write(file));
    CHECK(sl_win32_file_get_type(NULL) == (sl_win32_file_type)0);
    CHECK(!sl_win32_file_can_read(NULL));
    CHECK(!sl_win32_file_can_write(NULL));

    sl_win32_file_destroy(file);
    errno = 0;
    CHECK(fcntl(descriptors[1], F_GETFD) == -1);
    CHECK(errno == EBADF);
    sl_win32_file_destroy(NULL);
    CHECK(close(descriptors[0]) == 0);
    return true;
}

static bool test_character_file_operations(void) {
    int descriptors[2] = {-1, -1};
    CHECK(pipe(descriptors) == 0);
    sl_win32_file *file = NULL;
    CHECK(sl_win32_file_create_owned_fd(
              descriptors[1], SL_WIN32_GENERIC_WRITE,
              SL_WIN32_FILE_TYPE_CHAR, &file) == SL_OK);

    size_t written = SIZE_MAX;
    int host_error = -1;
    CHECK(sl_win32_file_write(file, "abc", 3U, &written, &host_error) ==
          SL_OK);
    CHECK(written == 3U && host_error == 0);
    char received[3] = {0};
    CHECK(read(descriptors[0], received, sizeof(received)) ==
          (ssize_t)sizeof(received));
    CHECK(memcmp(received, "abc", sizeof(received)) == 0);

    written = SIZE_MAX;
    host_error = -1;
    CHECK(sl_win32_file_write(file, NULL, 0U, &written, &host_error) ==
          SL_OK);
    CHECK(written == 0U && host_error == 0);

    uint64_t position = UINT64_MAX;
    host_error = 0;
    CHECK(sl_win32_file_seek(file, 0, SL_WIN32_FILE_SEEK_CURRENT,
                             &position, &host_error) == SL_ERROR_IO);
    CHECK(position == UINT64_MAX && host_error == ESPIPE);
    host_error = 0;
    CHECK(sl_win32_file_flush(file, &host_error) == SL_ERROR_IO);
    CHECK(host_error == EBADF);
    sl_win32_file_destroy(file);
    CHECK(close(descriptors[0]) == 0);

    CHECK(pipe(descriptors) == 0);
    CHECK(sl_win32_file_create_owned_fd(
              descriptors[1], SL_WIN32_GENERIC_READ,
              SL_WIN32_FILE_TYPE_CHAR, &file) == SL_OK);
    written = SIZE_MAX;
    host_error = 0;
    CHECK(sl_win32_file_write(file, "x", 1U, &written, &host_error) ==
          SL_ERROR_IO);
    CHECK(written == 0U && host_error == EACCES);
    sl_win32_file_destroy(file);
    CHECK(close(descriptors[0]) == 0);
    return true;
}

static bool test_disk_seek_and_flush(void) {
    char path[] = "/tmp/sadlayer-file-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(unlink(path) == 0);

    sl_win32_file *file = NULL;
    CHECK(sl_win32_file_create_owned_fd(
              fd, SL_WIN32_GENERIC_READ | SL_WIN32_GENERIC_WRITE,
              SL_WIN32_FILE_TYPE_DISK, &file) == SL_OK);
    CHECK(sl_win32_file_get_type(file) == SL_WIN32_FILE_TYPE_DISK);
    CHECK(sl_win32_file_can_read(file));
    CHECK(sl_win32_file_can_write(file));

    size_t written = 0U;
    int host_error = -1;
    CHECK(sl_win32_file_write(file, "abcdef", 6U, &written, &host_error) ==
          SL_OK);
    CHECK(written == 6U && host_error == 0);

    uint64_t position = UINT64_MAX;
    CHECK(sl_win32_file_seek(file, 2, SL_WIN32_FILE_SEEK_BEGIN,
                             &position, &host_error) == SL_OK);
    CHECK(position == 2U && host_error == 0);
    CHECK(sl_win32_file_seek(file, 2, SL_WIN32_FILE_SEEK_CURRENT,
                             &position, &host_error) == SL_OK);
    CHECK(position == 4U);
    CHECK(sl_win32_file_seek(file, -1, SL_WIN32_FILE_SEEK_END,
                             &position, &host_error) == SL_OK);
    CHECK(position == 5U);

    position = UINT64_MAX;
    host_error = 0;
    CHECK(sl_win32_file_seek(file, -100, SL_WIN32_FILE_SEEK_CURRENT,
                             &position, &host_error) == SL_ERROR_IO);
    CHECK(position == UINT64_MAX && host_error == EINVAL);
    CHECK(sl_win32_file_seek(file, 0, SL_WIN32_FILE_SEEK_CURRENT,
                             &position, &host_error) == SL_OK);
    CHECK(position == 5U);
    CHECK(sl_win32_file_seek(file, 32, SL_WIN32_FILE_SEEK_BEGIN,
                             &position, &host_error) == SL_OK);
    CHECK(position == 32U);
    struct stat metadata;
    CHECK(fstat(fd, &metadata) == 0);
    CHECK(metadata.st_size == 6);
    CHECK(sl_win32_file_flush(file, &host_error) == SL_OK);
    CHECK(host_error == 0);
    sl_win32_file_destroy(file);

    fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    CHECK(sl_win32_file_create_owned_fd(
              fd, SL_WIN32_GENERIC_READ, SL_WIN32_FILE_TYPE_DISK,
              &file) == SL_OK);
    host_error = 0;
    CHECK(sl_win32_file_flush(file, &host_error) == SL_ERROR_IO);
    CHECK(host_error == EACCES);
    sl_win32_file_destroy(file);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"arguments and descriptor ownership",
         test_arguments_and_descriptor_ownership},
        {"character file operations", test_character_file_operations},
        {"disk seek and flush", test_disk_seek_and_flush},
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
    printf("%zu file tests passed\n", passed);
    return 0;
}
