#include "sadlayer/unicode.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            return false;                                                       \
        }                                                                      \
    } while (false)

static bool test_utf8_utf16_roundtrip(void) {
    static const char input[] = "SadLayer \xf0\x9f\x90\x9b";
    uint16_t wide[32] = {0};
    size_t wide_length = 0U;
    CHECK(sl_utf8_to_utf16(input, sizeof(input) - 1U, NULL, 0U,
                           &wide_length) == SL_OK);
    CHECK(wide_length == 11U);
    CHECK(sl_utf8_to_utf16(input, sizeof(input) - 1U, wide,
                           sizeof(wide) / sizeof(wide[0]),
                           &wide_length) == SL_OK);
    CHECK(wide[9] == 0xd83dU);
    CHECK(wide[10] == 0xdc1bU);

    char output[32] = {0};
    size_t output_length = 0U;
    CHECK(sl_utf16_to_utf8(wide, wide_length, output, sizeof(output),
                           &output_length) == SL_OK);
    CHECK(output_length == sizeof(input) - 1U);
    CHECK(memcmp(output, input, output_length) == 0);
    return true;
}

static bool test_invalid_sequences(void) {
    static const char overlong[] = "\xc0\x80";
    static const char truncated[] = "\xf0\x9f\x90";
    static const uint16_t lone_high[] = {0xd800U};
    static const uint16_t lone_low[] = {0xdc00U};
    size_t written = 0U;
    CHECK(sl_utf8_to_utf16(overlong, sizeof(overlong) - 1U, NULL, 0U,
                           &written) == SL_ERROR_INVALID_ENCODING);
    CHECK(sl_utf8_to_utf16(truncated, sizeof(truncated) - 1U, NULL, 0U,
                           &written) == SL_ERROR_INVALID_ENCODING);
    CHECK(sl_utf16_to_utf8(lone_high, 1U, NULL, 0U, &written) ==
          SL_ERROR_INVALID_ENCODING);
    CHECK(sl_utf16_to_utf8(lone_low, 1U, NULL, 0U, &written) ==
          SL_ERROR_INVALID_ENCODING);
    return true;
}

static bool test_capacity_is_atomic(void) {
    static const char input[] = "hello";
    uint16_t output[4] = {0xaaaaU, 0xaaaaU, 0xaaaaU, 0xaaaaU};
    size_t written = 0U;
    CHECK(sl_utf8_to_utf16(input, sizeof(input) - 1U, output, 4U, &written) ==
          SL_ERROR_BUFFER_TOO_SMALL);
    CHECK(written == 5U);
    for (size_t index = 0U; index < 4U; ++index) {
        CHECK(output[index] == 0xaaaaU);
    }
    return true;
}

static bool test_lossy_replacement(void) {
    static const char invalid_utf8[] = {(char)0xff, 'A'};
    uint16_t wide[2] = {0U, 0U};
    size_t written = 0U;
    CHECK(sl_utf8_to_utf16_lossy(invalid_utf8, sizeof(invalid_utf8), wide, 2U,
                                 &written) == SL_OK);
    CHECK(written == 2U);
    CHECK(wide[0] == 0xfffdU && wide[1] == (uint16_t)'A');

    static const uint16_t invalid_utf16[] = {0xd800U, (uint16_t)'A'};
    char utf8[4] = {0};
    CHECK(sl_utf16_to_utf8_lossy(invalid_utf16, 2U, utf8, sizeof(utf8),
                                 &written) == SL_OK);
    CHECK(written == 4U);
    CHECK(memcmp(utf8, "\xef\xbf\xbd" "A", 4U) == 0);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"UTF-8/UTF-16 roundtrip", test_utf8_utf16_roundtrip},
        {"invalid Unicode sequences", test_invalid_sequences},
        {"atomic destination capacity", test_capacity_is_atomic},
        {"lossy replacement", test_lossy_replacement},
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
    printf("%zu Unicode tests passed\n", passed);
    return 0;
}
