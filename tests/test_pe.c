#include "sadlayer/loader.h"
#include "sadlayer/pe.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FIXTURE_SIZE 1024U

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,  \
                    #condition);                                                \
            return false;                                                       \
        }                                                                      \
    } while (false)

static void put_u16(uint8_t *data, size_t offset, uint16_t value) {
    data[offset] = (uint8_t)(value & 0xffU);
    data[offset + 1U] = (uint8_t)(value >> 8U);
}

static void put_u32(uint8_t *data, size_t offset, uint32_t value) {
    data[offset] = (uint8_t)(value & 0xffU);
    data[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
    data[offset + 2U] = (uint8_t)((value >> 16U) & 0xffU);
    data[offset + 3U] = (uint8_t)(value >> 24U);
}

static void put_u64(uint8_t *data, size_t offset, uint64_t value) {
    put_u32(data, offset, (uint32_t)(value & UINT32_MAX));
    put_u32(data, offset + 4U, (uint32_t)(value >> 32U));
}

static void make_pe64_fixture(uint8_t data[FIXTURE_SIZE]) {
    const size_t pe = 0x80U;
    const size_t coff = pe + 4U;
    const size_t optional = coff + 20U;
    const size_t section = optional + 0xf0U;

    memset(data, 0, FIXTURE_SIZE);
    data[0] = 'M';
    data[1] = 'Z';
    put_u32(data, 0x3cU, (uint32_t)pe);
    memcpy(data + pe, "PE\0\0", 4U);
    put_u16(data, coff, SL_PE_MACHINE_AMD64);
    put_u16(data, coff + 2U, 1U);
    put_u16(data, coff + 16U, 0xf0U);

    put_u16(data, optional, 0x020bU);
    put_u32(data, optional + 16U, 0x1000U);
    put_u64(data, optional + 24U, UINT64_C(0x140000000));
    put_u32(data, optional + 32U, 0x1000U);
    put_u32(data, optional + 36U, 0x200U);
    put_u32(data, optional + 56U, 0x2000U);
    put_u32(data, optional + 60U, 0x200U);
    put_u16(data, optional + 68U, 3U);
    put_u32(data, optional + 108U, 16U);
    put_u32(data, optional + 112U + 8U, 0x1020U);
    put_u32(data, optional + 112U + 12U, 40U);

    memcpy(data + section, ".rdata", 6U);
    put_u32(data, section + 8U, 0x200U);
    put_u32(data, section + 12U, 0x1000U);
    put_u32(data, section + 16U, 0x200U);
    put_u32(data, section + 20U, 0x200U);
    put_u32(data, section + 36U, 0x40000040U);

    put_u32(data, 0x220U, 0x1090U);
    put_u32(data, 0x22cU, 0x1080U);
    put_u32(data, 0x230U, 0x1090U);
    memcpy(data + 0x280U, "KERNEL32.dll", 13U);
    data[0x200U] = 0xabu;
}

static void make_pe32_fixture(uint8_t data[FIXTURE_SIZE]) {
    const size_t pe = 0x80U;
    const size_t coff = pe + 4U;
    const size_t optional = coff + 20U;
    const size_t section = optional + 0xe0U;

    memset(data, 0, FIXTURE_SIZE);
    data[0] = 'M';
    data[1] = 'Z';
    put_u32(data, 0x3cU, (uint32_t)pe);
    memcpy(data + pe, "PE\0\0", 4U);
    put_u16(data, coff, SL_PE_MACHINE_I386);
    put_u16(data, coff + 2U, 1U);
    put_u16(data, coff + 16U, 0xe0U);

    put_u16(data, optional, 0x010bU);
    put_u32(data, optional + 16U, 0x1000U);
    put_u32(data, optional + 28U, 0x00400000U);
    put_u32(data, optional + 32U, 0x1000U);
    put_u32(data, optional + 36U, 0x200U);
    put_u32(data, optional + 56U, 0x2000U);
    put_u32(data, optional + 60U, 0x200U);
    put_u16(data, optional + 68U, 2U);
    put_u32(data, optional + 92U, 16U);

    memcpy(data + section, ".text", 5U);
    put_u32(data, section + 8U, 0x100U);
    put_u32(data, section + 12U, 0x1000U);
    put_u32(data, section + 16U, 0x200U);
    put_u32(data, section + 20U, 0x200U);
    put_u32(data, section + 36U, 0x60000020U);
}

static bool test_parse_pe64(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(image.machine == SL_PE_MACHINE_AMD64);
    CHECK(image.is_pe32_plus);
    CHECK(image.image_base == UINT64_C(0x140000000));
    CHECK(image.entry_rva == 0x1000U);
    CHECK(image.image_size == 0x2000U);
    CHECK(image.section_count == 1U);
    CHECK(strcmp(image.sections[0].name, ".rdata") == 0);
    return true;
}

static bool test_parse_pe32(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    make_pe32_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(image.machine == SL_PE_MACHINE_I386);
    CHECK(!image.is_pe32_plus);
    CHECK(image.image_base == UINT64_C(0x00400000));
    CHECK(image.subsystem == 2U);
    CHECK(strcmp(image.sections[0].name, ".text") == 0);
    return true;
}

static bool test_rva_translation_and_mapping(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    size_t offset = 0U;
    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_pe_rva_to_file_offset(&image, 0x1080U, &offset) == SL_OK);
    CHECK(offset == 0x280U);
    CHECK(sl_pe_rva_to_file_offset(&image, 0x1300U, &offset) ==
          SL_ERROR_RVA_NOT_MAPPED);
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    CHECK(mapped.size == 0x2000U);
    CHECK(mapped.bytes[0x1000U] == 0xabU);
    CHECK(memcmp(mapped.bytes + 0x1080U, "KERNEL32.dll", 13U) == 0);
    sl_loader_unmap_image(&mapped);
    CHECK(mapped.bytes == NULL);
    return true;
}

typedef struct {
    size_t count;
    char name[32];
} import_capture;

static bool capture_import(const char *module_name, void *context) {
    import_capture *capture = context;
    ++capture->count;
    (void)snprintf(capture->name, sizeof(capture->name), "%s", module_name);
    return true;
}

static bool test_import_enumeration(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    import_capture capture = {0U, {0}};
    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_pe_for_each_import(&image, capture_import, &capture) == SL_OK);
    CHECK(capture.count == 1U);
    CHECK(strcmp(capture.name, "KERNEL32.dll") == 0);
    return true;
}

static bool test_rejects_malformed_files(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    make_pe64_fixture(fixture);
    fixture[0] = 'N';
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_ERROR_BAD_DOS_SIGNATURE);

    make_pe64_fixture(fixture);
    fixture[0x80U] = 'Q';
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_ERROR_BAD_PE_SIGNATURE);

    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, 32U}, &image) ==
          SL_ERROR_TRUNCATED_FILE);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"parse PE32+", test_parse_pe64},
        {"parse PE32", test_parse_pe32},
        {"translate RVA and map image", test_rva_translation_and_mapping},
        {"enumerate imports", test_import_enumeration},
        {"reject malformed files", test_rejects_malformed_files},
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
    printf("%zu tests passed\n", passed);
    return 0;
}
