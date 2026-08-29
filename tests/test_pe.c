#include "sadlayer/loader.h"
#include "sadlayer/module.h"
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

static uint32_t get_u32(const uint8_t *data, size_t offset) {
    return (uint32_t)data[offset] | ((uint32_t)data[offset + 1U] << 8U) |
           ((uint32_t)data[offset + 2U] << 16U) |
           ((uint32_t)data[offset + 3U] << 24U);
}

static uint64_t get_u64(const uint8_t *data, size_t offset) {
    return (uint64_t)get_u32(data, offset) |
           ((uint64_t)get_u32(data, offset + 4U) << 32U);
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
    put_u32(data, optional + 112U, 0x10e0U);
    put_u32(data, optional + 116U, 0x80U);
    put_u32(data, optional + 112U + 8U, 0x1020U);
    put_u32(data, optional + 112U + 12U, 40U);
    put_u32(data, optional + 112U + 40U, 0x10d0U);
    put_u32(data, optional + 112U + 44U, 12U);

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
    put_u64(data, 0x290U, UINT64_C(0x10b0));
    put_u64(data, 0x298U, UINT64_C(0x8000000000000042));
    put_u64(data, 0x2a0U, 0U);
    put_u16(data, 0x2b0U, 7U);
    memcpy(data + 0x2b2U, "ExitProcess", 12U);
    put_u64(data, 0x210U, UINT64_C(0x140001234));
    put_u32(data, 0x2d0U, 0x1000U);
    put_u32(data, 0x2d4U, 12U);
    put_u16(data, 0x2d8U, 0xa010U);
    put_u16(data, 0x2daU, 0U);
    put_u32(data, 0x2f0U, 1U);
    put_u32(data, 0x2f4U, 2U);
    put_u32(data, 0x2f8U, 1U);
    put_u32(data, 0x2fcU, 0x1120U);
    put_u32(data, 0x300U, 0x1128U);
    put_u32(data, 0x304U, 0x112cU);
    put_u32(data, 0x320U, 0x1050U);
    put_u32(data, 0x324U, 0x1150U);
    put_u32(data, 0x328U, 0x1140U);
    put_u16(data, 0x32cU, 0U);
    memcpy(data + 0x330U, "Fixture.dll", 12U);
    memcpy(data + 0x340U, "UnityMain2", 11U);
    memcpy(data + 0x350U, "KERNEL32.Sleep", 15U);
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
    put_u32(data, optional + 96U + 8U, 0x1020U);
    put_u32(data, optional + 96U + 12U, 40U);
    put_u32(data, optional + 96U + 40U, 0x10d0U);
    put_u32(data, optional + 96U + 44U, 12U);

    memcpy(data + section, ".text", 5U);
    put_u32(data, section + 8U, 0x100U);
    put_u32(data, section + 12U, 0x1000U);
    put_u32(data, section + 16U, 0x200U);
    put_u32(data, section + 20U, 0x200U);
    put_u32(data, section + 36U, 0x60000020U);

    put_u32(data, 0x220U, 0x1090U);
    put_u32(data, 0x22cU, 0x1080U);
    put_u32(data, 0x230U, 0x1090U);
    memcpy(data + 0x280U, "KERNEL32.dll", 13U);
    put_u32(data, 0x290U, 0x10b0U);
    put_u32(data, 0x294U, 0x80000042U);
    put_u32(data, 0x298U, 0U);
    put_u16(data, 0x2b0U, 7U);
    memcpy(data + 0x2b2U, "ExitProcess", 12U);
    put_u32(data, 0x210U, 0x00401234U);
    put_u32(data, 0x2d0U, 0x1000U);
    put_u32(data, 0x2d4U, 12U);
    put_u16(data, 0x2d8U, 0x3010U);
    put_u16(data, 0x2daU, 0U);
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

typedef struct {
    size_t count;
    sl_pe_import_symbol symbols[2];
    char named_symbol[32];
} symbol_capture;

static bool capture_symbol(const sl_pe_import_symbol *symbol, void *context) {
    symbol_capture *capture = context;
    if (capture->count >= 2U) {
        return false;
    }
    capture->symbols[capture->count] = *symbol;
    if (symbol->symbol_name != NULL) {
        (void)snprintf(capture->named_symbol, sizeof(capture->named_symbol),
                       "%s", symbol->symbol_name);
        capture->symbols[capture->count].symbol_name = capture->named_symbol;
    }
    ++capture->count;
    return true;
}

static bool test_import_symbol_enumeration(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    symbol_capture capture = {0U, {{0}}, {0}};
    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_pe_for_each_import_symbol(&image, capture_symbol, &capture) ==
          SL_OK);
    CHECK(capture.count == 2U);
    CHECK(strcmp(capture.symbols[0].module_name, "KERNEL32.dll") == 0);
    CHECK(strcmp(capture.symbols[0].symbol_name, "ExitProcess") == 0);
    CHECK(capture.symbols[0].hint == 7U);
    CHECK(capture.symbols[0].iat_rva == 0x1090U);
    CHECK(!capture.symbols[0].by_ordinal);
    CHECK(capture.symbols[1].by_ordinal);
    CHECK(capture.symbols[1].ordinal == 0x42U);
    CHECK(capture.symbols[1].iat_rva == 0x1098U);

    capture = (symbol_capture){0U, {{0}}, {0}};
    make_pe32_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_pe_for_each_import_symbol(&image, capture_symbol, &capture) ==
          SL_OK);
    CHECK(capture.count == 2U);
    CHECK(strcmp(capture.symbols[0].symbol_name, "ExitProcess") == 0);
    CHECK(capture.symbols[0].iat_rva == 0x1090U);
    CHECK(capture.symbols[1].by_ordinal);
    CHECK(capture.symbols[1].ordinal == 0x42U);
    CHECK(capture.symbols[1].iat_rva == 0x1094U);
    return true;
}

static bool test_base_relocations(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};

    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    CHECK(mapped.load_base == UINT64_C(0x140000000));
    CHECK(sl_loader_apply_relocations(&image, &mapped,
                                      UINT64_C(0x150000000)) == SL_OK);
    CHECK(mapped.load_base == UINT64_C(0x150000000));
    CHECK(get_u64(mapped.bytes, 0x1010U) == UINT64_C(0x150001234));
    sl_loader_unmap_image(&mapped);

    make_pe32_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    CHECK(sl_loader_apply_relocations(&image, &mapped,
                                      UINT64_C(0x00500000)) == SL_OK);
    CHECK(mapped.load_base == UINT64_C(0x00500000));
    CHECK(get_u32(mapped.bytes, 0x1010U) == 0x00501234U);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_relocation_failures_are_atomic(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    mapped.bytes[0x10d8U] = 0x10U;
    mapped.bytes[0x10d9U] = 0x50U;
    uint64_t original = get_u64(mapped.bytes, 0x1010U);
    CHECK(sl_loader_apply_relocations(&image, &mapped,
                                      UINT64_C(0x150000000)) ==
          SL_ERROR_UNSUPPORTED_RELOCATION);
    CHECK(mapped.load_base == mapped.preferred_base);
    CHECK(get_u64(mapped.bytes, 0x1010U) == original);
    sl_loader_unmap_image(&mapped);

    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    image.directories[SL_PE_DIRECTORY_BASERELOC] =
        (sl_pe_data_directory){0U, 0U};
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    CHECK(sl_loader_apply_relocations(&image, &mapped,
                                      UINT64_C(0x150000000)) ==
          SL_ERROR_RELOCATION_REQUIRED);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_export_lookup(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_pe_export export;
    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_pe_find_export_by_name(&image, "UnityMain2", &export) == SL_OK);
    CHECK(strcmp(export.name, "UnityMain2") == 0);
    CHECK(export.ordinal == 1U);
    CHECK(export.rva == 0x1050U);
    CHECK(!export.is_forwarder);

    CHECK(sl_pe_find_export_by_ordinal(&image, 2U, &export) == SL_OK);
    CHECK(export.name == NULL);
    CHECK(export.ordinal == 2U);
    CHECK(export.rva == 0x1150U);
    CHECK(export.is_forwarder);
    CHECK(strcmp(export.forwarder, "KERNEL32.Sleep") == 0);
    CHECK(sl_pe_find_export_by_name(&image, "Missing", &export) ==
          SL_ERROR_EXPORT_NOT_FOUND);
    CHECK(sl_pe_find_export_by_ordinal(&image, 3U, &export) ==
          SL_ERROR_EXPORT_NOT_FOUND);
    return true;
}

static bool test_module_registry_resolution(void) {
    uint8_t unity_fixture[FIXTURE_SIZE];
    uint8_t kernel_fixture[FIXTURE_SIZE];
    sl_pe_image unity_image;
    sl_pe_image kernel_image;
    sl_mapped_image unity_mapped = {0};
    sl_mapped_image kernel_mapped = {0};
    sl_module_registry registry;
    sl_resolved_symbol resolved;

    make_pe64_fixture(unity_fixture);
    make_pe64_fixture(kernel_fixture);
    memcpy(kernel_fixture + 0x340U, "Sleep\0\0\0\0\0\0", 11U);
    CHECK(sl_pe_parse((sl_byte_view){unity_fixture, sizeof(unity_fixture)},
                      &unity_image) == SL_OK);
    CHECK(sl_pe_parse((sl_byte_view){kernel_fixture, sizeof(kernel_fixture)},
                      &kernel_image) == SL_OK);
    CHECK(sl_loader_map_image(&unity_image, &unity_mapped) == SL_OK);
    CHECK(sl_loader_map_image(&kernel_image, &kernel_mapped) == SL_OK);

    sl_module_registry_init(&registry);
    CHECK(sl_module_registry_add(&registry, "UnityPlayer.dll", &unity_image,
                                 &unity_mapped) == SL_OK);
    CHECK(sl_module_registry_add(&registry, "KERNEL32.dll", &kernel_image,
                                 &kernel_mapped) == SL_OK);
    CHECK(sl_module_registry_add(&registry, "kernel32.DLL", &kernel_image,
                                 &kernel_mapped) ==
          SL_ERROR_DUPLICATE_MODULE);

    sl_pe_import_symbol import = {
        .module_name = "unityplayer.DLL",
        .symbol_name = "UnityMain2",
        .iat_rva = 0U,
        .hint = 0U,
        .ordinal = 0U,
        .by_ordinal = false,
    };
    CHECK(sl_module_registry_resolve(&registry, &import, &resolved) == SL_OK);
    CHECK(resolved.module == &registry.modules[0]);
    CHECK(resolved.guest_address == unity_mapped.load_base + 0x1050U);
    CHECK(resolved.forward_depth == 0U);

    import.symbol_name = NULL;
    import.ordinal = 2U;
    import.by_ordinal = true;
    CHECK(sl_module_registry_resolve(&registry, &import, &resolved) == SL_OK);
    CHECK(resolved.module == &registry.modules[1]);
    CHECK(strcmp(resolved.export.name, "Sleep") == 0);
    CHECK(resolved.guest_address == kernel_mapped.load_base + 0x1050U);
    CHECK(resolved.forward_depth == 1U);

    import.module_name = "missing.dll";
    CHECK(sl_module_registry_resolve(&registry, &import, &resolved) ==
          SL_ERROR_MODULE_NOT_FOUND);
    sl_loader_unmap_image(&kernel_mapped);
    sl_loader_unmap_image(&unity_mapped);
    return true;
}

typedef struct {
    bool fail_on_ordinal;
    uint64_t named_address;
    uint64_t ordinal_address;
} mock_resolver_context;

static sl_status mock_import_resolver(const sl_pe_import_symbol *import,
                                      uint64_t *guest_address, void *context) {
    const mock_resolver_context *mock = context;
    if (import->by_ordinal) {
        if (mock->fail_on_ordinal) {
            return SL_ERROR_EXPORT_NOT_FOUND;
        }
        *guest_address = mock->ordinal_address;
    } else {
        *guest_address = mock->named_address;
    }
    return SL_OK;
}

static bool test_atomic_iat_binding(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    mock_resolver_context resolver = {
        false, UINT64_C(0x180001000), UINT64_C(0x180002000)};
    size_t bound_count = 0U;

    make_pe64_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    CHECK(sl_loader_bind_imports(&image, &mapped, mock_import_resolver,
                                 &resolver, &bound_count) == SL_OK);
    CHECK(bound_count == 2U);
    CHECK(get_u64(mapped.bytes, 0x1090U) == UINT64_C(0x180001000));
    CHECK(get_u64(mapped.bytes, 0x1098U) == UINT64_C(0x180002000));
    sl_loader_unmap_image(&mapped);

    make_pe32_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    resolver.named_address = UINT64_C(0x00501000);
    resolver.ordinal_address = UINT64_C(0x00502000);
    CHECK(sl_loader_bind_imports(&image, &mapped, mock_import_resolver,
                                 &resolver, &bound_count) == SL_OK);
    CHECK(bound_count == 2U);
    CHECK(get_u32(mapped.bytes, 0x1090U) == 0x00501000U);
    CHECK(get_u32(mapped.bytes, 0x1094U) == 0x00502000U);
    sl_loader_unmap_image(&mapped);

    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    resolver.fail_on_ordinal = true;
    uint32_t original_name = get_u32(mapped.bytes, 0x1090U);
    uint32_t original_ordinal = get_u32(mapped.bytes, 0x1094U);
    CHECK(sl_loader_bind_imports(&image, &mapped, mock_import_resolver,
                                 &resolver, &bound_count) ==
          SL_ERROR_EXPORT_NOT_FOUND);
    CHECK(bound_count == 0U);
    CHECK(get_u32(mapped.bytes, 0x1090U) == original_name);
    CHECK(get_u32(mapped.bytes, 0x1094U) == original_ordinal);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_registry_backed_iat_binding(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_module_registry registry;
    size_t bound_count = 0U;

    make_pe64_fixture(fixture);
    memset(fixture + 0x2b2U, 0, 12U);
    memcpy(fixture + 0x2b2U, "Sleep", 6U);
    put_u64(fixture, 0x298U, UINT64_C(0x8000000000000002));
    memset(fixture + 0x340U, 0, 11U);
    memcpy(fixture + 0x340U, "Sleep", 6U);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image(&image, &mapped) == SL_OK);
    sl_module_registry_init(&registry);
    CHECK(sl_module_registry_add(&registry, "KERNEL32.dll", &image, &mapped) ==
          SL_OK);
    CHECK(sl_loader_bind_imports(&image, &mapped,
                                 sl_module_registry_import_resolver, &registry,
                                 &bound_count) == SL_OK);
    CHECK(bound_count == 2U);
    CHECK(get_u64(mapped.bytes, 0x1090U) == mapped.load_base + 0x1050U);
    CHECK(get_u64(mapped.bytes, 0x1098U) == mapped.load_base + 0x1050U);
    sl_loader_unmap_image(&mapped);
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
        {"enumerate import symbols", test_import_symbol_enumeration},
        {"apply base relocations", test_base_relocations},
        {"reject invalid relocations atomically",
         test_relocation_failures_are_atomic},
        {"find exports", test_export_lookup},
        {"resolve modules and forwarders", test_module_registry_resolution},
        {"bind IAT atomically", test_atomic_iat_binding},
        {"bind IAT from module registry", test_registry_backed_iat_binding},
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
