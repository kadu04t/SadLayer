#include "sadlayer/kernel32.h"
#include "sadlayer/loader.h"
#include "sadlayer/module.h"
#include "sadlayer/pe.h"
#include "sadlayer/process.h"
#include "sadlayer/runtime.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FIXTURE_SIZE 2048U
#define FIXTURE_RESULT UINT32_C(0x12345678)
#define FIXTURE_RELOCATED_RVA 0x2140U
#define FIXTURE_RELOCATED_OFFSET UINT64_C(0x1234)

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

static uint64_t load_u64(const uint8_t *data) {
    uint64_t value = 0U;
    memcpy(&value, data, sizeof(value));
    return value;
}

static void put_section(uint8_t *data, size_t offset, const char *name,
                        uint32_t virtual_size, uint32_t virtual_address,
                        uint32_t raw_size, uint32_t raw_offset,
                        uint32_t characteristics) {
    size_t name_length = strlen(name);
    if (name_length > 8U) {
        name_length = 8U;
    }
    memcpy(data + offset, name, name_length);
    put_u32(data, offset + 8U, virtual_size);
    put_u32(data, offset + 12U, virtual_address);
    put_u32(data, offset + 16U, raw_size);
    put_u32(data, offset + 20U, raw_offset);
    put_u32(data, offset + 36U, characteristics);
}

static void make_runtime_fixture(uint8_t data[FIXTURE_SIZE]) {
    const size_t pe = 0x80U;
    const size_t coff = pe + 4U;
    const size_t optional = coff + 20U;
    const size_t sections = optional + 0xf0U;
    static const uint8_t entry_code[] = {
        0x48U, 0x83U, 0xecU, 0x28U,             /* sub rsp, 0x28 */
        0xb9U, 0x78U, 0x56U, 0x34U, 0x12U,      /* mov ecx, value */
        0xffU, 0x15U, 0xf1U, 0x0fU, 0x00U, 0x00U, /* call IAT[0] */
        0xffU, 0x15U, 0xf3U, 0x0fU, 0x00U, 0x00U, /* call IAT[1] */
        0x48U, 0x83U, 0xc4U, 0x28U,             /* add rsp, 0x28 */
        0xc3U,                                   /* ret */
    };

    memset(data, 0, FIXTURE_SIZE);
    data[0] = 'M';
    data[1] = 'Z';
    put_u32(data, 0x3cU, (uint32_t)pe);
    memcpy(data + pe, "PE\0\0", 4U);
    put_u16(data, coff, SL_PE_MACHINE_AMD64);
    put_u16(data, coff + 2U, 3U);
    put_u16(data, coff + 16U, 0xf0U);

    put_u16(data, optional, 0x020bU);
    put_u32(data, optional + 16U, 0x1000U);
    put_u64(data, optional + 24U, UINT64_C(0x140000000));
    put_u32(data, optional + 32U, 0x1000U);
    put_u32(data, optional + 36U, 0x200U);
    put_u32(data, optional + 56U, 0x5000U);
    put_u32(data, optional + 60U, 0x200U);
    put_u16(data, optional + 68U, 3U);
    put_u32(data, optional + 108U, 16U);
    put_u32(data, optional + 120U, 0x2080U);
    put_u32(data, optional + 124U, 40U);
    put_u32(data, optional + 152U, 0x4000U);
    put_u32(data, optional + 156U, 12U);

    put_section(data, sections, ".text", 0x200U, 0x1000U, 0x200U, 0x200U,
                UINT32_C(0x60000020));
    put_section(data, sections + 40U, ".idata", 0x200U, 0x2000U, 0x200U,
                0x400U, UINT32_C(0xc0000040));
    put_section(data, sections + 80U, ".reloc", 0x200U, 0x4000U, 0x200U,
                0x600U, UINT32_C(0x42000040));

    memcpy(data + 0x200U, entry_code, sizeof(entry_code));
    put_u64(data, 0x400U, 0x2100U);
    put_u64(data, 0x408U, 0x2120U);
    put_u64(data, 0x410U, 0U);
    put_u32(data, 0x480U, 0x20e0U);
    put_u32(data, 0x48cU, 0x20c0U);
    put_u32(data, 0x490U, 0x2000U);
    memcpy(data + 0x4c0U, "KERNEL32.dll", 13U);
    put_u64(data, 0x4e0U, 0x2100U);
    put_u64(data, 0x4e8U, 0x2120U);
    put_u64(data, 0x4f0U, 0U);
    put_u16(data, 0x500U, 0U);
    memcpy(data + 0x502U, "SetLastError", 13U);
    put_u16(data, 0x520U, 0U);
    memcpy(data + 0x522U, "GetLastError", 13U);
    put_u64(data, 0x540U,
            UINT64_C(0x140000000) + FIXTURE_RELOCATED_OFFSET);
    put_u32(data, 0x600U, 0x2000U);
    put_u32(data, 0x604U, 12U);
    put_u16(data, 0x608U, 0xa140U);
    put_u16(data, 0x60aU, 0U);
}

static bool read_mapping_permissions(const void *address,
                                     char permissions[5]) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        return false;
    }
    uintptr_t target = (uintptr_t)address;
    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), maps) != NULL) {
        unsigned long start = 0UL;
        unsigned long end = 0UL;
        char current[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, current) == 3 &&
            target >= (uintptr_t)start && target < (uintptr_t)end) {
            memcpy(permissions, current, sizeof(current));
            found = true;
            break;
        }
    }
    (void)fclose(maps);
    return found;
}

static bool test_address_stable_mapping(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image first;
    sl_mapped_image second = {0};
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image_for_execution(&image, &first) == SL_OK);
    CHECK(first.storage == SL_IMAGE_STORAGE_VIRTUAL);
    CHECK(first.load_base == (uint64_t)(uintptr_t)first.bytes);
    CHECK((uintptr_t)first.bytes % (64U * 1024U) == 0U);
    CHECK(load_u64(first.bytes + FIXTURE_RELOCATED_RVA) ==
          first.load_base + FIXTURE_RELOCATED_OFFSET);
    first.bytes[0x3000U] = 0x5aU;

    CHECK(sl_loader_map_image_for_execution(&image, &second) == SL_OK);
    CHECK(second.bytes != first.bytes);
    CHECK(second.load_base == (uint64_t)(uintptr_t)second.bytes);
    CHECK((uintptr_t)second.bytes % (64U * 1024U) == 0U);
    CHECK(load_u64(second.bytes + FIXTURE_RELOCATED_RVA) ==
          second.load_base + FIXTURE_RELOCATED_OFFSET);
    CHECK(first.bytes[0x3000U] == 0x5aU);

    sl_loader_unmap_image(&second);
    sl_loader_unmap_image(&first);
    CHECK(first.bytes == NULL && first.storage == SL_IMAGE_STORAGE_NONE);
    sl_loader_unmap_image(&first);
    return true;
}

static bool test_final_protections_and_handoff(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    sl_module_registry registry;
    sl_win32_process *process = NULL;
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image_for_execution(&image, &mapped) == SL_OK);

    sl_module_registry_init(&registry);
    CHECK(sl_kernel32_register(&registry) == SL_OK);
    size_t bound_count = 0U;
    CHECK(sl_loader_bind_imports(&image, &mapped,
                                 sl_module_registry_import_resolver, &registry,
                                 &bound_count) == SL_OK);
    CHECK(bound_count == 2U);
    CHECK(sl_loader_finalize_image(&image, &mapped) == SL_OK);
    CHECK(mapped.protections_finalized);

    char permissions[5] = {0};
    CHECK(read_mapping_permissions(mapped.bytes, permissions));
    CHECK(memcmp(permissions, "r--", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x1000U, permissions));
    CHECK(memcmp(permissions, "r-x", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x2000U, permissions));
    CHECK(memcmp(permissions, "rw-", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x3000U, permissions));
    CHECK(memcmp(permissions, "---", 3U) == 0);
    CHECK(read_mapping_permissions(mapped.bytes + 0x4000U, permissions));
    CHECK(memcmp(permissions, "r--", 3U) == 0);

    CHECK(sl_win32_process_create(&process) == SL_OK);
    sl_win32_thread_context thread = {
        .process = process,
        .last_error = 7U,
        .thread_id = 0U,
    };
    uint32_t result = 0U;
    CHECK(sl_runtime_call_trusted_entry(&image, &mapped, &thread, &result) ==
          SL_OK);
    CHECK(result == FIXTURE_RESULT);
    CHECK(thread.last_error == FIXTURE_RESULT);
    CHECK(sl_win32_context_current() == NULL);

    CHECK(sl_loader_bind_imports(&image, &mapped,
                                 sl_module_registry_import_resolver, &registry,
                                 &bound_count) == SL_ERROR_INVALID_STATE);
    CHECK(sl_loader_apply_relocations(&image, &mapped, mapped.load_base) ==
          SL_ERROR_INVALID_STATE);
    mapped.entry_rva = 0x2000U;
    CHECK(sl_runtime_call_trusted_entry(&image, &mapped, &thread, &result) ==
          SL_ERROR_INVALID_STATE);
    mapped.entry_rva = image.entry_rva;
    sl_pe_image malformed = image;
    malformed.section_count = SL_PE_MAX_SECTIONS + 1U;
    CHECK(sl_runtime_call_trusted_entry(&malformed, &mapped, &thread,
                                        &result) == SL_ERROR_INVALID_STATE);

    CHECK(sl_win32_process_destroy(process) == SL_OK);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_rejects_writable_executable_page(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    image.sections[0].characteristics |= UINT32_C(0x80000000);
    CHECK(sl_loader_map_image_for_execution(&image, &mapped) == SL_OK);
    CHECK(sl_loader_finalize_image(&image, &mapped) ==
          SL_ERROR_WX_CONFLICT);
    CHECK(!mapped.protections_finalized);
    sl_loader_unmap_image(&mapped);
    return true;
}

static bool test_failed_protection_rollback_taints_mapping(void) {
    uint8_t fixture[FIXTURE_SIZE];
    sl_pe_image image;
    sl_mapped_image mapped = {0};
    make_runtime_fixture(fixture);
    CHECK(sl_pe_parse((sl_byte_view){fixture, sizeof(fixture)}, &image) ==
          SL_OK);
    CHECK(sl_loader_map_image_for_execution(&image, &mapped) == SL_OK);

    long page_size = sysconf(_SC_PAGESIZE);
    CHECK(page_size > 0L);
    CHECK((size_t)page_size <= SIZE_MAX / 3U);
    size_t hole_offset = (size_t)page_size * 3U;
    CHECK(hole_offset <= mapped.allocation_size);
    CHECK((size_t)page_size <= mapped.allocation_size - hole_offset);
    CHECK(munmap(mapped.bytes + hole_offset, (size_t)page_size) == 0);
    CHECK(sl_loader_finalize_image(&image, &mapped) ==
          SL_ERROR_MEMORY_PROTECTION);
    CHECK(mapped.storage == SL_IMAGE_STORAGE_VIRTUAL_TAINTED);
    CHECK(!mapped.protections_finalized);
    CHECK(sl_loader_finalize_image(&image, &mapped) == SL_ERROR_INVALID_STATE);
    CHECK(sl_loader_apply_relocations(&image, &mapped, mapped.load_base) ==
          SL_ERROR_INVALID_STATE);
    sl_module_registry registry;
    sl_module_registry_init(&registry);
    CHECK(sl_kernel32_register(&registry) == SL_OK);
    size_t bound_count = 0U;
    CHECK(sl_loader_bind_imports(&image, &mapped,
                                 sl_module_registry_import_resolver, &registry,
                                 &bound_count) == SL_ERROR_INVALID_STATE);
    CHECK(bound_count == 0U);

    sl_loader_unmap_image(&mapped);
    CHECK(mapped.bytes == NULL && mapped.storage == SL_IMAGE_STORAGE_NONE);
    return true;
}

int main(void) {
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"address-stable executable mapping", test_address_stable_mapping},
        {"final protections and PE handoff",
         test_final_protections_and_handoff},
        {"reject writable executable pages",
         test_rejects_writable_executable_page},
        {"taint mapping after failed protection rollback",
         test_failed_protection_rollback_taints_mapping},
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
    printf("%zu runtime tests passed\n", passed);
    return 0;
}
