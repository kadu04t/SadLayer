#define _GNU_SOURCE

#include "sadlayer/loader.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SL_BASE_RELOCATION_HEADER_SIZE 8U
#define SL_RELOCATION_ABSOLUTE 0U
#define SL_RELOCATION_HIGHLOW 3U
#define SL_RELOCATION_DIR64 10U
#define SL_WINDOWS_ALLOCATION_GRANULARITY (64U * 1024U)
#define SL_SECTION_MEM_EXECUTE UINT32_C(0x20000000)
#define SL_SECTION_MEM_READ UINT32_C(0x40000000)
#define SL_SECTION_MEM_WRITE UINT32_C(0x80000000)

static uint16_t load_u16(const uint8_t *data) {
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8U));
}

static uint32_t load_u32(const uint8_t *data) {
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8U) |
           ((uint32_t)data[2] << 16U) | ((uint32_t)data[3] << 24U);
}

static uint64_t load_u64(const uint8_t *data) {
    return (uint64_t)load_u32(data) | ((uint64_t)load_u32(data + 4U) << 32U);
}

static void store_u32(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)(value & 0xffU);
    data[1] = (uint8_t)((value >> 8U) & 0xffU);
    data[2] = (uint8_t)((value >> 16U) & 0xffU);
    data[3] = (uint8_t)(value >> 24U);
}

static void store_u64(uint8_t *data, uint64_t value) {
    store_u32(data, (uint32_t)(value & UINT32_MAX));
    store_u32(data + 4U, (uint32_t)(value >> 32U));
}

typedef struct {
    uint32_t iat_rva;
    uint64_t guest_address;
} sl_pending_import;

typedef struct {
    size_t count;
    bool overflow;
} sl_import_count_context;

typedef struct {
    const sl_pe_image *image;
    const sl_mapped_image *mapped;
    sl_import_address_resolver resolver;
    void *resolver_context;
    sl_pending_import *pending;
    size_t capacity;
    size_t count;
    sl_status status;
} sl_import_resolve_context;

static bool count_import_symbol(const sl_pe_import_symbol *import,
                                void *context) {
    (void)import;
    sl_import_count_context *count = context;
    if (count->count == SIZE_MAX) {
        count->overflow = true;
        return false;
    }
    ++count->count;
    return true;
}

static bool resolve_import_symbol(const sl_pe_import_symbol *import,
                                  void *context) {
    sl_import_resolve_context *resolve = context;
    size_t width = resolve->image->is_pe32_plus ? 8U : 4U;
    if (resolve->count >= resolve->capacity ||
        (size_t)import->iat_rva > resolve->mapped->size ||
        width > resolve->mapped->size - (size_t)import->iat_rva ||
        (size_t)import->iat_rva % width != 0U) {
        resolve->status = SL_ERROR_INVALID_IMAGE;
        return false;
    }

    uint64_t guest_address = 0U;
    resolve->status =
        resolve->resolver(import, &guest_address, resolve->resolver_context);
    if (resolve->status != SL_OK) {
        return false;
    }
    if (!resolve->image->is_pe32_plus && guest_address > UINT32_MAX) {
        resolve->status = SL_ERROR_ADDRESS_OUT_OF_RANGE;
        return false;
    }
    resolve->pending[resolve->count] = (sl_pending_import){
        .iat_rva = import->iat_rva,
        .guest_address = guest_address,
    };
    ++resolve->count;
    return true;
}

static sl_status process_relocations(const sl_pe_image *image,
                                     sl_mapped_image *mapped,
                                     sl_pe_data_directory relocations,
                                     uint64_t delta, bool apply) {
    size_t cursor = relocations.rva;
    size_t directory_start = cursor;
    size_t end = cursor + relocations.size;
    while (cursor < end) {
        if (end - cursor < SL_BASE_RELOCATION_HEADER_SIZE) {
            return SL_ERROR_INVALID_IMAGE;
        }
        uint32_t page_rva = load_u32(mapped->bytes + cursor);
        uint32_t block_size = load_u32(mapped->bytes + cursor + 4U);
        if (block_size < SL_BASE_RELOCATION_HEADER_SIZE ||
            (block_size - SL_BASE_RELOCATION_HEADER_SIZE) % 2U != 0U ||
            (size_t)block_size > end - cursor) {
            return SL_ERROR_INVALID_IMAGE;
        }

        size_t entry_cursor = cursor + SL_BASE_RELOCATION_HEADER_SIZE;
        size_t block_end = cursor + block_size;
        while (entry_cursor < block_end) {
            uint16_t entry = load_u16(mapped->bytes + entry_cursor);
            uint16_t type = (uint16_t)(entry >> 12U);
            uint32_t offset = entry & 0x0fffU;
            if (page_rva > UINT32_MAX - offset) {
                return SL_ERROR_INVALID_IMAGE;
            }
            size_t patch_rva = (size_t)(page_rva + offset);

            if (type == SL_RELOCATION_ABSOLUTE) {
                entry_cursor += 2U;
                continue;
            }
            if (type == SL_RELOCATION_DIR64 && image->is_pe32_plus) {
                if (patch_rva > mapped->size ||
                    8U > mapped->size - patch_rva) {
                    return SL_ERROR_INVALID_IMAGE;
                }
                if (patch_rva < end && patch_rva + 8U > directory_start) {
                    return SL_ERROR_INVALID_IMAGE;
                }
                if (apply) {
                    uint64_t value = load_u64(mapped->bytes + patch_rva);
                    store_u64(mapped->bytes + patch_rva, value + delta);
                }
            } else if (type == SL_RELOCATION_HIGHLOW &&
                       !image->is_pe32_plus) {
                if (patch_rva > mapped->size ||
                    4U > mapped->size - patch_rva) {
                    return SL_ERROR_INVALID_IMAGE;
                }
                if (patch_rva < end && patch_rva + 4U > directory_start) {
                    return SL_ERROR_INVALID_IMAGE;
                }
                if (apply) {
                    uint32_t value = load_u32(mapped->bytes + patch_rva);
                    store_u32(mapped->bytes + patch_rva,
                              value + (uint32_t)delta);
                }
            } else {
                return SL_ERROR_UNSUPPORTED_RELOCATION;
            }
            entry_cursor += 2U;
        }
        cursor = block_end;
    }
    return SL_OK;
}

static sl_status validate_mapping(const sl_pe_image *image) {
    if (image == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (image->image_size == 0U || image->headers_size > image->image_size ||
        image->headers_size > image->file.size) {
        return SL_ERROR_INVALID_IMAGE;
    }
    return SL_OK;
}

static sl_status populate_mapping(const sl_pe_image *image,
                                  sl_mapped_image *mapped) {
    memcpy(mapped->bytes, image->file.data, image->headers_size);

    for (uint16_t index = 0U; index < image->section_count; ++index) {
        const sl_pe_section *section = &image->sections[index];
        if (section->raw_size == 0U) {
            continue;
        }
        if ((size_t)section->virtual_address > mapped->size ||
            (size_t)section->raw_size >
                mapped->size - (size_t)section->virtual_address ||
            (size_t)section->raw_offset > image->file.size ||
            (size_t)section->raw_size >
                image->file.size - (size_t)section->raw_offset) {
            return SL_ERROR_INVALID_IMAGE;
        }
        memcpy(mapped->bytes + section->virtual_address,
               image->file.data + section->raw_offset, section->raw_size);
    }
    return SL_OK;
}

static void initialize_mapping(const sl_pe_image *image,
                               sl_mapped_image *mapped, uint8_t *bytes,
                               size_t allocation_size,
                               sl_image_storage storage) {
    mapped->bytes = bytes;
    mapped->size = image->image_size;
    mapped->allocation_size = allocation_size;
    mapped->preferred_base = image->image_base;
    mapped->load_base = image->image_base;
    mapped->entry_rva = image->entry_rva;
    mapped->storage = storage;
    mapped->protections_finalized = false;
}

sl_status sl_loader_map_image(const sl_pe_image *image,
                              sl_mapped_image *mapped) {
    if (mapped == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    memset(mapped, 0, sizeof(*mapped));
    sl_status status = validate_mapping(image);
    if (status != SL_OK) {
        return status;
    }

    uint8_t *bytes = calloc((size_t)image->image_size, 1U);
    if (bytes == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    initialize_mapping(image, mapped, bytes, image->image_size,
                       SL_IMAGE_STORAGE_HEAP);
    status = populate_mapping(image, mapped);
    if (status != SL_OK) {
        sl_loader_unmap_image(mapped);
    }
    return status;
}

static sl_status host_page_size(size_t *page_size) {
    long value = sysconf(_SC_PAGESIZE);
    if (value <= 0L || (unsigned long)value > SIZE_MAX) {
        return SL_ERROR_MEMORY_MAPPING;
    }
    size_t converted = (size_t)value;
    if ((converted & (converted - 1U)) != 0U) {
        return SL_ERROR_MEMORY_MAPPING;
    }
    *page_size = converted;
    return SL_OK;
}

static bool round_up_size(size_t value, size_t alignment, size_t *result) {
    size_t remainder = value & (alignment - 1U);
    if (remainder == 0U) {
        *result = value;
        return true;
    }
    size_t addition = alignment - remainder;
    if (value > SIZE_MAX - addition) {
        return false;
    }
    *result = value + addition;
    return true;
}

static void *map_preferred_address(uint64_t preferred_base,
                                   size_t allocation_size,
                                   size_t address_alignment) {
    if (preferred_base == 0U || preferred_base > UINTPTR_MAX ||
        preferred_base % address_alignment != 0U ||
        allocation_size > UINTPTR_MAX - (uintptr_t)preferred_base) {
        return MAP_FAILED;
    }
    void *requested = (void *)(uintptr_t)preferred_base;
    void *address = mmap(requested, allocation_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1,
                         0);
    if (address != MAP_FAILED && address != requested) {
        (void)munmap(address, allocation_size);
        return MAP_FAILED;
    }
    return address;
}

static void *map_aligned_address(size_t allocation_size, size_t page_size,
                                 size_t address_alignment) {
    size_t padding = address_alignment - page_size;
    if (allocation_size > SIZE_MAX - padding) {
        return MAP_FAILED;
    }
    size_t reservation_size = allocation_size + padding;
    uint8_t *reservation =
        mmap(NULL, reservation_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) {
        return MAP_FAILED;
    }

    uintptr_t reservation_address = (uintptr_t)reservation;
    if (reservation_address > UINTPTR_MAX - (address_alignment - 1U)) {
        (void)munmap(reservation, reservation_size);
        return MAP_FAILED;
    }
    uintptr_t aligned_address =
        (reservation_address + address_alignment - 1U) &
        ~(uintptr_t)(address_alignment - 1U);
    size_t prefix_size = (size_t)(aligned_address - reservation_address);
    size_t suffix_size = reservation_size - prefix_size - allocation_size;

    if (prefix_size != 0U && munmap(reservation, prefix_size) != 0) {
        (void)munmap(reservation, reservation_size);
        return MAP_FAILED;
    }
    uint8_t *aligned = (uint8_t *)aligned_address;
    if (suffix_size != 0U &&
        munmap(aligned + allocation_size, suffix_size) != 0) {
        (void)munmap(aligned, reservation_size - prefix_size);
        return MAP_FAILED;
    }
    return aligned;
}

sl_status sl_loader_map_image_for_execution(const sl_pe_image *image,
                                            sl_mapped_image *mapped) {
    if (mapped == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    memset(mapped, 0, sizeof(*mapped));
    sl_status status = validate_mapping(image);
    if (status != SL_OK) {
        return status;
    }
    if (!image->is_pe32_plus || image->machine != SL_PE_MACHINE_AMD64) {
        return SL_ERROR_UNSUPPORTED_MACHINE;
    }

    size_t page_size = 0U;
    status = host_page_size(&page_size);
    size_t allocation_size = 0U;
    if (status != SL_OK ||
        !round_up_size((size_t)image->image_size, page_size,
                       &allocation_size)) {
        return status != SL_OK ? status : SL_ERROR_MEMORY_MAPPING;
    }
    size_t address_alignment = SL_WINDOWS_ALLOCATION_GRANULARITY;
    if (page_size > address_alignment) {
        address_alignment = page_size;
    }

    void *address = map_preferred_address(image->image_base, allocation_size,
                                          address_alignment);
    if (address == MAP_FAILED) {
        address = map_aligned_address(allocation_size, page_size,
                                      address_alignment);
    }
    if (address == MAP_FAILED) {
        return SL_ERROR_MEMORY_MAPPING;
    }

    initialize_mapping(image, mapped, address, allocation_size,
                       SL_IMAGE_STORAGE_VIRTUAL);
    status = populate_mapping(image, mapped);
    if (status == SL_OK) {
        status = sl_loader_apply_relocations(
            image, mapped, (uint64_t)(uintptr_t)mapped->bytes);
    }
    if (status != SL_OK) {
        sl_loader_unmap_image(mapped);
    }
    return status;
}

sl_status sl_loader_apply_relocations(const sl_pe_image *image,
                                      sl_mapped_image *mapped,
                                      uint64_t load_base) {
    if (image == NULL || mapped == NULL || mapped->bytes == NULL ||
        mapped->size != image->image_size) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (mapped->protections_finalized ||
        mapped->storage == SL_IMAGE_STORAGE_VIRTUAL_TAINTED) {
        return SL_ERROR_INVALID_STATE;
    }
    if (mapped->storage == SL_IMAGE_STORAGE_VIRTUAL &&
        load_base != (uint64_t)(uintptr_t)mapped->bytes) {
        return SL_ERROR_INVALID_STATE;
    }
    if (!image->is_pe32_plus && load_base > UINT32_MAX) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (load_base == mapped->load_base) {
        return SL_OK;
    }

    sl_pe_data_directory relocations =
        image->directories[SL_PE_DIRECTORY_BASERELOC];
    if (relocations.rva == 0U || relocations.size == 0U) {
        return SL_ERROR_RELOCATION_REQUIRED;
    }
    if ((size_t)relocations.rva > mapped->size ||
        (size_t)relocations.size > mapped->size - (size_t)relocations.rva) {
        return SL_ERROR_INVALID_IMAGE;
    }

    uint64_t delta = load_base - mapped->load_base;
    sl_status status =
        process_relocations(image, mapped, relocations, delta, false);
    if (status != SL_OK) {
        return status;
    }
    status = process_relocations(image, mapped, relocations, delta, true);
    if (status != SL_OK) {
        return status;
    }
    mapped->load_base = load_base;
    return SL_OK;
}

sl_status sl_loader_bind_imports(const sl_pe_image *image,
                                 sl_mapped_image *mapped,
                                 sl_import_address_resolver resolver,
                                 void *context, size_t *bound_count) {
    if (bound_count != NULL) {
        *bound_count = 0U;
    }
    if (image == NULL || mapped == NULL || mapped->bytes == NULL ||
        mapped->size != image->image_size || resolver == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (mapped->protections_finalized ||
        mapped->storage == SL_IMAGE_STORAGE_VIRTUAL_TAINTED) {
        return SL_ERROR_INVALID_STATE;
    }

    sl_import_count_context count = {0U, false};
    sl_status status =
        sl_pe_for_each_import_symbol(image, count_import_symbol, &count);
    if (status != SL_OK) {
        return status;
    }
    if (count.overflow || count.count > SIZE_MAX / sizeof(sl_pending_import)) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    if (count.count == 0U) {
        return SL_OK;
    }

    sl_pending_import *pending = calloc(count.count, sizeof(*pending));
    if (pending == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    sl_import_resolve_context resolve = {
        .image = image,
        .mapped = mapped,
        .resolver = resolver,
        .resolver_context = context,
        .pending = pending,
        .capacity = count.count,
        .count = 0U,
        .status = SL_OK,
    };
    status = sl_pe_for_each_import_symbol(image, resolve_import_symbol, &resolve);
    if (status == SL_OK && resolve.status != SL_OK) {
        status = resolve.status;
    }
    if (status == SL_OK && resolve.count != count.count) {
        status = SL_ERROR_INVALID_IMAGE;
    }

    if (status == SL_OK) {
        for (size_t index = 0U; index < resolve.count; ++index) {
            uint8_t *destination = mapped->bytes + pending[index].iat_rva;
            if (image->is_pe32_plus) {
                store_u64(destination, pending[index].guest_address);
            } else {
                store_u32(destination, (uint32_t)pending[index].guest_address);
            }
        }
        if (bound_count != NULL) {
            *bound_count = resolve.count;
        }
    }
    free(pending);
    return status;
}

static sl_status add_page_permissions(uint8_t *permissions, size_t page_count,
                                      size_t page_size, size_t image_size,
                                      size_t start, size_t length,
                                      uint8_t protection) {
    if (length == 0U) {
        return SL_OK;
    }
    if (start > image_size || length > image_size - start) {
        return SL_ERROR_INVALID_IMAGE;
    }
    size_t end = start + length;
    size_t first_page = start / page_size;
    size_t last_page = (end - 1U) / page_size;
    if (first_page >= page_count || last_page >= page_count) {
        return SL_ERROR_INVALID_IMAGE;
    }
    for (size_t page = first_page; page <= last_page; ++page) {
        permissions[page] |= protection;
    }
    return SL_OK;
}

sl_status sl_loader_finalize_image(const sl_pe_image *image,
                                   sl_mapped_image *mapped) {
    if (mapped != NULL &&
        mapped->storage == SL_IMAGE_STORAGE_VIRTUAL_TAINTED) {
        return SL_ERROR_INVALID_STATE;
    }
    if (image == NULL || mapped == NULL || mapped->bytes == NULL ||
        mapped->storage != SL_IMAGE_STORAGE_VIRTUAL ||
        mapped->size != image->image_size || mapped->allocation_size == 0U) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (mapped->protections_finalized) {
        return SL_OK;
    }

    size_t page_size = 0U;
    sl_status status = host_page_size(&page_size);
    if (status != SL_OK || mapped->allocation_size % page_size != 0U) {
        return status != SL_OK ? status : SL_ERROR_INVALID_STATE;
    }
    size_t page_count = mapped->allocation_size / page_size;
    uint8_t *permissions = calloc(page_count, sizeof(*permissions));
    if (permissions == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }

    status = add_page_permissions(
        permissions, page_count, page_size, mapped->size, 0U,
        image->headers_size, (uint8_t)PROT_READ);
    for (uint16_t index = 0U; status == SL_OK &&
                              index < image->section_count;
         ++index) {
        const sl_pe_section *section = &image->sections[index];
        size_t length = section->virtual_size;
        if ((size_t)section->raw_size > length) {
            length = section->raw_size;
        }
        uint8_t protection = 0U;
        if ((section->characteristics & SL_SECTION_MEM_READ) != 0U) {
            protection |= (uint8_t)PROT_READ;
        }
        if ((section->characteristics & SL_SECTION_MEM_WRITE) != 0U) {
            protection |= (uint8_t)PROT_WRITE;
        }
        if ((section->characteristics & SL_SECTION_MEM_EXECUTE) != 0U) {
            protection |= (uint8_t)PROT_EXEC;
        }
        status = add_page_permissions(
            permissions, page_count, page_size, mapped->size,
            section->virtual_address, length, protection);
    }

    for (size_t page = 0U; status == SL_OK && page < page_count; ++page) {
        if ((permissions[page] & (uint8_t)PROT_WRITE) != 0U &&
            (permissions[page] & (uint8_t)PROT_EXEC) != 0U) {
            status = SL_ERROR_WX_CONFLICT;
        }
    }
    if (status == SL_OK) {
        __builtin___clear_cache((char *)mapped->bytes,
                                (char *)mapped->bytes + mapped->size);
        size_t first_page = 0U;
        while (first_page < page_count) {
            size_t end_page = first_page + 1U;
            while (end_page < page_count &&
                   permissions[end_page] == permissions[first_page]) {
                ++end_page;
            }
            if (mprotect(mapped->bytes + first_page * page_size,
                         (end_page - first_page) * page_size,
                         (int)permissions[first_page]) != 0) {
                status = SL_ERROR_MEMORY_PROTECTION;
                break;
            }
            first_page = end_page;
        }
    }
    free(permissions);

    if (status != SL_OK) {
        if (mprotect(mapped->bytes, mapped->allocation_size,
                     PROT_READ | PROT_WRITE) != 0) {
            mapped->storage = SL_IMAGE_STORAGE_VIRTUAL_TAINTED;
            return SL_ERROR_MEMORY_PROTECTION;
        }
        return status;
    }
    mapped->protections_finalized = true;
    return SL_OK;
}

void sl_loader_unmap_image(sl_mapped_image *mapped) {
    if (mapped == NULL) {
        return;
    }
    if (mapped->storage == SL_IMAGE_STORAGE_VIRTUAL ||
        mapped->storage == SL_IMAGE_STORAGE_VIRTUAL_TAINTED) {
        if (mapped->bytes != NULL && mapped->allocation_size != 0U) {
            (void)munmap(mapped->bytes, mapped->allocation_size);
        }
    } else {
        free(mapped->bytes);
    }
    memset(mapped, 0, sizeof(*mapped));
}
