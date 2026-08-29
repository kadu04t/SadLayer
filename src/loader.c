#include "sadlayer/loader.h"

#include <stdlib.h>
#include <string.h>

#define SL_BASE_RELOCATION_HEADER_SIZE 8U
#define SL_RELOCATION_ABSOLUTE 0U
#define SL_RELOCATION_HIGHLOW 3U
#define SL_RELOCATION_DIR64 10U

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

sl_status sl_loader_map_image(const sl_pe_image *image, sl_mapped_image *mapped) {
    if (image == NULL || mapped == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    memset(mapped, 0, sizeof(*mapped));
    if (image->image_size == 0U || image->headers_size > image->image_size ||
        image->headers_size > image->file.size) {
        return SL_ERROR_INVALID_IMAGE;
    }

    mapped->bytes = calloc((size_t)image->image_size, 1U);
    if (mapped->bytes == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    mapped->size = image->image_size;
    mapped->preferred_base = image->image_base;
    mapped->load_base = image->image_base;
    mapped->entry_rva = image->entry_rva;
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
            sl_loader_unmap_image(mapped);
            return SL_ERROR_INVALID_IMAGE;
        }
        memcpy(mapped->bytes + section->virtual_address,
               image->file.data + section->raw_offset, section->raw_size);
    }
    return SL_OK;
}

sl_status sl_loader_apply_relocations(const sl_pe_image *image,
                                      sl_mapped_image *mapped,
                                      uint64_t load_base) {
    if (image == NULL || mapped == NULL || mapped->bytes == NULL ||
        mapped->size != image->image_size) {
        return SL_ERROR_INVALID_ARGUMENT;
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

void sl_loader_unmap_image(sl_mapped_image *mapped) {
    if (mapped == NULL) {
        return;
    }
    free(mapped->bytes);
    memset(mapped, 0, sizeof(*mapped));
}
