#include "sadlayer/loader.h"

#include <stdlib.h>
#include <string.h>

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

void sl_loader_unmap_image(sl_mapped_image *mapped) {
    if (mapped == NULL) {
        return;
    }
    free(mapped->bytes);
    memset(mapped, 0, sizeof(*mapped));
}

