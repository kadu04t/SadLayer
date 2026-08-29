#ifndef SADLAYER_LOADER_H
#define SADLAYER_LOADER_H

#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"
#include "sadlayer/pe.h"

typedef struct {
    uint8_t *bytes;
    size_t size;
    uint64_t preferred_base;
    uint64_t load_base;
    uint32_t entry_rva;
} sl_mapped_image;

sl_status sl_loader_map_image(const sl_pe_image *image, sl_mapped_image *mapped);
sl_status sl_loader_apply_relocations(const sl_pe_image *image,
                                      sl_mapped_image *mapped,
                                      uint64_t load_base);
void sl_loader_unmap_image(sl_mapped_image *mapped);

#endif
