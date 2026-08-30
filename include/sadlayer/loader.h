#ifndef SADLAYER_LOADER_H
#define SADLAYER_LOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"
#include "sadlayer/pe.h"

typedef enum {
    SL_IMAGE_STORAGE_NONE = 0,
    SL_IMAGE_STORAGE_HEAP,
    SL_IMAGE_STORAGE_VIRTUAL,
    /* A virtual mapping with an indeterminate protection layout; unmap only. */
    SL_IMAGE_STORAGE_VIRTUAL_TAINTED,
} sl_image_storage;

typedef struct {
    uint8_t *bytes;
    size_t size;
    size_t allocation_size;
    uint64_t preferred_base;
    uint64_t load_base;
    uint32_t entry_rva;
    sl_image_storage storage;
    bool protections_finalized;
} sl_mapped_image;

typedef sl_status (*sl_import_address_resolver)(
    const sl_pe_import_symbol *import, uint64_t *guest_address, void *context);

/*
 * Mapping functions treat mapped as a write-only output, so it need not be
 * initialized. A live mapping must be passed to sl_loader_unmap_image before
 * the same object is reused.
 */
sl_status sl_loader_map_image(const sl_pe_image *image, sl_mapped_image *mapped);
/* Returns a mutable NX mmap with a 64-KiB-aligned actual load_base. */
sl_status sl_loader_map_image_for_execution(const sl_pe_image *image,
                                            sl_mapped_image *mapped);
sl_status sl_loader_apply_relocations(const sl_pe_image *image,
                                      sl_mapped_image *mapped,
                                      uint64_t load_base);
sl_status sl_loader_bind_imports(const sl_pe_image *image,
                                 sl_mapped_image *mapped,
                                 sl_import_address_resolver resolver,
                                 void *context, size_t *bound_count);
sl_status sl_loader_finalize_image(const sl_pe_image *image,
                                   sl_mapped_image *mapped);
void sl_loader_unmap_image(sl_mapped_image *mapped);

#endif
