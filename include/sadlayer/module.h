#ifndef SADLAYER_MODULE_H
#define SADLAYER_MODULE_H

#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"
#include "sadlayer/loader.h"
#include "sadlayer/pe.h"

#define SL_MODULE_REGISTRY_CAPACITY 128U

typedef struct {
    const char *name;
    const sl_pe_image *image;
    const sl_mapped_image *mapped;
} sl_loaded_module;

typedef struct {
    sl_loaded_module modules[SL_MODULE_REGISTRY_CAPACITY];
    size_t count;
} sl_module_registry;

typedef struct {
    const sl_loaded_module *module;
    sl_pe_export export;
    uint64_t guest_address;
    uint32_t forward_depth;
} sl_resolved_symbol;

void sl_module_registry_init(sl_module_registry *registry);
sl_status sl_module_registry_add(sl_module_registry *registry, const char *name,
                                 const sl_pe_image *image,
                                 const sl_mapped_image *mapped);
const sl_loaded_module *sl_module_registry_find(
    const sl_module_registry *registry, const char *name);
sl_status sl_module_registry_resolve(const sl_module_registry *registry,
                                     const sl_pe_import_symbol *import,
                                     sl_resolved_symbol *result);

#endif

