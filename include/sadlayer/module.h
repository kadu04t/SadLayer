#ifndef SADLAYER_MODULE_H
#define SADLAYER_MODULE_H

#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"
#include "sadlayer/loader.h"
#include "sadlayer/pe.h"

#define SL_MODULE_REGISTRY_CAPACITY 128U
#define SL_MODULE_NAME_CAPACITY 128U

typedef enum {
    SL_MODULE_PE = 0,
    SL_MODULE_NATIVE
} sl_module_kind;

typedef struct {
    const char *name;
    const char *forwarder;
    uint32_t ordinal;
    bool has_ordinal;
    uint64_t guest_address;
} sl_native_export;

typedef struct {
    char name[SL_MODULE_NAME_CAPACITY];
    sl_module_kind kind;
    const sl_pe_image *image;
    const sl_mapped_image *mapped;
    const sl_native_export *native_exports;
    size_t native_export_count;
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
    bool is_native;
} sl_resolved_symbol;

typedef struct {
    const char *module_name;
    const char *symbol_name;
    uint32_t ordinal;
    bool by_ordinal;
} sl_module_symbol;

void sl_module_registry_init(sl_module_registry *registry);
sl_status sl_module_registry_add(sl_module_registry *registry, const char *name,
                                 const sl_pe_image *image,
                                 const sl_mapped_image *mapped);
/*
 * Native export tables and their strings are borrowed. They must remain
 * immutable and alive for the registry's lifetime. Publish a registry to other
 * threads only after all modules have been added.
 */
sl_status sl_module_registry_add_native(
    sl_module_registry *registry, const char *name,
    const sl_native_export *exports, size_t export_count);
const sl_loaded_module *sl_module_registry_find(
    const sl_module_registry *registry, const char *name);
sl_status sl_module_registry_resolve_symbol(
    const sl_module_registry *registry, const sl_module_symbol *symbol,
    sl_resolved_symbol *result);
sl_status sl_module_registry_resolve(const sl_module_registry *registry,
                                     const sl_pe_import_symbol *import,
                                     sl_resolved_symbol *result);
sl_status sl_module_registry_import_resolver(
    const sl_pe_import_symbol *import, uint64_t *guest_address, void *context);

#endif
