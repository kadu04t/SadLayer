#include "sadlayer/module.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define SL_FORWARDER_MODULE_CAPACITY 128U
#define SL_FORWARDER_DEPTH_LIMIT 16U

static bool ascii_equal_ignore_case(const char *left, const char *right) {
    if (left == NULL || right == NULL) {
        return false;
    }
    while (*left != '\0' && *right != '\0') {
        unsigned char left_char = (unsigned char)*left;
        unsigned char right_char = (unsigned char)*right;
        if (tolower(left_char) != tolower(right_char)) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

void sl_module_registry_init(sl_module_registry *registry) {
    if (registry != NULL) {
        memset(registry, 0, sizeof(*registry));
    }
}

const sl_loaded_module *sl_module_registry_find(
    const sl_module_registry *registry, const char *name) {
    if (registry == NULL || name == NULL) {
        return NULL;
    }
    for (size_t index = 0U; index < registry->count; ++index) {
        if (ascii_equal_ignore_case(registry->modules[index].name, name)) {
            return &registry->modules[index];
        }
    }
    return NULL;
}

sl_status sl_module_registry_add(sl_module_registry *registry, const char *name,
                                 const sl_pe_image *image,
                                 const sl_mapped_image *mapped) {
    if (registry == NULL || name == NULL || name[0] == '\0' || image == NULL ||
        mapped == NULL || mapped->bytes == NULL ||
        mapped->size != image->image_size) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (sl_module_registry_find(registry, name) != NULL) {
        return SL_ERROR_DUPLICATE_MODULE;
    }
    if (registry->count >= SL_MODULE_REGISTRY_CAPACITY) {
        return SL_ERROR_MODULE_REGISTRY_FULL;
    }
    registry->modules[registry->count] = (sl_loaded_module){
        .name = name,
        .image = image,
        .mapped = mapped,
    };
    ++registry->count;
    return SL_OK;
}

static sl_status parse_forwarder(const char *forwarder, char *module_name,
                                 size_t module_capacity, const char **symbol,
                                 uint32_t *ordinal, bool *by_ordinal) {
    const char *separator = strchr(forwarder, '.');
    if (separator == NULL || separator == forwarder || separator[1] == '\0') {
        return SL_ERROR_INVALID_FORWARDER;
    }
    size_t module_length = (size_t)(separator - forwarder);
    static const char suffix[] = ".dll";
    if (module_length > module_capacity - sizeof(suffix)) {
        return SL_ERROR_INVALID_FORWARDER;
    }
    memcpy(module_name, forwarder, module_length);
    memcpy(module_name + module_length, suffix, sizeof(suffix));

    *symbol = separator + 1;
    *ordinal = 0U;
    *by_ordinal = (*symbol)[0] == '#';
    if (*by_ordinal) {
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(*symbol + 1, &end, 10);
        if ((*symbol)[1] == '\0' || end == NULL || *end != '\0' ||
            errno != 0 || value > UINT32_MAX) {
            return SL_ERROR_INVALID_FORWARDER;
        }
        *ordinal = (uint32_t)value;
    }
    return SL_OK;
}

static sl_status resolve_symbol(const sl_module_registry *registry,
                                const char *module_name, const char *symbol_name,
                                uint32_t ordinal, bool by_ordinal,
                                uint32_t depth, sl_resolved_symbol *result) {
    if (depth > SL_FORWARDER_DEPTH_LIMIT) {
        return SL_ERROR_FORWARDER_LIMIT;
    }
    const sl_loaded_module *module =
        sl_module_registry_find(registry, module_name);
    if (module == NULL) {
        return SL_ERROR_MODULE_NOT_FOUND;
    }

    sl_pe_export export;
    sl_status status = by_ordinal
                           ? sl_pe_find_export_by_ordinal(module->image, ordinal,
                                                          &export)
                           : sl_pe_find_export_by_name(module->image, symbol_name,
                                                       &export);
    if (status != SL_OK) {
        return status;
    }
    if (export.is_forwarder) {
        char forwarded_module[SL_FORWARDER_MODULE_CAPACITY];
        const char *forwarded_symbol = NULL;
        uint32_t forwarded_ordinal = 0U;
        bool forwarded_by_ordinal = false;
        status = parse_forwarder(export.forwarder, forwarded_module,
                                 sizeof(forwarded_module), &forwarded_symbol,
                                 &forwarded_ordinal, &forwarded_by_ordinal);
        if (status != SL_OK) {
            return status;
        }
        return resolve_symbol(registry, forwarded_module, forwarded_symbol,
                              forwarded_ordinal, forwarded_by_ordinal,
                              depth + 1U, result);
    }
    if (module->mapped->load_base > UINT64_MAX - export.rva) {
        return SL_ERROR_INVALID_IMAGE;
    }
    *result = (sl_resolved_symbol){
        .module = module,
        .export = export,
        .guest_address = module->mapped->load_base + export.rva,
        .forward_depth = depth,
    };
    return SL_OK;
}

sl_status sl_module_registry_resolve(const sl_module_registry *registry,
                                     const sl_pe_import_symbol *import,
                                     sl_resolved_symbol *result) {
    if (registry == NULL || import == NULL || result == NULL ||
        import->module_name == NULL ||
        (!import->by_ordinal && import->symbol_name == NULL)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    return resolve_symbol(registry, import->module_name, import->symbol_name,
                          import->ordinal, import->by_ordinal, 0U, result);
}

sl_status sl_module_registry_import_resolver(
    const sl_pe_import_symbol *import, uint64_t *guest_address, void *context) {
    if (guest_address == NULL || context == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_resolved_symbol resolved;
    sl_status status = sl_module_registry_resolve(
        (const sl_module_registry *)context, import, &resolved);
    if (status == SL_OK) {
        *guest_address = resolved.guest_address;
    }
    return status;
}
