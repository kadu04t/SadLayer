#include "sadlayer/module.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define SL_FORWARDER_MODULE_CAPACITY 128U
#define SL_FORWARDER_DEPTH_LIMIT 16U

static unsigned char ascii_fold(unsigned char character) {
    if (character >= (unsigned char)'A' && character <= (unsigned char)'Z') {
        return (unsigned char)(character + ((unsigned char)'a' -
                                             (unsigned char)'A'));
    }
    return character;
}

static bool ascii_equal_ignore_case(const char *left, const char *right) {
    if (left == NULL || right == NULL) {
        return false;
    }
    while (*left != '\0' && *right != '\0') {
        unsigned char left_char = (unsigned char)*left;
        unsigned char right_char = (unsigned char)*right;
        if (ascii_fold(left_char) != ascii_fold(right_char)) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static bool module_name_length(const char *name, size_t *length) {
    if (name == NULL || length == NULL) {
        return false;
    }
    for (size_t index = 0U; index < SL_MODULE_NAME_CAPACITY; ++index) {
        if (name[index] == '\0') {
            if (index == 0U) {
                return false;
            }
            *length = index;
            return true;
        }
    }
    return false;
}

static const sl_module_alias *find_alias(const sl_module_registry *registry,
                                         const char *name) {
    if (registry == NULL || name == NULL) {
        return NULL;
    }
    for (size_t index = 0U; index < registry->alias_count; ++index) {
        if (ascii_equal_ignore_case(registry->aliases[index].contract_name,
                                    name)) {
            return &registry->aliases[index];
        }
    }
    return NULL;
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
    size_t name_length = 0U;
    if (registry == NULL || image == NULL || mapped == NULL ||
        mapped->bytes == NULL || mapped->size != image->image_size ||
        !module_name_length(name, &name_length)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (sl_module_registry_find(registry, name) != NULL ||
        find_alias(registry, name) != NULL) {
        return SL_ERROR_DUPLICATE_MODULE;
    }
    if (registry->count >= SL_MODULE_REGISTRY_CAPACITY) {
        return SL_ERROR_MODULE_REGISTRY_FULL;
    }
    sl_loaded_module *module = &registry->modules[registry->count];
    *module = (sl_loaded_module){
        .kind = SL_MODULE_PE,
        .image = image,
        .mapped = mapped,
        .native_exports = NULL,
        .native_export_count = 0U,
    };
    memcpy(module->name, name, name_length + 1U);
    ++registry->count;
    return SL_OK;
}

sl_status sl_module_registry_add_native(
    sl_module_registry *registry, const char *name,
    const sl_native_export *exports, size_t export_count) {
    size_t name_length = 0U;
    if (registry == NULL || exports == NULL || export_count == 0U ||
        !module_name_length(name, &name_length)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (sl_module_registry_find(registry, name) != NULL ||
        find_alias(registry, name) != NULL) {
        return SL_ERROR_DUPLICATE_MODULE;
    }
    if (registry->count >= SL_MODULE_REGISTRY_CAPACITY) {
        return SL_ERROR_MODULE_REGISTRY_FULL;
    }
    for (size_t index = 0U; index < export_count; ++index) {
        const sl_native_export *candidate = &exports[index];
        bool has_name = candidate->name != NULL && candidate->name[0] != '\0';
        bool has_target = candidate->guest_address != 0U ||
                          (candidate->forwarder != NULL &&
                           candidate->forwarder[0] != '\0');
        if ((!has_name && !candidate->has_ordinal) || !has_target ||
            (candidate->guest_address != 0U && candidate->forwarder != NULL)) {
            return SL_ERROR_INVALID_ARGUMENT;
        }
        for (size_t previous = 0U; previous < index; ++previous) {
            const sl_native_export *existing = &exports[previous];
            if ((has_name && existing->name != NULL &&
                 strcmp(candidate->name, existing->name) == 0) ||
                (candidate->has_ordinal && existing->has_ordinal &&
                 candidate->ordinal == existing->ordinal)) {
                return SL_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    sl_loaded_module *module = &registry->modules[registry->count];
    *module = (sl_loaded_module){
        .kind = SL_MODULE_NATIVE,
        .image = NULL,
        .mapped = NULL,
        .native_exports = exports,
        .native_export_count = export_count,
    };
    memcpy(module->name, name, name_length + 1U);
    ++registry->count;
    return SL_OK;
}

sl_status sl_module_registry_add_alias(sl_module_registry *registry,
                                       const char *contract_name,
                                       const char *target_name) {
    size_t contract_length = 0U;
    size_t target_length = 0U;
    if (registry == NULL ||
        !module_name_length(contract_name, &contract_length) ||
        !module_name_length(target_name, &target_length)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (sl_module_registry_find(registry, contract_name) != NULL ||
        find_alias(registry, contract_name) != NULL) {
        return SL_ERROR_DUPLICATE_MODULE;
    }
    const sl_loaded_module *target =
        sl_module_registry_find(registry, target_name);
    if (target == NULL) {
        return SL_ERROR_MODULE_NOT_FOUND;
    }
    if (registry->alias_count >= SL_MODULE_ALIAS_CAPACITY) {
        return SL_ERROR_MODULE_REGISTRY_FULL;
    }

    sl_module_alias *alias = &registry->aliases[registry->alias_count];
    memcpy(alias->contract_name, contract_name, contract_length + 1U);
    memcpy(alias->target_name, target->name, target_length + 1U);
    ++registry->alias_count;
    return SL_OK;
}

sl_status sl_module_registry_resolve_module(
    const sl_module_registry *registry, const char *name,
    const sl_loaded_module **result) {
    size_t name_length = 0U;
    if (registry == NULL || result == NULL ||
        !module_name_length(name, &name_length)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    (void)name_length;

    const sl_loaded_module *module = sl_module_registry_find(registry, name);
    if (module == NULL) {
        const sl_module_alias *alias = find_alias(registry, name);
        if (alias == NULL) {
            return SL_ERROR_MODULE_NOT_FOUND;
        }
        module = sl_module_registry_find(registry, alias->target_name);
        if (module == NULL) {
            return SL_ERROR_MODULE_NOT_FOUND;
        }
    }
    *result = module;
    return SL_OK;
}

static sl_status parse_forwarder(const char *forwarder, char *module_name,
                                 size_t module_capacity, const char **symbol,
                                 uint32_t *ordinal, bool *by_ordinal) {
    const char *separator = strrchr(forwarder, '.');
    if (separator == NULL || separator == forwarder || separator[1] == '\0') {
        return SL_ERROR_INVALID_FORWARDER;
    }
    size_t module_length = (size_t)(separator - forwarder);
    static const char suffix[] = ".dll";
    bool has_dll_suffix =
        module_length >= 4U &&
        ascii_fold((unsigned char)forwarder[module_length - 4U]) ==
            (unsigned char)'.' &&
        ascii_fold((unsigned char)forwarder[module_length - 3U]) ==
            (unsigned char)'d' &&
        ascii_fold((unsigned char)forwarder[module_length - 2U]) ==
            (unsigned char)'l' &&
        ascii_fold((unsigned char)forwarder[module_length - 1U]) ==
            (unsigned char)'l';
    size_t required = module_length + (has_dll_suffix ? 1U : sizeof(suffix));
    if (required > module_capacity) {
        return SL_ERROR_INVALID_FORWARDER;
    }
    memcpy(module_name, forwarder, module_length);
    if (has_dll_suffix) {
        module_name[module_length] = '\0';
    } else {
        memcpy(module_name + module_length, suffix, sizeof(suffix));
    }

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

static sl_status resolve_symbol_recursive(
    const sl_module_registry *registry, const char *module_name,
    const char *symbol_name, uint32_t ordinal, bool by_ordinal, uint32_t depth,
    sl_resolved_symbol *result) {
    if (depth > SL_FORWARDER_DEPTH_LIMIT) {
        return SL_ERROR_FORWARDER_LIMIT;
    }
    const sl_loaded_module *module = NULL;
    sl_status status =
        sl_module_registry_resolve_module(registry, module_name, &module);
    if (status != SL_OK) {
        return status;
    }

    if (module->kind == SL_MODULE_NATIVE) {
        const sl_native_export *native_export = NULL;
        for (size_t index = 0U; index < module->native_export_count; ++index) {
            const sl_native_export *candidate = &module->native_exports[index];
            if ((by_ordinal && candidate->has_ordinal &&
                 candidate->ordinal == ordinal) ||
                (!by_ordinal && candidate->name != NULL &&
                 strcmp(candidate->name, symbol_name) == 0)) {
                native_export = candidate;
                break;
            }
        }
        if (native_export == NULL) {
            return SL_ERROR_EXPORT_NOT_FOUND;
        }
        if (native_export->forwarder != NULL) {
            char forwarded_module[SL_FORWARDER_MODULE_CAPACITY];
            const char *forwarded_symbol = NULL;
            uint32_t forwarded_ordinal = 0U;
            bool forwarded_by_ordinal = false;
            status = parse_forwarder(
                native_export->forwarder, forwarded_module,
                sizeof(forwarded_module), &forwarded_symbol,
                &forwarded_ordinal, &forwarded_by_ordinal);
            if (status != SL_OK) {
                return status;
            }
            return resolve_symbol_recursive(
                registry, forwarded_module, forwarded_symbol,
                forwarded_ordinal, forwarded_by_ordinal, depth + 1U, result);
        }
        *result = (sl_resolved_symbol){
            .module = module,
            .export =
                (sl_pe_export){
                    .name = native_export->name,
                    .forwarder = NULL,
                    .ordinal = native_export->ordinal,
                    .rva = 0U,
                    .is_forwarder = false,
                },
            .guest_address = native_export->guest_address,
            .forward_depth = depth,
            .is_native = true,
        };
        return SL_OK;
    }

    sl_pe_export export;
    status = by_ordinal
                 ? sl_pe_find_export_by_ordinal(module->image, ordinal, &export)
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
        return resolve_symbol_recursive(
            registry, forwarded_module, forwarded_symbol, forwarded_ordinal,
            forwarded_by_ordinal, depth + 1U, result);
    }
    if (module->mapped->load_base > UINT64_MAX - export.rva) {
        return SL_ERROR_INVALID_IMAGE;
    }
    *result = (sl_resolved_symbol){
        .module = module,
        .export = export,
        .guest_address = module->mapped->load_base + export.rva,
        .forward_depth = depth,
        .is_native = false,
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
    sl_module_symbol symbol = {
        .module_name = import->module_name,
        .symbol_name = import->symbol_name,
        .ordinal = import->ordinal,
        .by_ordinal = import->by_ordinal,
    };
    return sl_module_registry_resolve_symbol(registry, &symbol, result);
}

sl_status sl_module_registry_resolve_symbol(
    const sl_module_registry *registry, const sl_module_symbol *symbol,
    sl_resolved_symbol *result) {
    if (registry == NULL || symbol == NULL || result == NULL ||
        symbol->module_name == NULL ||
        (!symbol->by_ordinal && symbol->symbol_name == NULL)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_resolved_symbol resolved;
    sl_status status = resolve_symbol_recursive(
        registry, symbol->module_name, symbol->symbol_name, symbol->ordinal,
        symbol->by_ordinal, 0U, &resolved);
    if (status == SL_OK) {
        *result = resolved;
    }
    return status;
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
