#include "sadlayer/module_space.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *file_bytes;
    sl_pe_image image;
    sl_mapped_image mapped;
    bool imports_bound;
} sl_owned_pe_module;

struct sl_module_space {
    sl_module_registry registry;
    sl_owned_pe_module owned[SL_MODULE_REGISTRY_CAPACITY];
    size_t owned_count;
};

static sl_owned_pe_module *find_owned_module(
    sl_module_space *space, const sl_loaded_module *module) {
    if (space == NULL || module == NULL || module->kind != SL_MODULE_PE) {
        return NULL;
    }
    bool registered = false;
    for (size_t index = 0U; index < space->registry.count; ++index) {
        if (&space->registry.modules[index] == module) {
            registered = true;
            break;
        }
    }
    if (!registered) {
        return NULL;
    }
    for (size_t index = 0U; index < space->owned_count; ++index) {
        sl_owned_pe_module *owned = &space->owned[index];
        if (module->image == &owned->image && module->mapped == &owned->mapped) {
            return owned;
        }
    }
    return NULL;
}

static sl_status preflight_pe_name(const sl_module_space *space,
                                   const char *name) {
    const sl_loaded_module *existing = NULL;
    sl_status status =
        sl_module_registry_resolve_module(&space->registry, name, &existing);
    if (status == SL_OK) {
        return SL_ERROR_DUPLICATE_MODULE;
    }
    if (status != SL_ERROR_MODULE_NOT_FOUND) {
        return status;
    }
    if (space->registry.count >= SL_MODULE_REGISTRY_CAPACITY ||
        space->owned_count >= SL_MODULE_REGISTRY_CAPACITY) {
        return SL_ERROR_MODULE_REGISTRY_FULL;
    }
    return SL_OK;
}

sl_status sl_module_space_create(sl_module_space **out_space) {
    if (out_space == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    *out_space = NULL;
    sl_module_space *space = calloc(1U, sizeof(*space));
    if (space == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    sl_module_registry_init(&space->registry);
    *out_space = space;
    return SL_OK;
}

void sl_module_space_destroy(sl_module_space *space) {
    if (space == NULL) {
        return;
    }
    for (size_t index = space->owned_count; index > 0U; --index) {
        sl_owned_pe_module *owned = &space->owned[index - 1U];
        sl_loader_unmap_image(&owned->mapped);
        free(owned->file_bytes);
    }
    memset(space, 0, sizeof(*space));
    free(space);
}

sl_status sl_module_space_add_pe(sl_module_space *space, const char *name,
                                 sl_byte_view file,
                                 const sl_loaded_module **out_module) {
    if (out_module != NULL) {
        *out_module = NULL;
    }
    if (space == NULL || name == NULL || file.data == NULL || file.size == 0U) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_status status = preflight_pe_name(space, name);
    if (status != SL_OK) {
        return status;
    }

    sl_owned_pe_module *owned = &space->owned[space->owned_count];
    memset(owned, 0, sizeof(*owned));
    owned->file_bytes = malloc(file.size);
    if (owned->file_bytes == NULL) {
        return SL_ERROR_OUT_OF_MEMORY;
    }
    memcpy(owned->file_bytes, file.data, file.size);

    status = sl_pe_parse(
        (sl_byte_view){owned->file_bytes, file.size}, &owned->image);
    if (status == SL_OK) {
        status = sl_loader_map_image_for_execution(&owned->image,
                                                   &owned->mapped);
    }
    if (status == SL_OK) {
        status = sl_module_registry_add(&space->registry, name, &owned->image,
                                        &owned->mapped);
    }
    if (status != SL_OK) {
        sl_loader_unmap_image(&owned->mapped);
        free(owned->file_bytes);
        memset(owned, 0, sizeof(*owned));
        return status;
    }

    ++space->owned_count;
    if (out_module != NULL) {
        *out_module = sl_module_registry_find(&space->registry, name);
    }
    return SL_OK;
}

sl_status sl_module_space_add_native(
    sl_module_space *space, const char *name,
    const sl_native_export *exports, size_t export_count,
    const sl_loaded_module **out_module) {
    if (out_module != NULL) {
        *out_module = NULL;
    }
    if (space == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_status status = sl_module_registry_add_native(
        &space->registry, name, exports, export_count);
    if (status == SL_OK && out_module != NULL) {
        *out_module = sl_module_registry_find(&space->registry, name);
    }
    return status;
}

sl_status sl_module_space_add_alias(sl_module_space *space,
                                    const char *contract_name,
                                    const char *target_name) {
    if (space == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    return sl_module_registry_add_alias(&space->registry, contract_name,
                                        target_name);
}

sl_status sl_module_space_bind_imports(sl_module_space *space,
                                       const sl_loaded_module *module,
                                       size_t *bound_count) {
    if (bound_count != NULL) {
        *bound_count = 0U;
    }
    if (space == NULL || module == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_owned_pe_module *owned = find_owned_module(space, module);
    if (owned == NULL) {
        return SL_ERROR_INVALID_STATE;
    }
    sl_status status = sl_loader_bind_imports(
        &owned->image, &owned->mapped, sl_module_registry_import_resolver,
        &space->registry, bound_count);
    if (status == SL_OK) {
        owned->imports_bound = true;
    }
    return status;
}

sl_status sl_module_space_finalize(sl_module_space *space,
                                   const sl_loaded_module *module) {
    if (space == NULL || module == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_owned_pe_module *owned = find_owned_module(space, module);
    if (owned == NULL) {
        return SL_ERROR_INVALID_STATE;
    }
    if (!owned->imports_bound) {
        return SL_ERROR_INVALID_STATE;
    }
    return sl_loader_finalize_image(&owned->image, &owned->mapped);
}

const sl_module_registry *sl_module_space_registry(
    const sl_module_space *space) {
    return space == NULL ? NULL : &space->registry;
}

size_t sl_module_space_owned_count(const sl_module_space *space) {
    return space == NULL ? 0U : space->owned_count;
}
