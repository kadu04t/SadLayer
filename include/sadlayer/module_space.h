#ifndef SADLAYER_MODULE_SPACE_H
#define SADLAYER_MODULE_SPACE_H

#include <stddef.h>

#include "sadlayer/module.h"

typedef struct sl_module_space sl_module_space;

/*
 * A module space owns the source bytes, parsed metadata, and execution-intended
 * mapping of every PE added through sl_module_space_add_pe. Mutation is
 * single-threaded and bootstrap-only; no DLL entry point or guest code runs.
 */
sl_status sl_module_space_create(sl_module_space **out_space);
void sl_module_space_destroy(sl_module_space *space);

/*
 * Copies file before parsing it. A module becomes visible in the registry only
 * after copying, parsing, mapping, and relocation all succeed. On failure,
 * out_module is NULL and the existing space is unchanged.
 */
sl_status sl_module_space_add_pe(sl_module_space *space, const char *name,
                                 sl_byte_view file,
                                 const sl_loaded_module **out_module);

/*
 * Native export tables remain borrowed and must have static/module-space
 * lifetime. Aliases retain the registry's bounded one-hop semantics.
 */
sl_status sl_module_space_add_native(
    sl_module_space *space, const char *name,
    const sl_native_export *exports, size_t export_count,
    const sl_loaded_module **out_module);
sl_status sl_module_space_add_alias(sl_module_space *space,
                                    const char *contract_name,
                                    const char *target_name);

/*
 * These phase operations accept only PE modules owned by this space.
 * Finalization requires at least one successful import-binding pass, including
 * the zero-import case.
 */
sl_status sl_module_space_bind_imports(sl_module_space *space,
                                       const sl_loaded_module *module,
                                       size_t *bound_count);
sl_status sl_module_space_finalize(sl_module_space *space,
                                   const sl_loaded_module *module);

/* The registry view is read-only; all mutation goes through the space. */
const sl_module_registry *sl_module_space_registry(
    const sl_module_space *space);
size_t sl_module_space_owned_count(const sl_module_space *space);

#endif
