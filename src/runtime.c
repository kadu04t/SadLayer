#include "sadlayer/runtime.h"

#include "sadlayer/win32.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SL_SECTION_MEM_EXECUTE UINT32_C(0x20000000)

typedef uint32_t(SL_WINAPI *sl_guest_entry)(void);

static bool entry_is_executable(const sl_pe_image *image, uint32_t entry_rva) {
    for (uint16_t index = 0U; index < image->section_count; ++index) {
        const sl_pe_section *section = &image->sections[index];
        uint32_t length = section->virtual_size;
        if (section->raw_size > length) {
            length = section->raw_size;
        }
        if (length == 0U || entry_rva < section->virtual_address) {
            continue;
        }
        uint32_t offset = entry_rva - section->virtual_address;
        if (offset < length &&
            (section->characteristics & SL_SECTION_MEM_EXECUTE) != 0U) {
            return true;
        }
    }
    return false;
}

sl_status sl_runtime_call_trusted_entry(const sl_pe_image *image,
                                        const sl_mapped_image *mapped,
                                        sl_win32_thread_context *thread,
                                        uint32_t *result) {
    if (result != NULL) {
        *result = 0U;
    }
    if (image == NULL || mapped == NULL || thread == NULL || result == NULL ||
        thread->process == NULL || !image->is_pe32_plus ||
        image->machine != SL_PE_MACHINE_AMD64 || mapped->bytes == NULL ||
        mapped->storage != SL_IMAGE_STORAGE_VIRTUAL ||
        !mapped->protections_finalized || mapped->size != image->image_size ||
        mapped->allocation_size < mapped->size ||
        mapped->preferred_base != image->image_base ||
        mapped->load_base != (uint64_t)(uintptr_t)mapped->bytes ||
        image->section_count > SL_PE_MAX_SECTIONS ||
        mapped->entry_rva != image->entry_rva || mapped->entry_rva == 0U ||
        mapped->entry_rva >= mapped->size ||
        !entry_is_executable(image, mapped->entry_rva)) {
        return SL_ERROR_INVALID_STATE;
    }

    uintptr_t address =
        (uintptr_t)(mapped->bytes + (size_t)mapped->entry_rva);
    sl_guest_entry entry = NULL;
    _Static_assert(sizeof(entry) <= sizeof(address),
                   "guest entry pointer does not fit uintptr_t");
    memcpy(&entry, &address, sizeof(entry));

    sl_win32_context_scope scope;
    sl_status status = sl_win32_context_enter(thread, &scope);
    if (status != SL_OK) {
        return status;
    }
    uint32_t guest_result = entry();
    status = sl_win32_context_leave(&scope);
    if (status != SL_OK) {
        return status;
    }
    *result = guest_result;
    return SL_OK;
}
