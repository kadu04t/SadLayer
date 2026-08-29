#include "sadlayer/pe.h"

#include <limits.h>
#include <string.h>

#define SL_DOS_E_LFANEW_OFFSET 0x3cU
#define SL_COFF_HEADER_SIZE 20U
#define SL_SECTION_HEADER_SIZE 40U
#define SL_IMPORT_DESCRIPTOR_SIZE 20U
#define SL_EXPORT_DIRECTORY_SIZE 40U

static bool range_fits(size_t offset, size_t length, size_t total) {
    return offset <= total && length <= total - offset;
}

static bool read_u16(sl_byte_view view, size_t offset, uint16_t *value) {
    if (!range_fits(offset, 2U, view.size)) {
        return false;
    }
    *value = (uint16_t)((uint16_t)view.data[offset] |
                        ((uint16_t)view.data[offset + 1U] << 8U));
    return true;
}

static bool read_u32(sl_byte_view view, size_t offset, uint32_t *value) {
    if (!range_fits(offset, 4U, view.size)) {
        return false;
    }
    *value = (uint32_t)view.data[offset] |
             ((uint32_t)view.data[offset + 1U] << 8U) |
             ((uint32_t)view.data[offset + 2U] << 16U) |
             ((uint32_t)view.data[offset + 3U] << 24U);
    return true;
}

static bool read_u64(sl_byte_view view, size_t offset, uint64_t *value) {
    uint32_t low = 0U;
    uint32_t high = 0U;
    if (!read_u32(view, offset, &low) || !read_u32(view, offset + 4U, &high)) {
        return false;
    }
    *value = (uint64_t)low | ((uint64_t)high << 32U);
    return true;
}

static bool add_size(size_t left, size_t right, size_t *result) {
    if (right > SIZE_MAX - left) {
        return false;
    }
    *result = left + right;
    return true;
}

static bool u32_range_fits(uint32_t offset, uint32_t length, uint32_t total) {
    return offset <= total && length <= total - offset;
}

static sl_status parse_optional_header(sl_byte_view file, size_t offset,
                                       uint16_t size, sl_pe_image *image) {
    uint16_t magic = 0U;
    uint32_t directory_count = 0U;
    size_t directory_offset = 0U;
    size_t minimum_size = 0U;

    if (!range_fits(offset, (size_t)size, file.size) ||
        !read_u16(file, offset, &magic)) {
        return SL_ERROR_TRUNCATED_FILE;
    }

    if (magic == 0x010bU) {
        uint32_t base = 0U;
        image->is_pe32_plus = false;
        minimum_size = 96U;
        directory_offset = 96U;
        if ((size_t)size < minimum_size || !read_u32(file, offset + 28U, &base)) {
            return SL_ERROR_TRUNCATED_FILE;
        }
        image->image_base = base;
        if (!read_u32(file, offset + 92U, &directory_count)) {
            return SL_ERROR_TRUNCATED_FILE;
        }
    } else if (magic == 0x020bU) {
        image->is_pe32_plus = true;
        minimum_size = 112U;
        directory_offset = 112U;
        if ((size_t)size < minimum_size ||
            !read_u64(file, offset + 24U, &image->image_base) ||
            !read_u32(file, offset + 108U, &directory_count)) {
            return SL_ERROR_TRUNCATED_FILE;
        }
    } else {
        return SL_ERROR_UNSUPPORTED_OPTIONAL_HEADER;
    }

    if (!read_u32(file, offset + 16U, &image->entry_rva) ||
        !read_u32(file, offset + 32U, &image->section_alignment) ||
        !read_u32(file, offset + 36U, &image->file_alignment) ||
        !read_u32(file, offset + 56U, &image->image_size) ||
        !read_u32(file, offset + 60U, &image->headers_size) ||
        !read_u16(file, offset + 68U, &image->subsystem)) {
        return SL_ERROR_TRUNCATED_FILE;
    }

    if (image->image_size == 0U || image->headers_size == 0U ||
        image->headers_size > image->image_size ||
        image->headers_size > file.size ||
        (image->entry_rva != 0U && image->entry_rva >= image->image_size)) {
        return SL_ERROR_INVALID_IMAGE;
    }

    if (directory_count > SL_PE_DATA_DIRECTORY_COUNT) {
        directory_count = SL_PE_DATA_DIRECTORY_COUNT;
    }
    for (uint32_t index = 0U; index < directory_count; ++index) {
        size_t relative = directory_offset + (size_t)index * 8U;
        if (relative + 8U > (size_t)size ||
            !read_u32(file, offset + relative, &image->directories[index].rva) ||
            !read_u32(file, offset + relative + 4U,
                      &image->directories[index].size)) {
            return SL_ERROR_TRUNCATED_FILE;
        }
    }
    return SL_OK;
}

sl_status sl_pe_parse(sl_byte_view file, sl_pe_image *image) {
    uint32_t pe_offset_u32 = 0U;
    size_t pe_offset = 0U;
    size_t coff_offset = 0U;
    size_t optional_offset = 0U;
    size_t sections_offset = 0U;
    uint16_t optional_size = 0U;
    uint32_t signature = 0U;

    if (file.data == NULL || image == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    memset(image, 0, sizeof(*image));
    image->file = file;

    if (file.size < 64U) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    if (file.data[0] != 'M' || file.data[1] != 'Z') {
        return SL_ERROR_BAD_DOS_SIGNATURE;
    }
    if (!read_u32(file, SL_DOS_E_LFANEW_OFFSET, &pe_offset_u32)) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    pe_offset = (size_t)pe_offset_u32;
    if (!read_u32(file, pe_offset, &signature)) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    if (signature != 0x00004550U) {
        return SL_ERROR_BAD_PE_SIGNATURE;
    }
    if (!add_size(pe_offset, 4U, &coff_offset) ||
        !range_fits(coff_offset, SL_COFF_HEADER_SIZE, file.size) ||
        !read_u16(file, coff_offset, &image->machine) ||
        !read_u16(file, coff_offset + 2U, &image->section_count) ||
        !read_u16(file, coff_offset + 16U, &optional_size)) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    if (image->machine != SL_PE_MACHINE_I386 &&
        image->machine != SL_PE_MACHINE_AMD64) {
        return SL_ERROR_UNSUPPORTED_MACHINE;
    }
    if (image->section_count == 0U ||
        image->section_count > SL_PE_MAX_SECTIONS) {
        return SL_ERROR_INVALID_IMAGE;
    }
    if (!add_size(coff_offset, SL_COFF_HEADER_SIZE, &optional_offset)) {
        return SL_ERROR_INVALID_IMAGE;
    }

    sl_status status =
        parse_optional_header(file, optional_offset, optional_size, image);
    if (status != SL_OK) {
        return status;
    }
    if ((image->machine == SL_PE_MACHINE_AMD64) != image->is_pe32_plus) {
        return SL_ERROR_INVALID_IMAGE;
    }
    if (!add_size(optional_offset, (size_t)optional_size, &sections_offset) ||
        !range_fits(sections_offset,
                    (size_t)image->section_count * SL_SECTION_HEADER_SIZE,
                    file.size)) {
        return SL_ERROR_TRUNCATED_FILE;
    }

    for (uint16_t index = 0U; index < image->section_count; ++index) {
        sl_pe_section *section = &image->sections[index];
        size_t cursor = sections_offset + (size_t)index * SL_SECTION_HEADER_SIZE;
        memcpy(section->name, file.data + cursor, 8U);
        section->name[8] = '\0';
        if (!read_u32(file, cursor + 8U, &section->virtual_size) ||
            !read_u32(file, cursor + 12U, &section->virtual_address) ||
            !read_u32(file, cursor + 16U, &section->raw_size) ||
            !read_u32(file, cursor + 20U, &section->raw_offset) ||
            !read_u32(file, cursor + 36U, &section->characteristics)) {
            return SL_ERROR_TRUNCATED_FILE;
        }
        if (section->raw_size != 0U &&
            (!range_fits((size_t)section->raw_offset,
                         (size_t)section->raw_size, file.size) ||
             !u32_range_fits(section->virtual_address, section->raw_size,
                             image->image_size))) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (section->virtual_size != 0U &&
            !u32_range_fits(section->virtual_address, section->virtual_size,
                            image->image_size)) {
            return SL_ERROR_INVALID_IMAGE;
        }
    }
    return SL_OK;
}

static sl_status rva_file_window(const sl_pe_image *image, uint32_t rva,
                                 size_t *offset, size_t *available) {
    if (image == NULL || offset == NULL || available == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (rva < image->headers_size && (size_t)rva < image->file.size) {
        *offset = (size_t)rva;
        size_t header_available = (size_t)image->headers_size - (size_t)rva;
        size_t file_available = image->file.size - (size_t)rva;
        *available = header_available < file_available ? header_available
                                                      : file_available;
        return SL_OK;
    }
    for (uint16_t index = 0U; index < image->section_count; ++index) {
        const sl_pe_section *section = &image->sections[index];
        uint32_t span = section->virtual_size > section->raw_size
                            ? section->virtual_size
                            : section->raw_size;
        if (rva >= section->virtual_address &&
            rva - section->virtual_address < span) {
            uint32_t delta = rva - section->virtual_address;
            if (delta >= section->raw_size ||
                !range_fits((size_t)section->raw_offset + (size_t)delta, 1U,
                            image->file.size)) {
                return SL_ERROR_RVA_NOT_MAPPED;
            }
            *offset = (size_t)section->raw_offset + (size_t)delta;
            size_t section_available =
                (size_t)section->raw_size - (size_t)delta;
            size_t file_available = image->file.size - *offset;
            *available = section_available < file_available ? section_available
                                                            : file_available;
            return SL_OK;
        }
    }
    return SL_ERROR_RVA_NOT_MAPPED;
}

sl_status sl_pe_rva_to_file_offset(const sl_pe_image *image, uint32_t rva,
                                   size_t *offset) {
    size_t available = 0U;
    return rva_file_window(image, rva, offset, &available);
}

static sl_status read_rva_u32(const sl_pe_image *image, uint32_t rva,
                              uint32_t *value) {
    size_t offset = 0U;
    size_t available = 0U;
    sl_status status = rva_file_window(image, rva, &offset, &available);
    if (status != SL_OK) {
        return status;
    }
    if (available < 4U) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    return read_u32(image->file, offset, value) ? SL_OK : SL_ERROR_TRUNCATED_FILE;
}

static sl_status read_rva_u16(const sl_pe_image *image, uint32_t rva,
                              uint16_t *value) {
    size_t offset = 0U;
    size_t available = 0U;
    sl_status status = rva_file_window(image, rva, &offset, &available);
    if (status != SL_OK) {
        return status;
    }
    if (available < 2U) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    return read_u16(image->file, offset, value) ? SL_OK : SL_ERROR_TRUNCATED_FILE;
}

static sl_status read_rva_u64(const sl_pe_image *image, uint32_t rva,
                              uint64_t *value) {
    size_t offset = 0U;
    size_t available = 0U;
    sl_status status = rva_file_window(image, rva, &offset, &available);
    if (status != SL_OK) {
        return status;
    }
    if (available < 8U) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    return read_u64(image->file, offset, value) ? SL_OK : SL_ERROR_TRUNCATED_FILE;
}

static sl_status read_rva_string(const sl_pe_image *image, uint32_t rva,
                                 const char **string) {
    size_t offset = 0U;
    size_t available = 0U;
    sl_status status = rva_file_window(image, rva, &offset, &available);
    if (status != SL_OK) {
        return status;
    }
    const uint8_t *start = image->file.data + offset;
    if (memchr(start, '\0', available) == NULL) {
        return SL_ERROR_TRUNCATED_FILE;
    }
    *string = (const char *)start;
    return SL_OK;
}

sl_status sl_pe_for_each_import(const sl_pe_image *image,
                                sl_pe_import_callback callback, void *context) {
    if (image == NULL || callback == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_pe_data_directory imports = image->directories[SL_PE_DIRECTORY_IMPORT];
    if (imports.rva == 0U || imports.size == 0U) {
        return SL_OK;
    }
    if (imports.rva >= image->image_size ||
        imports.size > image->image_size - imports.rva) {
        return SL_ERROR_INVALID_IMAGE;
    }

    uint32_t consumed = 0U;
    while (consumed + SL_IMPORT_DESCRIPTOR_SIZE <= imports.size) {
        uint32_t cursor = imports.rva + consumed;
        uint32_t original_thunk = 0U;
        uint32_t timestamp = 0U;
        uint32_t forwarder_chain = 0U;
        uint32_t name_rva = 0U;
        uint32_t first_thunk = 0U;
        if (cursor < imports.rva ||
            read_rva_u32(image, cursor, &original_thunk) != SL_OK ||
            read_rva_u32(image, cursor + 4U, &timestamp) != SL_OK ||
            read_rva_u32(image, cursor + 8U, &forwarder_chain) != SL_OK ||
            read_rva_u32(image, cursor + 12U, &name_rva) != SL_OK ||
            read_rva_u32(image, cursor + 16U, &first_thunk) != SL_OK) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (original_thunk == 0U && timestamp == 0U && forwarder_chain == 0U &&
            name_rva == 0U && first_thunk == 0U) {
            return SL_OK;
        }
        const char *module_name = NULL;
        sl_status status = read_rva_string(image, name_rva, &module_name);
        if (status != SL_OK) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (!callback(module_name, context)) {
            return SL_OK;
        }
        consumed += SL_IMPORT_DESCRIPTOR_SIZE;
    }
    return SL_ERROR_INVALID_IMAGE;
}

static sl_status visit_import_thunks(const sl_pe_image *image,
                                     const char *module_name,
                                     uint32_t original_thunk,
                                     uint32_t first_thunk,
                                     sl_pe_import_symbol_callback callback,
                                     void *context, bool *keep_visiting) {
    uint32_t lookup_rva = original_thunk != 0U ? original_thunk : first_thunk;
    uint32_t iat_rva = first_thunk;
    uint32_t entry_size = image->is_pe32_plus ? 8U : 4U;
    uint64_t ordinal_flag = image->is_pe32_plus
                                ? UINT64_C(0x8000000000000000)
                                : UINT64_C(0x80000000);

    if (lookup_rva == 0U || iat_rva == 0U) {
        return SL_ERROR_INVALID_IMAGE;
    }
    for (;;) {
        size_t iat_offset = 0U;
        size_t iat_available = 0U;
        if (rva_file_window(image, iat_rva, &iat_offset, &iat_available) !=
                SL_OK ||
            iat_available < entry_size) {
            return SL_ERROR_INVALID_IMAGE;
        }
        uint64_t thunk = 0U;
        sl_status status = SL_OK;
        if (image->is_pe32_plus) {
            status = read_rva_u64(image, lookup_rva, &thunk);
        } else {
            uint32_t thunk32 = 0U;
            status = read_rva_u32(image, lookup_rva, &thunk32);
            thunk = thunk32;
        }
        if (status != SL_OK) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (thunk == 0U) {
            return SL_OK;
        }

        sl_pe_import_symbol symbol = {
            .module_name = module_name,
            .symbol_name = NULL,
            .iat_rva = iat_rva,
            .hint = 0U,
            .ordinal = 0U,
            .by_ordinal = (thunk & ordinal_flag) != 0U,
        };
        if (symbol.by_ordinal) {
            if ((thunk & ~(ordinal_flag | UINT16_MAX)) != 0U) {
                return SL_ERROR_INVALID_IMAGE;
            }
            symbol.ordinal = (uint16_t)(thunk & UINT16_MAX);
        } else {
            if (thunk > UINT32_MAX) {
                return SL_ERROR_INVALID_IMAGE;
            }
            uint32_t name_rva = (uint32_t)thunk;
            if (name_rva > UINT32_MAX - 2U ||
                read_rva_u16(image, name_rva, &symbol.hint) != SL_OK ||
                read_rva_string(image, name_rva + 2U, &symbol.symbol_name) !=
                    SL_OK) {
                return SL_ERROR_INVALID_IMAGE;
            }
        }
        if (!callback(&symbol, context)) {
            *keep_visiting = false;
            return SL_OK;
        }
        if (lookup_rva > UINT32_MAX - entry_size ||
            iat_rva > UINT32_MAX - entry_size) {
            return SL_ERROR_INVALID_IMAGE;
        }
        lookup_rva += entry_size;
        iat_rva += entry_size;
    }
}

sl_status sl_pe_for_each_import_symbol(
    const sl_pe_image *image, sl_pe_import_symbol_callback callback,
    void *context) {
    if (image == NULL || callback == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_pe_data_directory imports = image->directories[SL_PE_DIRECTORY_IMPORT];
    if (imports.rva == 0U || imports.size == 0U) {
        return SL_OK;
    }
    if (imports.rva >= image->image_size ||
        imports.size > image->image_size - imports.rva) {
        return SL_ERROR_INVALID_IMAGE;
    }

    uint32_t consumed = 0U;
    while (consumed + SL_IMPORT_DESCRIPTOR_SIZE <= imports.size) {
        uint32_t cursor = imports.rva + consumed;
        uint32_t original_thunk = 0U;
        uint32_t timestamp = 0U;
        uint32_t forwarder_chain = 0U;
        uint32_t name_rva = 0U;
        uint32_t first_thunk = 0U;
        if (cursor < imports.rva ||
            read_rva_u32(image, cursor, &original_thunk) != SL_OK ||
            read_rva_u32(image, cursor + 4U, &timestamp) != SL_OK ||
            read_rva_u32(image, cursor + 8U, &forwarder_chain) != SL_OK ||
            read_rva_u32(image, cursor + 12U, &name_rva) != SL_OK ||
            read_rva_u32(image, cursor + 16U, &first_thunk) != SL_OK) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (original_thunk == 0U && timestamp == 0U && forwarder_chain == 0U &&
            name_rva == 0U && first_thunk == 0U) {
            return SL_OK;
        }
        const char *module_name = NULL;
        if (read_rva_string(image, name_rva, &module_name) != SL_OK) {
            return SL_ERROR_INVALID_IMAGE;
        }
        bool keep_visiting = true;
        sl_status status =
            visit_import_thunks(image, module_name, original_thunk, first_thunk,
                                callback, context, &keep_visiting);
        if (status != SL_OK) {
            return status;
        }
        if (!keep_visiting) {
            return SL_OK;
        }
        consumed += SL_IMPORT_DESCRIPTOR_SIZE;
    }
    return SL_ERROR_INVALID_IMAGE;
}

typedef struct {
    sl_pe_data_directory range;
    uint32_t ordinal_base;
    uint32_t function_count;
    uint32_t name_count;
    uint32_t functions_rva;
    uint32_t names_rva;
    uint32_t name_ordinals_rva;
} sl_export_directory;

static bool rva_table_fits(const sl_pe_image *image, uint32_t rva,
                           uint32_t count, size_t element_size) {
    size_t offset = 0U;
    size_t available = 0U;
    if (count == 0U) {
        return true;
    }
    if ((size_t)count > SIZE_MAX / element_size ||
        rva_file_window(image, rva, &offset, &available) != SL_OK) {
        return false;
    }
    return (size_t)count * element_size <= available;
}

static sl_status read_export_directory(const sl_pe_image *image,
                                       sl_export_directory *exports) {
    exports->range = image->directories[SL_PE_DIRECTORY_EXPORT];
    if (exports->range.rva == 0U || exports->range.size == 0U) {
        return SL_ERROR_EXPORT_NOT_FOUND;
    }
    if (exports->range.size < SL_EXPORT_DIRECTORY_SIZE ||
        exports->range.rva >= image->image_size ||
        exports->range.size > image->image_size - exports->range.rva ||
        read_rva_u32(image, exports->range.rva + 16U,
                     &exports->ordinal_base) != SL_OK ||
        read_rva_u32(image, exports->range.rva + 20U,
                     &exports->function_count) != SL_OK ||
        read_rva_u32(image, exports->range.rva + 24U,
                     &exports->name_count) != SL_OK ||
        read_rva_u32(image, exports->range.rva + 28U,
                     &exports->functions_rva) != SL_OK ||
        read_rva_u32(image, exports->range.rva + 32U,
                     &exports->names_rva) != SL_OK ||
        read_rva_u32(image, exports->range.rva + 36U,
                     &exports->name_ordinals_rva) != SL_OK) {
        return SL_ERROR_INVALID_IMAGE;
    }
    if (exports->function_count == 0U ||
        exports->name_count > exports->function_count ||
        !rva_table_fits(image, exports->functions_rva,
                        exports->function_count, 4U) ||
        !rva_table_fits(image, exports->names_rva, exports->name_count, 4U) ||
        !rva_table_fits(image, exports->name_ordinals_rva,
                        exports->name_count, 2U)) {
        return SL_ERROR_INVALID_IMAGE;
    }
    return SL_OK;
}

static sl_status build_export_result(const sl_pe_image *image,
                                     const sl_export_directory *exports,
                                     uint32_t function_index, const char *name,
                                     sl_pe_export *result) {
    if (function_index >= exports->function_count ||
        function_index > (UINT32_MAX - exports->functions_rva) / 4U) {
        return SL_ERROR_INVALID_IMAGE;
    }
    uint32_t function_rva = 0U;
    if (read_rva_u32(image, exports->functions_rva + function_index * 4U,
                     &function_rva) != SL_OK) {
        return SL_ERROR_INVALID_IMAGE;
    }
    if (function_rva == 0U) {
        return SL_ERROR_EXPORT_NOT_FOUND;
    }
    if (function_rva >= image->image_size ||
        function_index > UINT32_MAX - exports->ordinal_base) {
        return SL_ERROR_INVALID_IMAGE;
    }

    *result = (sl_pe_export){
        .name = name,
        .forwarder = NULL,
        .ordinal = exports->ordinal_base + function_index,
        .rva = function_rva,
        .is_forwarder = false,
    };
    uint32_t exports_end = exports->range.rva + exports->range.size;
    if (function_rva >= exports->range.rva && function_rva < exports_end) {
        if (read_rva_string(image, function_rva, &result->forwarder) != SL_OK) {
            return SL_ERROR_INVALID_IMAGE;
        }
        result->is_forwarder = true;
    }
    return SL_OK;
}

sl_status sl_pe_find_export_by_name(const sl_pe_image *image, const char *name,
                                    sl_pe_export *result) {
    if (image == NULL || name == NULL || result == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_export_directory exports;
    sl_status status = read_export_directory(image, &exports);
    if (status != SL_OK) {
        return status;
    }
    for (uint32_t index = 0U; index < exports.name_count; ++index) {
        uint32_t name_rva = 0U;
        uint16_t function_index = 0U;
        const char *candidate = NULL;
        if (index > (UINT32_MAX - exports.names_rva) / 4U ||
            index > (UINT32_MAX - exports.name_ordinals_rva) / 2U ||
            read_rva_u32(image, exports.names_rva + index * 4U, &name_rva) !=
                SL_OK ||
            read_rva_u16(image, exports.name_ordinals_rva + index * 2U,
                         &function_index) != SL_OK ||
            read_rva_string(image, name_rva, &candidate) != SL_OK) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (strcmp(candidate, name) == 0) {
            return build_export_result(image, &exports, function_index,
                                       candidate, result);
        }
    }
    return SL_ERROR_EXPORT_NOT_FOUND;
}

sl_status sl_pe_find_export_by_ordinal(const sl_pe_image *image,
                                       uint32_t ordinal,
                                       sl_pe_export *result) {
    if (image == NULL || result == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_export_directory exports;
    sl_status status = read_export_directory(image, &exports);
    if (status != SL_OK) {
        return status;
    }
    if (ordinal < exports.ordinal_base ||
        ordinal - exports.ordinal_base >= exports.function_count) {
        return SL_ERROR_EXPORT_NOT_FOUND;
    }
    return build_export_result(image, &exports, ordinal - exports.ordinal_base,
                               NULL, result);
}

const char *sl_pe_machine_name(uint16_t machine) {
    switch (machine) {
    case SL_PE_MACHINE_I386:
        return "x86";
    case SL_PE_MACHINE_AMD64:
        return "x86-64";
    default:
        return "unknown";
    }
}

const char *sl_pe_subsystem_name(uint16_t subsystem) {
    switch (subsystem) {
    case 2U:
        return "Windows GUI";
    case 3U:
        return "Windows console";
    case 9U:
        return "Windows CE GUI";
    case 10U:
        return "EFI application";
    default:
        return "unknown";
    }
}
