#include "sadlayer/pe.h"

#include <limits.h>
#include <string.h>

#define SL_DOS_E_LFANEW_OFFSET 0x3cU
#define SL_COFF_HEADER_SIZE 20U
#define SL_SECTION_HEADER_SIZE 40U
#define SL_IMPORT_DESCRIPTOR_SIZE 20U

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
