#ifndef SADLAYER_PE_H
#define SADLAYER_PE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"

#define SL_PE_MAX_SECTIONS 96U
#define SL_PE_DATA_DIRECTORY_COUNT 16U
#define SL_PE_DIRECTORY_IMPORT 1U
#define SL_PE_MACHINE_I386 0x014cU
#define SL_PE_MACHINE_AMD64 0x8664U

typedef struct {
    const uint8_t *data;
    size_t size;
} sl_byte_view;

typedef struct {
    uint32_t rva;
    uint32_t size;
} sl_pe_data_directory;

typedef struct {
    char name[9];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t characteristics;
} sl_pe_section;

typedef struct {
    sl_byte_view file;
    uint16_t machine;
    uint16_t section_count;
    bool is_pe32_plus;
    uint16_t subsystem;
    uint64_t image_base;
    uint32_t entry_rva;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint32_t image_size;
    uint32_t headers_size;
    sl_pe_data_directory directories[SL_PE_DATA_DIRECTORY_COUNT];
    sl_pe_section sections[SL_PE_MAX_SECTIONS];
} sl_pe_image;

typedef bool (*sl_pe_import_callback)(const char *module_name, void *context);

sl_status sl_pe_parse(sl_byte_view file, sl_pe_image *image);
sl_status sl_pe_rva_to_file_offset(const sl_pe_image *image, uint32_t rva,
                                   size_t *offset);
sl_status sl_pe_for_each_import(const sl_pe_image *image,
                                sl_pe_import_callback callback, void *context);
const char *sl_pe_machine_name(uint16_t machine);
const char *sl_pe_subsystem_name(uint16_t subsystem);

#endif

