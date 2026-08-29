#include "sadlayer/loader.h"
#include "sadlayer/pe.h"
#include "sadlayer/win32.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t size;
} owned_file;

typedef struct {
    size_t count;
    size_t bootstrap_count;
} import_summary;

typedef struct {
    size_t count;
    size_t named_count;
    size_t ordinal_count;
} symbol_summary;

static void print_usage(FILE *stream, const char *program) {
    fprintf(stream,
            "SadLayer - experimental Windows compatibility layer\n\n"
            "Usage:\n"
            "  %s inspect <program.exe>\n"
            "  %s imports <program.exe>\n"
            "  %s map <program.exe>\n"
            "  %s run <program.exe>\n",
            program, program, program, program);
}

static sl_status read_entire_file(const char *path, owned_file *file) {
    FILE *stream = fopen(path, "rb");
    long length = 0L;
    if (stream == NULL) {
        return SL_ERROR_IO;
    }
    if (fseek(stream, 0L, SEEK_END) != 0 || (length = ftell(stream)) < 0L ||
        fseek(stream, 0L, SEEK_SET) != 0) {
        (void)fclose(stream);
        return SL_ERROR_IO;
    }
    if ((unsigned long)length > SIZE_MAX) {
        (void)fclose(stream);
        return SL_ERROR_OUT_OF_MEMORY;
    }
    file->size = (size_t)length;
    file->data = malloc(file->size == 0U ? 1U : file->size);
    if (file->data == NULL) {
        (void)fclose(stream);
        return SL_ERROR_OUT_OF_MEMORY;
    }
    if (file->size != 0U && fread(file->data, 1U, file->size, stream) != file->size) {
        free(file->data);
        memset(file, 0, sizeof(*file));
        (void)fclose(stream);
        return SL_ERROR_IO;
    }
    if (fclose(stream) != 0) {
        free(file->data);
        memset(file, 0, sizeof(*file));
        return SL_ERROR_IO;
    }
    return SL_OK;
}

static bool print_import(const char *module_name, void *context) {
    import_summary *summary = context;
    bool bootstrap = sl_win32_is_bootstrap_module(module_name);
    printf("    %-28s %s\n", module_name,
           bootstrap ? "bootstrap target" : "not classified");
    ++summary->count;
    if (bootstrap) {
        ++summary->bootstrap_count;
    }
    return true;
}

static sl_status inspect_image(const sl_pe_image *image) {
    printf("Format:       PE32%s\n", image->is_pe32_plus ? "+" : "");
    printf("Machine:      %s (0x%04x)\n", sl_pe_machine_name(image->machine),
           image->machine);
    printf("Subsystem:    %s (%u)\n", sl_pe_subsystem_name(image->subsystem),
           image->subsystem);
    printf("Image base:   0x%016" PRIx64 "\n", image->image_base);
    printf("Entry RVA:    0x%08" PRIx32 "\n", image->entry_rva);
    printf("Image size:   0x%08" PRIx32 "\n", image->image_size);
    printf("Sections:     %u\n", image->section_count);
    for (uint16_t index = 0U; index < image->section_count; ++index) {
        const sl_pe_section *section = &image->sections[index];
        printf("  %-8s RVA=0x%08" PRIx32 " virtual=0x%08" PRIx32
               " raw=0x%08" PRIx32 "\n",
               section->name, section->virtual_address, section->virtual_size,
               section->raw_size);
    }

    puts("Imports:");
    import_summary summary = {0U, 0U};
    sl_status status = sl_pe_for_each_import(image, print_import, &summary);
    if (status != SL_OK) {
        return status;
    }
    if (summary.count == 0U) {
        puts("    (none)");
    } else {
        printf("Import coverage: %zu/%zu modules classified for bootstrap\n",
               summary.bootstrap_count, summary.count);
    }
    return SL_OK;
}

static bool print_import_symbol(const sl_pe_import_symbol *symbol,
                                void *context) {
    symbol_summary *summary = context;
    printf("  %s!", symbol->module_name);
    if (symbol->by_ordinal) {
        printf("#%u", symbol->ordinal);
        ++summary->ordinal_count;
    } else {
        printf("%s (hint %u)", symbol->symbol_name, symbol->hint);
        ++summary->named_count;
    }
    printf(" -> IAT RVA 0x%08" PRIx32 "\n", symbol->iat_rva);
    ++summary->count;
    return true;
}

static sl_status inspect_import_symbols(const sl_pe_image *image) {
    symbol_summary summary = {0U, 0U, 0U};
    puts("Imported symbols:");
    sl_status status =
        sl_pe_for_each_import_symbol(image, print_import_symbol, &summary);
    if (status != SL_OK) {
        return status;
    }
    printf("Total: %zu symbols (%zu by name, %zu by ordinal)\n", summary.count,
           summary.named_count, summary.ordinal_count);
    return SL_OK;
}

static sl_status map_image(const sl_pe_image *image) {
    sl_mapped_image mapped = {0};
    sl_status status = sl_loader_map_image(image, &mapped);
    if (status == SL_OK) {
        printf("Mapped %zu bytes; guest entry point is base + 0x%08" PRIx32
               ".\n",
               mapped.size, mapped.entry_rva);
    }
    sl_loader_unmap_image(&mapped);
    return status;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        print_usage(stderr, argv[0]);
        return 2;
    }
    bool inspect = strcmp(argv[1], "inspect") == 0;
    bool list_imports = strcmp(argv[1], "imports") == 0;
    bool map = strcmp(argv[1], "map") == 0;
    bool run = strcmp(argv[1], "run") == 0;
    if (!inspect && !list_imports && !map && !run) {
        print_usage(stderr, argv[0]);
        return 2;
    }

    owned_file file = {0};
    sl_status status = read_entire_file(argv[2], &file);
    if (status != SL_OK) {
        fprintf(stderr, "sadlayer: cannot read '%s': %s (%s)\n", argv[2],
                sl_status_string(status), strerror(errno));
        return 1;
    }
    sl_pe_image image;
    status = sl_pe_parse((sl_byte_view){file.data, file.size}, &image);
    if (status == SL_OK && inspect) {
        status = inspect_image(&image);
    } else if (status == SL_OK && list_imports) {
        status = inspect_import_symbols(&image);
    } else if (status == SL_OK) {
        status = map_image(&image);
        if (status == SL_OK && run) {
            fputs("sadlayer: execution handoff is the next milestone; image and "
                  "entry point are valid.\n",
                  stderr);
            status = SL_ERROR_NOT_IMPLEMENTED;
        }
    }
    free(file.data);
    if (status != SL_OK) {
        fprintf(stderr, "sadlayer: %s\n", sl_status_string(status));
        return status == SL_ERROR_NOT_IMPLEMENTED ? 3 : 1;
    }
    return 0;
}
