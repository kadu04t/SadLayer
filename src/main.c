#include "sadlayer/kernel32.h"
#include "sadlayer/loader.h"
#include "sadlayer/module.h"
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

typedef struct {
    const sl_module_registry *registry;
    size_t resolved_count;
    size_t unresolved_count;
    sl_status fatal_status;
} link_summary;

static void print_usage(FILE *stream, const char *program) {
    fprintf(stream,
            "SadLayer - experimental Windows compatibility layer\n\n"
            "Usage:\n"
            "  %s inspect <program.exe>\n"
            "  %s imports <program.exe>\n"
            "  %s resolve-export <library.dll> <name|#ordinal>\n"
            "  %s link-check <program.exe> <library.dll>\n"
            "  %s map <program.exe>\n"
            "  %s run <program.exe>\n",
            program, program, program, program, program, program);
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

static sl_status inspect_export(const sl_pe_image *image, const char *query) {
    sl_pe_export export;
    sl_status status = SL_OK;
    if (query[0] == '#') {
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(query + 1, &end, 10);
        if (query[1] == '\0' || end == NULL || *end != '\0' || errno != 0 ||
            value > UINT32_MAX) {
            return SL_ERROR_INVALID_ARGUMENT;
        }
        status = sl_pe_find_export_by_ordinal(image, (uint32_t)value, &export);
    } else {
        status = sl_pe_find_export_by_name(image, query, &export);
    }
    if (status != SL_OK) {
        return status;
    }

    printf("Export:       %s\n", export.name != NULL ? export.name : query);
    printf("Ordinal:      %" PRIu32 "\n", export.ordinal);
    printf("RVA:          0x%08" PRIx32 "\n", export.rva);
    if (export.is_forwarder) {
        printf("Forwarder:    %s\n", export.forwarder);
    } else {
        if (image->image_base > UINT64_MAX - export.rva) {
            return SL_ERROR_INVALID_IMAGE;
        }
        printf("Guest VA:     0x%016" PRIx64 "\n",
               image->image_base + export.rva);
    }
    return SL_OK;
}

static const char *path_basename(const char *path) {
    const char *basename = path;
    for (const char *cursor = path; *cursor != '\0'; ++cursor) {
        if (*cursor == '/' || *cursor == '\\') {
            basename = cursor + 1;
        }
    }
    return basename;
}

static bool print_link_result(const sl_pe_import_symbol *import,
                              void *context) {
    link_summary *summary = context;
    sl_resolved_symbol resolved;
    sl_status status =
        sl_module_registry_resolve(summary->registry, import, &resolved);
    if (status == SL_OK) {
        printf("  resolved   %s!", import->module_name);
        if (import->by_ordinal) {
            printf("#%u", import->ordinal);
        } else {
            printf("%s", import->symbol_name);
        }
        if (resolved.is_native) {
            printf(" -> %s[native] (0x%016" PRIx64 ")\n",
                   resolved.module->name, resolved.guest_address);
        } else {
            printf(" -> %s+0x%08" PRIx32 " (0x%016" PRIx64 ")\n",
                   resolved.module->name, resolved.export.rva,
                   resolved.guest_address);
        }
        ++summary->resolved_count;
        return true;
    }
    if (status == SL_ERROR_MODULE_NOT_FOUND ||
        status == SL_ERROR_EXPORT_NOT_FOUND) {
        printf("  unresolved %s!", import->module_name);
        if (import->by_ordinal) {
            printf("#%u", import->ordinal);
        } else {
            printf("%s", import->symbol_name);
        }
        printf(" (%s)\n", sl_status_string(status));
        ++summary->unresolved_count;
        return true;
    }
    summary->fatal_status = status;
    return false;
}

static sl_status check_link(const sl_pe_image *program_image,
                            const char *library_path) {
    owned_file library_file = {0};
    sl_pe_image library_image;
    sl_mapped_image program_mapped = {0};
    sl_mapped_image library_mapped = {0};
    sl_module_registry registry;
    sl_status status = read_entire_file(library_path, &library_file);
    if (status != SL_OK) {
        return status;
    }
    status = sl_pe_parse(
        (sl_byte_view){library_file.data, library_file.size}, &library_image);
    if (status == SL_OK) {
        status = sl_loader_map_image(program_image, &program_mapped);
    }
    if (status == SL_OK) {
        status = sl_loader_map_image(&library_image, &library_mapped);
    }

    const char *library_name = path_basename(library_path);
    if (status == SL_OK && library_name[0] == '\0') {
        status = SL_ERROR_INVALID_ARGUMENT;
    }
    if (status == SL_OK) {
        sl_module_registry_init(&registry);
        status = sl_module_registry_add(&registry, library_name, &library_image,
                                        &library_mapped);
    }
    if (status == SL_OK &&
        sl_module_registry_find(&registry, "KERNEL32.dll") == NULL) {
        status = sl_kernel32_register(&registry);
    }

    link_summary summary = {&registry, 0U, 0U, SL_OK};
    if (status == SL_OK) {
        printf("Link check with module %s:\n", library_name);
        status = sl_pe_for_each_import_symbol(program_image, print_link_result,
                                              &summary);
        if (status == SL_OK && summary.fatal_status != SL_OK) {
            status = summary.fatal_status;
        }
    }
    if (status == SL_OK && summary.unresolved_count == 0U) {
        size_t bound_count = 0U;
        status = sl_loader_bind_imports(
            program_image, &program_mapped, sl_module_registry_import_resolver,
            &registry, &bound_count);
        if (status == SL_OK) {
            printf("IAT binding complete: %zu symbols written.\n", bound_count);
        }
    } else if (status == SL_OK) {
        puts("IAT binding skipped: unresolved symbols leave the image unchanged.");
    }
    if (status == SL_OK) {
        printf("Link coverage: %zu resolved, %zu unresolved.\n",
               summary.resolved_count, summary.unresolved_count);
    }

    sl_loader_unmap_image(&library_mapped);
    sl_loader_unmap_image(&program_mapped);
    free(library_file.data);
    return status;
}

static sl_status map_image(const sl_pe_image *image) {
    sl_mapped_image mapped = {0};
    sl_status status = sl_loader_map_image_for_execution(image, &mapped);
    if (status == SL_OK) {
        status = sl_loader_finalize_image(image, &mapped);
    }
    if (status == SL_OK) {
        printf("Mapped %zu bytes at 0x%016" PRIx64
               " with final protections; guest entry point is 0x%016" PRIx64
               ".\n",
               mapped.size, mapped.load_base,
               mapped.load_base + mapped.entry_rva);
    }
    sl_loader_unmap_image(&mapped);
    return status;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        print_usage(stderr, argv[0]);
        return 2;
    }
    bool inspect = strcmp(argv[1], "inspect") == 0;
    bool list_imports = strcmp(argv[1], "imports") == 0;
    bool resolve_export = strcmp(argv[1], "resolve-export") == 0;
    bool link_check = strcmp(argv[1], "link-check") == 0;
    bool map = strcmp(argv[1], "map") == 0;
    bool run = strcmp(argv[1], "run") == 0;
    bool needs_two_paths = resolve_export || link_check;
    if ((!needs_two_paths && argc != 3) || (needs_two_paths && argc != 4) ||
        (!inspect && !list_imports && !resolve_export && !link_check && !map &&
         !run)) {
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
    } else if (status == SL_OK && resolve_export) {
        status = inspect_export(&image, argv[3]);
    } else if (status == SL_OK && link_check) {
        status = check_link(&image, argv[3]);
    } else if (status == SL_OK) {
        status = map_image(&image);
        if (status == SL_OK && run) {
            fputs("sadlayer: arbitrary guest handoff is disabled; the guarded "
                  "GS/TEB worker is the next execution gate.\n",
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
