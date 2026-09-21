#include "sadlayer/win64_unwind.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SL_WIN64_RUNTIME_FUNCTION_SIZE 12U
#define SL_WIN64_MAX_CHAIN_DEPTH 32U

enum {
    SL_UWOP_PUSH_NONVOL = 0,
    SL_UWOP_ALLOC_LARGE = 1,
    SL_UWOP_ALLOC_SMALL = 2,
    SL_UWOP_SET_FPREG = 3,
    SL_UWOP_SAVE_NONVOL = 4,
    SL_UWOP_SAVE_NONVOL_FAR = 5,
    SL_UWOP_EPILOG = 6,
    SL_UWOP_SAVE_XMM128 = 8,
    SL_UWOP_SAVE_XMM128_FAR = 9,
    SL_UWOP_PUSH_MACHFRAME = 10,
};

_Static_assert(sizeof(sl_win64_m128a) == 16U,
               "Windows M128A layout changed");
_Static_assert(_Alignof(sl_win64_m128a) == 16U,
               "Windows M128A alignment changed");
_Static_assert(sizeof(sl_win64_xmm_save_area32) == 512U,
               "Windows XMM_SAVE_AREA32 layout changed");
_Static_assert(offsetof(sl_win64_context, context_flags) == 0x30U,
               "Windows CONTEXT flags offset changed");
_Static_assert(offsetof(sl_win64_context, rax) == 0x78U,
               "Windows CONTEXT RAX offset changed");
_Static_assert(offsetof(sl_win64_context, rsp) == 0x98U,
               "Windows CONTEXT RSP offset changed");
_Static_assert(offsetof(sl_win64_context, rip) == 0xf8U,
               "Windows CONTEXT RIP offset changed");
_Static_assert(offsetof(sl_win64_context, flt_save) == 0x100U,
               "Windows CONTEXT floating-state offset changed");
_Static_assert(sizeof(sl_win64_context) == 0x4d0U,
               "Windows AMD64 CONTEXT layout changed");
_Static_assert(_Alignof(sl_win64_context) == 16U,
               "Windows AMD64 CONTEXT alignment changed");
_Static_assert(sizeof(sl_win64_exception_record) == 0x98U,
               "Windows EXCEPTION_RECORD layout changed");
_Static_assert(offsetof(sl_win64_exception_record, exception_information) ==
                   0x20U,
               "Windows EXCEPTION_RECORD information offset changed");
_Static_assert(sizeof(sl_win64_exception_pointers) == 16U,
               "Windows EXCEPTION_POINTERS layout changed");
_Static_assert(sizeof(sl_win64_runtime_function) ==
                   SL_WIN64_RUNTIME_FUNCTION_SIZE,
               "Windows RUNTIME_FUNCTION layout changed");
_Static_assert(sizeof(sl_win64_nonvolatile_context_pointers) == 256U,
               "Windows context-pointer layout changed");
_Static_assert(sizeof(sl_win64_unwind_history_table) == 0xd8U,
               "Windows UNWIND_HISTORY_TABLE layout changed");
_Static_assert(offsetof(sl_win64_dispatcher_context, history_table) == 0x40U,
               "Windows DISPATCHER_CONTEXT history offset changed");
_Static_assert(sizeof(sl_win64_dispatcher_context) == 0x50U,
               "Windows DISPATCHER_CONTEXT layout changed");

typedef struct sl_handler_unwind_link sl_handler_unwind_link;

struct sl_handler_unwind_link {
    sl_handler_unwind_link *previous;
    sl_win64_context guest_unwind_origin;
};

static _Thread_local sl_handler_unwind_link *sl_active_handler_unwind_link;

int32_t sl_win64_execute_handler(
    sl_win64_exception_routine language_handler,
    sl_win64_exception_record *exception_record, uint64_t establisher_frame,
    sl_win64_context *handler_context,
    sl_win64_dispatcher_context *dispatcher_context,
    const sl_win64_context *guest_unwind_origin) {
    if (language_handler == NULL || exception_record == NULL ||
        handler_context == NULL || dispatcher_context == NULL ||
        guest_unwind_origin == NULL) {
        return INT32_MIN;
    }
    sl_handler_unwind_link link = {
        .previous = sl_active_handler_unwind_link,
        .guest_unwind_origin = *guest_unwind_origin,
    };
    sl_active_handler_unwind_link = &link;
    int32_t disposition = language_handler(
        exception_record, establisher_frame, handler_context,
        dispatcher_context);
    if (sl_active_handler_unwind_link == &link) {
        sl_active_handler_unwind_link = link.previous;
    } else {
        /* A consumed link must not leave pointers into an abandoned stack. */
        sl_active_handler_unwind_link = NULL;
    }
    return disposition;
}

bool sl_win64_take_handler_unwind_origin(sl_win64_context *context_record) {
    if (context_record == NULL || sl_active_handler_unwind_link == NULL) {
        return false;
    }
    *context_record = sl_active_handler_unwind_link->guest_unwind_origin;
    /* RtlUnwindEx will abandon every host callback frame above this link. */
    sl_active_handler_unwind_link = NULL;
    return true;
}

static bool add_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (right > UINT64_MAX - left) {
        return false;
    }
    *result = left + right;
    return true;
}

static uint16_t load_u16(const void *source) {
    uint16_t value = 0U;
    memcpy(&value, source, sizeof(value));
    return value;
}

static uint32_t load_u32(const void *source) {
    uint32_t value = 0U;
    memcpy(&value, source, sizeof(value));
    return value;
}

static uint64_t load_u64(const void *source) {
    uint64_t value = 0U;
    memcpy(&value, source, sizeof(value));
    return value;
}

static bool module_window(const sl_loaded_module *module, uint32_t rva,
                          size_t size, const uint8_t **bytes) {
    if (module == NULL || module->kind != SL_MODULE_PE ||
        module->image == NULL || module->mapped == NULL ||
        module->mapped->bytes == NULL || module->mapped->size !=
                                             module->image->image_size ||
        (size_t)rva > module->mapped->size ||
        size > module->mapped->size - (size_t)rva) {
        return false;
    }
    *bytes = module->mapped->bytes + (size_t)rva;
    return true;
}

static bool runtime_function_is_valid(const sl_loaded_module *module,
                                      const sl_win64_runtime_function *entry) {
    return module->image->image_size >= 4U &&
           entry->begin_address < entry->end_address &&
           entry->end_address <= module->image->image_size &&
           entry->unwind_data != 0U &&
           (entry->unwind_data & UINT32_C(3)) == 0U &&
           entry->unwind_data <= module->image->image_size - 4U;
}

static bool exception_directory(
    const sl_loaded_module *module, const uint8_t **table,
    size_t *entry_count) {
    if (module == NULL || module->kind != SL_MODULE_PE ||
        module->image == NULL || !module->image->is_pe32_plus ||
        module->image->machine != SL_PE_MACHINE_AMD64) {
        return false;
    }
    sl_pe_data_directory directory =
        module->image->directories[SL_PE_DIRECTORY_EXCEPTION];
    if (directory.rva == 0U || directory.size == 0U ||
        directory.size % SL_WIN64_RUNTIME_FUNCTION_SIZE != 0U ||
        !module_window(module, directory.rva, (size_t)directory.size,
                       table)) {
        return false;
    }
    *entry_count = (size_t)directory.size / SL_WIN64_RUNTIME_FUNCTION_SIZE;
    return *entry_count != 0U;
}

static sl_win64_runtime_function read_runtime_function(
    const uint8_t *source) {
    sl_win64_runtime_function entry;
    entry.begin_address = load_u32(source);
    entry.end_address = load_u32(source + 4U);
    entry.unwind_data = load_u32(source + 8U);
    return entry;
}

sl_status sl_win64_lookup_function_entry(
    const sl_module_registry *registry, uint64_t control_pc,
    uint64_t *image_base, const sl_win64_runtime_function **function_entry,
    const sl_loaded_module **module_out) {
    if (image_base == NULL || function_entry == NULL || module_out == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    const sl_loaded_module *module = NULL;
    if (registry == NULL ||
        sl_module_registry_resolve_address(registry, control_pc, &module) !=
            SL_OK ||
        module == NULL || module->kind != SL_MODULE_PE ||
        module->mapped == NULL || control_pc < module->mapped->load_base) {
        return SL_ERROR_ADDRESS_OUT_OF_RANGE;
    }

    const uint8_t *table = NULL;
    size_t entry_count = 0U;
    if (!exception_directory(module, &table, &entry_count)) {
        return SL_ERROR_ADDRESS_OUT_OF_RANGE;
    }
    uint64_t relative_pc = control_pc - module->mapped->load_base;
    if (relative_pc > UINT32_MAX) {
        return SL_ERROR_ADDRESS_OUT_OF_RANGE;
    }

    const sl_win64_runtime_function *match = NULL;
    uint32_t previous_end = 0U;
    for (size_t index = 0U; index < entry_count; ++index) {
        const uint8_t *entry_bytes =
            table + index * SL_WIN64_RUNTIME_FUNCTION_SIZE;
        sl_win64_runtime_function entry =
            read_runtime_function(entry_bytes);
        if (!runtime_function_is_valid(module, &entry) ||
            (index != 0U && entry.begin_address < previous_end)) {
            return SL_ERROR_INVALID_IMAGE;
        }
        previous_end = entry.end_address;
        if ((uint64_t)entry.begin_address <= relative_pc &&
            relative_pc < (uint64_t)entry.end_address) {
            match = (const sl_win64_runtime_function *)(const void *)entry_bytes;
        }
    }
    if (match == NULL) {
        return SL_ERROR_ADDRESS_OUT_OF_RANGE;
    }

    *image_base = module->mapped->load_base;
    *function_entry = match;
    *module_out = module;
    return SL_OK;
}

static uint64_t *integer_register(sl_win64_context *context,
                                  uint8_t number) {
    switch (number) {
    case 0U:
        return &context->rax;
    case 1U:
        return &context->rcx;
    case 2U:
        return &context->rdx;
    case 3U:
        return &context->rbx;
    case 4U:
        return &context->rsp;
    case 5U:
        return &context->rbp;
    case 6U:
        return &context->rsi;
    case 7U:
        return &context->rdi;
    case 8U:
        return &context->r8;
    case 9U:
        return &context->r9;
    case 10U:
        return &context->r10;
    case 11U:
        return &context->r11;
    case 12U:
        return &context->r12;
    case 13U:
        return &context->r13;
    case 14U:
        return &context->r14;
    case 15U:
        return &context->r15;
    default:
        return NULL;
    }
}

static bool is_nonvolatile_integer_register(uint8_t number) {
    return number == 3U || number == 5U || number == 6U || number == 7U ||
           number >= 12U;
}

static bool is_nonvolatile_xmm_register(uint8_t number) {
    return number >= 6U && number <= 15U;
}

static size_t unwind_operation_slots(uint8_t version, uint8_t operation,
                                     uint8_t info) {
    switch (operation) {
    case SL_UWOP_PUSH_NONVOL:
    case SL_UWOP_ALLOC_SMALL:
    case SL_UWOP_SET_FPREG:
    case SL_UWOP_PUSH_MACHFRAME:
        return 1U;
    case SL_UWOP_ALLOC_LARGE:
        return info == 0U ? 2U : info == 1U ? 3U : 0U;
    case SL_UWOP_SAVE_NONVOL:
    case SL_UWOP_SAVE_XMM128:
        return 2U;
    case SL_UWOP_SAVE_NONVOL_FAR:
    case SL_UWOP_SAVE_XMM128_FAR:
        return 3U;
    case SL_UWOP_EPILOG:
        return version == 2U ? 2U : 0U;
    default:
        return 0U;
    }
}

static bool unwind_operation_is_valid(uint8_t operation, uint8_t info) {
    switch (operation) {
    case SL_UWOP_PUSH_NONVOL:
    case SL_UWOP_SAVE_NONVOL:
    case SL_UWOP_SAVE_NONVOL_FAR:
        return is_nonvolatile_integer_register(info);
    case SL_UWOP_ALLOC_LARGE:
        return info <= 1U;
    case SL_UWOP_ALLOC_SMALL:
        return true;
    case SL_UWOP_SET_FPREG:
        return true;
    case SL_UWOP_SAVE_XMM128:
    case SL_UWOP_SAVE_XMM128_FAR:
        return is_nonvolatile_xmm_register(info);
    case SL_UWOP_PUSH_MACHFRAME:
        return info <= 1U;
    default:
        return false;
    }
}

static bool stack_range_fits(const sl_win64_stack_bounds *stack,
                             uint64_t address, size_t size) {
    return stack != NULL && stack->limit < stack->base &&
           address >= stack->limit && address <= stack->base &&
           (uint64_t)size <= stack->base - address &&
           address <= UINTPTR_MAX;
}

static bool stack_frame_is_valid(const sl_win64_stack_bounds *stack,
                                 uint64_t address) {
    return stack != NULL && stack->limit < stack->base &&
           address >= stack->limit && address < stack->base &&
           (address & UINT64_C(7)) == 0U && address <= UINTPTR_MAX;
}

static bool read_stack_u64(const sl_win64_stack_bounds *stack,
                           uint64_t address, uint64_t *value) {
    if (!stack_range_fits(stack, address, sizeof(*value))) {
        return false;
    }
    *value = load_u64((const void *)(uintptr_t)address);
    return true;
}

static bool read_stack_m128(const sl_win64_stack_bounds *stack,
                            uint64_t address, sl_win64_m128a *value) {
    if (!stack_range_fits(stack, address, sizeof(*value))) {
        return false;
    }
    memcpy(value, (const void *)(uintptr_t)address, sizeof(*value));
    return true;
}

static bool add_stack_offset(uint64_t base, uint64_t offset,
                             uint64_t *address) {
    return add_u64(base, offset, address) && *address <= UINTPTR_MAX;
}

typedef struct {
    bool present;
    bool implicit_at_end;
    uint8_t size;
    uint8_t code_slots;
} sl_v2_epilogue_info;

/*
 * Version 2 stores an even-sized prefix of epilogue descriptors before the
 * ordinary prologue unwind operations.  The first descriptor carries the
 * common epilogue size and a flag for an implicit epilogue at FunctionEnd;
 * each following descriptor is one 12-bit distance back from FunctionEnd.
 * A zero-distance descriptor is counted padding, not an epilogue.
 *
 * Windows treats UWOP_EPILOG as a two-slot operation while skipping this
 * prefix during prologue unwinding.  Decode every individual descriptor here
 * first so malformed entries cannot hide in the second slot of such a pair.
 */
static bool parse_v2_epilogue_prefix(const uint8_t *codes,
                                     uint8_t code_count, uint8_t version,
                                     sl_v2_epilogue_info *epilogues) {
    *epilogues = (sl_v2_epilogue_info){0};
    if (version != 2U || code_count == 0U ||
        (codes[1] & UINT8_C(0x0f)) != SL_UWOP_EPILOG) {
        return true;
    }

    uint8_t size = codes[0];
    uint8_t flags = codes[1] >> 4U;
    if (size == 0U || (flags & ~UINT8_C(1)) != 0U) {
        return false;
    }

    bool has_epilogue = (flags & UINT8_C(1)) != 0U;
    size_t index = 1U;
    while (index < (size_t)code_count) {
        const uint8_t *descriptor = codes + index * 2U;
        if ((descriptor[1] & UINT8_C(0x0f)) != SL_UWOP_EPILOG) {
            break;
        }
        uint16_t distance =
            (uint16_t)descriptor[0] |
            (uint16_t)((uint16_t)(descriptor[1] >> 4U) << 8U);
        ++index;
        if (distance == 0U) {
            break;
        }
        has_epilogue = true;
    }

    /* The native prologue walker skips the descriptor prefix in pairs. */
    if (!has_epilogue || (index & 1U) != 0U ||
        (index < (size_t)code_count &&
         (codes[index * 2U + 1U] & UINT8_C(0x0f)) == SL_UWOP_EPILOG)) {
        return false;
    }

    epilogues->present = true;
    epilogues->implicit_at_end = (flags & UINT8_C(1)) != 0U;
    epilogues->size = size;
    epilogues->code_slots = (uint8_t)index;
    return true;
}

static bool validate_unwind_codes(const uint8_t *codes, uint8_t code_count,
                                  uint8_t version,
                                  uint8_t prologue_size,
                                  uint8_t frame_register,
                                  uint8_t frame_offset,
                                  sl_v2_epilogue_info *epilogues,
                                  bool *has_frame_setup) {
    if (!parse_v2_epilogue_prefix(codes, code_count, version, epilogues)) {
        return false;
    }
    size_t index = epilogues->code_slots;
    uint8_t previous_offset = UINT8_MAX;
    bool found_frame_setup = false;
    while (index < (size_t)code_count) {
        uint8_t code_offset = codes[index * 2U];
        uint8_t operation_and_info = codes[index * 2U + 1U];
        uint8_t operation = operation_and_info & UINT8_C(0x0f);
        uint8_t info = operation_and_info >> 4U;
        size_t slots = unwind_operation_slots(version, operation, info);
        if (operation == SL_UWOP_EPILOG || code_offset > prologue_size ||
            code_offset > previous_offset || slots == 0U ||
            slots > (size_t)code_count - index ||
            !unwind_operation_is_valid(operation, info)) {
            return false;
        }
        if (operation == SL_UWOP_SET_FPREG) {
            if (frame_register == 0U || found_frame_setup ||
                (info != 0U && info != frame_offset)) {
                return false;
            }
            found_frame_setup = true;
        }
        if (operation == SL_UWOP_SAVE_NONVOL_FAR &&
            (load_u32(codes + (index + 1U) * 2U) & UINT32_C(7)) != 0U) {
            return false;
        }
        if (operation == SL_UWOP_SAVE_XMM128_FAR &&
            (load_u32(codes + (index + 1U) * 2U) & UINT32_C(15)) != 0U) {
            return false;
        }
        previous_offset = code_offset;
        index += slots;
    }
    *has_frame_setup = found_frame_setup;
    return true;
}

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint8_t prologue_size;
    uint8_t code_count;
    uint8_t frame_register;
    uint8_t frame_offset;
    const uint8_t *codes;
    size_t record_size;
    uint32_t trailer_rva;
    bool has_frame_setup;
    sl_v2_epilogue_info epilogues;
} sl_unwind_record_view;

static bool read_unwind_record(const sl_loaded_module *module,
                               uint32_t unwind_rva,
                               sl_unwind_record_view *view) {
    const uint8_t *header = NULL;
    if ((unwind_rva & UINT32_C(3)) != 0U ||
        !module_window(module, unwind_rva, 4U, &header)) {
        return false;
    }
    uint8_t version = header[0] & UINT8_C(7);
    uint8_t flags = header[0] >> 3U;
    uint8_t prologue_size = header[1];
    uint8_t code_count = header[2];
    uint8_t frame_register = header[3] & UINT8_C(0x0f);
    uint8_t frame_offset = header[3] >> 4U;
    size_t padded_code_count = ((size_t)code_count + 1U) & ~(size_t)1U;
    size_t record_size = 4U + padded_code_count * 2U;
    const uint8_t *record = NULL;
    if ((version != 1U && version != 2U) ||
        (flags & ~(SL_WIN64_UNW_FLAG_EHANDLER |
                   SL_WIN64_UNW_FLAG_UHANDLER |
                   SL_WIN64_UNW_FLAG_CHAININFO)) != 0U ||
        ((flags & SL_WIN64_UNW_FLAG_CHAININFO) != 0U &&
         (flags & (SL_WIN64_UNW_FLAG_EHANDLER |
                   SL_WIN64_UNW_FLAG_UHANDLER)) != 0U) ||
        (frame_register != 0U &&
         !is_nonvolatile_integer_register(frame_register)) ||
        (frame_register == 0U && frame_offset != 0U) ||
        !module_window(module, unwind_rva, record_size, &record)) {
        return false;
    }
    bool has_frame_setup = false;
    sl_v2_epilogue_info epilogues;
    const uint8_t *codes = record + 4U;
    if (!validate_unwind_codes(codes, code_count, version, prologue_size,
                               frame_register, frame_offset,
                               &epilogues,
                               &has_frame_setup)) {
        return false;
    }
    size_t trailer_rva = (size_t)unwind_rva + record_size;
    if (trailer_rva > UINT32_MAX) {
        return false;
    }
    view->version = version;
    view->flags = flags;
    view->prologue_size = prologue_size;
    view->code_count = code_count;
    view->frame_register = frame_register;
    view->frame_offset = frame_offset;
    view->codes = codes;
    view->record_size = record_size;
    view->trailer_rva = (uint32_t)trailer_rva;
    view->has_frame_setup = has_frame_setup;
    view->epilogues = epilogues;
    return true;
}

static bool validate_v2_epilogue_ranges(
    const sl_unwind_record_view *record,
    const sl_win64_runtime_function *entry) {
    uint32_t function_size = entry->end_address - entry->begin_address;
    if ((uint32_t)record->prologue_size > function_size) {
        return false;
    }
    if (!record->epilogues.present) {
        return true;
    }

    if ((uint32_t)record->epilogues.size > function_size ||
        (record->epilogues.implicit_at_end &&
         function_size - (uint32_t)record->epilogues.size <
             (uint32_t)record->prologue_size)) {
        return false;
    }
    for (size_t index = 1U;
         index < (size_t)record->epilogues.code_slots; ++index) {
        const uint8_t *descriptor = record->codes + index * 2U;
        uint32_t distance =
            (uint32_t)descriptor[0] |
            ((uint32_t)(descriptor[1] >> 4U) << 8U);
        if (distance != 0U &&
            (distance < (uint32_t)record->epilogues.size ||
             distance > function_size ||
             function_size - distance <
                 (uint32_t)record->prologue_size)) {
            return false;
        }
    }
    return true;
}

static bool find_v2_epilogue(const sl_unwind_record_view *record,
                             const sl_win64_runtime_function *entry,
                             uint32_t relative_pc,
                             uint32_t *epilogue_offset) {
    if (!record->epilogues.present) {
        return false;
    }

    uint32_t size = record->epilogues.size;
    if (record->epilogues.implicit_at_end) {
        uint32_t start = entry->end_address - size;
        if (relative_pc >= start && relative_pc - start < size) {
            *epilogue_offset = relative_pc - start;
            return true;
        }
    }
    for (size_t index = 1U;
         index < (size_t)record->epilogues.code_slots; ++index) {
        const uint8_t *descriptor = record->codes + index * 2U;
        uint32_t distance =
            (uint32_t)descriptor[0] |
            ((uint32_t)(descriptor[1] >> 4U) << 8U);
        if (distance == 0U) {
            break;
        }
        uint32_t start = entry->end_address - distance;
        if (relative_pc >= start && relative_pc - start < size) {
            *epilogue_offset = relative_pc - start;
            return true;
        }
    }
    return false;
}

static sl_status validate_unwind_chain(
    const sl_loaded_module *module,
    const sl_win64_runtime_function *first_entry,
    sl_unwind_record_view *first_record) {
    sl_win64_runtime_function current_entry = *first_entry;
    uint32_t unwind_rva = current_entry.unwind_data;
    uint8_t expected_frame_register = 0U;
    uint8_t expected_frame_offset = 0U;
    for (size_t depth = 0U; depth < SL_WIN64_MAX_CHAIN_DEPTH; ++depth) {
        sl_unwind_record_view record;
        if (!read_unwind_record(module, unwind_rva, &record)) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (!validate_v2_epilogue_ranges(&record, &current_entry)) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if (depth == 0U) {
            *first_record = record;
            expected_frame_register = record.frame_register;
            expected_frame_offset = record.frame_offset;
        } else if (record.frame_register != expected_frame_register ||
                   record.frame_offset != expected_frame_offset) {
            return SL_ERROR_INVALID_IMAGE;
        }

        if ((record.flags & SL_WIN64_UNW_FLAG_CHAININFO) != 0U) {
            const uint8_t *chain_bytes = NULL;
            if (!module_window(module, record.trailer_rva,
                               SL_WIN64_RUNTIME_FUNCTION_SIZE,
                               &chain_bytes)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            sl_win64_runtime_function chained =
                read_runtime_function(chain_bytes);
            if (!runtime_function_is_valid(module, &chained)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            current_entry = chained;
            unwind_rva = chained.unwind_data;
            continue;
        }

        if (record.frame_register != 0U && !record.has_frame_setup) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if ((record.flags & (SL_WIN64_UNW_FLAG_EHANDLER |
                             SL_WIN64_UNW_FLAG_UHANDLER)) != 0U) {
            const uint8_t *handler_bytes = NULL;
            if (!module_window(module, record.trailer_rva, 4U,
                               &handler_bytes)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            uint32_t handler_rva = load_u32(handler_bytes);
            if (handler_rva == 0U || handler_rva >= module->mapped->size) {
                return SL_ERROR_INVALID_IMAGE;
            }
        }
        return SL_OK;
    }
    return SL_ERROR_FORWARDER_LIMIT;
}

static bool frame_register_is_established(const uint8_t *codes,
                                          uint8_t code_count,
                                          uint8_t version,
                                          bool in_prologue,
                                          uint8_t prologue_offset) {
    size_t index = 0U;
    while (index < (size_t)code_count) {
        uint8_t code_offset = codes[index * 2U];
        uint8_t operation_and_info = codes[index * 2U + 1U];
        uint8_t operation = operation_and_info & UINT8_C(0x0f);
        uint8_t info = operation_and_info >> 4U;
        if (operation == SL_UWOP_SET_FPREG) {
            return !in_prologue || code_offset <= prologue_offset;
        }
        index += unwind_operation_slots(version, operation, info);
    }
    return false;
}

static bool restore_integer(
    sl_win64_context *context,
    sl_win64_nonvolatile_context_pointers *context_pointers,
    const sl_win64_stack_bounds *stack, uint8_t register_number,
    uint64_t address) {
    uint64_t *destination = integer_register(context, register_number);
    if (destination == NULL ||
        !read_stack_u64(stack, address, destination)) {
        return false;
    }
    if (context_pointers != NULL) {
        context_pointers->integer_context[register_number] =
            (uint64_t *)(uintptr_t)address;
    }
    return true;
}

static bool restore_xmm(
    sl_win64_context *context,
    sl_win64_nonvolatile_context_pointers *context_pointers,
    const sl_win64_stack_bounds *stack, uint8_t register_number,
    uint64_t address) {
    sl_win64_m128a *destination =
        &context->flt_save.xmm_registers[register_number];
    if (!read_stack_m128(stack, address, destination)) {
        return false;
    }
    if (context_pointers != NULL) {
        context_pointers->floating_context[register_number] =
            (sl_win64_m128a *)(uintptr_t)address;
    }
    return true;
}

static bool apply_unwind_codes(
    const uint8_t *codes, uint8_t code_count, uint8_t version,
    bool in_prologue,
    uint8_t prologue_offset, uint64_t frame_base, sl_win64_context *context,
    const sl_win64_stack_bounds *stack,
    sl_win64_nonvolatile_context_pointers *context_pointers,
    bool *machine_frame) {
    size_t index = 0U;
    while (index < (size_t)code_count) {
        uint8_t code_offset = codes[index * 2U];
        uint8_t operation_and_info = codes[index * 2U + 1U];
        uint8_t operation = operation_and_info & UINT8_C(0x0f);
        uint8_t info = operation_and_info >> 4U;
        size_t slots = unwind_operation_slots(version, operation, info);
        if (in_prologue && code_offset > prologue_offset) {
            index += slots;
            continue;
        }

        uint64_t offset = 0U;
        uint64_t address = 0U;
        switch (operation) {
        case SL_UWOP_PUSH_NONVOL:
            address = context->rsp;
            if (!restore_integer(context, context_pointers, stack, info,
                                 address) ||
                !add_u64(context->rsp, 8U, &context->rsp)) {
                return false;
            }
            break;
        case SL_UWOP_ALLOC_LARGE:
            if (info == 0U) {
                offset = (uint64_t)load_u16(codes + (index + 1U) * 2U) * 8U;
            } else {
                offset = (uint64_t)load_u32(codes + (index + 1U) * 2U);
            }
            if (offset == 0U || (offset & UINT64_C(7)) != 0U ||
                !add_u64(context->rsp, offset, &context->rsp)) {
                return false;
            }
            break;
        case SL_UWOP_ALLOC_SMALL:
            offset = (uint64_t)info * 8U + 8U;
            if (!add_u64(context->rsp, offset, &context->rsp)) {
                return false;
            }
            break;
        case SL_UWOP_SET_FPREG:
            context->rsp = frame_base;
            break;
        case SL_UWOP_SAVE_NONVOL:
            offset = (uint64_t)load_u16(codes + (index + 1U) * 2U) * 8U;
            if (!add_stack_offset(frame_base, offset, &address) ||
                !restore_integer(context, context_pointers, stack, info,
                                 address)) {
                return false;
            }
            break;
        case SL_UWOP_SAVE_NONVOL_FAR:
            offset = (uint64_t)load_u32(codes + (index + 1U) * 2U);
            if (!add_stack_offset(frame_base, offset, &address) ||
                !restore_integer(context, context_pointers, stack, info,
                                 address)) {
                return false;
            }
            break;
        case SL_UWOP_SAVE_XMM128:
            offset =
                (uint64_t)load_u16(codes + (index + 1U) * 2U) * 16U;
            if (!add_stack_offset(frame_base, offset, &address) ||
                !restore_xmm(context, context_pointers, stack, info,
                             address)) {
                return false;
            }
            break;
        case SL_UWOP_SAVE_XMM128_FAR:
            offset = (uint64_t)load_u32(codes + (index + 1U) * 2U);
            if (!add_stack_offset(frame_base, offset, &address) ||
                !restore_xmm(context, context_pointers, stack, info,
                             address)) {
                return false;
            }
            break;
        case SL_UWOP_PUSH_MACHFRAME: {
            uint64_t bias = info == 0U ? 0U : 8U;
            uint64_t rip = 0U;
            uint64_t old_rsp = 0U;
            uint64_t flags = 0U;
            uint64_t code_segment = 0U;
            uint64_t stack_segment = 0U;
            if (!add_stack_offset(context->rsp, bias, &address) ||
                !read_stack_u64(stack, address, &rip) ||
                !add_stack_offset(context->rsp, bias + 8U, &address) ||
                !read_stack_u64(stack, address, &code_segment) ||
                !add_stack_offset(context->rsp, bias + 16U, &address) ||
                !read_stack_u64(stack, address, &flags) ||
                !add_stack_offset(context->rsp, bias + 24U, &address) ||
                !read_stack_u64(stack, address, &old_rsp) ||
                !add_stack_offset(context->rsp, bias + 32U, &address) ||
                !read_stack_u64(stack, address, &stack_segment)) {
                return false;
            }
            context->rip = rip;
            context->rsp = old_rsp;
            context->e_flags = (uint32_t)flags;
            context->seg_cs = (uint16_t)code_segment;
            context->seg_ss = (uint16_t)stack_segment;
            *machine_frame = true;
            break;
        }
        case SL_UWOP_EPILOG:
            break;
        default:
            return false;
        }
        index += slots;
    }
    return true;
}

static bool runtime_entry_from_pointer(
    const sl_loaded_module *module,
    const sl_win64_runtime_function *function_entry,
    sl_win64_runtime_function *entry) {
    const uint8_t *table = NULL;
    size_t entry_count = 0U;
    if (!exception_directory(module, &table, &entry_count)) {
        return false;
    }
    uintptr_t table_address = (uintptr_t)table;
    uintptr_t entry_address = (uintptr_t)function_entry;
    size_t table_size = entry_count * SL_WIN64_RUNTIME_FUNCTION_SIZE;
    if (entry_address < table_address ||
        entry_address - table_address >
            table_size - SL_WIN64_RUNTIME_FUNCTION_SIZE ||
        (entry_address - table_address) % SL_WIN64_RUNTIME_FUNCTION_SIZE !=
            0U) {
        return false;
    }
    *entry = read_runtime_function((const uint8_t *)function_entry);
    return runtime_function_is_valid(module, entry);
}

/*
 * Unwind a version-2 epilogue from its declared byte offset.  The stack
 * allocation and MOV-based restores happen before the range described by
 * UWOP_EPILOG.  Inside the range, Windows only has to account for the suffix
 * of PUSH_NONVOL operations that has not yet executed, an optional one-byte
 * pop used to undo pushfq, and the final control transfer.
 */
static bool unwind_v2_epilogue(
    const sl_loaded_module *module,
    const sl_win64_runtime_function *function_entry,
    uint32_t epilogue_offset, sl_win64_context *context,
    const sl_win64_stack_bounds *stack,
    sl_win64_nonvolatile_context_pointers *context_pointers) {
    sl_win64_runtime_function entry = *function_entry;
    sl_unwind_record_view record = {0};
    size_t index = 0U;
    bool selected_record = false;
    size_t selected_depth = 0U;

    for (size_t depth = 0U; depth < SL_WIN64_MAX_CHAIN_DEPTH; ++depth) {
        if (!read_unwind_record(module, entry.unwind_data, &record) ||
            !validate_v2_epilogue_ranges(&record, &entry)) {
            return false;
        }
        index = record.epilogues.code_slots;
        while (index < (size_t)record.code_count) {
            uint8_t operation_and_info = record.codes[index * 2U + 1U];
            uint8_t operation = operation_and_info & UINT8_C(0x0f);
            uint8_t info = operation_and_info >> 4U;
            if (operation == SL_UWOP_PUSH_NONVOL ||
                operation == SL_UWOP_PUSH_MACHFRAME) {
                selected_record = true;
                break;
            }
            size_t slots =
                unwind_operation_slots(record.version, operation, info);
            if (slots == 0U ||
                slots > (size_t)record.code_count - index) {
                return false;
            }
            index += slots;
        }
        if (selected_record ||
            (record.flags & SL_WIN64_UNW_FLAG_CHAININFO) == 0U) {
            selected_record = true;
            selected_depth = depth;
            break;
        }

        const uint8_t *chain_bytes = NULL;
        if (!module_window(module, record.trailer_rva,
                           SL_WIN64_RUNTIME_FUNCTION_SIZE, &chain_bytes)) {
            return false;
        }
        entry = read_runtime_function(chain_bytes);
        if (!runtime_function_is_valid(module, &entry)) {
            return false;
        }
    }
    if (!selected_record) {
        return false;
    }

    /*
     * The native v2 algorithm requires every PUSH_NONVOL/PUSH_MACHFRAME in a
     * chained function to live in the one record selected above.  Compilers
     * honor that invariant; rejecting a parent that violates it is safer than
     * silently treating one of its saved values as the return address.
     */
    sl_win64_runtime_function parent_entry = entry;
    sl_unwind_record_view parent_record = record;
    for (size_t depth = selected_depth;
         (parent_record.flags & SL_WIN64_UNW_FLAG_CHAININFO) != 0U; ++depth) {
        if (depth + 1U >= SL_WIN64_MAX_CHAIN_DEPTH) {
            return false;
        }
        const uint8_t *chain_bytes = NULL;
        if (!module_window(module, parent_record.trailer_rva,
                           SL_WIN64_RUNTIME_FUNCTION_SIZE, &chain_bytes)) {
            return false;
        }
        parent_entry = read_runtime_function(chain_bytes);
        if (!runtime_function_is_valid(module, &parent_entry) ||
            !read_unwind_record(module, parent_entry.unwind_data,
                                &parent_record) ||
            !validate_v2_epilogue_ranges(&parent_record, &parent_entry)) {
            return false;
        }
        size_t parent_index = parent_record.epilogues.code_slots;
        while (parent_index < (size_t)parent_record.code_count) {
            uint8_t operation_and_info =
                parent_record.codes[parent_index * 2U + 1U];
            uint8_t operation = operation_and_info & UINT8_C(0x0f);
            uint8_t info = operation_and_info >> 4U;
            if (operation == SL_UWOP_PUSH_NONVOL ||
                operation == SL_UWOP_PUSH_MACHFRAME) {
                return false;
            }
            size_t slots =
                unwind_operation_slots(parent_record.version, operation, info);
            if (slots == 0U ||
                slots > (size_t)parent_record.code_count - parent_index) {
                return false;
            }
            parent_index += slots;
        }
    }

    uint32_t current_offset = 0U;
    while (index < (size_t)record.code_count) {
        uint8_t operation_and_info = record.codes[index * 2U + 1U];
        uint8_t operation = operation_and_info & UINT8_C(0x0f);
        uint8_t info = operation_and_info >> 4U;
        if (operation != SL_UWOP_PUSH_NONVOL) {
            break;
        }
        if (current_offset >= epilogue_offset) {
            uint64_t saved_address = context->rsp;
            if (!restore_integer(context, context_pointers, stack, info,
                                 saved_address) ||
                !add_u64(context->rsp, 8U, &context->rsp)) {
                return false;
            }
        }
        current_offset += info >= 8U ? 2U : 1U;
        ++index;
    }

    /* A volatile one-byte pop may mirror a prologue pushfq. */
    if (index < (size_t)record.code_count) {
        uint8_t operation_and_info = record.codes[index * 2U + 1U];
        uint8_t operation = operation_and_info & UINT8_C(0x0f);
        uint8_t info = operation_and_info >> 4U;
        if (operation == SL_UWOP_ALLOC_SMALL && info == 0U) {
            if (current_offset >= epilogue_offset &&
                !add_u64(context->rsp, 8U, &context->rsp)) {
                return false;
            }
            ++current_offset;
            ++index;
        }
    }

    if (index < (size_t)record.code_count) {
        uint8_t operation_and_info = record.codes[index * 2U + 1U];
        uint8_t operation = operation_and_info & UINT8_C(0x0f);
        uint8_t info = operation_and_info >> 4U;
        if (operation != SL_UWOP_PUSH_MACHFRAME ||
            index + 1U != (size_t)record.code_count) {
            return false;
        }
        (void)info;
        uint64_t address = 0U;
        uint64_t rip = 0U;
        uint64_t old_rsp = 0U;
        /* The optional error code has already been removed in an epilogue. */
        if (!read_stack_u64(stack, context->rsp, &rip) ||
            !add_stack_offset(context->rsp, 24U, &address) ||
            !read_stack_u64(stack, address, &old_rsp)) {
            return false;
        }
        context->rip = rip;
        context->rsp = old_rsp;
        return true;
    }

    uint64_t return_address = 0U;
    if (!read_stack_u64(stack, context->rsp, &return_address) ||
        !add_u64(context->rsp, 8U, &context->rsp)) {
        return false;
    }
    context->rip = return_address;
    return true;
}

static bool simulate_epilogue(
    const sl_loaded_module *module, const sl_win64_runtime_function *entry,
    uint8_t frame_register, uint64_t control_pc, sl_win64_context *context,
    const sl_win64_stack_bounds *stack,
    sl_win64_nonvolatile_context_pointers *context_pointers) {
    uint64_t image_base = module->mapped->load_base;
    if (control_pc < image_base || control_pc - image_base > UINT32_MAX) {
        return false;
    }
    uint32_t cursor_rva = (uint32_t)(control_pc - image_base);
    if (cursor_rva < entry->begin_address || cursor_rva >= entry->end_address) {
        return false;
    }

    sl_win64_context candidate = *context;
    sl_win64_nonvolatile_context_pointers candidate_pointers;
    if (context_pointers != NULL) {
        candidate_pointers = *context_pointers;
    }
    bool first_instruction = true;
    bool transfer_prefix_seen = false;
    for (size_t instruction_count = 0U; instruction_count < 32U;
         ++instruction_count) {
        const uint8_t *code = NULL;
        size_t remaining = (size_t)entry->end_address - (size_t)cursor_rva;
        if (remaining == 0U ||
            !module_window(module, cursor_rva, remaining, &code)) {
            return false;
        }

        size_t length = 0U;
        if (first_instruction && remaining >= 4U && code[0] == 0x48U &&
            code[1] == 0x83U && code[2] == 0xc4U) {
            int8_t immediate = (int8_t)code[3];
            if (immediate <= 0 ||
                !add_u64(candidate.rsp, (uint64_t)immediate,
                         &candidate.rsp)) {
                return false;
            }
            length = 4U;
        } else if (first_instruction && remaining >= 7U &&
                   code[0] == 0x48U && code[1] == 0x81U &&
                   code[2] == 0xc4U) {
            int32_t immediate = (int32_t)load_u32(code + 3U);
            if (immediate <= 0 ||
                !add_u64(candidate.rsp, (uint64_t)immediate,
                         &candidate.rsp)) {
                return false;
            }
            length = 7U;
        } else if (first_instruction && frame_register != 0U &&
                   remaining >= 4U &&
                   (code[0] & UINT8_C(0xf8)) == UINT8_C(0x48) &&
                   (code[0] & UINT8_C(0x04)) == 0U && code[1] == 0x8dU) {
            uint8_t modrm = code[2];
            uint8_t mode = modrm >> 6U;
            uint8_t destination = (modrm >> 3U) & UINT8_C(7);
            uint8_t encoded_base = modrm & UINT8_C(7);
            uint8_t base_register =
                encoded_base | ((code[0] & UINT8_C(1)) << 3U);
            size_t displacement_offset = 3U;
            if (destination != 4U || (mode != 1U && mode != 2U)) {
                return false;
            }
            if (encoded_base == 4U) {
                if (remaining < 5U || (code[0] & UINT8_C(2)) != 0U ||
                    code[3] != UINT8_C(0x24)) {
                    return false;
                }
                displacement_offset = 4U;
            }
            if (base_register != frame_register) {
                return false;
            }
            int64_t displacement = 0;
            if (mode == 1U) {
                displacement = (int8_t)code[displacement_offset];
                length = displacement_offset + 1U;
            } else {
                if (remaining < displacement_offset + 4U) {
                    return false;
                }
                displacement =
                    (int32_t)load_u32(code + displacement_offset);
                length = displacement_offset + 4U;
            }
            uint64_t base_value = *integer_register(&candidate, base_register);
            if (displacement >= 0) {
                if (!add_u64(base_value, (uint64_t)displacement,
                             &candidate.rsp)) {
                    return false;
                }
            } else {
                uint64_t magnitude = (uint64_t)(-displacement);
                if (base_value < magnitude) {
                    return false;
                }
                candidate.rsp = base_value - magnitude;
            }
        } else if (!transfer_prefix_seen && code[0] >= 0x58U &&
                   code[0] <= 0x5fU) {
            uint8_t register_number =
                (uint8_t)(code[0] - UINT8_C(0x58));
            if (!is_nonvolatile_integer_register(register_number) ||
                !restore_integer(
                    &candidate,
                    context_pointers == NULL ? NULL : &candidate_pointers,
                    stack, register_number, candidate.rsp) ||
                !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
                return false;
            }
            length = 1U;
        } else if (!transfer_prefix_seen && remaining >= 2U &&
                   (code[0] & UINT8_C(0xf0)) == UINT8_C(0x40) &&
                   code[1] >= 0x58U && code[1] <= 0x5fU) {
            uint8_t register_number =
                (uint8_t)((uint8_t)(code[1] - UINT8_C(0x58)) |
                          ((code[0] & UINT8_C(1)) << 3U));
            if (!is_nonvolatile_integer_register(register_number) ||
                !restore_integer(
                    &candidate,
                    context_pointers == NULL ? NULL : &candidate_pointers,
                    stack, register_number, candidate.rsp) ||
                !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
                return false;
            }
            length = 2U;
        } else if (!transfer_prefix_seen && code[0] == 0xf2U) {
            transfer_prefix_seen = true;
            length = 1U;
        } else if (code[0] == 0xc3U ||
                   (remaining >= 2U && code[0] == 0xf3U &&
                    code[1] == 0xc3U)) {
            uint64_t return_address = 0U;
            if (!read_stack_u64(stack, candidate.rsp, &return_address) ||
                !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
                return false;
            }
            candidate.rip = return_address;
            *context = candidate;
            if (context_pointers != NULL) {
                *context_pointers = candidate_pointers;
            }
            return true;
        } else if (remaining >= 3U && code[0] == 0xc2U) {
            uint64_t return_address = 0U;
            uint64_t adjustment = (uint64_t)load_u16(code + 1U) + 8U;
            if (!read_stack_u64(stack, candidate.rsp, &return_address) ||
                !add_u64(candidate.rsp, adjustment, &candidate.rsp)) {
                return false;
            }
            candidate.rip = return_address;
            *context = candidate;
            if (context_pointers != NULL) {
                *context_pointers = candidate_pointers;
            }
            return true;
        } else {
            int64_t displacement = 0;
            size_t jump_length = 0U;
            if (remaining >= 2U && code[0] == 0xebU) {
                displacement = (int8_t)code[1];
                jump_length = 2U;
            } else if (remaining >= 5U && code[0] == 0xe9U) {
                displacement = (int32_t)load_u32(code + 1U);
                jump_length = 5U;
            }
            if (jump_length != 0U) {
                uint64_t next = image_base + (uint64_t)cursor_rva +
                                (uint64_t)jump_length;
                uint64_t target = displacement >= 0
                                      ? next + (uint64_t)displacement
                                      : next - (uint64_t)(-displacement);
                uint64_t begin = image_base + entry->begin_address;
                uint64_t end = image_base + entry->end_address;
                if ((displacement < 0 && next < (uint64_t)(-displacement)) ||
                    (displacement >= 0 &&
                     UINT64_MAX - next < (uint64_t)displacement) ||
                    (target > begin && target < end)) {
                    return false;
                }
                /* A tail jump ends the frame, so unwind it like a return. */
                if (!read_stack_u64(stack, candidate.rsp, &candidate.rip) ||
                    !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
                    return false;
                }
                *context = candidate;
                if (context_pointers != NULL) {
                    *context_pointers = candidate_pointers;
                }
                return true;
            }

            if (remaining >= 6U && code[0] == 0xffU && code[1] == 0x25U) {
                if (!read_stack_u64(stack, candidate.rsp, &candidate.rip) ||
                    !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
                    return false;
                }
                *context = candidate;
                if (context_pointers != NULL) {
                    *context_pointers = candidate_pointers;
                }
                return true;
            }

            if (remaining >= 3U &&
                (code[0] & UINT8_C(0xf8)) == UINT8_C(0x48) &&
                code[1] == 0xffU &&
                (code[2] & UINT8_C(0x38)) == UINT8_C(0x20)) {
                uint8_t mode = code[2] >> 6U;
                uint8_t encoded_base = code[2] & UINT8_C(7);
                size_t jump_size = 3U;
                if (mode != 3U && encoded_base == 4U) {
                    if (remaining < 4U) {
                        return false;
                    }
                    uint8_t sib_base = code[3] & UINT8_C(7);
                    jump_size = 4U;
                    if (mode == 0U && sib_base == 5U) {
                        jump_size += 4U;
                    }
                }
                if (mode == 0U && encoded_base == 5U) {
                    jump_size += 4U;
                } else if (mode == 1U) {
                    jump_size += 1U;
                } else if (mode == 2U) {
                    jump_size += 4U;
                }
                if (jump_size > remaining) {
                    return false;
                }
                if (!read_stack_u64(stack, candidate.rsp, &candidate.rip) ||
                    !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
                    return false;
                }
                *context = candidate;
                if (context_pointers != NULL) {
                    *context_pointers = candidate_pointers;
                }
                return true;
            }
            return false;
        }

        if (length == 0U || length > remaining) {
            return false;
        }
        cursor_rva += (uint32_t)length;
        first_instruction = false;
    }
    return false;
}

sl_status sl_win64_virtual_unwind(
    const sl_loaded_module *module, uint32_t handler_type,
    uint64_t control_pc, const sl_win64_runtime_function *function_entry,
    sl_win64_context *context_record, const sl_win64_stack_bounds *stack,
    void **handler_data,
    uint64_t *establisher_frame,
    sl_win64_nonvolatile_context_pointers *context_pointers,
    sl_win64_exception_routine *language_handler) {
    if (module == NULL || function_entry == NULL || context_record == NULL ||
        handler_data == NULL || establisher_frame == NULL ||
        language_handler == NULL || stack == NULL ||
        stack->limit >= stack->base ||
        (handler_type != SL_WIN64_UNW_FLAG_NHANDLER &&
         handler_type != SL_WIN64_UNW_FLAG_EHANDLER &&
         handler_type != SL_WIN64_UNW_FLAG_UHANDLER)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }

    sl_win64_runtime_function entry;
    if (!runtime_entry_from_pointer(module, function_entry, &entry) ||
        module->mapped == NULL || control_pc < module->mapped->load_base ||
        control_pc - module->mapped->load_base < entry.begin_address ||
        control_pc - module->mapped->load_base >= entry.end_address) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_unwind_record_view first_record;
    sl_status metadata_status =
        validate_unwind_chain(module, &entry, &first_record);
    if (metadata_status != SL_OK) {
        return metadata_status;
    }

    sl_win64_context candidate = *context_record;
    sl_win64_nonvolatile_context_pointers candidate_pointers;
    if (context_pointers != NULL) {
        candidate_pointers = *context_pointers;
    }
    uint64_t original_rsp = candidate.rsp;
    uint64_t initial_procedure_offset =
        control_pc - module->mapped->load_base - entry.begin_address;
    bool initially_in_prologue =
        initial_procedure_offset < first_record.prologue_size;
    uint8_t initial_prologue_offset =
        initially_in_prologue ? (uint8_t)initial_procedure_offset : UINT8_MAX;
    bool initial_frame_established = first_record.frame_register != 0U &&
        (((first_record.flags & SL_WIN64_UNW_FLAG_CHAININFO) != 0U &&
          !first_record.has_frame_setup) ||
         frame_register_is_established(
             first_record.codes, first_record.code_count,
             first_record.version, initially_in_prologue,
             initial_prologue_offset));
    uint64_t initial_establisher = original_rsp;
    if (initial_frame_established) {
        uint64_t frame_value =
            *integer_register(&candidate, first_record.frame_register);
        uint64_t scaled_offset =
            (uint64_t)first_record.frame_offset * UINT64_C(16);
        if (frame_value < scaled_offset) {
            return SL_ERROR_INVALID_IMAGE;
        }
        initial_establisher = frame_value - scaled_offset;
    }
    bool unwound_epilogue = false;
    if (first_record.version == 1U) {
        unwound_epilogue = simulate_epilogue(
            module, &entry, first_record.frame_register, control_pc,
            &candidate, stack,
            context_pointers == NULL ? NULL : &candidate_pointers);
    } else {
        uint32_t relative_pc =
            (uint32_t)(control_pc - module->mapped->load_base);
        uint32_t epilogue_offset = 0U;
        if (find_v2_epilogue(&first_record, &entry, relative_pc,
                             &epilogue_offset)) {
            if (!unwind_v2_epilogue(
                    module, &entry, epilogue_offset, &candidate, stack,
                    context_pointers == NULL ? NULL : &candidate_pointers)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            unwound_epilogue = true;
        }
    }
    if (unwound_epilogue) {
        *context_record = candidate;
        if (context_pointers != NULL) {
            *context_pointers = candidate_pointers;
        }
        *handler_data = NULL;
        *establisher_frame = initial_establisher;
        *language_handler = NULL;
        return SL_OK;
    }

    bool machine_frame = false;
    bool allow_handler = true;
    uint64_t final_establisher = original_rsp;
    sl_win64_exception_routine final_handler = NULL;
    void *final_handler_data = NULL;
    uint32_t unwind_rva = entry.unwind_data;
    for (size_t depth = 0U; depth < SL_WIN64_MAX_CHAIN_DEPTH; ++depth) {
        const uint8_t *header = NULL;
        if (!module_window(module, unwind_rva, 4U, &header)) {
            return SL_ERROR_INVALID_IMAGE;
        }
        uint8_t version_and_flags = header[0];
        uint8_t version = version_and_flags & UINT8_C(7);
        uint8_t flags = version_and_flags >> 3U;
        uint8_t prologue_size = header[1];
        uint8_t code_count = header[2];
        uint8_t frame = header[3];
        uint8_t frame_register = frame & UINT8_C(0x0f);
        uint8_t frame_offset = frame >> 4U;
        size_t padded_code_count = ((size_t)code_count + 1U) & ~(size_t)1U;
        size_t record_size = 4U + padded_code_count * 2U;
        const uint8_t *record = NULL;
        if ((version != 1U && version != 2U) ||
            (flags & ~(SL_WIN64_UNW_FLAG_EHANDLER |
                       SL_WIN64_UNW_FLAG_UHANDLER |
                       SL_WIN64_UNW_FLAG_CHAININFO)) != 0U ||
            ((flags & SL_WIN64_UNW_FLAG_CHAININFO) != 0U &&
             (flags & (SL_WIN64_UNW_FLAG_EHANDLER |
                       SL_WIN64_UNW_FLAG_UHANDLER)) != 0U) ||
            (frame_register != 0U &&
             !is_nonvolatile_integer_register(frame_register)) ||
            !module_window(module, unwind_rva, record_size, &record)) {
            return SL_ERROR_INVALID_IMAGE;
        }
        const uint8_t *codes = record + 4U;
        bool has_frame_setup = false;
        sl_v2_epilogue_info epilogues;
        if ((frame_register == 0U && frame_offset != 0U) ||
            !validate_unwind_codes(codes, code_count, version, prologue_size,
                                   frame_register, frame_offset,
                                   &epilogues,
                                   &has_frame_setup)) {
            return SL_ERROR_INVALID_IMAGE;
        }

        uint64_t relative_pc = control_pc - module->mapped->load_base;
        uint64_t procedure_offset =
            relative_pc >= entry.begin_address
                ? relative_pc - (uint64_t)entry.begin_address
                : UINT64_MAX;
        bool in_prologue = depth == 0U && procedure_offset < prologue_size;
        uint8_t prologue_offset =
            in_prologue ? (uint8_t)procedure_offset : UINT8_MAX;
        bool frame_established = frame_register != 0U &&
            (((flags & SL_WIN64_UNW_FLAG_CHAININFO) != 0U &&
              !has_frame_setup) ||
             frame_register_is_established(codes, code_count, version,
                                           in_prologue, prologue_offset));
        uint64_t frame_base = candidate.rsp;
        if (frame_established) {
            uint64_t frame_value =
                *integer_register(&candidate, frame_register);
            uint64_t scaled_offset = (uint64_t)frame_offset * 16U;
            if (frame_value < scaled_offset) {
                return SL_ERROR_INVALID_IMAGE;
            }
            frame_base = frame_value - scaled_offset;
        }
        if (depth == 0U) {
            final_establisher = frame_base;
            if (in_prologue) {
                allow_handler = false;
            }
        }

        if (!apply_unwind_codes(
                codes, code_count, version, in_prologue, prologue_offset,
                frame_base, &candidate, stack,
                context_pointers == NULL ? NULL : &candidate_pointers,
                &machine_frame)) {
            return SL_ERROR_INVALID_IMAGE;
        }

        size_t trailer_rva = (size_t)unwind_rva + record_size;
        if (trailer_rva > UINT32_MAX) {
            return SL_ERROR_INVALID_IMAGE;
        }
        if ((flags & SL_WIN64_UNW_FLAG_CHAININFO) != 0U) {
            const uint8_t *chain_bytes = NULL;
            if (!module_window(module, (uint32_t)trailer_rva,
                               SL_WIN64_RUNTIME_FUNCTION_SIZE,
                               &chain_bytes)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            entry = read_runtime_function(chain_bytes);
            if (!runtime_function_is_valid(module, &entry)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            unwind_rva = entry.unwind_data;
            continue;
        }

        if (allow_handler &&
            (flags & (uint8_t)handler_type) != 0U) {
            const uint8_t *handler_bytes = NULL;
            if (!module_window(module, (uint32_t)trailer_rva, 4U,
                               &handler_bytes)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            uint32_t handler_rva = load_u32(handler_bytes);
            if (handler_rva == 0U || handler_rva >= module->mapped->size ||
                trailer_rva + 4U > module->mapped->size) {
                return SL_ERROR_INVALID_IMAGE;
            }
            uintptr_t handler_address =
                (uintptr_t)(module->mapped->bytes + (size_t)handler_rva);
            _Static_assert(sizeof(final_handler) <= sizeof(handler_address),
                           "exception routine pointer does not fit uintptr_t");
            memcpy(&final_handler, &handler_address, sizeof(final_handler));
            final_handler_data =
                module->mapped->bytes + trailer_rva + 4U;
        }
        if (!machine_frame) {
            uint64_t return_address = 0U;
            if (!read_stack_u64(stack, candidate.rsp, &return_address) ||
                !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
                return SL_ERROR_INVALID_IMAGE;
            }
            candidate.rip = return_address;
        }

        *context_record = candidate;
        if (context_pointers != NULL) {
            *context_pointers = candidate_pointers;
        }
        *handler_data = final_handler_data;
        *establisher_frame = final_establisher;
        *language_handler = final_handler;
        return SL_OK;
    }
    return SL_ERROR_FORWARDER_LIMIT;
}

sl_status sl_win64_unwind_leaf(sl_win64_context *context_record,
                               const sl_win64_stack_bounds *stack) {
    if (context_record == NULL || stack == NULL ||
        stack->limit >= stack->base) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_win64_context candidate = *context_record;
    uint64_t return_address = 0U;
    if (!read_stack_u64(stack, candidate.rsp, &return_address) ||
        !add_u64(candidate.rsp, 8U, &candidate.rsp)) {
        return SL_ERROR_INVALID_IMAGE;
    }
    candidate.rip = return_address;
    *context_record = candidate;
    return SL_OK;
}

sl_status sl_win64_unwind_to_frame(
    const sl_module_registry *registry, uint64_t target_frame,
    uint64_t target_ip, sl_win64_exception_record *exception_record,
    uint64_t return_value, const sl_win64_context *context_record,
    sl_win64_unwind_history_table *history_table,
    const sl_win64_stack_bounds *stack, sl_win64_context *target_context) {
    if (registry == NULL || exception_record == NULL ||
        context_record == NULL || stack == NULL || target_context == NULL ||
        !stack_frame_is_valid(stack, context_record->rsp) ||
        (target_frame != 0U &&
         (!stack_frame_is_valid(stack, target_frame) ||
          target_frame < context_record->rsp || target_ip == 0U))) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    if (target_frame != 0U) {
        const sl_loaded_module *target_module = NULL;
        if (sl_module_registry_resolve_address(
                registry, target_ip, &target_module) != SL_OK ||
            target_module == NULL || target_module->kind != SL_MODULE_PE) {
            return SL_ERROR_ADDRESS_OUT_OF_RANGE;
        }
    }

    uint32_t unwind_flags =
        (exception_record->exception_flags &
         SL_WIN64_EXCEPTION_NONCONTINUABLE) |
        SL_WIN64_EXCEPTION_UNWINDING;
    if (target_frame == 0U) {
        unwind_flags |= SL_WIN64_EXCEPTION_EXIT_UNWIND;
    }
    exception_record->exception_flags = unwind_flags;

    sl_win64_context walking = *context_record;
    for (size_t depth = 0U; depth < 256U; ++depth) {
        if (!stack_frame_is_valid(stack, walking.rsp)) {
            return SL_ERROR_INVALID_IMAGE;
        }
        const sl_loaded_module *containing_module = NULL;
        if (sl_module_registry_resolve_address(
                registry, walking.rip, &containing_module) != SL_OK) {
            return target_frame == 0U ? SL_ERROR_NOT_IMPLEMENTED
                                      : SL_ERROR_INVALID_STATE;
        }

        uint64_t image_base = 0U;
        const sl_win64_runtime_function *function_entry = NULL;
        const sl_loaded_module *function_module = NULL;
        sl_status lookup_status = sl_win64_lookup_function_entry(
            registry, walking.rip, &image_base, &function_entry,
            &function_module);
        if (lookup_status == SL_ERROR_ADDRESS_OUT_OF_RANGE) {
            uint64_t establisher_frame = walking.rsp;
            if (target_frame != 0U && establisher_frame == target_frame) {
                sl_win64_context result = walking;
                result.rax = return_value;
                result.rip = target_ip;
                *target_context = result;
                return SL_OK;
            }
            uint64_t previous_rsp = walking.rsp;
            if (sl_win64_unwind_leaf(&walking, stack) != SL_OK ||
                walking.rsp <= previous_rsp) {
                return SL_ERROR_INVALID_IMAGE;
            }
            continue;
        }
        if (lookup_status != SL_OK || function_module != containing_module) {
            return lookup_status;
        }

        uint64_t control_pc = walking.rip;
        sl_win64_context caller = walking;
        void *handler_data = NULL;
        uint64_t establisher_frame = 0U;
        sl_win64_exception_routine language_handler = NULL;
        sl_status unwind_status = sl_win64_virtual_unwind(
            function_module, SL_WIN64_UNW_FLAG_UHANDLER, control_pc,
            function_entry, &caller, stack, &handler_data,
            &establisher_frame, NULL, &language_handler);
        if (unwind_status != SL_OK || caller.rsp <= walking.rsp ||
            !stack_frame_is_valid(stack, establisher_frame)) {
            return unwind_status == SL_OK ? SL_ERROR_INVALID_IMAGE
                                          : unwind_status;
        }
        bool at_target =
            target_frame != 0U && establisher_frame == target_frame;
        if (target_frame != 0U && establisher_frame > target_frame) {
            return SL_ERROR_INVALID_STATE;
        }

        if (language_handler != NULL) {
            if (at_target) {
                exception_record->exception_flags |=
                    SL_WIN64_EXCEPTION_TARGET_UNWIND;
            }
            walking.rax = return_value;
            sl_win64_dispatcher_context dispatcher = {
                .control_pc = control_pc,
                .image_base = image_base,
                .function_entry = function_entry,
                .establisher_frame = establisher_frame,
                .target_ip = target_ip,
                .context_record = &walking,
                .language_handler = language_handler,
                .handler_data = handler_data,
                .history_table = history_table,
                .scope_index = 0U,
                .fill0 = 0U,
            };
            int32_t disposition = sl_win64_execute_handler(
                language_handler, exception_record, establisher_frame,
                &walking, &dispatcher, &walking);
            exception_record->exception_flags = unwind_flags;
            if (disposition !=
                SL_WIN64_EXCEPTION_DISPOSITION_CONTINUE_SEARCH) {
                return disposition ==
                               SL_WIN64_EXCEPTION_DISPOSITION_COLLIDED_UNWIND
                           ? SL_ERROR_NOT_IMPLEMENTED
                           : SL_ERROR_INVALID_STATE;
            }
        }
        if (at_target) {
            sl_win64_context result = walking;
            result.rax = return_value;
            result.rip = target_ip;
            *target_context = result;
            return SL_OK;
        }
        walking = caller;
    }
    return SL_ERROR_FORWARDER_LIMIT;
}
