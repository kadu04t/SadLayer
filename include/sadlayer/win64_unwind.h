#ifndef SADLAYER_WIN64_UNWIND_H
#define SADLAYER_WIN64_UNWIND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"
#include "sadlayer/module.h"
#include "sadlayer/win32.h"

#define SL_WIN64_CONTEXT_AMD64 UINT32_C(0x00100000)
#define SL_WIN64_CONTEXT_CONTROL                                                \
    (SL_WIN64_CONTEXT_AMD64 | UINT32_C(0x00000001))
#define SL_WIN64_CONTEXT_INTEGER                                                \
    (SL_WIN64_CONTEXT_AMD64 | UINT32_C(0x00000002))
#define SL_WIN64_CONTEXT_SEGMENTS                                               \
    (SL_WIN64_CONTEXT_AMD64 | UINT32_C(0x00000004))
#define SL_WIN64_CONTEXT_FLOATING_POINT                                         \
    (SL_WIN64_CONTEXT_AMD64 | UINT32_C(0x00000008))
#define SL_WIN64_CONTEXT_FULL                                                   \
    (SL_WIN64_CONTEXT_CONTROL | SL_WIN64_CONTEXT_INTEGER |                     \
     SL_WIN64_CONTEXT_FLOATING_POINT)
#define SL_WIN64_CONTEXT_CAPTURED                                               \
    (SL_WIN64_CONTEXT_FULL | SL_WIN64_CONTEXT_SEGMENTS)

#define SL_WIN64_UNW_FLAG_NHANDLER UINT32_C(0x0)
#define SL_WIN64_UNW_FLAG_EHANDLER UINT32_C(0x1)
#define SL_WIN64_UNW_FLAG_UHANDLER UINT32_C(0x2)
#define SL_WIN64_UNW_FLAG_CHAININFO UINT32_C(0x4)

#define SL_WIN64_EXCEPTION_CONTINUE_EXECUTION INT32_C(-1)
#define SL_WIN64_EXCEPTION_CONTINUE_SEARCH INT32_C(0)
#define SL_WIN64_EXCEPTION_EXECUTE_HANDLER INT32_C(1)
#define SL_WIN64_EXCEPTION_NONCONTINUABLE UINT32_C(0x00000001)
#define SL_WIN64_EXCEPTION_UNWINDING UINT32_C(0x00000002)
#define SL_WIN64_EXCEPTION_EXIT_UNWIND UINT32_C(0x00000004)
#define SL_WIN64_EXCEPTION_TARGET_UNWIND UINT32_C(0x00000020)
#define SL_WIN64_EXCEPTION_COLLIDED_UNWIND UINT32_C(0x00000040)
#define SL_WIN64_EXCEPTION_MAXIMUM_PARAMETERS 15U
#define SL_WIN64_STATUS_UNWIND UINT32_C(0xc0000027)

#define SL_WIN64_EXCEPTION_DISPOSITION_CONTINUE_EXECUTION INT32_C(0)
#define SL_WIN64_EXCEPTION_DISPOSITION_CONTINUE_SEARCH INT32_C(1)
#define SL_WIN64_EXCEPTION_DISPOSITION_NESTED_EXCEPTION INT32_C(2)
#define SL_WIN64_EXCEPTION_DISPOSITION_COLLIDED_UNWIND INT32_C(3)

typedef struct {
    _Alignas(16) uint64_t low;
    int64_t high;
} sl_win64_m128a;

typedef struct {
    uint16_t control_word;
    uint16_t status_word;
    uint8_t tag_word;
    uint8_t reserved1;
    uint16_t error_opcode;
    uint32_t error_offset;
    uint16_t error_selector;
    uint16_t reserved2;
    uint32_t data_offset;
    uint16_t data_selector;
    uint16_t reserved3;
    uint32_t mx_csr;
    uint32_t mx_csr_mask;
    sl_win64_m128a float_registers[8];
    sl_win64_m128a xmm_registers[16];
    uint8_t reserved4[96];
} sl_win64_xmm_save_area32;

typedef struct {
    _Alignas(16) uint64_t p1_home;
    uint64_t p2_home;
    uint64_t p3_home;
    uint64_t p4_home;
    uint64_t p5_home;
    uint64_t p6_home;
    uint32_t context_flags;
    uint32_t mx_csr;
    uint16_t seg_cs;
    uint16_t seg_ds;
    uint16_t seg_es;
    uint16_t seg_fs;
    uint16_t seg_gs;
    uint16_t seg_ss;
    uint32_t e_flags;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    sl_win64_xmm_save_area32 flt_save;
    sl_win64_m128a vector_register[26];
    uint64_t vector_control;
    uint64_t debug_control;
    uint64_t last_branch_to_rip;
    uint64_t last_branch_from_rip;
    uint64_t last_exception_to_rip;
    uint64_t last_exception_from_rip;
} sl_win64_context;

typedef struct sl_win64_exception_record sl_win64_exception_record;

struct sl_win64_exception_record {
    uint32_t exception_code;
    uint32_t exception_flags;
    sl_win64_exception_record *exception_record;
    void *exception_address;
    uint32_t number_parameters;
    uint32_t alignment;
    uint64_t exception_information[SL_WIN64_EXCEPTION_MAXIMUM_PARAMETERS];
};

typedef struct {
    sl_win64_exception_record *exception_record;
    sl_win64_context *context_record;
} sl_win64_exception_pointers;

typedef struct {
    uint32_t begin_address;
    uint32_t end_address;
    uint32_t unwind_data;
} sl_win64_runtime_function;

typedef struct {
    uint64_t image_base;
    const sl_win64_runtime_function *function_entry;
} sl_win64_unwind_history_entry;

typedef struct {
    uint32_t count;
    uint8_t local_hint;
    uint8_t global_hint;
    uint8_t search;
    uint8_t once;
    uint64_t low_address;
    uint64_t high_address;
    sl_win64_unwind_history_entry entries[12];
} sl_win64_unwind_history_table;

typedef struct {
    sl_win64_m128a *floating_context[16];
    uint64_t *integer_context[16];
} sl_win64_nonvolatile_context_pointers;

typedef struct {
    uint64_t limit;
    uint64_t base;
} sl_win64_stack_bounds;

typedef struct sl_win64_dispatcher_context sl_win64_dispatcher_context;

typedef int32_t(SL_WINAPI *sl_win64_exception_routine)(
    sl_win64_exception_record *exception_record, uint64_t establisher_frame,
    sl_win64_context *context_record,
    sl_win64_dispatcher_context *dispatcher_context);

typedef int32_t(SL_WINAPI *sl_win64_top_level_exception_filter)(
    sl_win64_exception_pointers *exception_pointers);

struct sl_win64_dispatcher_context {
    uint64_t control_pc;
    uint64_t image_base;
    const sl_win64_runtime_function *function_entry;
    uint64_t establisher_frame;
    uint64_t target_ip;
    sl_win64_context *context_record;
    sl_win64_exception_routine language_handler;
    void *handler_data;
    sl_win64_unwind_history_table *history_table;
    uint32_t scope_index;
    uint32_t fill0;
};

/*
 * Looks only in immutable PE32+ exception directories registered in the
 * supplied module catalog. Dynamic/JIT function tables are not modeled yet.
 */
sl_status sl_win64_lookup_function_entry(
    const sl_module_registry *registry, uint64_t control_pc,
    uint64_t *image_base, const sl_win64_runtime_function **function_entry,
    const sl_loaded_module **module);

/*
 * Applies AMD64 version-1/version-2 PE unwind metadata to one frame. Outputs
 * and the context are committed only when the complete record is valid and
 * supported.
 */
sl_status sl_win64_virtual_unwind(
    const sl_loaded_module *module, uint32_t handler_type,
    uint64_t control_pc, const sl_win64_runtime_function *function_entry,
    sl_win64_context *context_record, const sl_win64_stack_bounds *stack,
    void **handler_data,
    uint64_t *establisher_frame,
    sl_win64_nonvolatile_context_pointers *context_pointers,
    sl_win64_exception_routine *language_handler);
sl_status sl_win64_unwind_leaf(sl_win64_context *context_record,
                               const sl_win64_stack_bounds *stack);

/*
 * Executes a language handler behind a thread-local unwind link.  If the
 * handler starts RtlUnwindEx, the runtime can resume from the guest frame that
 * caused the callback instead of trying to interpret SadLayer's host frames.
 */
int32_t sl_win64_execute_handler(
    sl_win64_exception_routine language_handler,
    sl_win64_exception_record *exception_record, uint64_t establisher_frame,
    sl_win64_context *handler_context,
    sl_win64_dispatcher_context *dispatcher_context,
    const sl_win64_context *guest_unwind_origin);
bool sl_win64_take_handler_unwind_origin(sl_win64_context *context_record);

/* Executes the table-driven second pass and returns a restorable target. */
sl_status sl_win64_unwind_to_frame(
    const sl_module_registry *registry, uint64_t target_frame,
    uint64_t target_ip, sl_win64_exception_record *exception_record,
    uint64_t return_value, const sl_win64_context *context_record,
    sl_win64_unwind_history_table *history_table,
    const sl_win64_stack_bounds *stack, sl_win64_context *target_context);

_Noreturn void SL_WINAPI sl_win64_restore_context(
    const sl_win64_context *context_record);

#endif
