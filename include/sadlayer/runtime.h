#ifndef SADLAYER_RUNTIME_H
#define SADLAYER_RUNTIME_H

#include <stdint.h>

#include "sadlayer/context.h"
#include "sadlayer/loader.h"
#include "sadlayer/pe.h"

#define SL_RUNTIME_REPORT_HAS_CRASH_CONTEXT UINT32_C(0x00000001)
#define SL_RUNTIME_REPORT_HAS_SIGNAL_CODE UINT32_C(0x00000002)
#define SL_RUNTIME_REPORT_HAS_FAULT_ADDRESS UINT32_C(0x00000004)
#define SL_RUNTIME_REPORT_HANDLER_ON_ALTSTACK UINT32_C(0x00000008)

typedef enum {
    SL_RUNTIME_OUTCOME_NONE = 0,
    SL_RUNTIME_OUTCOME_RETURNED,
    SL_RUNTIME_OUTCOME_FAILED,
    SL_RUNTIME_OUTCOME_EXITED,
    SL_RUNTIME_OUTCOME_SIGNALLED,
} sl_runtime_outcome;

typedef struct {
    sl_runtime_outcome outcome;
    /* Meaningful for RETURNED/FAILED; EXITED/SIGNALLED use their own fields. */
    sl_status worker_status;
    /* Populated after the entry returns; authoritative for RETURNED. */
    uint32_t return_value;
    uint32_t last_error;
    uint32_t worker_process_id;
    /* Current EXITED reports expose the decoded host exit code (0..255). */
    int32_t exit_code;
    int32_t signal_number;
    /* HAS_CRASH_CONTEXT makes RIP/RSP valid host VAs; zero is still valid. */
    uint32_t report_flags;
    /* Valid only with HAS_SIGNAL_CODE. */
    int32_t signal_code;
    /* Valid only with HAS_FAULT_ADDRESS; RIP/RSP use HAS_CRASH_CONTEXT. */
    uint64_t fault_address;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
} sl_runtime_report;

/*
 * Directly calls an AMD64 entry point trusted by the caller on the host stack,
 * without crash isolation or GS-backed TEB installation. Only repository
 * fixtures may use this low-level test hook.
 */
sl_status sl_runtime_call_trusted_entry(const sl_pe_image *image,
                                        const sl_mapped_image *mapped,
                                        sl_win32_thread_context *thread,
                                        uint32_t *result);

/*
 * Runs a caller-trusted entry in a separate bootstrap process whose active
 * stack is guarded and whose GS base points at its TEB. This first worker gate
 * reports return/worker-failure/exit/signal outcomes. Fatal synchronous signals
 * run on a guarded alternate signal stack and can include fixed-width signal
 * code, fault address, RIP, and RSP fields, each qualified by report_flags. A
 * valid worker report is an execution result, so FAILED, EXITED, and SIGNALLED
 * still return SL_OK; other statuses describe parent-side validation, launch,
 * wait, or protocol errors.
 * Before guest execution, the worker normalizes inherited catchable signal
 * dispositions, installs its crash handlers, and starts with an empty signal
 * mask. The parent's signal dispositions and mask are left unchanged.
 * The caller must be single-threaded, must not have an active guest context,
 * must retain the default reapable SIGCHLD disposition, and must keep image,
 * mapped, and process alive and unchanged until return.
 */
sl_status sl_runtime_run_trusted_worker(const sl_pe_image *image,
                                        const sl_mapped_image *mapped,
                                        sl_win32_process *process,
                                        sl_runtime_report *report);

#endif
