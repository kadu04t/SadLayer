#define _GNU_SOURCE

#include "sadlayer/runtime.h"

#include "sadlayer/teb.h"
#include "sadlayer/win32.h"

#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define SL_SECTION_MEM_EXECUTE UINT32_C(0x20000000)
#define SL_RUNTIME_STACK_USABLE_SIZE (1024U * 1024U)
#define SL_RUNTIME_SIGNAL_STACK_USABLE_SIZE (128U * 1024U)
#define SL_RUNTIME_WIRE_MAGIC UINT32_C(0x57524c53)
#define SL_RUNTIME_WIRE_VERSION 2U
#define SL_RUNTIME_CRASH_EXIT_BASE 128
#define SL_RUNTIME_KERNEL_SIGNAL_COUNT 64

#if defined(__GNUC__) || defined(__clang__)
#define SL_RUNTIME_NO_SANITIZE                                             \
    __attribute__((no_sanitize("address", "undefined", "thread")))
#else
#define SL_RUNTIME_NO_SANITIZE
#endif

typedef uint32_t(SL_WINAPI *sl_guest_entry)(void);

typedef struct {
    uint8_t *mapping;
    size_t mapping_size;
    uint8_t *limit;
    uint8_t *base;
} sl_guarded_stack;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t size;
    uint32_t outcome;
    uint32_t worker_status;
    uint32_t return_value;
    uint32_t last_error;
    uint32_t process_id;
    int32_t exit_code;
    int32_t signal_number;
    uint32_t report_flags;
    int32_t signal_code;
    uint64_t fault_address;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
} sl_runtime_wire_report;

/* Linux x86-64 rt_sigaction uses a one-word kernel signal set. */
typedef uint64_t sl_runtime_kernel_signal_set;

typedef struct {
    uintptr_t handler;
    unsigned long flags;
    uintptr_t restorer;
    sl_runtime_kernel_signal_set mask;
} sl_runtime_kernel_sigaction;

typedef struct {
    const sl_pe_image *image;
    const sl_mapped_image *mapped;
    sl_win32_process *process;
    uintptr_t stack_limit;
    uintptr_t stack_base;
    uintptr_t signal_stack_limit;
    uintptr_t signal_stack_base;
    int read_fd;
    int write_fd;
} sl_runtime_worker_state;

typedef struct {
    volatile sig_atomic_t armed;
    volatile sig_atomic_t handling;
    volatile sig_atomic_t write_fd;
    volatile sig_atomic_t process_id;
    atomic_uintptr_t stack_limit;
    atomic_uintptr_t stack_base;
} sl_runtime_crash_handler_state;

static const int sl_runtime_crash_signals[] = {
    SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP,
};

static sl_runtime_crash_handler_state sl_runtime_crash_state;

_Static_assert(sizeof(sl_runtime_wire_report) <= PIPE_BUF,
               "runtime report must fit in one atomic pipe write");
_Static_assert(sizeof(sl_runtime_wire_report) == 72U,
               "runtime wire report layout changed");
_Static_assert(offsetof(sl_runtime_wire_report, report_flags) == 40U,
               "runtime wire flags offset changed");
_Static_assert(offsetof(sl_runtime_wire_report, signal_code) == 44U,
               "runtime wire signal-code offset changed");
_Static_assert(offsetof(sl_runtime_wire_report, fault_address) == 48U,
               "runtime wire fault offset changed");
_Static_assert(offsetof(sl_runtime_wire_report, instruction_pointer) == 56U,
               "runtime wire RIP offset changed");
_Static_assert(offsetof(sl_runtime_wire_report, stack_pointer) == 64U,
               "runtime wire RSP offset changed");
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2,
               "crash handler stack bounds require lock-free pointers");
_Static_assert(sizeof(sl_runtime_kernel_sigaction) == 32U,
               "unexpected Linux x86-64 sigaction layout");
_Static_assert(offsetof(sl_runtime_kernel_sigaction, flags) == 8U,
               "unexpected Linux x86-64 sigaction flags offset");
_Static_assert(offsetof(sl_runtime_kernel_sigaction, restorer) == 16U,
               "unexpected Linux x86-64 sigaction restorer offset");
_Static_assert(offsetof(sl_runtime_kernel_sigaction, mask) == 24U,
               "unexpected Linux x86-64 sigaction mask offset");

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

static sl_status validate_trusted_entry(const sl_pe_image *image,
                                        const sl_mapped_image *mapped) {
    if (image == NULL || mapped == NULL || !image->is_pe32_plus ||
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
    return SL_OK;
}

sl_status sl_runtime_call_trusted_entry(const sl_pe_image *image,
                                        const sl_mapped_image *mapped,
                                        sl_win32_thread_context *thread,
                                        uint32_t *result) {
    if (result != NULL) {
        *result = 0U;
    }
    if (thread == NULL || result == NULL || thread->process == NULL ||
        validate_trusted_entry(image, mapped) != SL_OK) {
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

static bool round_up_size(size_t value, size_t alignment, size_t *result) {
    size_t remainder = value & (alignment - 1U);
    if (remainder == 0U) {
        *result = value;
        return true;
    }
    size_t addition = alignment - remainder;
    if (value > SIZE_MAX - addition) {
        return false;
    }
    *result = value + addition;
    return true;
}

static sl_status create_guarded_stack(size_t requested_usable_size,
                                      sl_guarded_stack *stack) {
    memset(stack, 0, sizeof(*stack));
    long page_value = sysconf(_SC_PAGESIZE);
    if (page_value <= 0L || (unsigned long)page_value > SIZE_MAX) {
        return SL_ERROR_MEMORY_MAPPING;
    }
    size_t page_size = (size_t)page_value;
    if ((page_size & (page_size - 1U)) != 0U) {
        return SL_ERROR_MEMORY_MAPPING;
    }

    size_t usable_size = 0U;
    if (requested_usable_size == 0U ||
        !round_up_size(requested_usable_size, page_size, &usable_size) ||
        page_size > (SIZE_MAX - usable_size) / 2U) {
        return SL_ERROR_MEMORY_MAPPING;
    }
    size_t mapping_size = usable_size + page_size * 2U;
    uint8_t *mapping = mmap(NULL, mapping_size, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (mapping == MAP_FAILED) {
        return SL_ERROR_MEMORY_MAPPING;
    }
    uint8_t *limit = mapping + page_size;
    if (mprotect(limit, usable_size, PROT_READ | PROT_WRITE) != 0) {
        (void)munmap(mapping, mapping_size);
        return SL_ERROR_MEMORY_PROTECTION;
    }

    stack->mapping = mapping;
    stack->mapping_size = mapping_size;
    stack->limit = limit;
    stack->base = limit + usable_size;
    return SL_OK;
}

static void destroy_guarded_stack(sl_guarded_stack *stack) {
    if (stack->mapping != NULL && stack->mapping_size != 0U) {
        (void)munmap(stack->mapping, stack->mapping_size);
    }
    memset(stack, 0, sizeof(*stack));
}

static sl_status get_gs_base(uintptr_t *base) {
    unsigned long value = 0UL;
    if (syscall(SYS_arch_prctl, ARCH_GET_GS, &value) != 0) {
        return SL_ERROR_THREAD_ENVIRONMENT;
    }
    *base = (uintptr_t)value;
    return SL_OK;
}

static sl_status set_gs_base(uintptr_t base) {
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)base) != 0) {
        return SL_ERROR_THREAD_ENVIRONMENT;
    }
    return SL_OK;
}

static bool is_runtime_crash_signal(int signal_number) {
    for (size_t index = 0U;
         index < sizeof(sl_runtime_crash_signals) /
                     sizeof(sl_runtime_crash_signals[0]);
         ++index) {
        if (sl_runtime_crash_signals[index] == signal_number) {
            return true;
        }
    }
    return false;
}

static sl_status set_kernel_signal_mask(
    sl_runtime_kernel_signal_set mask,
    sl_runtime_kernel_signal_set *previous_mask) {
    /* The libc wrapper deliberately omits NPTL's reserved signals. */
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &mask, previous_mask,
                sizeof(mask)) != 0) {
        return SL_ERROR_THREAD_ENVIRONMENT;
    }
    return SL_OK;
}

static sl_status reset_worker_signal_environment(void) {
    sl_status status = set_kernel_signal_mask(UINT64_MAX, NULL);
    if (status != SL_OK) {
        return status;
    }

    const sl_runtime_kernel_sigaction default_action = {0};
    for (int signal_number = 1;
         signal_number <= SL_RUNTIME_KERNEL_SIGNAL_COUNT; ++signal_number) {
        /* Crash actions are replaced below through the libc/sanitizer shim. */
        if (signal_number == SIGKILL || signal_number == SIGSTOP ||
            is_runtime_crash_signal(signal_number)) {
            continue;
        }
        if (syscall(SYS_rt_sigaction, signal_number, &default_action, NULL,
                    sizeof(default_action.mask)) != 0) {
            return SL_ERROR_THREAD_ENVIRONMENT;
        }
    }
    return SL_OK;
}

static int runtime_crash_exit_code(int signal_number) {
    return SL_RUNTIME_CRASH_EXIT_BASE + signal_number;
}

/* Avoid libc/sanitizer interceptors while reporting from a corrupted worker. */
static SL_RUNTIME_NO_SANITIZE ssize_t runtime_crash_write(
    int fd, const void *buffer, size_t size) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "0"((long)SYS_write), "D"((long)fd), "S"(buffer),
                       "d"((long)size)
                     : "rcx", "r11", "memory");
    return (ssize_t)result;
}

static SL_RUNTIME_NO_SANITIZE _Noreturn void runtime_crash_exit(
    int exit_code) {
    __asm__ volatile("syscall"
                     :
                     : "a"((long)SYS_exit_group), "D"((long)exit_code)
                     : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static SL_RUNTIME_NO_SANITIZE void runtime_crash_signal_handler(
    int signal_number, siginfo_t *info, void *context_address) {
    int exit_code = SL_RUNTIME_CRASH_EXIT_BASE + signal_number;
    if (sl_runtime_crash_state.armed == 0 ||
        sl_runtime_crash_state.handling != 0) {
        runtime_crash_exit(exit_code);
    }
    sl_runtime_crash_state.handling = 1;

    uint64_t fault_address = 0U;
    int32_t signal_code = 0;
    uint32_t report_flags = 0U;
    if (info != NULL) {
        signal_code = (int32_t)info->si_code;
        report_flags |= SL_RUNTIME_REPORT_HAS_SIGNAL_CODE;
        if (info->si_code > 0 &&
            (signal_number == SIGBUS || signal_number == SIGFPE ||
             signal_number == SIGILL || signal_number == SIGSEGV ||
             signal_number == SIGTRAP)) {
            fault_address = (uint64_t)(uintptr_t)info->si_addr;
            report_flags |= SL_RUNTIME_REPORT_HAS_FAULT_ADDRESS;
        }
    }

    uint64_t instruction_pointer = 0U;
    uint64_t stack_pointer = 0U;
    if (context_address != NULL) {
        ucontext_t *context = context_address;
        instruction_pointer =
            (uint64_t)(uintptr_t)context->uc_mcontext.gregs[REG_RIP];
        stack_pointer =
            (uint64_t)(uintptr_t)context->uc_mcontext.gregs[REG_RSP];
        report_flags |= SL_RUNTIME_REPORT_HAS_CRASH_CONTEXT;
    }

    sl_runtime_wire_report wire;
    uintptr_t handler_address = (uintptr_t)&wire;
    uintptr_t alternate_limit = atomic_load_explicit(
        &sl_runtime_crash_state.stack_limit, memory_order_relaxed);
    uintptr_t alternate_base = atomic_load_explicit(
        &sl_runtime_crash_state.stack_base, memory_order_relaxed);
    if (handler_address >= alternate_limit &&
        handler_address < alternate_base) {
        report_flags |= SL_RUNTIME_REPORT_HANDLER_ON_ALTSTACK;
    }

    wire.magic = SL_RUNTIME_WIRE_MAGIC;
    wire.version = SL_RUNTIME_WIRE_VERSION;
    wire.size = (uint32_t)sizeof(wire);
    wire.outcome = SL_RUNTIME_OUTCOME_SIGNALLED;
    wire.worker_status = SL_OK;
    wire.return_value = 0U;
    wire.last_error = 0U;
    wire.process_id = (uint32_t)sl_runtime_crash_state.process_id;
    wire.exit_code = 0;
    wire.signal_number = (int32_t)signal_number;
    wire.report_flags = report_flags;
    wire.signal_code = signal_code;
    wire.fault_address = fault_address;
    wire.instruction_pointer = instruction_pointer;
    wire.stack_pointer = stack_pointer;

    ssize_t written = runtime_crash_write(
        (int)sl_runtime_crash_state.write_fd, &wire, sizeof(wire));
    (void)written;
    runtime_crash_exit(exit_code);
}

static sl_status install_worker_crash_reporting(
    uintptr_t signal_stack_limit, uintptr_t signal_stack_base, int write_fd,
    uint32_t process_id) {
    if (signal_stack_limit >= signal_stack_base || write_fd < 0) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    size_t signal_stack_size =
        (size_t)(signal_stack_base - signal_stack_limit);
#ifdef _SC_MINSIGSTKSZ
    long minimum_signal_stack_size = sysconf(_SC_MINSIGSTKSZ);
    if (minimum_signal_stack_size <= 0L ||
        (unsigned long)minimum_signal_stack_size > SIZE_MAX ||
        signal_stack_size < (size_t)minimum_signal_stack_size) {
        return SL_ERROR_THREAD_ENVIRONMENT;
    }
#endif

    stack_t alternate_stack = {
        .ss_sp = (void *)signal_stack_limit,
        .ss_size = signal_stack_size,
        .ss_flags = 0,
    };
    if (sigaltstack(&alternate_stack, NULL) != 0) {
        return SL_ERROR_THREAD_ENVIRONMENT;
    }

    sl_runtime_crash_state.armed = 0;
    sl_runtime_crash_state.handling = 0;
    sl_runtime_crash_state.write_fd = (sig_atomic_t)write_fd;
    sl_runtime_crash_state.process_id = (sig_atomic_t)process_id;
    atomic_store_explicit(&sl_runtime_crash_state.stack_limit,
                          signal_stack_limit, memory_order_relaxed);
    atomic_store_explicit(&sl_runtime_crash_state.stack_base,
                          signal_stack_base, memory_order_relaxed);

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = runtime_crash_signal_handler;
    action.sa_flags = (int)(SA_SIGINFO | SA_ONSTACK | SA_RESETHAND);
    if (sigfillset(&action.sa_mask) != 0) {
        return SL_ERROR_THREAD_ENVIRONMENT;
    }
    for (size_t index = 0U;
         index < sizeof(sl_runtime_crash_signals) /
                     sizeof(sl_runtime_crash_signals[0]);
         ++index) {
        if (sigaction(sl_runtime_crash_signals[index], &action, NULL) != 0) {
            return SL_ERROR_THREAD_ENVIRONMENT;
        }
    }

    sl_runtime_crash_state.armed = 1;
    if (set_kernel_signal_mask(0U, NULL) != SL_OK) {
        sl_runtime_crash_state.armed = 0;
        return SL_ERROR_THREAD_ENVIRONMENT;
    }
    return SL_OK;
}

static sl_status validate_parent_sigchld_state(void) {
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action) != 0 ||
        action.sa_handler != SIG_DFL ||
        (action.sa_flags & SA_NOCLDWAIT) != 0) {
        return SL_ERROR_THREAD_ENVIRONMENT;
    }
    return SL_OK;
}

static _Noreturn void write_worker_report_and_exit(
    int fd, const sl_runtime_wire_report *wire) {
    /* Block delivery before disarming so a preceding signal remains reportable. */
    if (set_kernel_signal_mask(UINT64_MAX, NULL) != SL_OK) {
        runtime_crash_exit(126);
    }
    sl_runtime_crash_state.armed = 0;
    ssize_t written = runtime_crash_write(fd, wire, sizeof(*wire));
    runtime_crash_exit(written == (ssize_t)sizeof(*wire) ? 0 : 126);
}

static int run_worker_child(void *opaque) {
    sl_runtime_worker_state *state = opaque;
    (void)close(state->read_fd);

    sl_runtime_wire_report wire = {
        .magic = SL_RUNTIME_WIRE_MAGIC,
        .version = SL_RUNTIME_WIRE_VERSION,
        .size = (uint32_t)sizeof(wire),
        .outcome = SL_RUNTIME_OUTCOME_NONE,
        .worker_status = SL_OK,
        .process_id = (uint32_t)getpid(),
    };
    sl_win32_thread_context thread = {
        .process = state->process,
        .last_error = 0U,
        .thread_id = wire.process_id,
    };
    sl_win32_teb *teb = NULL;
    bool attached = false;
    bool gs_change_attempted = false;
    bool gs_restore_verified = false;
    uintptr_t original_gs = 0U;
    uintptr_t installed_gs = 0U;
    uintptr_t restored_gs = 0U;
    sl_status status = reset_worker_signal_environment();
    if (status == SL_OK) {
        status = install_worker_crash_reporting(
            state->signal_stack_limit, state->signal_stack_base,
            state->write_fd, wire.process_id);
    }
    if (status == SL_OK) {
        status =
            sl_win32_process_set_image_base(state->process,
                                            state->mapped->load_base);
    }
    if (status == SL_OK) {
        status = sl_win32_teb_create(&thread, state->stack_limit,
                                     state->stack_base, &teb);
    }
    if (status == SL_OK) {
        status = sl_win32_thread_attach_teb(&thread, teb);
        attached = status == SL_OK;
    }
    if (status == SL_OK) {
        status = get_gs_base(&original_gs);
    }
    if (status == SL_OK) {
        gs_change_attempted = true;
        uintptr_t teb_base = (uintptr_t)sl_win32_teb_base(teb);
        status = set_gs_base(teb_base);
        if (status == SL_OK) {
            status = get_gs_base(&installed_gs);
            if (status == SL_OK && installed_gs != teb_base) {
                status = SL_ERROR_THREAD_ENVIRONMENT;
            }
        }
    }

    uint32_t result = 0U;
    if (status == SL_OK) {
        status = sl_runtime_call_trusted_entry(state->image, state->mapped,
                                               &thread, &result);
        wire.return_value = result;
        wire.last_error = *thread.last_error_address;
    }
    if (gs_change_attempted) {
        sl_status restore_status = set_gs_base(original_gs);
        if (restore_status == SL_OK) {
            restore_status = get_gs_base(&restored_gs);
            gs_restore_verified =
                restore_status == SL_OK && restored_gs == original_gs;
        }
        if (!gs_restore_verified) {
            status = SL_ERROR_THREAD_ENVIRONMENT;
        }
    }

    if (!gs_change_attempted || gs_restore_verified) {
        if (attached) {
            sl_status detach_status =
                sl_win32_thread_detach_teb(&thread, teb);
            attached = detach_status != SL_OK;
            if (status == SL_OK && detach_status != SL_OK) {
                status = detach_status;
            }
        }
        if (teb != NULL && !attached) {
            sl_status destroy_status = sl_win32_teb_destroy(teb);
            if (status == SL_OK && destroy_status != SL_OK) {
                status = destroy_status;
            }
        }
    }

    wire.worker_status = (uint32_t)status;
    if (status == SL_OK) {
        wire.outcome = SL_RUNTIME_OUTCOME_RETURNED;
    } else {
        wire.outcome = SL_RUNTIME_OUTCOME_FAILED;
    }
    write_worker_report_and_exit(state->write_fd, &wire);
}

static sl_status read_worker_report(int fd, sl_runtime_wire_report *wire,
                                    size_t *bytes_read, bool *has_extra_data) {
    *bytes_read = 0U;
    *has_extra_data = false;
    while (*bytes_read < sizeof(*wire)) {
        ssize_t result = read(fd, (uint8_t *)wire + *bytes_read,
                              sizeof(*wire) - *bytes_read);
        if (result > 0) {
            *bytes_read += (size_t)result;
            continue;
        }
        if (result == 0) {
            return SL_OK;
        }
        if (errno != EINTR) {
            return SL_ERROR_IO;
        }
    }
    uint8_t extra_byte = 0U;
    for (;;) {
        ssize_t result = read(fd, &extra_byte, sizeof(extra_byte));
        if (result > 0) {
            *has_extra_data = true;
            return SL_OK;
        }
        if (result == 0) {
            return SL_OK;
        }
        if (errno != EINTR) {
            return SL_ERROR_IO;
        }
    }
}

static sl_status wait_for_worker(pid_t process_id, int *wait_status) {
    pid_t result;
    do {
        result = waitpid(process_id, wait_status, 0);
    } while (result < 0 && errno == EINTR);
    return result == process_id ? SL_OK : SL_ERROR_IO;
}

static bool wire_report_is_valid(const sl_runtime_wire_report *wire,
                                 pid_t process_id) {
    if (wire->magic != SL_RUNTIME_WIRE_MAGIC ||
        wire->version != SL_RUNTIME_WIRE_VERSION ||
        wire->size != sizeof(*wire) ||
        wire->process_id != (uint32_t)process_id ||
        wire->worker_status > SL_ERROR_NOT_IMPLEMENTED) {
        return false;
    }
    if (wire->outcome == SL_RUNTIME_OUTCOME_RETURNED ||
        wire->outcome == SL_RUNTIME_OUTCOME_FAILED) {
        return wire->exit_code == 0 && wire->report_flags == 0U &&
               wire->signal_number == 0 && wire->signal_code == 0 &&
               wire->fault_address == 0U &&
               wire->instruction_pointer == 0U && wire->stack_pointer == 0U &&
               ((wire->outcome == SL_RUNTIME_OUTCOME_RETURNED &&
                 wire->worker_status == SL_OK) ||
                (wire->outcome == SL_RUNTIME_OUTCOME_FAILED &&
                 wire->worker_status != SL_OK));
    }
    const uint32_t required_flags =
        SL_RUNTIME_REPORT_HAS_CRASH_CONTEXT |
        SL_RUNTIME_REPORT_HAS_SIGNAL_CODE |
        SL_RUNTIME_REPORT_HANDLER_ON_ALTSTACK;
    const uint32_t allowed_flags =
        required_flags | SL_RUNTIME_REPORT_HAS_FAULT_ADDRESS;
    bool signal_has_fault_address =
        wire->signal_code > 0 &&
        (wire->signal_number == SIGBUS || wire->signal_number == SIGFPE ||
         wire->signal_number == SIGILL || wire->signal_number == SIGSEGV ||
         wire->signal_number == SIGTRAP);
    bool report_has_fault_address =
        (wire->report_flags & SL_RUNTIME_REPORT_HAS_FAULT_ADDRESS) != 0U;
    bool fault_address_is_consistent =
        signal_has_fault_address == report_has_fault_address &&
        (report_has_fault_address || wire->fault_address == 0U);
    return wire->outcome == SL_RUNTIME_OUTCOME_SIGNALLED &&
           wire->worker_status == SL_OK &&
           (wire->report_flags & required_flags) == required_flags &&
           (wire->report_flags & ~allowed_flags) == 0U &&
           fault_address_is_consistent &&
           wire->return_value == 0U && wire->last_error == 0U &&
           wire->exit_code == 0 &&
           is_runtime_crash_signal(wire->signal_number);
}

static bool wire_exit_status_is_valid(const sl_runtime_wire_report *wire,
                                      int wait_status) {
    int expected_exit_code = 0;
    if (wire->outcome == SL_RUNTIME_OUTCOME_SIGNALLED) {
        expected_exit_code = runtime_crash_exit_code(wire->signal_number);
    }
    return WIFEXITED(wait_status) &&
           WEXITSTATUS(wait_status) == expected_exit_code;
}

static void decode_wire_report(const sl_runtime_wire_report *wire,
                               sl_runtime_report *report) {
    report->outcome = (sl_runtime_outcome)wire->outcome;
    report->worker_status = (sl_status)wire->worker_status;
    report->return_value = wire->return_value;
    report->last_error = wire->last_error;
    report->worker_process_id = wire->process_id;
    report->exit_code = wire->exit_code;
    report->signal_number = wire->signal_number;
    report->report_flags = wire->report_flags;
    report->signal_code = wire->signal_code;
    report->fault_address = wire->fault_address;
    report->instruction_pointer = wire->instruction_pointer;
    report->stack_pointer = wire->stack_pointer;
}

sl_status sl_runtime_run_trusted_worker(const sl_pe_image *image,
                                        const sl_mapped_image *mapped,
                                        sl_win32_process *process,
                                        sl_runtime_report *report) {
    if (report == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    memset(report, 0, sizeof(*report));
    if (process == NULL || sl_win32_context_current() != NULL) {
        return SL_ERROR_INVALID_STATE;
    }
    sl_status status = validate_trusted_entry(image, mapped);
    if (status != SL_OK) {
        return status;
    }
    status = validate_parent_sigchld_state();
    if (status != SL_OK) {
        return status;
    }
    status = sl_win32_process_retain(process);
    if (status != SL_OK) {
        return status;
    }

    sl_guarded_stack stack;
    status = create_guarded_stack(SL_RUNTIME_STACK_USABLE_SIZE, &stack);
    if (status != SL_OK) {
        sl_win32_process_release(process);
        return status;
    }
    sl_guarded_stack signal_stack;
    status = create_guarded_stack(SL_RUNTIME_SIGNAL_STACK_USABLE_SIZE,
                                  &signal_stack);
    if (status != SL_OK) {
        destroy_guarded_stack(&stack);
        sl_win32_process_release(process);
        return status;
    }
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        destroy_guarded_stack(&signal_stack);
        destroy_guarded_stack(&stack);
        sl_win32_process_release(process);
        return SL_ERROR_IO;
    }

    sl_runtime_worker_state state = {
        .image = image,
        .mapped = mapped,
        .process = process,
        .stack_limit = (uintptr_t)stack.limit,
        .stack_base = (uintptr_t)stack.base,
        .signal_stack_limit = (uintptr_t)signal_stack.limit,
        .signal_stack_base = (uintptr_t)signal_stack.base,
        .read_fd = pipe_fds[0],
        .write_fd = pipe_fds[1],
    };
    sl_runtime_kernel_signal_set parent_signal_mask = 0U;
    status = set_kernel_signal_mask(UINT64_MAX, &parent_signal_mask);
    if (status != SL_OK) {
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        destroy_guarded_stack(&signal_stack);
        destroy_guarded_stack(&stack);
        sl_win32_process_release(process);
        return status;
    }
    int child = clone(run_worker_child, stack.base, SIGCHLD, &state);
    sl_status parent_mask_status =
        set_kernel_signal_mask(parent_signal_mask, NULL);
    if (child < 0) {
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        destroy_guarded_stack(&signal_stack);
        destroy_guarded_stack(&stack);
        sl_win32_process_release(process);
        if (parent_mask_status != SL_OK) {
            return parent_mask_status;
        }
        return SL_ERROR_PROCESS_CREATION;
    }
    (void)close(pipe_fds[1]);

    sl_runtime_wire_report wire = {0};
    size_t bytes_read = 0U;
    bool has_extra_data = false;
    sl_status read_status =
        read_worker_report(pipe_fds[0], &wire, &bytes_read, &has_extra_data);
    (void)close(pipe_fds[0]);
    int wait_status = 0;
    sl_status wait_status_result = wait_for_worker((pid_t)child, &wait_status);
    destroy_guarded_stack(&signal_stack);
    destroy_guarded_stack(&stack);
    sl_win32_process_release(process);

    report->worker_process_id = (uint32_t)child;
    if (parent_mask_status != SL_OK) {
        return parent_mask_status;
    }
    if (read_status != SL_OK) {
        return read_status;
    }
    if (wait_status_result != SL_OK) {
        return wait_status_result;
    }
    if (WIFSIGNALED(wait_status)) {
        if (bytes_read != 0U || has_extra_data) {
            return SL_ERROR_WORKER_PROTOCOL;
        }
        report->outcome = SL_RUNTIME_OUTCOME_SIGNALLED;
        report->signal_number = WTERMSIG(wait_status);
        return SL_OK;
    }
    if (!WIFEXITED(wait_status)) {
        return SL_ERROR_WORKER_PROTOCOL;
    }
    if (bytes_read == 0U) {
        report->outcome = SL_RUNTIME_OUTCOME_EXITED;
        report->exit_code = WEXITSTATUS(wait_status);
        return SL_OK;
    }
    if (bytes_read != sizeof(wire) || has_extra_data ||
        !wire_report_is_valid(&wire, (pid_t)child) ||
        !wire_exit_status_is_valid(&wire, wait_status)) {
        return SL_ERROR_WORKER_PROTOCOL;
    }
    decode_wire_report(&wire, report);
    return SL_OK;
}
