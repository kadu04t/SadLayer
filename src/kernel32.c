#define _GNU_SOURCE

#include "sadlayer/context.h"
#include "sadlayer/kernel32.h"
#include "sadlayer/process.h"
#include "sadlayer/unicode.h"

#include <limits.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <threads.h>
#include <unistd.h>

#if !defined(__x86_64__) || (!defined(__GNUC__) && !defined(__clang__))
#error "SadLayer native Win32 thunks currently require x86-64 GCC or Clang"
#endif

#define SL_ERROR_SUCCESS 0U
#define SL_ERROR_INVALID_FUNCTION 1U
#define SL_ERROR_INVALID_HANDLE 6U
#define SL_ERROR_NOT_ENOUGH_MEMORY 8U
#define SL_ERROR_WRITE_FAULT 29U
#define SL_ERROR_INVALID_PARAMETER 87U
#define SL_ERROR_INSUFFICIENT_BUFFER 122U
#define SL_ERROR_INVALID_FLAGS 1004U
#define SL_ERROR_NO_UNICODE_TRANSLATION 1113U
#define SL_HEAP_ZERO_MEMORY 0x00000008U
#define SL_HEAP_REALLOC_IN_PLACE_ONLY 0x00000010U
#define SL_HEAP_MAGIC UINT64_C(0x534c484541504d47)
#define SL_LOCAL_SLOT_COUNT SL_WIN32_LOCAL_SLOT_COUNT
#define SL_SLOT_FREE 0U
#define SL_SLOT_INITIALIZING 1U
#define SL_SLOT_ALLOCATED 2U
#define SL_FILETIME_UNIX_EPOCH_DELTA UINT64_C(11644473600)
#define SL_FILETIME_TICKS_PER_SECOND UINT64_C(10000000)
#define SL_CRITICAL_SECTION_MAGIC UINT64_C(0x534c435249544943)
#define SL_ENVIRONMENT_MAGIC UINT64_C(0x534c454e56424c4b)
#define SL_COMMAND_LINE_CAPACITY 32768U
#define SL_KERNEL32_EXPORT_CAPACITY 96U

#define SL_STD_INPUT_ID UINT32_C(0xfffffff6)
#define SL_STD_OUTPUT_ID UINT32_C(0xfffffff5)
#define SL_STD_ERROR_ID UINT32_C(0xfffffff4)
#define SL_STDIN_HANDLE ((uintptr_t)1U)
#define SL_STDOUT_HANDLE ((uintptr_t)2U)
#define SL_STDERR_HANDLE ((uintptr_t)3U)
#define SL_PROCESS_HEAP_HANDLE ((uintptr_t)4U)
#define SL_CURRENT_PROCESS_HANDLE UINTPTR_MAX

typedef union {
    max_align_t alignment;
    struct {
        uint64_t magic;
        size_t size;
    } metadata;
} sl_heap_header;

typedef union sl_environment_header sl_environment_header;

union sl_environment_header {
    max_align_t alignment;
    struct {
        uint64_t magic;
        size_t unit_count;
        sl_environment_header *next;
    } metadata;
};

typedef struct {
    atomic_uint state;
    atomic_uint_least64_t generation;
    atomic_uintptr_t callback_address;
} sl_local_slot;

typedef void(SL_WINAPI *sl_fls_callback)(void *value);

typedef struct {
    uint32_t cb;
    uint16_t *reserved;
    uint16_t *desktop;
    uint16_t *title;
    uint32_t x;
    uint32_t y;
    uint32_t x_size;
    uint32_t y_size;
    uint32_t x_count_chars;
    uint32_t y_count_chars;
    uint32_t fill_attribute;
    uint32_t flags;
    uint16_t show_window;
    uint16_t reserved2_size;
    uint8_t *reserved2;
    void *standard_input;
    void *standard_output;
    void *standard_error;
} sl_startup_info_w;

typedef struct {
    uint32_t max_char_size;
    uint8_t default_char[2];
    uint8_t lead_byte[12];
} sl_cp_info;

typedef struct {
    uint64_t magic;
    mtx_t mutex;
} sl_critical_section;

_Static_assert(sizeof(sl_win32_filetime) == 8U,
               "Windows FILETIME must contain exactly 64 bits");
_Static_assert(sizeof(sl_startup_info_w) == 104U,
               "Windows x64 STARTUPINFOW layout changed");
_Static_assert(sizeof(sl_cp_info) == 20U, "Windows CPINFO layout changed");

static _Thread_local uint32_t sl_fallback_last_error = SL_ERROR_SUCCESS;
static _Thread_local uint32_t sl_fallback_thread_id = 0U;
static _Thread_local sl_win32_local_value
    sl_fallback_tls_values[SL_LOCAL_SLOT_COUNT];
static _Thread_local sl_win32_local_value
    sl_fallback_fls_values[SL_LOCAL_SLOT_COUNT];
static atomic_uint_least32_t sl_next_thread_id = ATOMIC_VAR_INIT(1U);
static sl_local_slot sl_tls_slots[SL_LOCAL_SLOT_COUNT];
static sl_local_slot sl_fls_slots[SL_LOCAL_SLOT_COUNT];
static atomic_uintptr_t sl_standard_input = ATOMIC_VAR_INIT(SL_STDIN_HANDLE);
static atomic_uintptr_t sl_standard_output = ATOMIC_VAR_INIT(SL_STDOUT_HANDLE);
static atomic_uintptr_t sl_standard_error = ATOMIC_VAR_INIT(SL_STDERR_HANDLE);
static char sl_command_line_a[SL_COMMAND_LINE_CAPACITY];
static uint16_t sl_command_line_w[SL_COMMAND_LINE_CAPACITY];
static once_flag sl_environment_lock_once = ONCE_FLAG_INIT;
static mtx_t sl_environment_lock;
static sl_environment_header *sl_environment_blocks;

#ifdef SADLAYER_TESTING
static sl_kernel32_local_set_test_hook sl_local_set_test_hook;
static void *sl_local_set_test_context;

void sl_kernel32_test_set_local_set_hook(
    sl_kernel32_local_set_test_hook hook, void *context) {
    sl_local_set_test_hook = hook;
    sl_local_set_test_context = context;
}
#endif

extern char **environ;

static uint32_t *current_last_error(void) {
    sl_win32_thread_context *thread = sl_win32_context_current();
    if (thread == NULL) {
        return &sl_fallback_last_error;
    }
    return thread->last_error_address == NULL ? &thread->last_error
                                               : thread->last_error_address;
}

static sl_win32_local_value *current_tls_values(void) {
    sl_win32_thread_context *thread = sl_win32_context_current();
    return thread == NULL ? sl_fallback_tls_values : thread->tls_values;
}

static sl_win32_local_value *current_fls_values(void) {
    sl_win32_thread_context *thread = sl_win32_context_current();
    return thread == NULL ? sl_fallback_fls_values : thread->fls_values;
}

#define sl_last_error (*current_last_error())

static bool is_process_heap(const void *heap) {
    return (uintptr_t)heap == SL_PROCESS_HEAP_HANDLE;
}

static uint32_t next_thread_id(void) {
    uint32_t id = (uint32_t)atomic_fetch_add_explicit(
        &sl_next_thread_id, 1U, memory_order_relaxed);
    if (id == 0U) {
        id = (uint32_t)atomic_fetch_add_explicit(&sl_next_thread_id, 1U,
                                                 memory_order_relaxed);
    }
    return id;
}

uint32_t SL_WINAPI sl_kernel32_get_last_error(void) { return sl_last_error; }

void SL_WINAPI sl_kernel32_set_last_error(uint32_t error) {
    sl_last_error = error;
}

uint32_t SL_WINAPI sl_kernel32_get_current_process_id(void) {
    return (uint32_t)getpid();
}

uint32_t SL_WINAPI sl_kernel32_get_current_thread_id(void) {
    sl_win32_thread_context *thread = sl_win32_context_current();
    uint32_t *thread_id =
        thread == NULL ? &sl_fallback_thread_id : &thread->thread_id;
    if (*thread_id == 0U) {
        *thread_id = next_thread_id();
    }
    return *thread_id;
}

void *SL_WINAPI sl_kernel32_get_current_process(void) {
    return (void *)SL_CURRENT_PROCESS_HANDLE;
}

sl_win32_bool SL_WINAPI sl_kernel32_is_debugger_present(void) {
    return SL_WIN32_FALSE;
}

sl_win32_bool SL_WINAPI sl_kernel32_query_performance_counter(int64_t *counter) {
    if (counter == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        sl_last_error = SL_ERROR_INVALID_FUNCTION;
        return SL_WIN32_FALSE;
    }
    *counter = (int64_t)now.tv_sec * INT64_C(1000000000) + now.tv_nsec;
    return SL_WIN32_TRUE;
}

sl_win32_bool SL_WINAPI sl_kernel32_query_performance_frequency(
    int64_t *frequency) {
    if (frequency == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    *frequency = INT64_C(1000000000);
    return SL_WIN32_TRUE;
}

void SL_WINAPI sl_kernel32_get_system_time_as_file_time(
    sl_win32_filetime *filetime) {
    if (filetime == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        memset(filetime, 0, sizeof(*filetime));
        sl_last_error = SL_ERROR_INVALID_FUNCTION;
        return;
    }
    uint64_t ticks = ((uint64_t)now.tv_sec + SL_FILETIME_UNIX_EPOCH_DELTA) *
                         SL_FILETIME_TICKS_PER_SECOND +
                     (uint64_t)now.tv_nsec / 100U;
    filetime->low_date_time = (uint32_t)(ticks & UINT32_MAX);
    filetime->high_date_time = (uint32_t)(ticks >> 32U);
}

void *SL_WINAPI sl_kernel32_get_process_heap(void) {
    return (void *)SL_PROCESS_HEAP_HANDLE;
}

void *SL_WINAPI sl_kernel32_heap_alloc(void *heap, uint32_t flags,
                                       size_t bytes) {
    if (!is_process_heap(heap) || bytes > SIZE_MAX - sizeof(sl_heap_header)) {
        return NULL;
    }
    size_t payload_size = bytes == 0U ? 1U : bytes;
    if (payload_size > SIZE_MAX - sizeof(sl_heap_header)) {
        return NULL;
    }
    sl_heap_header *header = malloc(sizeof(*header) + payload_size);
    if (header == NULL) {
        return NULL;
    }
    header->metadata.magic = SL_HEAP_MAGIC;
    header->metadata.size = bytes;
    void *memory = header + 1;
    if ((flags & SL_HEAP_ZERO_MEMORY) != 0U) {
        memset(memory, 0, payload_size);
    }
    return memory;
}

static sl_heap_header *heap_header(void *memory) {
    if (memory == NULL) {
        return NULL;
    }
    return (sl_heap_header *)memory - 1;
}

sl_win32_bool SL_WINAPI sl_kernel32_heap_free(void *heap, uint32_t flags,
                                              void *memory) {
    (void)flags;
    if (!is_process_heap(heap) || memory == NULL) {
        return SL_WIN32_FALSE;
    }
    sl_heap_header *header = heap_header(memory);
    if (header->metadata.magic != SL_HEAP_MAGIC) {
        return SL_WIN32_FALSE;
    }
    header->metadata.magic = 0U;
    free(header);
    return SL_WIN32_TRUE;
}

void *SL_WINAPI sl_kernel32_heap_realloc(void *heap, uint32_t flags,
                                         void *memory, size_t bytes) {
    if (!is_process_heap(heap) || memory == NULL ||
        bytes > SIZE_MAX - sizeof(sl_heap_header)) {
        return NULL;
    }
    sl_heap_header *header = heap_header(memory);
    if (header->metadata.magic != SL_HEAP_MAGIC) {
        return NULL;
    }
    size_t old_size = header->metadata.size;
    if ((flags & SL_HEAP_REALLOC_IN_PLACE_ONLY) != 0U) {
        if (bytes > old_size) {
            return NULL;
        }
        header->metadata.size = bytes;
        return memory;
    }
    size_t payload_size = bytes == 0U ? 1U : bytes;
    sl_heap_header *resized =
        realloc(header, sizeof(*header) + payload_size);
    if (resized == NULL) {
        return NULL;
    }
    resized->metadata.magic = SL_HEAP_MAGIC;
    resized->metadata.size = bytes;
    void *result = resized + 1;
    if ((flags & SL_HEAP_ZERO_MEMORY) != 0U && bytes > old_size) {
        memset((uint8_t *)result + old_size, 0, bytes - old_size);
    }
    return result;
}

size_t SL_WINAPI sl_kernel32_heap_size(void *heap, uint32_t flags,
                                       const void *memory) {
    (void)flags;
    if (!is_process_heap(heap) || memory == NULL) {
        return SIZE_MAX;
    }
    const sl_heap_header *header = (const sl_heap_header *)memory - 1;
    if (header->metadata.magic != SL_HEAP_MAGIC) {
        return SIZE_MAX;
    }
    return header->metadata.size;
}

static uint32_t local_alloc(sl_local_slot slots[SL_LOCAL_SLOT_COUNT],
                            uintptr_t callback_address) {
    for (uint32_t index = 0U; index < SL_LOCAL_SLOT_COUNT; ++index) {
        unsigned int expected = SL_SLOT_FREE;
        if (atomic_compare_exchange_strong_explicit(
                &slots[index].state, &expected, SL_SLOT_INITIALIZING,
                memory_order_acq_rel, memory_order_relaxed)) {
            uint64_t generation = (uint64_t)atomic_fetch_add_explicit(
                                      &slots[index].generation, 1U,
                                      memory_order_relaxed) +
                                  1U;
            if (generation == 0U) {
                generation = (uint64_t)atomic_fetch_add_explicit(
                                 &slots[index].generation, 1U,
                                 memory_order_relaxed) +
                             1U;
            }
            atomic_store_explicit(&slots[index].callback_address,
                                  callback_address, memory_order_release);
            atomic_store_explicit(&slots[index].state, SL_SLOT_ALLOCATED,
                                  memory_order_release);
            return index;
        }
    }
    sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
    return SL_WIN32_TLS_OUT_OF_INDEXES;
}

static sl_win32_bool local_free(sl_local_slot slots[SL_LOCAL_SLOT_COUNT],
                                sl_win32_local_value
                                    values[SL_LOCAL_SLOT_COUNT],
                                uint32_t index, bool invoke_callback) {
    if (index >= SL_LOCAL_SLOT_COUNT) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    unsigned int expected = SL_SLOT_ALLOCATED;
    if (!atomic_compare_exchange_strong_explicit(
            &slots[index].state, &expected, SL_SLOT_INITIALIZING,
            memory_order_acq_rel, memory_order_relaxed)) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    uint64_t generation = (uint64_t)atomic_load_explicit(
        &slots[index].generation, memory_order_relaxed);
    void *value = values[index].generation == generation
                      ? values[index].value
                      : NULL;
    uintptr_t callback_address = atomic_load_explicit(
        &slots[index].callback_address, memory_order_acquire);
    values[index] = (sl_win32_local_value){NULL, 0U};
    atomic_store_explicit(&slots[index].callback_address, 0U,
                          memory_order_release);
    if (invoke_callback && callback_address != 0U && value != NULL) {
        sl_fls_callback callback = NULL;
        _Static_assert(sizeof(callback) <= sizeof(callback_address),
                       "FLS callback pointer does not fit uintptr_t");
        memcpy(&callback, &callback_address, sizeof(callback));
        callback(value);
    }
    atomic_store_explicit(&slots[index].state, SL_SLOT_FREE,
                          memory_order_release);
    return SL_WIN32_TRUE;
}

static bool local_generation(sl_local_slot *slot, uint64_t *generation) {
    for (;;) {
        uint64_t before = (uint64_t)atomic_load_explicit(
            &slot->generation, memory_order_acquire);
        if (atomic_load_explicit(&slot->state, memory_order_acquire) !=
            SL_SLOT_ALLOCATED) {
            return false;
        }
        uint64_t after = (uint64_t)atomic_load_explicit(
            &slot->generation, memory_order_acquire);
        if (before == after) {
            *generation = after;
            return true;
        }
    }
}

static void *local_get(sl_local_slot slots[SL_LOCAL_SLOT_COUNT],
                       sl_win32_local_value values[SL_LOCAL_SLOT_COUNT],
                       uint32_t index) {
    if (index >= SL_LOCAL_SLOT_COUNT) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return NULL;
    }

    uint64_t generation = 0U;
    if (!local_generation(&slots[index], &generation)) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return NULL;
    }
    void *value = values[index].generation == generation
                      ? values[index].value
                      : NULL;
    unsigned int expected = SL_SLOT_ALLOCATED;
    if (!atomic_compare_exchange_strong_explicit(
            &slots[index].state, &expected, SL_SLOT_ALLOCATED,
            memory_order_acquire, memory_order_relaxed) ||
        atomic_load_explicit(&slots[index].generation, memory_order_acquire) !=
            generation) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return NULL;
    }
    sl_last_error = SL_ERROR_SUCCESS;
    return value;
}

static sl_win32_bool local_set(sl_local_slot slots[SL_LOCAL_SLOT_COUNT],
                               sl_win32_local_value
                                   values[SL_LOCAL_SLOT_COUNT],
                               uint32_t index, void *value) {
    if (index >= SL_LOCAL_SLOT_COUNT) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }

    uint64_t generation = 0U;
    if (!local_generation(&slots[index], &generation)) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    values[index] = (sl_win32_local_value){
        .value = value,
        .generation = generation,
    };
#ifdef SADLAYER_TESTING
    if (sl_local_set_test_hook != NULL) {
        sl_local_set_test_hook(sl_local_set_test_context);
    }
#endif
    unsigned int expected = SL_SLOT_ALLOCATED;
    if (!atomic_compare_exchange_strong_explicit(
            &slots[index].state, &expected, SL_SLOT_ALLOCATED,
            memory_order_acquire, memory_order_relaxed) ||
        atomic_load_explicit(&slots[index].generation, memory_order_acquire) !=
            generation) {
        values[index] = (sl_win32_local_value){NULL, 0U};
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    return SL_WIN32_TRUE;
}

uint32_t SL_WINAPI sl_kernel32_tls_alloc(void) {
    return local_alloc(sl_tls_slots, 0U);
}

sl_win32_bool SL_WINAPI sl_kernel32_tls_free(uint32_t index) {
    return local_free(sl_tls_slots, current_tls_values(), index, false);
}

void *SL_WINAPI sl_kernel32_tls_get_value(uint32_t index) {
    return local_get(sl_tls_slots, current_tls_values(), index);
}

sl_win32_bool SL_WINAPI sl_kernel32_tls_set_value(uint32_t index, void *value) {
    return local_set(sl_tls_slots, current_tls_values(), index, value);
}

uint32_t SL_WINAPI sl_kernel32_fls_alloc(uintptr_t callback_address) {
    return local_alloc(sl_fls_slots, callback_address);
}

sl_win32_bool SL_WINAPI sl_kernel32_fls_free(uint32_t index) {
    return local_free(sl_fls_slots, current_fls_values(), index, true);
}

void *SL_WINAPI sl_kernel32_fls_get_value(uint32_t index) {
    return local_get(sl_fls_slots, current_fls_values(), index);
}

sl_win32_bool SL_WINAPI sl_kernel32_fls_set_value(uint32_t index, void *value) {
    return local_set(sl_fls_slots, current_fls_values(), index, value);
}

static sl_critical_section *critical_section_from_guest(void *guest) {
    sl_critical_section *critical = NULL;
    if (guest != NULL) {
        memcpy(&critical, guest, sizeof(critical));
    }
    return critical;
}

sl_win32_bool SL_WINAPI sl_kernel32_initialize_critical_section_and_spin_count(
    void *critical_section, uint32_t spin_count) {
    (void)spin_count;
    if (critical_section == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    sl_critical_section *internal = calloc(1U, sizeof(*internal));
    if (internal == NULL) {
        sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
        return SL_WIN32_FALSE;
    }
    if (mtx_init(&internal->mutex, mtx_recursive) != thrd_success) {
        free(internal);
        sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
        return SL_WIN32_FALSE;
    }
    internal->magic = SL_CRITICAL_SECTION_MAGIC;
    memset(critical_section, 0, 40U);
    memcpy(critical_section, &internal, sizeof(internal));
    return SL_WIN32_TRUE;
}

void SL_WINAPI sl_kernel32_enter_critical_section(void *critical_section) {
    sl_critical_section *internal =
        critical_section_from_guest(critical_section);
    if (internal == NULL || internal->magic != SL_CRITICAL_SECTION_MAGIC ||
        mtx_lock(&internal->mutex) != thrd_success) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
    }
}

void SL_WINAPI sl_kernel32_leave_critical_section(void *critical_section) {
    sl_critical_section *internal =
        critical_section_from_guest(critical_section);
    if (internal == NULL || internal->magic != SL_CRITICAL_SECTION_MAGIC ||
        mtx_unlock(&internal->mutex) != thrd_success) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
    }
}

void SL_WINAPI sl_kernel32_delete_critical_section(void *critical_section) {
    sl_critical_section *internal =
        critical_section_from_guest(critical_section);
    if (internal == NULL || internal->magic != SL_CRITICAL_SECTION_MAGIC) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return;
    }
    internal->magic = 0U;
    mtx_destroy(&internal->mutex);
    free(internal);
    memset(critical_section, 0, 40U);
}

sl_win32_bool SL_WINAPI sl_kernel32_is_processor_feature_present(
    uint32_t feature) {
    switch (feature) {
    case 2U:  /* PF_COMPARE_EXCHANGE_DOUBLE */
    case 3U:  /* PF_MMX_INSTRUCTIONS_AVAILABLE */
    case 6U:  /* PF_XMMI_INSTRUCTIONS_AVAILABLE */
    case 8U:  /* PF_RDTSC_INSTRUCTION_AVAILABLE */
    case 10U: /* PF_XMMI64_INSTRUCTIONS_AVAILABLE */
    case 12U: /* PF_NX_ENABLED */
        return SL_WIN32_TRUE;
    default:
        return SL_WIN32_FALSE;
    }
}

static void SL_WINAPI sl_kernel32_initialize_slist_head(void *list_head) {
    if (list_head != NULL) {
        memset(list_head, 0, 16U);
    }
}

static const sl_win32_process *current_process(void) {
    sl_win32_thread_context *thread = sl_win32_context_current();
    if (thread == NULL || thread->process == NULL) {
        /* The future guest dispatcher must install a process before handoff. */
        abort();
    }
    return thread->process;
}

static void *SL_WINAPI sl_kernel32_encode_pointer(void *pointer) {
    uintptr_t encoded = sl_win32_process_encode_pointer(
        current_process(), (uintptr_t)pointer);
    return (void *)encoded;
}

static void *SL_WINAPI sl_kernel32_decode_pointer(void *pointer) {
    uintptr_t decoded = sl_win32_process_decode_pointer(
        current_process(), (uintptr_t)pointer);
    return (void *)decoded;
}

static uint32_t SL_WINAPI sl_kernel32_get_acp(void) { return 1252U; }

static uint32_t SL_WINAPI sl_kernel32_get_oemcp(void) { return 437U; }

static uint32_t SL_WINAPI sl_kernel32_get_console_output_cp(void) {
    return 65001U;
}

static sl_win32_bool SL_WINAPI sl_kernel32_is_valid_code_page(uint32_t page) {
    return page == SL_WIN32_CP_ACP || page == SL_WIN32_CP_OEMCP ||
           page == SL_WIN32_CP_THREAD_ACP || page == 437U ||
           page == SL_WIN32_CP_UTF8 || page == 1252U;
}

static uint32_t normalize_code_page(uint32_t code_page) {
    if (code_page == SL_WIN32_CP_ACP ||
        code_page == SL_WIN32_CP_THREAD_ACP) {
        return 1252U;
    }
    if (code_page == SL_WIN32_CP_OEMCP) {
        return 437U;
    }
    return code_page;
}

static const uint16_t sl_cp1252_extension[32] = {
    0x20acU, 0xffffU, 0x201aU, 0x0192U, 0x201eU, 0x2026U, 0x2020U,
    0x2021U, 0x02c6U, 0x2030U, 0x0160U, 0x2039U, 0x0152U, 0xffffU,
    0x017dU, 0xffffU, 0xffffU, 0x2018U, 0x2019U, 0x201cU, 0x201dU,
    0x2022U, 0x2013U, 0x2014U, 0x02dcU, 0x2122U, 0x0161U, 0x203aU,
    0x0153U, 0xffffU, 0x017eU, 0x0178U,
};

static const uint16_t sl_cp437_extension[128] = {
    0x00c7U, 0x00fcU, 0x00e9U, 0x00e2U, 0x00e4U, 0x00e0U, 0x00e5U,
    0x00e7U, 0x00eaU, 0x00ebU, 0x00e8U, 0x00efU, 0x00eeU, 0x00ecU,
    0x00c4U, 0x00c5U, 0x00c9U, 0x00e6U, 0x00c6U, 0x00f4U, 0x00f6U,
    0x00f2U, 0x00fbU, 0x00f9U, 0x00ffU, 0x00d6U, 0x00dcU, 0x00a2U,
    0x00a3U, 0x00a5U, 0x20a7U, 0x0192U, 0x00e1U, 0x00edU, 0x00f3U,
    0x00faU, 0x00f1U, 0x00d1U, 0x00aaU, 0x00baU, 0x00bfU, 0x2310U,
    0x00acU, 0x00bdU, 0x00bcU, 0x00a1U, 0x00abU, 0x00bbU, 0x2591U,
    0x2592U, 0x2593U, 0x2502U, 0x2524U, 0x2561U, 0x2562U, 0x2556U,
    0x2555U, 0x2563U, 0x2551U, 0x2557U, 0x255dU, 0x255cU, 0x255bU,
    0x2510U, 0x2514U, 0x2534U, 0x252cU, 0x251cU, 0x2500U, 0x253cU,
    0x255eU, 0x255fU, 0x255aU, 0x2554U, 0x2569U, 0x2566U, 0x2560U,
    0x2550U, 0x256cU, 0x2567U, 0x2568U, 0x2564U, 0x2565U, 0x2559U,
    0x2558U, 0x2552U, 0x2553U, 0x256bU, 0x256aU, 0x2518U, 0x250cU,
    0x2588U, 0x2584U, 0x258cU, 0x2590U, 0x2580U, 0x03b1U, 0x00dfU,
    0x0393U, 0x03c0U, 0x03a3U, 0x03c3U, 0x00b5U, 0x03c4U, 0x03a6U,
    0x0398U, 0x03a9U, 0x03b4U, 0x221eU, 0x03c6U, 0x03b5U, 0x2229U,
    0x2261U, 0x00b1U, 0x2265U, 0x2264U, 0x2320U, 0x2321U, 0x00f7U,
    0x2248U, 0x00b0U, 0x2219U, 0x00b7U, 0x221aU, 0x207fU, 0x00b2U,
    0x25a0U, 0x00a0U,
};

static bool single_byte_to_utf16(uint32_t code_page, uint8_t byte,
                                 uint16_t *unit) {
    if (byte < 0x80U) {
        *unit = byte;
        return true;
    }
    if (code_page == 437U) {
        *unit = sl_cp437_extension[byte - 0x80U];
        return true;
    }
    if (byte < 0xa0U) {
        uint16_t mapped = sl_cp1252_extension[byte - 0x80U];
        if (mapped == 0xffffU) {
            return false;
        }
        *unit = mapped;
        return true;
    }
    *unit = byte;
    return true;
}

static bool utf16_to_single_byte(uint32_t code_page, uint32_t codepoint,
                                 uint8_t *byte) {
    if (codepoint < 0x80U) {
        *byte = (uint8_t)codepoint;
        return true;
    }
    if (code_page == 437U) {
        for (size_t index = 0U;
             index < sizeof(sl_cp437_extension) / sizeof(sl_cp437_extension[0]);
             ++index) {
            if (sl_cp437_extension[index] == codepoint) {
                *byte = (uint8_t)(index + 0x80U);
                return true;
            }
        }
        return false;
    }
    if (codepoint >= 0xa0U && codepoint <= 0xffU) {
        *byte = (uint8_t)codepoint;
        return true;
    }
    for (size_t index = 0U;
         index < sizeof(sl_cp1252_extension) / sizeof(sl_cp1252_extension[0]);
         ++index) {
        if (sl_cp1252_extension[index] == codepoint) {
            *byte = (uint8_t)(index + 0x80U);
            return true;
        }
    }
    return false;
}

static bool byte_source_length(const char *source, int32_t source_length,
                               size_t *length) {
    if (source == NULL || source_length == 0 || source_length < -1) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return false;
    }
    if (source_length == -1) {
        size_t measured = strlen(source);
        if (measured >= (size_t)INT32_MAX) {
            sl_last_error = SL_ERROR_INVALID_PARAMETER;
            return false;
        }
        *length = measured + 1U;
    } else {
        *length = (size_t)source_length;
    }
    return true;
}

static bool wide_source_length(const uint16_t *source, int32_t source_length,
                               size_t *length) {
    if (source == NULL || source_length == 0 || source_length < -1) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return false;
    }
    if (source_length == -1) {
        size_t measured = 0U;
        while (source[measured] != 0U) {
            if (measured >= (size_t)INT32_MAX - 1U) {
                sl_last_error = SL_ERROR_INVALID_PARAMETER;
                return false;
            }
            ++measured;
        }
        *length = measured + 1U;
    } else {
        *length = (size_t)source_length;
    }
    return true;
}

int32_t SL_WINAPI sl_kernel32_multi_byte_to_wide_char(
    uint32_t code_page, uint32_t flags, const char *source,
    int32_t source_length, uint16_t *destination, int32_t destination_capacity) {
    uint32_t normalized = normalize_code_page(code_page);
    bool is_utf8 = normalized == SL_WIN32_CP_UTF8;
    if ((flags & ~SL_WIN32_MB_ERR_INVALID_CHARS) != 0U) {
        sl_last_error = SL_ERROR_INVALID_FLAGS;
        return 0;
    }
    if ((normalized != 437U && normalized != 1252U && !is_utf8) ||
        destination_capacity < 0 ||
        (destination == NULL && destination_capacity != 0) ||
        (destination != NULL &&
         (const void *)source == (const void *)destination)) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return 0;
    }

    size_t input_length = 0U;
    if (!byte_source_length(source, source_length, &input_length)) {
        return 0;
    }
    size_t required = input_length;
    if (is_utf8) {
        sl_status status = (flags & SL_WIN32_MB_ERR_INVALID_CHARS) != 0U
                               ? sl_utf8_to_utf16(source, input_length, NULL,
                                                 0U, &required)
                               : sl_utf8_to_utf16_lossy(
                                     source, input_length, NULL, 0U, &required);
        if (status != SL_OK) {
            sl_last_error = status == SL_ERROR_INVALID_ENCODING
                                ? SL_ERROR_NO_UNICODE_TRANSLATION
                                : SL_ERROR_INVALID_PARAMETER;
            return 0;
        }
    } else {
        for (size_t index = 0U; index < input_length; ++index) {
            uint16_t unit = 0U;
            if (!single_byte_to_utf16(
                    normalized, (uint8_t)(unsigned char)source[index], &unit) &&
                (flags & SL_WIN32_MB_ERR_INVALID_CHARS) != 0U) {
                sl_last_error = SL_ERROR_NO_UNICODE_TRANSLATION;
                return 0;
            }
        }
    }
    if (required > (size_t)INT32_MAX) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return 0;
    }
    if (destination_capacity == 0) {
        return (int32_t)required;
    }
    if ((size_t)destination_capacity < required) {
        sl_last_error = SL_ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }

    if (is_utf8) {
        size_t written = 0U;
        sl_status status = (flags & SL_WIN32_MB_ERR_INVALID_CHARS) != 0U
                               ? sl_utf8_to_utf16(
                                     source, input_length, destination,
                                     (size_t)destination_capacity, &written)
                               : sl_utf8_to_utf16_lossy(
                                     source, input_length, destination,
                                     (size_t)destination_capacity, &written);
        if (status != SL_OK || written != required) {
            sl_last_error = status == SL_ERROR_INVALID_ENCODING
                                ? SL_ERROR_NO_UNICODE_TRANSLATION
                                : SL_ERROR_INVALID_PARAMETER;
            return 0;
        }
    } else {
        for (size_t index = 0U; index < input_length; ++index) {
            uint16_t unit = 0xfffdU;
            (void)single_byte_to_utf16(
                normalized, (uint8_t)(unsigned char)source[index], &unit);
            destination[index] = unit;
        }
    }
    return (int32_t)required;
}

static bool decode_wide_codepoint(const uint16_t *source, size_t length,
                                  size_t offset, uint32_t *codepoint,
                                  size_t *consumed) {
    uint32_t first = source[offset];
    if (first >= 0xd800U && first <= 0xdbffU) {
        if (offset + 1U >= length) {
            return false;
        }
        uint32_t second = source[offset + 1U];
        if (second < 0xdc00U || second > 0xdfffU) {
            return false;
        }
        *codepoint = 0x10000U + ((first - 0xd800U) << 10U) +
                     (second - 0xdc00U);
        *consumed = 2U;
        return true;
    }
    if (first >= 0xdc00U && first <= 0xdfffU) {
        return false;
    }
    *codepoint = first;
    *consumed = 1U;
    return true;
}

static bool single_byte_required(const uint16_t *source, size_t source_length,
                                 size_t *required) {
    size_t input = 0U;
    size_t output = 0U;
    while (input < source_length) {
        uint32_t codepoint = 0U;
        size_t consumed = 1U;
        if (!decode_wide_codepoint(source, source_length, input, &codepoint,
                                   &consumed)) {
            consumed = 1U;
        }
        ++output;
        input += consumed;
    }
    *required = output;
    return output <= (size_t)INT32_MAX;
}

int32_t SL_WINAPI sl_kernel32_wide_char_to_multi_byte(
    uint32_t code_page, uint32_t flags, const uint16_t *source,
    int32_t source_length, char *destination, int32_t destination_capacity,
    const char *default_character, sl_win32_bool *used_default_character) {
    uint32_t normalized = normalize_code_page(code_page);
    bool is_utf8 = normalized == SL_WIN32_CP_UTF8;
    if ((is_utf8 && (flags & ~SL_WIN32_WC_ERR_INVALID_CHARS) != 0U) ||
        (!is_utf8 && flags != 0U)) {
        sl_last_error = SL_ERROR_INVALID_FLAGS;
        return 0;
    }
    if ((normalized != 437U && normalized != 1252U && !is_utf8) ||
        destination_capacity < 0 ||
        (destination == NULL && destination_capacity != 0) ||
        (destination != NULL &&
         (const void *)source == (const void *)destination) ||
        (is_utf8 &&
         (default_character != NULL || used_default_character != NULL))) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return 0;
    }

    size_t input_length = 0U;
    if (!wide_source_length(source, source_length, &input_length)) {
        return 0;
    }
    size_t required = 0U;
    if (is_utf8) {
        sl_status status = (flags & SL_WIN32_WC_ERR_INVALID_CHARS) != 0U
                               ? sl_utf16_to_utf8(source, input_length, NULL,
                                                 0U, &required)
                               : sl_utf16_to_utf8_lossy(
                                     source, input_length, NULL, 0U, &required);
        if (status != SL_OK) {
            sl_last_error = status == SL_ERROR_INVALID_ENCODING
                                ? SL_ERROR_NO_UNICODE_TRANSLATION
                                : SL_ERROR_INVALID_PARAMETER;
            return 0;
        }
    } else if (!single_byte_required(source, input_length, &required)) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return 0;
    }
    if (required > (size_t)INT32_MAX) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return 0;
    }
    if (destination_capacity == 0) {
        return (int32_t)required;
    }
    if ((size_t)destination_capacity < required) {
        sl_last_error = SL_ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }

    if (is_utf8) {
        size_t written = 0U;
        sl_status status = (flags & SL_WIN32_WC_ERR_INVALID_CHARS) != 0U
                               ? sl_utf16_to_utf8(
                                     source, input_length, destination,
                                     (size_t)destination_capacity, &written)
                               : sl_utf16_to_utf8_lossy(
                                     source, input_length, destination,
                                     (size_t)destination_capacity, &written);
        if (status != SL_OK || written != required) {
            sl_last_error = status == SL_ERROR_INVALID_ENCODING
                                ? SL_ERROR_NO_UNICODE_TRANSLATION
                                : SL_ERROR_INVALID_PARAMETER;
            return 0;
        }
        return (int32_t)required;
    }

    bool used_default = false;
    uint8_t replacement = default_character == NULL
                              ? (uint8_t)'?'
                              : (uint8_t)(unsigned char)default_character[0];
    size_t input = 0U;
    size_t output = 0U;
    while (input < input_length) {
        uint32_t codepoint = 0U;
        size_t consumed = 1U;
        bool valid = decode_wide_codepoint(source, input_length, input,
                                           &codepoint, &consumed);
        uint8_t byte = replacement;
        if (!valid || !utf16_to_single_byte(normalized, codepoint, &byte)) {
            used_default = true;
        }
        destination[output++] = (char)byte;
        input += consumed;
    }
    if (used_default_character != NULL) {
        *used_default_character = used_default ? SL_WIN32_TRUE : SL_WIN32_FALSE;
    }
    return (int32_t)required;
}

sl_status sl_kernel32_set_command_line_utf8(const char *command_line) {
    if (command_line == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    size_t source_length = strlen(command_line);
    size_t wide_length = 0U;
    sl_status status = sl_utf8_to_utf16(command_line, source_length, NULL, 0U,
                                        &wide_length);
    if (status != SL_OK || wide_length >= SL_COMMAND_LINE_CAPACITY) {
        return status == SL_OK ? SL_ERROR_BUFFER_TOO_SMALL : status;
    }

    uint16_t *wide = calloc(wide_length + 1U, sizeof(*wide));
    char *ansi = calloc(wide_length + 1U, sizeof(*ansi));
    if (wide == NULL || ansi == NULL) {
        free(ansi);
        free(wide);
        return SL_ERROR_OUT_OF_MEMORY;
    }
    size_t written = 0U;
    status = sl_utf8_to_utf16(command_line, source_length, wide, wide_length,
                              &written);
    if (status == SL_OK && written == wide_length) {
        size_t input = 0U;
        size_t output = 0U;
        while (input < wide_length) {
            uint32_t codepoint = 0U;
            size_t consumed = 0U;
            if (!decode_wide_codepoint(wide, wide_length, input, &codepoint,
                                       &consumed)) {
                status = SL_ERROR_INVALID_ENCODING;
                break;
            }
            uint8_t byte = (uint8_t)'?';
            (void)utf16_to_single_byte(1252U, codepoint, &byte);
            ansi[output++] = (char)byte;
            input += consumed;
        }
        if (status == SL_OK) {
            memset(sl_command_line_a, 0, sizeof(sl_command_line_a));
            memset(sl_command_line_w, 0, sizeof(sl_command_line_w));
            memcpy(sl_command_line_a, ansi, output);
            memcpy(sl_command_line_w, wide, wide_length * sizeof(*wide));
        }
    }
    free(ansi);
    free(wide);
    return status;
}

char *SL_WINAPI sl_kernel32_get_command_line_a(void) {
    return sl_command_line_a;
}

uint16_t *SL_WINAPI sl_kernel32_get_command_line_w(void) {
    return sl_command_line_w;
}

static bool sl_environment_lock_ready;

static void initialize_environment_lock(void) {
    sl_environment_lock_ready =
        mtx_init(&sl_environment_lock, mtx_plain) == thrd_success;
}

static unsigned char fold_environment_byte(unsigned char byte) {
    if (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') {
        return (unsigned char)(byte + ((unsigned char)'a' -
                                      (unsigned char)'A'));
    }
    return byte;
}

static int compare_environment_entries(const void *left_pointer,
                                       const void *right_pointer) {
    const char *left = *(const char *const *)left_pointer;
    const char *right = *(const char *const *)right_pointer;
    const char *left_cursor = left;
    const char *right_cursor = right;
    while (*left_cursor != '\0' && *right_cursor != '\0') {
        unsigned char left_byte =
            fold_environment_byte((unsigned char)*left_cursor);
        unsigned char right_byte =
            fold_environment_byte((unsigned char)*right_cursor);
        if (left_byte != right_byte) {
            return left_byte < right_byte ? -1 : 1;
        }
        ++left_cursor;
        ++right_cursor;
    }
    if (*left_cursor != *right_cursor) {
        return *left_cursor == '\0' ? -1 : 1;
    }
    return strcmp(left, right);
}

uint16_t *SL_WINAPI sl_kernel32_get_environment_strings_w(void) {
    size_t entry_count = 0U;
    if (environ != NULL) {
        for (char **entry = environ; *entry != NULL; ++entry) {
            if (entry_count == SIZE_MAX / sizeof(char *)) {
                sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
                return NULL;
            }
            ++entry_count;
        }
    }

    char **entries = NULL;
    if (entry_count != 0U) {
        entries = malloc(entry_count * sizeof(*entries));
        if (entries == NULL) {
            sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
            return NULL;
        }
        for (size_t index = 0U; index < entry_count; ++index) {
            entries[index] = environ[index];
        }
        qsort(entries, entry_count, sizeof(*entries),
              compare_environment_entries);
    }

    size_t total_units = 1U;
    for (size_t index = 0U; index < entry_count; ++index) {
        size_t units = 0U;
        sl_status status = sl_utf8_to_utf16(
            entries[index], strlen(entries[index]), NULL, 0U, &units);
        if (status != SL_OK || units == SIZE_MAX ||
            total_units > SIZE_MAX - units - 1U) {
            free(entries);
            sl_last_error = status == SL_ERROR_INVALID_ENCODING
                                ? SL_ERROR_NO_UNICODE_TRANSLATION
                                : SL_ERROR_NOT_ENOUGH_MEMORY;
            return NULL;
        }
        total_units += units + 1U;
    }
    if (entry_count == 0U) {
        total_units = 2U;
    }
    if (total_units >
        (SIZE_MAX - sizeof(sl_environment_header)) / sizeof(uint16_t)) {
        free(entries);
        sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    sl_environment_header *header =
        calloc(1U, sizeof(*header) + total_units * sizeof(uint16_t));
    if (header == NULL) {
        free(entries);
        sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    header->metadata.magic = SL_ENVIRONMENT_MAGIC;
    header->metadata.unit_count = total_units;
    uint16_t *block = (uint16_t *)(header + 1);
    size_t offset = 0U;
    for (size_t index = 0U; index < entry_count; ++index) {
        size_t written = 0U;
        sl_status status = sl_utf8_to_utf16(
            entries[index], strlen(entries[index]), block + offset,
            total_units - offset - 1U, &written);
        if (status != SL_OK || written >= total_units - offset) {
            header->metadata.magic = 0U;
            free(header);
            free(entries);
            sl_last_error = status == SL_ERROR_INVALID_ENCODING
                                ? SL_ERROR_NO_UNICODE_TRANSLATION
                                : SL_ERROR_NOT_ENOUGH_MEMORY;
            return NULL;
        }
        offset += written + 1U;
    }
    free(entries);
    block[offset] = 0U;

    call_once(&sl_environment_lock_once, initialize_environment_lock);
    if (!sl_environment_lock_ready ||
        mtx_lock(&sl_environment_lock) != thrd_success) {
        header->metadata.magic = 0U;
        free(header);
        sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    header->metadata.next = sl_environment_blocks;
    sl_environment_blocks = header;
    (void)mtx_unlock(&sl_environment_lock);
    return block;
}

sl_win32_bool SL_WINAPI sl_kernel32_free_environment_strings_w(
    uint16_t *environment) {
    if (environment == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }

    call_once(&sl_environment_lock_once, initialize_environment_lock);
    if (!sl_environment_lock_ready ||
        mtx_lock(&sl_environment_lock) != thrd_success) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    sl_environment_header **link = &sl_environment_blocks;
    while (*link != NULL && (uint16_t *)(*link + 1) != environment) {
        link = &(*link)->metadata.next;
    }
    if (*link == NULL) {
        (void)mtx_unlock(&sl_environment_lock);
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    sl_environment_header *header = *link;
    *link = header->metadata.next;
    header->metadata.magic = 0U;
    header->metadata.next = NULL;
    (void)mtx_unlock(&sl_environment_lock);
    free(header);
    return SL_WIN32_TRUE;
}

static bool locale_source_length(const uint16_t *source, int32_t source_length,
                                 size_t *length) {
    if (source == NULL || source_length == 0) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return false;
    }
    if (source_length < 0) {
        size_t measured = 0U;
        while (source[measured] != 0U) {
            if (measured >= (size_t)INT32_MAX - 1U) {
                sl_last_error = SL_ERROR_INVALID_PARAMETER;
                return false;
            }
            ++measured;
        }
        *length = measured + 1U;
    } else {
        *length = (size_t)source_length;
    }
    return true;
}

static bool is_supported_ctype1_unit(uint16_t unit) {
    if (unit <= 0x00ffU) {
        return true;
    }
    switch (unit) {
    case 0x0152U:
    case 0x0153U:
    case 0x0160U:
    case 0x0161U:
    case 0x0178U:
    case 0x017dU:
    case 0x017eU:
    case 0x0192U:
    case 0x02c6U:
    case 0x02dcU:
    case 0x2013U:
    case 0x2014U:
    case 0x2018U:
    case 0x2019U:
    case 0x201aU:
    case 0x201cU:
    case 0x201dU:
    case 0x201eU:
    case 0x2020U:
    case 0x2021U:
    case 0x2022U:
    case 0x2026U:
    case 0x2030U:
    case 0x2039U:
    case 0x203aU:
    case 0x20acU:
    case 0x2122U:
        return true;
    default:
        return false;
    }
}

static uint16_t classify_ctype1(uint16_t unit) {
    bool ascii_upper = unit >= (uint16_t)'A' && unit <= (uint16_t)'Z';
    bool ascii_lower = unit >= (uint16_t)'a' && unit <= (uint16_t)'z';
    bool latin_upper = (unit >= 0x00c0U && unit <= 0x00d6U) ||
                       (unit >= 0x00d8U && unit <= 0x00deU) || unit == 0x0152U ||
                       unit == 0x0160U || unit == 0x0178U || unit == 0x017dU;
    bool latin_lower = unit == 0x00aaU || unit == 0x00b5U ||
                       unit == 0x00baU ||
                       (unit >= 0x00dfU && unit <= 0x00f6U) ||
                       (unit >= 0x00f8U && unit <= 0x00ffU) || unit == 0x0153U ||
                       unit == 0x0161U || unit == 0x017eU || unit == 0x0192U;
    bool digit = unit >= (uint16_t)'0' && unit <= (uint16_t)'9';
    bool control = unit <= 0x001fU ||
                   (unit >= 0x007fU && unit <= 0x009fU);
    bool space = unit == (uint16_t)' ' ||
                 (unit >= 0x0009U && unit <= 0x000dU) || unit == 0x0085U ||
                 unit == 0x00a0U;
    bool blank = unit == (uint16_t)' ' || unit == (uint16_t)'\t' ||
                 unit == 0x00a0U;
    bool punctuation =
        (unit >= (uint16_t)'!' && unit <= (uint16_t)'/') ||
        (unit >= (uint16_t)':' && unit <= (uint16_t)'@') ||
        (unit >= (uint16_t)'[' && unit <= (uint16_t)'`') ||
        (unit >= (uint16_t)'{' && unit <= (uint16_t)'~') ||
        (unit >= 0x00a1U && !latin_upper && !latin_lower && !space);
    bool hex_digit = digit || (unit >= (uint16_t)'A' && unit <= (uint16_t)'F') ||
                     (unit >= (uint16_t)'a' && unit <= (uint16_t)'f');
    bool defined = !(unit >= 0xd800U && unit <= 0xdfffU) && unit != 0xfffeU &&
                   unit != 0xffffU;

    uint16_t result = 0U;
    if (ascii_upper || latin_upper) {
        result |= SL_WIN32_C1_UPPER | SL_WIN32_C1_ALPHA;
    }
    if (ascii_lower || latin_lower) {
        result |= SL_WIN32_C1_LOWER | SL_WIN32_C1_ALPHA;
    }
    if (digit) {
        result |= SL_WIN32_C1_DIGIT;
    }
    if (space) {
        result |= SL_WIN32_C1_SPACE;
    }
    if (punctuation) {
        result |= SL_WIN32_C1_PUNCT;
    }
    if (control) {
        result |= SL_WIN32_C1_CNTRL;
    }
    if (blank) {
        result |= SL_WIN32_C1_BLANK;
    }
    if (hex_digit) {
        result |= SL_WIN32_C1_XDIGIT;
    }
    if (defined && result == 0U) {
        result |= SL_WIN32_C1_DEFINED;
    }
    return result;
}

sl_win32_bool SL_WINAPI sl_kernel32_get_string_type_w(
    uint32_t information_type, const uint16_t *source, int32_t source_length,
    uint16_t *character_types) {
    if (information_type != SL_WIN32_CT_CTYPE1) {
        sl_last_error = SL_ERROR_INVALID_FLAGS;
        return SL_WIN32_FALSE;
    }
    if (character_types == NULL ||
        (const void *)source == (const void *)character_types) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    size_t length = 0U;
    if (!locale_source_length(source, source_length, &length)) {
        return SL_WIN32_FALSE;
    }
    for (size_t index = 0U; index < length; ++index) {
        if (!is_supported_ctype1_unit(source[index])) {
            sl_last_error = SL_ERROR_NO_UNICODE_TRANSLATION;
            return SL_WIN32_FALSE;
        }
    }
    for (size_t index = 0U; index < length; ++index) {
        character_types[index] = classify_ctype1(source[index]);
    }
    return SL_WIN32_TRUE;
}

static uint16_t map_simple_case(uint16_t unit, bool uppercase) {
    if (uppercase) {
        if (unit >= (uint16_t)'a' && unit <= (uint16_t)'z') {
            return (uint16_t)(unit - ((uint16_t)'a' - (uint16_t)'A'));
        }
        if ((unit >= 0x00e0U && unit <= 0x00f6U) ||
            (unit >= 0x00f8U && unit <= 0x00feU)) {
            return (uint16_t)(unit - 0x20U);
        }
        if (unit == 0x0153U || unit == 0x0161U || unit == 0x017eU) {
            return (uint16_t)(unit - 1U);
        }
        return unit == 0x00ffU ? 0x0178U : unit;
    }
    if (unit >= (uint16_t)'A' && unit <= (uint16_t)'Z') {
        return (uint16_t)(unit + ((uint16_t)'a' - (uint16_t)'A'));
    }
    if ((unit >= 0x00c0U && unit <= 0x00d6U) ||
        (unit >= 0x00d8U && unit <= 0x00deU)) {
        return (uint16_t)(unit + 0x20U);
    }
    if (unit == 0x0152U || unit == 0x0160U || unit == 0x017dU) {
        return (uint16_t)(unit + 1U);
    }
    return unit == 0x0178U ? 0x00ffU : unit;
}

static bool is_supported_lcid(uint32_t locale) {
    return locale == 0x007fU || locale == 0x0400U || locale == 0x0800U ||
           locale == 0x0409U || locale == 0x0416U;
}

int32_t SL_WINAPI sl_kernel32_lc_map_string_w(
    uint32_t locale, uint32_t flags, const uint16_t *source,
    int32_t source_length, uint16_t *destination, int32_t destination_capacity) {
    if (flags != SL_WIN32_LCMAP_LOWERCASE &&
        flags != SL_WIN32_LCMAP_UPPERCASE) {
        sl_last_error = SL_ERROR_INVALID_FLAGS;
        return 0;
    }
    if (!is_supported_lcid(locale) || destination_capacity < 0 ||
        (destination == NULL && destination_capacity != 0)) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return 0;
    }
    size_t length = 0U;
    if (!locale_source_length(source, source_length, &length)) {
        return 0;
    }
    for (size_t index = 0U; index < length; ++index) {
        if (!is_supported_ctype1_unit(source[index])) {
            sl_last_error = SL_ERROR_NO_UNICODE_TRANSLATION;
            return 0;
        }
    }
    if (destination_capacity == 0) {
        return (int32_t)length;
    }
    if ((size_t)destination_capacity < length) {
        sl_last_error = SL_ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }
    bool uppercase = flags == SL_WIN32_LCMAP_UPPERCASE;
    for (size_t index = 0U; index < length; ++index) {
        destination[index] = map_simple_case(source[index], uppercase);
    }
    return (int32_t)length;
}

static sl_win32_bool SL_WINAPI sl_kernel32_get_cp_info(uint32_t page,
                                                       sl_cp_info *info) {
    if (info == NULL || !sl_kernel32_is_valid_code_page(page)) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    *info = (sl_cp_info){
        .max_char_size = page == 65001U ? 4U : 1U,
        .default_char = {'?', 0U},
        .lead_byte = {0U},
    };
    return SL_WIN32_TRUE;
}

static atomic_uintptr_t *atomic_standard_handle_slot(uint32_t identifier) {
    if (identifier == SL_STD_INPUT_ID) {
        return &sl_standard_input;
    }
    if (identifier == SL_STD_OUTPUT_ID) {
        return &sl_standard_output;
    }
    if (identifier == SL_STD_ERROR_ID) {
        return &sl_standard_error;
    }
    return NULL;
}

static void *SL_WINAPI sl_kernel32_get_std_handle(uint32_t identifier) {
    atomic_uintptr_t *slot = atomic_standard_handle_slot(identifier);
    if (slot == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return (void *)UINTPTR_MAX;
    }
    return (void *)atomic_load_explicit(slot, memory_order_relaxed);
}

static sl_win32_bool SL_WINAPI sl_kernel32_set_std_handle(uint32_t identifier,
                                                           void *handle) {
    atomic_uintptr_t *slot = atomic_standard_handle_slot(identifier);
    if (slot == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    atomic_store_explicit(slot, (uintptr_t)handle, memory_order_relaxed);
    return SL_WIN32_TRUE;
}

static FILE *stream_for_handle(const void *handle) {
    uintptr_t value = (uintptr_t)handle;
    if (value == 0U || value == UINTPTR_MAX) {
        return NULL;
    }
    if (value == atomic_load_explicit(&sl_standard_output,
                                     memory_order_relaxed)) {
        return stdout;
    }
    if (value == atomic_load_explicit(&sl_standard_error,
                                     memory_order_relaxed)) {
        return stderr;
    }
    return NULL;
}

static sl_win32_bool SL_WINAPI sl_kernel32_write_file(
    void *handle, const void *buffer, uint32_t byte_count,
    uint32_t *bytes_written, void *overlapped) {
    if (bytes_written != NULL) {
        *bytes_written = 0U;
    }
    if (overlapped != NULL) {
        sl_last_error = SL_ERROR_INVALID_FUNCTION;
        return SL_WIN32_FALSE;
    }
    FILE *stream = stream_for_handle(handle);
    if (stream == NULL || bytes_written == NULL ||
        (buffer == NULL && byte_count != 0U)) {
        sl_last_error = stream == NULL ? SL_ERROR_INVALID_HANDLE
                                       : SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    size_t written = fwrite(buffer, 1U, byte_count, stream);
    if (bytes_written != NULL) {
        *bytes_written = (uint32_t)written;
    }
    if (written != byte_count) {
        sl_last_error = SL_ERROR_WRITE_FAULT;
        return SL_WIN32_FALSE;
    }
    return SL_WIN32_TRUE;
}

static sl_win32_bool SL_WINAPI sl_kernel32_write_console_w(
    void *handle, const uint16_t *text, uint32_t character_count,
    uint32_t *characters_written, void *reserved) {
    (void)reserved;
    if (characters_written != NULL) {
        *characters_written = 0U;
    }
    FILE *stream = stream_for_handle(handle);
    if (stream == NULL || (text == NULL && character_count != 0U)) {
        sl_last_error = stream == NULL ? SL_ERROR_INVALID_HANDLE
                                       : SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    size_t byte_count = 0U;
    sl_status status = sl_utf16_to_utf8_lossy(
        text, character_count, NULL, 0U, &byte_count);
    if (status != SL_OK) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    char *encoded = malloc(byte_count == 0U ? 1U : byte_count);
    if (encoded == NULL) {
        sl_last_error = SL_ERROR_NOT_ENOUGH_MEMORY;
        return SL_WIN32_FALSE;
    }
    size_t converted = 0U;
    status = sl_utf16_to_utf8_lossy(text, character_count, encoded, byte_count,
                                    &converted);
    if (status != SL_OK || converted != byte_count) {
        free(encoded);
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return SL_WIN32_FALSE;
    }
    size_t bytes_written = fwrite(encoded, 1U, byte_count, stream);
    free(encoded);
    if (bytes_written != byte_count) {
        sl_last_error = SL_ERROR_WRITE_FAULT;
        return SL_WIN32_FALSE;
    }
    if (characters_written != NULL) {
        *characters_written = character_count;
    }
    return SL_WIN32_TRUE;
}

static sl_win32_bool SL_WINAPI sl_kernel32_get_console_mode(void *handle,
                                                             uint32_t *mode) {
    bool is_input =
        (uintptr_t)handle ==
        atomic_load_explicit(&sl_standard_input, memory_order_relaxed);
    if ((stream_for_handle(handle) == NULL && !is_input) || mode == NULL) {
        sl_last_error = mode == NULL ? SL_ERROR_INVALID_PARAMETER
                                     : SL_ERROR_INVALID_HANDLE;
        return SL_WIN32_FALSE;
    }
    *mode = 0U;
    return SL_WIN32_TRUE;
}

static uint32_t SL_WINAPI sl_kernel32_get_file_type(void *handle) {
    if (stream_for_handle(handle) != NULL ||
        (uintptr_t)handle ==
            atomic_load_explicit(&sl_standard_input, memory_order_relaxed)) {
        return 2U; /* FILE_TYPE_CHAR */
    }
    sl_last_error = SL_ERROR_INVALID_HANDLE;
    return 0U; /* FILE_TYPE_UNKNOWN */
}

static sl_win32_bool SL_WINAPI sl_kernel32_flush_file_buffers(void *handle) {
    FILE *stream = stream_for_handle(handle);
    if (stream == NULL) {
        sl_last_error = SL_ERROR_INVALID_HANDLE;
        return SL_WIN32_FALSE;
    }
    if (fflush(stream) != 0) {
        sl_last_error = SL_ERROR_WRITE_FAULT;
        return SL_WIN32_FALSE;
    }
    return SL_WIN32_TRUE;
}

static void SL_WINAPI sl_kernel32_get_startup_info_w(void *startup_info) {
    if (startup_info == NULL) {
        sl_last_error = SL_ERROR_INVALID_PARAMETER;
        return;
    }
    sl_startup_info_w *info = startup_info;
    memset(info, 0, sizeof(*info));
    info->cb = (uint32_t)sizeof(*info);
    info->standard_input = sl_kernel32_get_std_handle(SL_STD_INPUT_ID);
    info->standard_output = sl_kernel32_get_std_handle(SL_STD_OUTPUT_ID);
    info->standard_error = sl_kernel32_get_std_handle(SL_STD_ERROR_ID);
}

static sl_win32_bool SL_WINAPI sl_kernel32_close_handle(void *handle) {
    uintptr_t value = (uintptr_t)handle;
    if (value == SL_CURRENT_PROCESS_HANDLE || value == SL_STDIN_HANDLE ||
        value == SL_STDOUT_HANDLE || value == SL_STDERR_HANDLE) {
        return SL_WIN32_TRUE;
    }
    sl_last_error = SL_ERROR_INVALID_HANDLE;
    return SL_WIN32_FALSE;
}

static _Noreturn void SL_WINAPI sl_kernel32_exit_process(uint32_t exit_code) {
    (void)syscall(SYS_exit_group, (int)exit_code);
    abort();
}

static sl_win32_bool SL_WINAPI sl_kernel32_terminate_process(void *process,
                                                             uint32_t code) {
    if ((uintptr_t)process != SL_CURRENT_PROCESS_HANDLE) {
        sl_last_error = SL_ERROR_INVALID_HANDLE;
        return SL_WIN32_FALSE;
    }
    (void)syscall(SYS_exit_group, (int)code);
    abort();
}

static uint64_t function_address(const void *representation, size_t size) {
    uintptr_t address = 0U;
    if (size > sizeof(address)) {
        return 0U;
    }
    memcpy(&address, representation, size);
    return (uint64_t)address;
}

#define SL_ADD_EXPORT(table, count, windows_name, function)                    \
    do {                                                                       \
        if ((count) >= SL_KERNEL32_EXPORT_CAPACITY) {                           \
            abort();                                                           \
        }                                                                      \
        __typeof__(&(function)) sl_function_pointer = &(function);             \
        uint64_t sl_address = function_address(                                \
            &sl_function_pointer, sizeof(sl_function_pointer));                \
        (table)[(count)++] = (sl_native_export){                               \
            .name = (windows_name),                                            \
            .forwarder = NULL,                                                 \
            .ordinal = 0U,                                                     \
            .has_ordinal = false,                                              \
            .guest_address = sl_address,                                       \
        };                                                                     \
    } while (false)

static sl_native_export sl_kernel32_exports[SL_KERNEL32_EXPORT_CAPACITY];
static size_t sl_kernel32_export_count;
static once_flag sl_kernel32_exports_once = ONCE_FLAG_INIT;

static void initialize_kernel32_exports(void) {
    sl_native_export *exports = sl_kernel32_exports;
    size_t export_count = 0U;
    SL_ADD_EXPORT(exports, export_count, "GetLastError",
                  sl_kernel32_get_last_error);
    SL_ADD_EXPORT(exports, export_count, "SetLastError",
                  sl_kernel32_set_last_error);
    SL_ADD_EXPORT(exports, export_count, "GetCurrentProcessId",
                  sl_kernel32_get_current_process_id);
    SL_ADD_EXPORT(exports, export_count, "GetCurrentThreadId",
                  sl_kernel32_get_current_thread_id);
    SL_ADD_EXPORT(exports, export_count, "GetCurrentProcess",
                  sl_kernel32_get_current_process);
    SL_ADD_EXPORT(exports, export_count, "IsDebuggerPresent",
                  sl_kernel32_is_debugger_present);
    SL_ADD_EXPORT(exports, export_count, "QueryPerformanceCounter",
                  sl_kernel32_query_performance_counter);
    SL_ADD_EXPORT(exports, export_count, "QueryPerformanceFrequency",
                  sl_kernel32_query_performance_frequency);
    SL_ADD_EXPORT(exports, export_count, "GetSystemTimeAsFileTime",
                  sl_kernel32_get_system_time_as_file_time);
    SL_ADD_EXPORT(exports, export_count, "GetProcessHeap",
                  sl_kernel32_get_process_heap);
    SL_ADD_EXPORT(exports, export_count, "HeapAlloc",
                  sl_kernel32_heap_alloc);
    SL_ADD_EXPORT(exports, export_count, "HeapFree", sl_kernel32_heap_free);
    SL_ADD_EXPORT(exports, export_count, "HeapReAlloc",
                  sl_kernel32_heap_realloc);
    SL_ADD_EXPORT(exports, export_count, "HeapSize", sl_kernel32_heap_size);
    SL_ADD_EXPORT(exports, export_count, "TlsAlloc", sl_kernel32_tls_alloc);
    SL_ADD_EXPORT(exports, export_count, "TlsFree", sl_kernel32_tls_free);
    SL_ADD_EXPORT(exports, export_count, "TlsGetValue",
                  sl_kernel32_tls_get_value);
    SL_ADD_EXPORT(exports, export_count, "TlsSetValue",
                  sl_kernel32_tls_set_value);
    SL_ADD_EXPORT(exports, export_count, "FlsAlloc", sl_kernel32_fls_alloc);
    SL_ADD_EXPORT(exports, export_count, "FlsFree", sl_kernel32_fls_free);
    SL_ADD_EXPORT(exports, export_count, "FlsGetValue",
                  sl_kernel32_fls_get_value);
    SL_ADD_EXPORT(exports, export_count, "FlsSetValue",
                  sl_kernel32_fls_set_value);
    SL_ADD_EXPORT(exports, export_count, "EnterCriticalSection",
                  sl_kernel32_enter_critical_section);
    SL_ADD_EXPORT(exports, export_count, "LeaveCriticalSection",
                  sl_kernel32_leave_critical_section);
    SL_ADD_EXPORT(exports, export_count, "DeleteCriticalSection",
                  sl_kernel32_delete_critical_section);
    SL_ADD_EXPORT(exports, export_count,
                  "InitializeCriticalSectionAndSpinCount",
                  sl_kernel32_initialize_critical_section_and_spin_count);
    SL_ADD_EXPORT(exports, export_count, "IsProcessorFeaturePresent",
                  sl_kernel32_is_processor_feature_present);
    SL_ADD_EXPORT(exports, export_count, "InitializeSListHead",
                  sl_kernel32_initialize_slist_head);
    SL_ADD_EXPORT(exports, export_count, "EncodePointer",
                  sl_kernel32_encode_pointer);
    SL_ADD_EXPORT(exports, export_count, "DecodePointer",
                  sl_kernel32_decode_pointer);
    SL_ADD_EXPORT(exports, export_count, "GetACP", sl_kernel32_get_acp);
    SL_ADD_EXPORT(exports, export_count, "GetOEMCP", sl_kernel32_get_oemcp);
    SL_ADD_EXPORT(exports, export_count, "GetConsoleOutputCP",
                  sl_kernel32_get_console_output_cp);
    SL_ADD_EXPORT(exports, export_count, "IsValidCodePage",
                  sl_kernel32_is_valid_code_page);
    SL_ADD_EXPORT(exports, export_count, "GetCPInfo",
                  sl_kernel32_get_cp_info);
    SL_ADD_EXPORT(exports, export_count, "MultiByteToWideChar",
                  sl_kernel32_multi_byte_to_wide_char);
    SL_ADD_EXPORT(exports, export_count, "WideCharToMultiByte",
                  sl_kernel32_wide_char_to_multi_byte);
    SL_ADD_EXPORT(exports, export_count, "GetCommandLineA",
                  sl_kernel32_get_command_line_a);
    SL_ADD_EXPORT(exports, export_count, "GetCommandLineW",
                  sl_kernel32_get_command_line_w);
    SL_ADD_EXPORT(exports, export_count, "GetEnvironmentStringsW",
                  sl_kernel32_get_environment_strings_w);
    SL_ADD_EXPORT(exports, export_count, "FreeEnvironmentStringsW",
                  sl_kernel32_free_environment_strings_w);
    SL_ADD_EXPORT(exports, export_count, "GetStringTypeW",
                  sl_kernel32_get_string_type_w);
    SL_ADD_EXPORT(exports, export_count, "LCMapStringW",
                  sl_kernel32_lc_map_string_w);
    SL_ADD_EXPORT(exports, export_count, "GetStdHandle",
                  sl_kernel32_get_std_handle);
    SL_ADD_EXPORT(exports, export_count, "SetStdHandle",
                  sl_kernel32_set_std_handle);
    SL_ADD_EXPORT(exports, export_count, "WriteFile",
                  sl_kernel32_write_file);
    SL_ADD_EXPORT(exports, export_count, "WriteConsoleW",
                  sl_kernel32_write_console_w);
    SL_ADD_EXPORT(exports, export_count, "GetConsoleMode",
                  sl_kernel32_get_console_mode);
    SL_ADD_EXPORT(exports, export_count, "GetFileType",
                  sl_kernel32_get_file_type);
    SL_ADD_EXPORT(exports, export_count, "FlushFileBuffers",
                  sl_kernel32_flush_file_buffers);
    SL_ADD_EXPORT(exports, export_count, "GetStartupInfoW",
                  sl_kernel32_get_startup_info_w);
    SL_ADD_EXPORT(exports, export_count, "CloseHandle",
                  sl_kernel32_close_handle);
    SL_ADD_EXPORT(exports, export_count, "ExitProcess",
                  sl_kernel32_exit_process);
    SL_ADD_EXPORT(exports, export_count, "TerminateProcess",
                  sl_kernel32_terminate_process);
    sl_kernel32_export_count = export_count;
}

sl_status sl_kernel32_register(sl_module_registry *registry) {
    call_once(&sl_kernel32_exports_once, initialize_kernel32_exports);
    return sl_module_registry_add_native(
        registry, "KERNEL32.dll", sl_kernel32_exports,
        sl_kernel32_export_count);
}

#undef SL_ADD_EXPORT
#undef sl_last_error
