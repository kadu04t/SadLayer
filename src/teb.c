#define _GNU_SOURCE

#include "sadlayer/teb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SL_TEB_WRITABLE_PAGE_COUNT 2U
#define SL_TEB_TOTAL_PAGE_COUNT 4U
#define SL_TEB_OWNERSHIP_RESERVED UINTPTR_MAX

struct sl_win32_teb {
    sl_win32_process *process;
    sl_win32_thread_context *thread;
    bool attached;
    uint8_t *mapping;
    size_t mapping_size;
    uint8_t *bytes;
};

static void store_u32(uint8_t *destination, uint32_t value) {
    memcpy(destination, &value, sizeof(value));
}

static void store_uintptr(uint8_t *destination, uintptr_t value) {
    memcpy(destination, &value, sizeof(value));
}

sl_status sl_win32_teb_create(sl_win32_thread_context *thread,
                              uintptr_t stack_limit, uintptr_t stack_base,
                              sl_win32_teb **out_teb) {
    if (out_teb == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    *out_teb = NULL;
    if (thread == NULL || stack_limit >= stack_base) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_status status = sl_win32_context_claim_inactive(thread);
    if (status != SL_OK) {
        return status;
    }
    if (thread->process == NULL || thread->thread_id == 0U ||
        thread->teb != NULL || thread->last_error_address != NULL) {
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_INVALID_ARGUMENT;
    }
    uintptr_t expected_owner = 0U;
    if (!atomic_compare_exchange_strong_explicit(
            &thread->teb_owner_token, &expected_owner,
            SL_TEB_OWNERSHIP_RESERVED, memory_order_acq_rel,
            memory_order_acquire)) {
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_INVALID_STATE;
    }
    sl_win32_process *process = thread->process;
    status = sl_win32_process_retain(process);
    if (status != SL_OK) {
        atomic_store_explicit(&thread->teb_owner_token, 0U,
                              memory_order_release);
        sl_win32_context_release_inactive(thread);
        return status;
    }

    long page_value = sysconf(_SC_PAGESIZE);
    if (page_value <= 0L || (unsigned long)page_value > SIZE_MAX) {
        sl_win32_process_release(process);
        atomic_store_explicit(&thread->teb_owner_token, 0U,
                              memory_order_release);
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_MEMORY_MAPPING;
    }
    size_t page_size = (size_t)page_value;
    const size_t required_teb_size =
        SL_WIN32_TEB_TLS_SLOTS_OFFSET +
        SL_WIN32_TEB_TLS_SLOT_COUNT * sizeof(uintptr_t);
    if (page_size > SIZE_MAX / SL_TEB_TOTAL_PAGE_COUNT ||
        page_size * SL_TEB_WRITABLE_PAGE_COUNT < required_teb_size) {
        sl_win32_process_release(process);
        atomic_store_explicit(&thread->teb_owner_token, 0U,
                              memory_order_release);
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_MEMORY_MAPPING;
    }

    sl_win32_teb *teb = calloc(1U, sizeof(*teb));
    if (teb == NULL) {
        sl_win32_process_release(process);
        atomic_store_explicit(&thread->teb_owner_token, 0U,
                              memory_order_release);
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_OUT_OF_MEMORY;
    }
    teb->mapping_size = page_size * SL_TEB_TOTAL_PAGE_COUNT;
    teb->mapping = mmap(NULL, teb->mapping_size, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (teb->mapping == MAP_FAILED) {
        free(teb);
        sl_win32_process_release(process);
        atomic_store_explicit(&thread->teb_owner_token, 0U,
                              memory_order_release);
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_MEMORY_MAPPING;
    }
    teb->bytes = teb->mapping + page_size;
    if (mprotect(teb->bytes, page_size * SL_TEB_WRITABLE_PAGE_COUNT,
                 PROT_READ | PROT_WRITE) != 0) {
        (void)munmap(teb->mapping, teb->mapping_size);
        free(teb);
        sl_win32_process_release(process);
        atomic_store_explicit(&thread->teb_owner_token, 0U,
                              memory_order_release);
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_MEMORY_PROTECTION;
    }
    teb->process = process;
    teb->thread = thread;

    store_uintptr(teb->bytes + SL_WIN32_TEB_STACK_BASE_OFFSET, stack_base);
    store_uintptr(teb->bytes + SL_WIN32_TEB_STACK_LIMIT_OFFSET, stack_limit);
    store_uintptr(teb->bytes + SL_WIN32_TEB_SELF_OFFSET,
                  (uintptr_t)teb->bytes);
    store_uintptr(teb->bytes + SL_WIN32_TEB_PROCESS_ID_OFFSET,
                  (uintptr_t)(uint32_t)getpid());
    store_uintptr(teb->bytes + SL_WIN32_TEB_THREAD_ID_OFFSET,
                  (uintptr_t)thread->thread_id);
    store_uintptr(teb->bytes + SL_WIN32_TEB_PEB_OFFSET,
                  (uintptr_t)sl_win32_process_peb(process));
    store_u32(teb->bytes + SL_WIN32_TEB_LAST_ERROR_OFFSET,
              thread->last_error);

    atomic_store_explicit(&thread->teb_owner_token, (uintptr_t)teb,
                          memory_order_release);
    *out_teb = teb;
    sl_win32_context_release_inactive(thread);
    return SL_OK;
}

sl_status sl_win32_teb_destroy(sl_win32_teb *teb) {
    if (teb == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_win32_thread_context *thread = teb->thread;
    sl_status status = sl_win32_context_claim_inactive(thread);
    if (status != SL_OK) {
        return status;
    }
    if (teb->attached) {
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_INVALID_STATE;
    }
    uintptr_t expected_owner = (uintptr_t)teb;
    if (!atomic_compare_exchange_strong_explicit(
            &teb->thread->teb_owner_token, &expected_owner,
            SL_TEB_OWNERSHIP_RESERVED, memory_order_acq_rel,
            memory_order_acquire)) {
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_INVALID_STATE;
    }
    if (munmap(teb->mapping, teb->mapping_size) != 0) {
        atomic_store_explicit(&thread->teb_owner_token, (uintptr_t)teb,
                              memory_order_release);
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_MEMORY_MAPPING;
    }
    atomic_store_explicit(&thread->teb_owner_token, 0U, memory_order_release);
    sl_win32_process_release(teb->process);
    sl_win32_context_release_inactive(thread);
    free(teb);
    return SL_OK;
}

void *sl_win32_teb_base(sl_win32_teb *teb) {
    return teb == NULL ? NULL : teb->bytes;
}

uint32_t *sl_win32_teb_last_error(sl_win32_teb *teb) {
    if (teb == NULL) {
        return NULL;
    }
    return (uint32_t *)(void *)(teb->bytes + SL_WIN32_TEB_LAST_ERROR_OFFSET);
}

sl_status sl_win32_thread_attach_teb(sl_win32_thread_context *thread,
                                     sl_win32_teb *teb) {
    if (thread == NULL || teb == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_status status = sl_win32_context_claim_inactive(thread);
    if (status != SL_OK) {
        return status;
    }
    if (thread->process != teb->process ||
        thread != teb->thread || thread->teb != NULL ||
        thread->last_error_address != NULL || teb->attached ||
        atomic_load_explicit(&thread->teb_owner_token,
                             memory_order_acquire) != (uintptr_t)teb) {
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_INVALID_ARGUMENT;
    }
    store_u32(teb->bytes + SL_WIN32_TEB_LAST_ERROR_OFFSET,
              thread->last_error);
    thread->teb = teb->bytes;
    thread->last_error_address = sl_win32_teb_last_error(teb);
    teb->attached = true;
    sl_win32_context_release_inactive(thread);
    return SL_OK;
}

sl_status sl_win32_thread_detach_teb(sl_win32_thread_context *thread,
                                     sl_win32_teb *teb) {
    if (thread == NULL || teb == NULL) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    sl_status status = sl_win32_context_claim_inactive(thread);
    if (status != SL_OK) {
        return status;
    }
    if (thread->teb != teb->bytes ||
        thread->last_error_address != sl_win32_teb_last_error(teb) ||
        thread != teb->thread || !teb->attached) {
        sl_win32_context_release_inactive(thread);
        return SL_ERROR_INVALID_STATE;
    }
    thread->last_error = *thread->last_error_address;
    thread->last_error_address = NULL;
    thread->teb = NULL;
    teb->attached = false;
    sl_win32_context_release_inactive(thread);
    return SL_OK;
}
