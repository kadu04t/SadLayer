#ifndef SADLAYER_KERNEL32_H
#define SADLAYER_KERNEL32_H

#include <stddef.h>
#include <stdint.h>

#include "sadlayer/module.h"
#include "sadlayer/win32.h"

#define SL_WIN32_FALSE 0
#define SL_WIN32_TRUE 1
#define SL_WIN32_TLS_OUT_OF_INDEXES UINT32_MAX
#define SL_WIN32_CP_ACP 0U
#define SL_WIN32_CP_OEMCP 1U
#define SL_WIN32_CP_THREAD_ACP 3U
#define SL_WIN32_CP_UTF8 65001U
#define SL_WIN32_MB_ERR_INVALID_CHARS 0x00000008U
#define SL_WIN32_WC_ERR_INVALID_CHARS 0x00000080U
#define SL_WIN32_CT_CTYPE1 1U
#define SL_WIN32_C1_UPPER 0x0001U
#define SL_WIN32_C1_LOWER 0x0002U
#define SL_WIN32_C1_DIGIT 0x0004U
#define SL_WIN32_C1_SPACE 0x0008U
#define SL_WIN32_C1_PUNCT 0x0010U
#define SL_WIN32_C1_CNTRL 0x0020U
#define SL_WIN32_C1_BLANK 0x0040U
#define SL_WIN32_C1_XDIGIT 0x0080U
#define SL_WIN32_C1_ALPHA 0x0100U
#define SL_WIN32_C1_DEFINED 0x0200U
#define SL_WIN32_LCMAP_LOWERCASE 0x00000100U
#define SL_WIN32_LCMAP_UPPERCASE 0x00000200U
#define SL_WIN32_LCMAP_LINGUISTIC_CASING 0x01000000U

typedef int32_t sl_win32_bool;

typedef struct {
    uint32_t low_date_time;
    uint32_t high_date_time;
} sl_win32_filetime;

sl_status sl_kernel32_register(sl_module_registry *registry);
/* Configure once during process setup, before publishing any guest thread. */
sl_status sl_kernel32_set_command_line_utf8(const char *command_line);

uint32_t SL_WINAPI sl_kernel32_get_last_error(void);
void SL_WINAPI sl_kernel32_set_last_error(uint32_t error);
uint32_t SL_WINAPI sl_kernel32_get_current_process_id(void);
uint32_t SL_WINAPI sl_kernel32_get_current_thread_id(void);
void *SL_WINAPI sl_kernel32_get_current_process(void);
sl_win32_bool SL_WINAPI sl_kernel32_is_debugger_present(void);
sl_win32_bool SL_WINAPI sl_kernel32_query_performance_counter(int64_t *counter);
sl_win32_bool SL_WINAPI sl_kernel32_query_performance_frequency(
    int64_t *frequency);
void SL_WINAPI sl_kernel32_get_system_time_as_file_time(
    sl_win32_filetime *filetime);

void *SL_WINAPI sl_kernel32_get_process_heap(void);
void *SL_WINAPI sl_kernel32_heap_alloc(void *heap, uint32_t flags,
                                       size_t bytes);
sl_win32_bool SL_WINAPI sl_kernel32_heap_free(void *heap, uint32_t flags,
                                              void *memory);
void *SL_WINAPI sl_kernel32_heap_realloc(void *heap, uint32_t flags,
                                         void *memory, size_t bytes);
size_t SL_WINAPI sl_kernel32_heap_size(void *heap, uint32_t flags,
                                      const void *memory);

uint32_t SL_WINAPI sl_kernel32_tls_alloc(void);
sl_win32_bool SL_WINAPI sl_kernel32_tls_free(uint32_t index);
void *SL_WINAPI sl_kernel32_tls_get_value(uint32_t index);
sl_win32_bool SL_WINAPI sl_kernel32_tls_set_value(uint32_t index, void *value);
uint32_t SL_WINAPI sl_kernel32_fls_alloc(uintptr_t callback_address);
sl_win32_bool SL_WINAPI sl_kernel32_fls_free(uint32_t index);
void *SL_WINAPI sl_kernel32_fls_get_value(uint32_t index);
sl_win32_bool SL_WINAPI sl_kernel32_fls_set_value(uint32_t index, void *value);

void SL_WINAPI sl_kernel32_enter_critical_section(void *critical_section);
void SL_WINAPI sl_kernel32_leave_critical_section(void *critical_section);
void SL_WINAPI sl_kernel32_delete_critical_section(void *critical_section);
sl_win32_bool SL_WINAPI sl_kernel32_initialize_critical_section_and_spin_count(
    void *critical_section, uint32_t spin_count);
sl_win32_bool SL_WINAPI sl_kernel32_is_processor_feature_present(
    uint32_t feature);

int32_t SL_WINAPI sl_kernel32_multi_byte_to_wide_char(
    uint32_t code_page, uint32_t flags, const char *source,
    int32_t source_length, uint16_t *destination, int32_t destination_capacity);
int32_t SL_WINAPI sl_kernel32_wide_char_to_multi_byte(
    uint32_t code_page, uint32_t flags, const uint16_t *source,
    int32_t source_length, char *destination, int32_t destination_capacity,
    const char *default_character, sl_win32_bool *used_default_character);
char *SL_WINAPI sl_kernel32_get_command_line_a(void);
uint16_t *SL_WINAPI sl_kernel32_get_command_line_w(void);
uint16_t *SL_WINAPI sl_kernel32_get_environment_strings_w(void);
sl_win32_bool SL_WINAPI sl_kernel32_free_environment_strings_w(
    uint16_t *environment);
sl_win32_bool SL_WINAPI sl_kernel32_get_string_type_w(
    uint32_t information_type, const uint16_t *source, int32_t source_length,
    uint16_t *character_types);
int32_t SL_WINAPI sl_kernel32_lc_map_string_w(
    uint32_t locale, uint32_t flags, const uint16_t *source,
    int32_t source_length, uint16_t *destination, int32_t destination_capacity);

#ifdef SADLAYER_TESTING
typedef void (*sl_kernel32_local_set_test_hook)(void *context);
void sl_kernel32_test_set_local_set_hook(
    sl_kernel32_local_set_test_hook hook, void *context);
#endif

#endif
