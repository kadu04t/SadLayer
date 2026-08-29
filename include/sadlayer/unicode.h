#ifndef SADLAYER_UNICODE_H
#define SADLAYER_UNICODE_H

#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"

sl_status sl_utf8_to_utf16(const char *source, size_t source_length,
                           uint16_t *destination, size_t destination_capacity,
                           size_t *written);
sl_status sl_utf8_to_utf16_lossy(const char *source, size_t source_length,
                                 uint16_t *destination,
                                 size_t destination_capacity, size_t *written);
sl_status sl_utf16_to_utf8(const uint16_t *source, size_t source_length,
                           char *destination, size_t destination_capacity,
                           size_t *written);
sl_status sl_utf16_to_utf8_lossy(const uint16_t *source, size_t source_length,
                                 char *destination,
                                 size_t destination_capacity, size_t *written);

#endif
