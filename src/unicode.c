#include "sadlayer/unicode.h"

#include <stdbool.h>

static sl_status decode_utf8(const uint8_t *source, size_t available,
                             uint32_t *codepoint, size_t *consumed) {
    if (available == 0U) {
        return SL_ERROR_INVALID_ENCODING;
    }
    uint8_t first = source[0];
    if (first <= 0x7fU) {
        *codepoint = first;
        *consumed = 1U;
        return SL_OK;
    }

    size_t length = 0U;
    uint32_t value = 0U;
    uint32_t minimum = 0U;
    if (first >= 0xc2U && first <= 0xdfU) {
        length = 2U;
        value = first & 0x1fU;
        minimum = 0x80U;
    } else if (first >= 0xe0U && first <= 0xefU) {
        length = 3U;
        value = first & 0x0fU;
        minimum = 0x800U;
    } else if (first >= 0xf0U && first <= 0xf4U) {
        length = 4U;
        value = first & 0x07U;
        minimum = 0x10000U;
    } else {
        return SL_ERROR_INVALID_ENCODING;
    }
    if (length > available) {
        return SL_ERROR_INVALID_ENCODING;
    }
    for (size_t index = 1U; index < length; ++index) {
        uint8_t continuation = source[index];
        if ((continuation & 0xc0U) != 0x80U) {
            return SL_ERROR_INVALID_ENCODING;
        }
        value = (value << 6U) | (continuation & 0x3fU);
    }
    if (value < minimum || value > 0x10ffffU ||
        (value >= 0xd800U && value <= 0xdfffU)) {
        return SL_ERROR_INVALID_ENCODING;
    }
    *codepoint = value;
    *consumed = length;
    return SL_OK;
}

static sl_status utf8_required_units(const char *source, size_t source_length,
                                     bool replace_invalid, size_t *required) {
    size_t offset = 0U;
    size_t count = 0U;
    while (offset < source_length) {
        uint32_t codepoint = 0U;
        size_t consumed = 0U;
        sl_status status = decode_utf8((const uint8_t *)source + offset,
                                       source_length - offset, &codepoint,
                                       &consumed);
        if (status != SL_OK) {
            if (!replace_invalid) {
                return status;
            }
            codepoint = 0xfffdU;
            consumed = 1U;
        }
        size_t units = codepoint <= 0xffffU ? 1U : 2U;
        if (count > SIZE_MAX - units) {
            return SL_ERROR_OUT_OF_MEMORY;
        }
        count += units;
        offset += consumed;
    }
    *required = count;
    return SL_OK;
}

static sl_status utf8_to_utf16(const char *source, size_t source_length,
                               uint16_t *destination,
                               size_t destination_capacity, size_t *written,
                               bool replace_invalid) {
    if ((source == NULL && source_length != 0U) || written == NULL ||
        (destination == NULL && destination_capacity != 0U)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    size_t required = 0U;
    sl_status status = utf8_required_units(source, source_length,
                                           replace_invalid, &required);
    if (status != SL_OK) {
        return status;
    }
    *written = required;
    if (destination == NULL) {
        return SL_OK;
    }
    if (destination_capacity < required) {
        return SL_ERROR_BUFFER_TOO_SMALL;
    }

    size_t input = 0U;
    size_t output = 0U;
    while (input < source_length) {
        uint32_t codepoint = 0U;
        size_t consumed = 0U;
        status = decode_utf8((const uint8_t *)source + input,
                             source_length - input, &codepoint, &consumed);
        if (status != SL_OK) {
            if (!replace_invalid) {
                return status;
            }
            codepoint = 0xfffdU;
            consumed = 1U;
        }
        if (codepoint <= 0xffffU) {
            destination[output++] = (uint16_t)codepoint;
        } else {
            codepoint -= 0x10000U;
            destination[output++] = (uint16_t)(0xd800U | (codepoint >> 10U));
            destination[output++] =
                (uint16_t)(0xdc00U | (codepoint & 0x3ffU));
        }
        input += consumed;
    }
    return SL_OK;
}

sl_status sl_utf8_to_utf16(const char *source, size_t source_length,
                           uint16_t *destination, size_t destination_capacity,
                           size_t *written) {
    return utf8_to_utf16(source, source_length, destination,
                         destination_capacity, written, false);
}

sl_status sl_utf8_to_utf16_lossy(const char *source, size_t source_length,
                                 uint16_t *destination,
                                 size_t destination_capacity, size_t *written) {
    return utf8_to_utf16(source, source_length, destination,
                         destination_capacity, written, true);
}

static sl_status decode_utf16(const uint16_t *source, size_t available,
                              uint32_t *codepoint, size_t *consumed) {
    if (available == 0U) {
        return SL_ERROR_INVALID_ENCODING;
    }
    uint32_t first = source[0];
    if (first >= 0xd800U && first <= 0xdbffU) {
        if (available < 2U) {
            return SL_ERROR_INVALID_ENCODING;
        }
        uint32_t second = source[1];
        if (second < 0xdc00U || second > 0xdfffU) {
            return SL_ERROR_INVALID_ENCODING;
        }
        *codepoint = 0x10000U + ((first - 0xd800U) << 10U) +
                     (second - 0xdc00U);
        *consumed = 2U;
        return SL_OK;
    }
    if (first >= 0xdc00U && first <= 0xdfffU) {
        return SL_ERROR_INVALID_ENCODING;
    }
    *codepoint = first;
    *consumed = 1U;
    return SL_OK;
}

static size_t utf8_codepoint_size(uint32_t codepoint) {
    if (codepoint <= 0x7fU) {
        return 1U;
    }
    if (codepoint <= 0x7ffU) {
        return 2U;
    }
    if (codepoint <= 0xffffU) {
        return 3U;
    }
    return 4U;
}

static sl_status utf16_required_bytes(const uint16_t *source,
                                      size_t source_length,
                                      bool replace_invalid, size_t *required) {
    size_t offset = 0U;
    size_t count = 0U;
    while (offset < source_length) {
        uint32_t codepoint = 0U;
        size_t consumed = 0U;
        sl_status status = decode_utf16(source + offset, source_length - offset,
                                        &codepoint, &consumed);
        if (status != SL_OK) {
            if (!replace_invalid) {
                return status;
            }
            codepoint = 0xfffdU;
            consumed = 1U;
        }
        size_t bytes = utf8_codepoint_size(codepoint);
        if (count > SIZE_MAX - bytes) {
            return SL_ERROR_OUT_OF_MEMORY;
        }
        count += bytes;
        offset += consumed;
    }
    *required = count;
    return SL_OK;
}

static sl_status utf16_to_utf8(const uint16_t *source, size_t source_length,
                               char *destination,
                               size_t destination_capacity, size_t *written,
                               bool replace_invalid) {
    if ((source == NULL && source_length != 0U) || written == NULL ||
        (destination == NULL && destination_capacity != 0U)) {
        return SL_ERROR_INVALID_ARGUMENT;
    }
    size_t required = 0U;
    sl_status status = utf16_required_bytes(source, source_length,
                                            replace_invalid, &required);
    if (status != SL_OK) {
        return status;
    }
    *written = required;
    if (destination == NULL) {
        return SL_OK;
    }
    if (destination_capacity < required) {
        return SL_ERROR_BUFFER_TOO_SMALL;
    }

    size_t input = 0U;
    size_t output = 0U;
    while (input < source_length) {
        uint32_t codepoint = 0U;
        size_t consumed = 0U;
        status = decode_utf16(source + input, source_length - input, &codepoint,
                              &consumed);
        if (status != SL_OK) {
            if (!replace_invalid) {
                return status;
            }
            codepoint = 0xfffdU;
            consumed = 1U;
        }
        if (codepoint <= 0x7fU) {
            destination[output++] = (char)codepoint;
        } else if (codepoint <= 0x7ffU) {
            destination[output++] = (char)(0xc0U | (codepoint >> 6U));
            destination[output++] =
                (char)(0x80U | (codepoint & 0x3fU));
        } else if (codepoint <= 0xffffU) {
            destination[output++] = (char)(0xe0U | (codepoint >> 12U));
            destination[output++] =
                (char)(0x80U | ((codepoint >> 6U) & 0x3fU));
            destination[output++] =
                (char)(0x80U | (codepoint & 0x3fU));
        } else {
            destination[output++] = (char)(0xf0U | (codepoint >> 18U));
            destination[output++] =
                (char)(0x80U | ((codepoint >> 12U) & 0x3fU));
            destination[output++] =
                (char)(0x80U | ((codepoint >> 6U) & 0x3fU));
            destination[output++] =
                (char)(0x80U | (codepoint & 0x3fU));
        }
        input += consumed;
    }
    return SL_OK;
}

sl_status sl_utf16_to_utf8(const uint16_t *source, size_t source_length,
                           char *destination, size_t destination_capacity,
                           size_t *written) {
    return utf16_to_utf8(source, source_length, destination,
                         destination_capacity, written, false);
}

sl_status sl_utf16_to_utf8_lossy(const uint16_t *source, size_t source_length,
                                 char *destination,
                                 size_t destination_capacity, size_t *written) {
    return utf16_to_utf8(source, source_length, destination,
                         destination_capacity, written, true);
}
