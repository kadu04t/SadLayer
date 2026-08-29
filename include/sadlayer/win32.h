#ifndef SADLAYER_WIN32_H
#define SADLAYER_WIN32_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sadlayer/error.h"

typedef struct {
    const char *module;
    const char *symbol;
    uint16_t ordinal;
    bool by_ordinal;
} sl_win32_import;

typedef sl_status (*sl_win32_resolver)(const sl_win32_import *import,
                                      uintptr_t *host_address, void *context);

bool sl_win32_is_bootstrap_module(const char *module_name);

#endif

