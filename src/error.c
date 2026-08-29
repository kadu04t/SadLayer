#include "sadlayer/error.h"

const char *sl_status_string(sl_status status) {
    switch (status) {
    case SL_OK:
        return "success";
    case SL_ERROR_INVALID_ARGUMENT:
        return "invalid argument";
    case SL_ERROR_IO:
        return "I/O error";
    case SL_ERROR_OUT_OF_MEMORY:
        return "out of memory";
    case SL_ERROR_TRUNCATED_FILE:
        return "truncated file";
    case SL_ERROR_BAD_DOS_SIGNATURE:
        return "invalid DOS signature";
    case SL_ERROR_BAD_PE_SIGNATURE:
        return "invalid PE signature";
    case SL_ERROR_UNSUPPORTED_MACHINE:
        return "unsupported CPU architecture";
    case SL_ERROR_UNSUPPORTED_OPTIONAL_HEADER:
        return "unsupported PE optional header";
    case SL_ERROR_INVALID_IMAGE:
        return "invalid PE image";
    case SL_ERROR_RVA_NOT_MAPPED:
        return "RVA is not backed by file data";
    case SL_ERROR_EXPORT_NOT_FOUND:
        return "PE export was not found";
    case SL_ERROR_MODULE_NOT_FOUND:
        return "imported module was not found";
    case SL_ERROR_DUPLICATE_MODULE:
        return "module is already registered";
    case SL_ERROR_MODULE_REGISTRY_FULL:
        return "module registry is full";
    case SL_ERROR_INVALID_FORWARDER:
        return "invalid PE export forwarder";
    case SL_ERROR_FORWARDER_LIMIT:
        return "PE export forwarder limit reached";
    case SL_ERROR_RELOCATION_REQUIRED:
        return "image cannot be loaded away from its preferred base";
    case SL_ERROR_UNSUPPORTED_RELOCATION:
        return "unsupported PE base relocation";
    case SL_ERROR_NOT_IMPLEMENTED:
        return "not implemented yet";
    default:
        return "unknown error";
    }
}
