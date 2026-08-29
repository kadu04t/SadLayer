#include "sadlayer/win32.h"

#include <ctype.h>
#include <string.h>

static bool ascii_equal_ignore_case(const char *left, const char *right) {
    if (left == NULL || right == NULL) {
        return false;
    }
    while (*left != '\0' && *right != '\0') {
        unsigned char left_char = (unsigned char)*left;
        unsigned char right_char = (unsigned char)*right;
        if (tolower(left_char) != tolower(right_char)) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

bool sl_win32_is_bootstrap_module(const char *module_name) {
    static const char *const modules[] = {
        "advapi32.dll", "bcrypt.dll",  "comdlg32.dll", "d3d11.dll",
        "dxgi.dll",     "gdi32.dll",   "kernel32.dll",  "ntdll.dll",
        "ole32.dll",    "shell32.dll", "user32.dll",    "winmm.dll",
        "ws2_32.dll",   "xinput1_3.dll"
    };
    for (size_t index = 0U; index < sizeof(modules) / sizeof(modules[0]);
         ++index) {
        if (ascii_equal_ignore_case(module_name, modules[index])) {
            return true;
        }
    }
    return false;
}

