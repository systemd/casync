/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#include "gcc-macro.h"

int log_info_errno(int error, const char* fmt, ...) _printf_(2,3);
int log_error_errno(int error, const char* fmt, ...) _printf_(2,3);
int log_debug_errno(int error, const char* fmt, ...) _printf_(2,3);

#define log_info(fmt, ...) log_info_errno(0, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_error_errno(0, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) log_debug_errno(0, fmt, ##__VA_ARGS__)

static inline int log_oom(void) {
        log_error("Out of memory");
        return -ENOMEM;
}

#define assert_se(x)                                                    \
        do {                                                            \
                if (!(x)) {                                             \
                        log_error("%s:%d (%s): assertion failed: %s",   \
                                  __FILE__, __LINE__, __PRETTY_FUNCTION__, #x); \
                        abort();                                        \
                }                                                       \
        } while(false)

#define assert_not_reached(x)                                           \
        do {                                                            \
                log_error("%s:%d (%s): unreachable code reached: %s",   \
                          __FILE__, __LINE__, __PRETTY_FUNCTION__, x);  \
                abort();                                                \
        } while(false)

void set_log_level(int level);
int set_log_level_from_string(const char *str);

#ifdef LOG_TRACE
#  define log_trace(...) log_debug(__VA_ARGS__)
#else
#  define log_trace(...) do {} while (0)
#endif
