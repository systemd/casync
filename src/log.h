/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <errno.h>

int log_info_errno(int error, const char* fmt, ...);
int log_error_errno(int error, const char* format, ...);
#define log_info(fmt, ...) log_info_errno(0, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_error_errno(0, fmt, ##__VA_ARGS__)

static inline int log_oom(void) {
        log_error("Out of memory");
        return -ENOMEM;
}

#define assert_se(x)                                                    \
        do {                                                            \
                if (!(x)) {                                             \
                        log_error("%s:%d (%s): assertion failed:" #x "\n", \
                                  __FILE__, __LINE__, __PRETTY_FUNCTION__); \
                        abort();                                        \
                }                                                       \
        } while(false)

#define assert_not_reached(x)                                           \
        do {                                                            \
                log_error("%s:%d (%s): unreachable code reached:" x "\n", \
                          __FILE__, __LINE__, __PRETTY_FUNCTION__);     \
                abort();                                                \
        } while(false)
