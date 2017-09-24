/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdarg.h>
#include <stdio.h>

#include "log.h"
#include "util.h"

static int log_errorv(
                int error,
                const char *format,
                va_list ap) {

        int orig_errno = errno;
        const char *fmt;

        fmt = strjoina(format, "\n");
        errno = abs(error);
        vfprintf(stderr, fmt, ap);
        errno = orig_errno;
        return -abs(error);
}

int log_info_errno(int error, const char* format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = log_errorv(error, format, ap);
        va_end(ap);

        return r;
}

int log_error_errno(int error, const char* format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = log_errorv(error, format, ap);
        va_end(ap);

        return r;
}
