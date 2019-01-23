/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "log.h"
#include "util.h"

static int cached_log_level = -1;

static int get_log_level(void) {
        if (cached_log_level < 0) {
                const char *e;

                cached_log_level = LOG_INFO;

                e = getenv("CASYNC_LOG_LEVEL");
                if (e) {
                        if (STR_IN_SET(e, "emerg", "emergency", "0"))
                                cached_log_level = LOG_EMERG;
                        else if (STR_IN_SET(e, "alert", "1"))
                                cached_log_level = LOG_ALERT;
                        else if (STR_IN_SET(e, "crit", "critical", "2"))
                                cached_log_level = LOG_CRIT;
                        else if (STR_IN_SET(e, "err", "error", "3"))
                                cached_log_level = LOG_ERR;
                        else if (STR_IN_SET(e, "warn", "warning", "4"))
                                cached_log_level = LOG_WARNING;
                        else if (STR_IN_SET(e, "notice", "5"))
                                cached_log_level = LOG_NOTICE;
                        else if (STR_IN_SET(e, "debug", "7"))
                                cached_log_level = LOG_DEBUG;
                }
        }

        return cached_log_level;
}

void set_log_level(int level) {
        cached_log_level = level;
}

static int log_fullv(
                int level,
                int error,
                const char *format,
                va_list ap) {

        int orig_errno = errno;
        const char *fmt;

        if (level > get_log_level())
                return -abs(error);

        if (!endswith(format, "\n"))
                fmt = strjoina(format, "\n");

        if (error != 0)
                errno = abs(error);

        vfprintf(stderr, fmt, ap);
        errno = orig_errno;
        return -abs(error);
}

int log_info_errno(int error, const char* format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = log_fullv(LOG_INFO, error, format, ap);
        va_end(ap);

        return r;
}

int log_error_errno(int error, const char* format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = log_fullv(LOG_ERR, error, format, ap);
        va_end(ap);

        return r;
}

int log_debug_errno(int error, const char* format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = log_fullv(LOG_DEBUG, error, format, ap);
        va_end(ap);

        return r;
}
