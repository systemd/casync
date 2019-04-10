/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "log.h"
#include "util.h"

static int cached_log_level = -1;

static int level_from_string(const char *str) {
        if (STR_IN_SET(str, "emerg", "emergency", "0"))
                return LOG_EMERG;
        else if (STR_IN_SET(str, "alert", "1"))
                return LOG_ALERT;
        else if (STR_IN_SET(str, "crit", "critical", "2"))
                return LOG_CRIT;
        else if (STR_IN_SET(str, "err", "error", "3"))
                return LOG_ERR;
        else if (STR_IN_SET(str, "warn", "warning", "4"))
                return LOG_WARNING;
        else if (STR_IN_SET(str, "notice", "5"))
                return LOG_NOTICE;
        else if (STR_IN_SET(str, "info", "6"))
                return LOG_INFO;
        else if (STR_IN_SET(str, "debug", "7"))
                return LOG_DEBUG;
        else
                return -EINVAL;
}

static int get_log_level(void) {
        if (cached_log_level < 0) {
                const char *e;

                cached_log_level = LOG_INFO;

                e = getenv("CASYNC_LOG_LEVEL");
                if (e)
                        set_log_level_from_string(e);
        }

        return cached_log_level;
}

void set_log_level(int level) {
        cached_log_level = level;
}

int set_log_level_from_string(const char *str) {
        int level;

        level = level_from_string(str);
        if (level < 0)
                return level;

        cached_log_level = level;
        return level;
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

        if (endswith(format, "\n"))
                fmt = format;
        else
                fmt = strjoina(format, "\n");

        if (error != 0)
                errno = abs(error);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        vfprintf(stderr, fmt, ap);
#pragma GCC diagnostic pop

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
