/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocutmarkhfoo
#define foocutmarkhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct CaCutmark {
        uint64_t value;  /* Numeric value of the cutmark */
        uint64_t mask;   /* Mask to apply when matching the cutmark */
        int64_t delta;   /* Where to cut, as an offset (possibly negative) relative to the position right after the 64bit value. */
} CaCutmark;

int ca_cutmark_parse(CaCutmark *c, const char *p);

void ca_cutmark_sort(CaCutmark *c, size_t n);

int ca_cutmark_cmp(const CaCutmark *a, const CaCutmark *b);

#endif
