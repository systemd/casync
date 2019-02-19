/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sys/types.h>

#include "cacutmark.h"
#include "util.h"

int ca_cutmark_parse(CaCutmark *c, const char *p) {
        enum {
                VALUE,
                MASK,
                DELTA_PLUS,
                DELTA_MINUS,
        } state = VALUE;

        uint64_t value = 0, mask = 0, udelta = 0;
        int64_t delta = 0;
        size_t digits = 0;
        const char *q;

        /* Parsers a cutmark specification. Expects a value (in hex),
         * optionally followed by a slash and a mask (in hex), optionally
         * followed by +/- and a delta offset (in dec). */

        for (q = p;; q++) {

                switch (state) {

                case VALUE:
                        if (*q == 0) {
                                if (digits == 0)
                                        return -EINVAL;

                                goto done;

                        } else if (*q == '/') {
                                if (digits == 0)
                                        return -EINVAL;

                                state = MASK;
                                mask = 0;
                                digits = 0;

                        } else if (*q == '+') {
                                if (digits == 0)
                                        return -EINVAL;

                                state = DELTA_PLUS;
                                digits = 0;

                        } else if (*q == '-') {
                                if (digits == 0)
                                        return -EINVAL;

                                state = DELTA_MINUS;
                                digits = 0;

                        } else {
                                int k;

                                if (digits >= 16)
                                        return -EOVERFLOW;

                                k = unhexchar(*q);
                                if (k < 0)
                                        return k;

                                value = (value << 4) | k;
                                mask = (mask << 4) | 0xFU;
                                digits++;
                        }

                        break;

                case MASK:
                        if (*q == 0) {
                                if (digits == 0 || mask == 0)
                                        return -EINVAL;

                                goto done;

                        } else if (*q == '+') {
                                if (digits == 0 || mask == 0)
                                        return -EINVAL;

                                state = DELTA_PLUS;
                                digits = 0;
                        } else if (*q == '-') {
                                if (digits == 0 || mask == 0)
                                        return -EINVAL;

                                state = DELTA_MINUS;
                                digits = 0;
                        } else {
                                int k;

                                if (digits >= 16)
                                        return -EOVERFLOW;

                                k = unhexchar(*q);
                                if (k < 0)
                                        return k;

                                mask = (mask << 4) | k;
                                digits++;
                        }

                        break;

                case DELTA_PLUS:
                case DELTA_MINUS:

                        if (*q == 0) {
                                if (digits == 0)
                                        return -EINVAL;

                                if (state == DELTA_MINUS) {
                                        if (udelta > - (uint64_t) INT64_MIN)
                                                return -EOVERFLOW;

                                        if (udelta == -(uint64_t) INT64_MIN)
                                                delta = INT64_MIN;
                                        else
                                                delta = -(int64_t) udelta;
                                } else {
                                        if (udelta > INT64_MAX)
                                                return -EOVERFLOW;

                                        delta = (int64_t) udelta;
                                }

                                goto done;
                        } else {
                                uint64_t d;
                                int k;

                                k = undecchar(*q);
                                if (k < 0)
                                        return k;

                                d = udelta*10;
                                if (d < udelta)
                                        return -EOVERFLOW;
                                d += k;
                                if (d < udelta*10)
                                        return -EOVERFLOW;

                                udelta = d;
                                digits ++;
                        }

                        break;
                }
        }

done:
        *c = (CaCutmark) {
                .value = value,
                .mask = mask,
                .delta = delta,
        };

        return 0;
}

int ca_cutmark_cmp(const CaCutmark *a, const CaCutmark *b) {
        int r;

        if (a == b)
                return 0;
        if (!a)
                return -1;
        if (!b)
                return 1;

        r = CMP(a->value, b->value);
        if (r != 0)
                return r;

        r = CMP(a->mask, b->mask);
        if (r != 0)
                return r;

        return CMP(a->delta, b->delta);
}

void ca_cutmark_sort(CaCutmark *c, size_t n) {

        if (n <= 1)
                return;

        assert(c);
        qsort(c, n, sizeof(CaCutmark), (__compar_fn_t) ca_cutmark_cmp);
}
