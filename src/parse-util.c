#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-util.h"
#include "util.h"

int parse_size(const char *t, uint64_t *size) {

        struct table {
                const char *suffix;
                unsigned long long factor;
        };

        static const struct table table[] = {
                { "E", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "P", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "T", 1024ULL*1024ULL*1024ULL*1024ULL },
                { "G", 1024ULL*1024ULL*1024ULL },
                { "M", 1024ULL*1024ULL },
                { "K", 1024ULL },
                { "B", 1ULL },
                { "",  1ULL },
        };

        const char *p;
        unsigned long long r = 0;
        unsigned n_entries, start_pos = 0;

        assert(t);
        assert(size);

        n_entries = ELEMENTSOF(table);

        p = t;
        do {
                unsigned long long l, tmp;
                double frac = 0;
                char *e;
                unsigned i;

                p += strspn(p, WHITESPACE);

                errno = 0;
                l = strtoull(p, &e, 10);
                if (errno > 0)
                        return -errno;
                if (e == p)
                        return -EINVAL;
                if (*p == '-')
                        return -ERANGE;

                if (*e == '.') {
                        e++;

                        /* strtoull() itself would accept space/+/- */
                        if (*e >= '0' && *e <= '9') {
                                unsigned long long l2;
                                char *e2;

                                l2 = strtoull(e, &e2, 10);
                                if (errno > 0)
                                        return -errno;

                                /* Ignore failure. E.g. 10.M is valid */
                                frac = l2;
                                for (; e < e2; e++)
                                        frac /= 10;
                        }
                }

                e += strspn(e, WHITESPACE);
                for (i = start_pos; i < n_entries; i++)
                        if (startswith(e, table[i].suffix))
                                break;

                if (i >= n_entries)
                        return -EINVAL;

                if (l + (frac > 0) > ULLONG_MAX / table[i].factor)
                        return -ERANGE;

                tmp = l * table[i].factor + (unsigned long long) (frac * table[i].factor);
                if (tmp > ULLONG_MAX - r)
                        return -ERANGE;

                r += tmp;
                if ((unsigned long long) (uint64_t) r != r)
                        return -ERANGE;

                p = e + strlen(table[i].suffix);

                start_pos = i + 1;

        } while (*p);

        *size = r;

        return 0;
}
