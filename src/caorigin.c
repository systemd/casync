/* SPDX-License-Identifier: LGPL-2.1+ */

#include "caorigin.h"

/* #undef EUNATCH */
/* #define EUNATCH __LINE__ */

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

int ca_origin_new(CaOrigin **ret) {
        CaOrigin *origin;

        if (!ret)
                return -EINVAL;

        origin = new0(CaOrigin, 1);
        if (!origin)
                return -ENOMEM;

        *ret = origin;

        return 0;
}

void ca_origin_flush(CaOrigin *origin) {
        size_t i;

        if (!origin)
                return;

        for (i = 0; i < origin->n_items; i++)
                ca_location_unref(ca_origin_get(origin, i));

        origin->n_items = 0;
        origin->n_bytes = 0;
}

CaOrigin* ca_origin_unref(CaOrigin *origin) {
        if (!origin)
                return NULL;

        ca_origin_flush(origin);
        free(origin->others);

        return mfree(origin);
}

int ca_origin_put(CaOrigin *origin, CaLocation *location) {
        int r;

        if (!origin)
                return -EINVAL;
        if (!location)
                return -EINVAL;

        if (location->size == UINT64_MAX)
                return -EINVAL;

        if (origin->n_items == 0) {
                assert(origin->n_bytes == 0);

                origin->first = ca_location_ref(location);
                origin->n_items = 1;
                origin->n_bytes = location->size;
                return 0;
        }

        if (origin->n_items == 1)
                r = ca_location_merge(&origin->first, location);
        else
                r = ca_location_merge(origin->others + origin->n_items - 2, location);
        if (r < 0)
                return r;
        if (r > 0) { /* merged successfully */
                origin->n_bytes += location->size;
                return 0;
        }

        /* Couldn't merge, add one more item */
        if (!GREEDY_REALLOC(origin->others, origin->n_allocated, origin->n_items))
                return -ENOMEM;

        origin->others[origin->n_items-1] = ca_location_ref(location);
        origin->n_items++;
        origin->n_bytes += location->size;

        return 0;
}

CaLocation* ca_origin_get(CaOrigin *origin, size_t i) {

        if (i >= ca_origin_items(origin))
                return NULL;

        if (i == 0)
                return origin->first;

        return origin->others[i-1];
}

int ca_origin_concat(CaOrigin *origin, CaOrigin *other, uint64_t n_bytes) {
        CaLocation **copy;
        size_t n, i;
        int r;

        if (!origin)
                return -EINVAL;
        if (n_bytes == 0)
                return 0;
        if (n_bytes != UINT64_MAX && ca_origin_bytes(other) < n_bytes)
                return -ESPIPE;
        if (n_bytes == UINT64_MAX && ca_origin_items(other) == 0)
                return 0;

        n = other->n_items;

        if (other == origin) {
                /* If origin and other are identical, make a copy of the location array first, so that we don't run
                 * into our own modifications */

                copy = newa(CaLocation*, n);

                for (i = 0; i < n; i++)
                        copy[i] = ca_location_ref(ca_origin_get(other, i));
        } else
                copy = NULL;

        for (i = 0; i < n; i++) {
                CaLocation *l;

                if (copy)
                        l = copy[i];
                else
                        l = ca_origin_get(other, i);

                assert(l);
                assert(l->size != UINT64_MAX);

                if (n_bytes == UINT64_MAX) {
                        r = ca_origin_put(origin, l);
                        if (r < 0)
                                goto finish;
                } else {
                        ca_location_ref(l);

                        if (l->size > n_bytes) {
                                r = ca_location_patch_size(&l, n_bytes);
                                if (r < 0) {
                                        ca_location_unref(l);
                                        goto finish;
                                }
                        }

                        n_bytes -= l->size;

                        r = ca_origin_put(origin, l);
                        ca_location_unref(l);
                        if (r < 0)
                                goto finish;

                        if (n_bytes == 0)
                                break;
                }
        }

        r = n > 0;

finish:
        if (copy) {
                for (i = 0; i < n; i++)
                        ca_location_unref(copy[i]);
        }

        return r;
}

int ca_origin_advance_items(CaOrigin *origin, size_t n_drop) {
        uint64_t drop_bytes;
        size_t i;

        if (n_drop == 0)
                return 0;
        if (n_drop > ca_origin_items(origin))
                return -ESPIPE;
        if (n_drop == ca_origin_items(origin)) {
                ca_origin_flush(origin);
                return 0;
        }

        drop_bytes = origin->first->size;
        ca_location_unref(origin->first);

        for (i = 1; i < n_drop; i++) {
                assert(origin->others[i-1]->size != UINT64_MAX);

                drop_bytes += origin->others[i-1]->size;
                ca_location_unref(origin->others[i-1]);
        }

        origin->first = origin->others[n_drop-1];
        memmove(origin->others, origin->others + n_drop, (origin->n_items - n_drop - 1) * sizeof(CaLocation*));

        assert(origin->n_bytes > drop_bytes);

        origin->n_items -= n_drop;
        origin->n_bytes -= drop_bytes;

        return 0;
}

int ca_origin_advance_bytes(CaOrigin *origin, uint64_t n_bytes) {
        size_t i;
        int r;

        if (n_bytes == 0)
                return 0;
        if (n_bytes > ca_origin_bytes(origin))
                return -ESPIPE;
        if (n_bytes == ca_origin_bytes(origin)) {
                ca_origin_flush(origin);
                return 0;
        }

        for (i = 0; i < origin->n_items; i++) {
                CaLocation *l;

                l = ca_origin_get(origin, i);

                assert(l);
                assert(l->size != UINT64_MAX);

                if (l->size > n_bytes)
                        break;

                n_bytes -= l->size;
                l = NULL;
        }

        r = ca_origin_advance_items(origin, i);
        if (r < 0)
                return r;

        assert(origin->n_bytes > n_bytes);
        assert(origin->first);
        assert(origin->first->size > n_bytes);

        r = ca_location_advance(&origin->first, n_bytes);
        if (r < 0)
                return r;

        origin->n_bytes -= n_bytes;
        return 0;
}

int ca_origin_dump(FILE *f, CaOrigin *origin) {
        size_t i;

        if (!f)
                f = stderr;

        for (i = 0; i < origin->n_items; i++) {
                const char *c;

                c = ca_location_format(ca_origin_get(origin, i));
                if (!c)
                        return -ENOMEM;

                if (i > 0)
                        fputs(" → ", f);

                fputs(c, f);
        }

        fputc('\n', f);
        return 0;
}

int ca_origin_put_void(CaOrigin *origin, uint64_t n_bytes) {
        int r;

        if (!origin)
                return -EINVAL;
        if (n_bytes <= 0)
                return 0;

        if (origin->n_items == 1 &&
            origin->first->designator == CA_LOCATION_VOID) {

                /* If we are only void, simply extend it */
                r = ca_location_patch_size(&origin->first,
                                           origin->first->size + n_bytes);

        } else if (origin->n_items > 1 &&
                   origin->others[origin->n_items - 2]->designator == CA_LOCATION_VOID) {

                /* If we end with a void, extend it */

                r = ca_location_patch_size(origin->others + origin->n_items - 2,
                                           origin->others[origin->n_items - 2]->size + n_bytes);

        } else {
                CaLocation *v;

                /* Otherwise event a new void location object */

                r = ca_location_new_void(n_bytes, &v);
                if (r < 0)
                        return r;

                r = ca_origin_put(origin, v);
                ca_location_unref(v);

                return r;
        }

        if (r < 0)
                return r;

        origin->n_bytes += n_bytes;

        return 0;
}

int ca_origin_extract_bytes(CaOrigin *origin, uint64_t n_bytes, CaOrigin **ret) {
        _cleanup_(ca_origin_unrefp) CaOrigin *t = NULL;
        int r;

        if (n_bytes == 0) {
                *ret = NULL;
                return 0;
        }

        r = ca_origin_new(&t);
        if (r < 0)
                return r;

        r = ca_origin_concat(t, origin, n_bytes);
        if (r < 0)
                return r;

        *ret = t;
        t = NULL;

        return 0;
}
