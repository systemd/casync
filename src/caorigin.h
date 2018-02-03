/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocaoriginhfoo
#define foocaoriginhfoo

#include "calocation.h"

/* Describes the origin of a data stream, as a series of location objects. This is primarily useful for tracking data
 * origins for creating file system reflinks. */

typedef struct CaOrigin {
        CaLocation *first;
        CaLocation **others;
        size_t n_items;
        size_t n_allocated;
        uint64_t n_bytes;
} CaOrigin;

int ca_origin_new(CaOrigin **ret);
CaOrigin* ca_origin_unref(CaOrigin *origin);

void ca_origin_flush(CaOrigin *origin);

int ca_origin_put(CaOrigin *origin, CaLocation *location);
CaLocation* ca_origin_get(CaOrigin *origin, size_t i);
int ca_origin_concat(CaOrigin *origin, CaOrigin *other, uint64_t n_bytes);

int ca_origin_put_void(CaOrigin *origin, uint64_t n_bytes);

int ca_origin_advance_items(CaOrigin *origin, size_t n_drop);
int ca_origin_advance_bytes(CaOrigin *origin, uint64_t n_bytes);

int ca_origin_extract_bytes(CaOrigin *origin, uint64_t n_bytes, CaOrigin **ret);

int ca_origin_dump(FILE *f, CaOrigin *origin);

static inline size_t ca_origin_items(CaOrigin *origin) {
        return origin ? origin->n_items : 0;
}

static inline uint64_t ca_origin_bytes(CaOrigin *origin) {
        return origin ? origin->n_bytes : 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(CaOrigin*, ca_origin_unref);

#endif
