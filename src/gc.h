/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "cachunk.h"
#include "castore.h"

typedef struct CaChunkCollection CaChunkCollection;

CaChunkCollection* ca_chunk_collection_new(void);
CaChunkCollection* ca_chunk_collection_unref(CaChunkCollection *c);
static inline void ca_chunk_collection_unrefp(CaChunkCollection **c) {
        ca_chunk_collection_unref(*c);
}

int ca_chunk_collection_add_index(CaChunkCollection *coll, const char *path);
int ca_chunk_collection_usage(CaChunkCollection *c, size_t *ret);
int ca_chunk_collection_size(CaChunkCollection *c, size_t *ret);

enum {
        CA_GC_VERBOSE = 1U,
        CA_GC_DRY_RUN = 2U,
};

int ca_gc_cleanup_unused(CaStore *store, CaChunkCollection *coll, unsigned flags);
