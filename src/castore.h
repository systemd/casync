/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocastorehfoo
#define foocastorehfoo

#include "cachunk.h"
#include "cachunkid.h"
#include "cautil.h"

typedef struct CaStore CaStore;
typedef struct CaStoreIterator CaStoreIterator;

CaStore* ca_store_new(void);
CaStore *ca_store_new_cache(void);
CaStore* ca_store_unref(CaStore *store);
static inline void ca_store_unrefp(CaStore **store) {
        ca_store_unref(*store);
}

int ca_store_set_path(CaStore *store, const char *path);
int ca_store_set_compression(CaStore *store, CaChunkCompression c);
int ca_store_set_compression_type(CaStore *store, CaCompressionType compression);

int ca_store_get(CaStore *store, const CaChunkID *chunk_id, CaChunkCompression desired_compression, const void **ret, uint64_t *ret_size, CaChunkCompression *ret_effective_compression);
int ca_store_has(CaStore *store, const CaChunkID *chunk_id);
int ca_store_put(CaStore *store, const CaChunkID *chunk_id, CaChunkCompression effective_compression, const void *data, uint64_t size);

int ca_store_finalize(CaStore *store);

int ca_store_get_requests(CaStore *s, uint64_t *ret);
int ca_store_get_request_bytes(CaStore *s, uint64_t *ret);

int ca_store_set_digest_type(CaStore *s, CaDigestType type);

CaStoreIterator* ca_store_iterator_new(CaStore *store);
CaStoreIterator* ca_store_iterator_unref(CaStoreIterator *iter);
static inline void ca_store_iterator_unrefp(CaStoreIterator **iter) {
        ca_store_iterator_unref(*iter);
}
int ca_store_iterator_next(
                CaStoreIterator *iter,
                int *rootdir_fd,
                const char **subdir,
                int *subdir_fd,
                const char **chunk);

#endif
