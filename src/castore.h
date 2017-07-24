#ifndef foocastorehfoo
#define foocastorehfoo

#include "cachunkid.h"
#include "cautil.h"

typedef struct CaStore CaStore;

CaStore* ca_store_new(void);
CaStore *ca_store_new_cache(void);
CaStore* ca_store_unref(CaStore *store);

int ca_store_set_path(CaStore *store, const char *path);
int ca_store_set_compression(CaStore *store, CaChunkCompression c);

int ca_store_get(CaStore *store, const CaChunkID *chunk_id, CaChunkCompression desired_compression, const void **ret, uint64_t *ret_size, CaChunkCompression *ret_effective_compression);
int ca_store_has(CaStore *store, const CaChunkID *chunk_id);
int ca_store_put(CaStore *store, const CaChunkID *chunk_id, CaChunkCompression effective_compression, const void *data, uint64_t size);

int ca_store_get_requests(CaStore *s, uint64_t *ret);
int ca_store_get_request_bytes(CaStore *s, uint64_t *ret);

#endif
