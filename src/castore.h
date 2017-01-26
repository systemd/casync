#ifndef foocastorehfoo
#define foocastorehfoo

#include "caobjectid.h"

typedef struct CaStore CaStore;

CaStore* ca_store_new(void);
CaStore *ca_store_new_cache(void);
CaStore* ca_store_unref(CaStore *store);

int ca_store_set_path(CaStore *store, const char *path);
int ca_store_set_compress(CaStore *store, bool compress);

int ca_store_get(CaStore *store, const CaObjectID *object_id, const void **ret, size_t *ret_size);
int ca_store_has(CaStore *store, const CaObjectID *object_id);
int ca_store_put(CaStore *store, const CaObjectID *object_id, const void *data, size_t size);

#endif
