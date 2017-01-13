#ifndef foocastorehfoo
#define foocastorehfoo

#include "objectid.h"

typedef struct CaStore CaStore;
typedef struct CaStream CaStream;

typedef enum CaStoreType {
        CA_STORE_LOCAL,
        CA_STORE_PROCESS,
        _CA_STORE_TYPE_INVALID = -1,
} CaStoreType;

CaStore* ca_store_new(void);
CaStore* ca_store_unref(CaStore *store);

int ca_store_set_local(CaStore *store, const char *path);
int ca_store_set_compress(CaStore *store, bool compress);

int ca_store_get(CaStore *store, const ObjectID *object_id, void **ret, size_t *ret_size);
int ca_store_put(CaStore *store, const ObjectID *object_id, const void *data, size_t size);

#endif
