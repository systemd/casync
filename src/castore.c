#include <fcntl.h>
#include <lzma.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cachunk.h"
#include "castore.h"
#include "def.h"
#include "realloc-buffer.h"
#include "rm-rf.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

struct CaStore {
        char *root;
        bool destroy;
        ReallocBuffer buffer;

        CaChunkCompression compression;
};

CaStore* ca_store_new(void) {
        CaStore *store;

        store = new0(CaStore, 1);
        if (!store)
                return NULL;

        store->compression = CA_CHUNK_COMPRESSED;
        return store;
}

CaStore *ca_store_new_cache(void) {
        CaStore *s;

        s = new0(CaStore, 1);
        if (!s)
                return NULL;

        s->destroy = true;

        if (asprintf(&s->root, "/var/tmp/%" PRIx64 ".castr/", random_u64()) < 0) {
                free(s);
                return NULL;
        }

        s->compression = CA_CHUNK_AS_IS;
        return s;
}

CaStore* ca_store_unref(CaStore *store) {
        if (!store)
                return NULL;

        if (store->destroy && store->root)
                (void) rm_rf(store->root, REMOVE_ROOT|REMOVE_PHYSICAL);

        free(store->root);
        realloc_buffer_free(&store->buffer);

        return mfree(store);
}

int ca_store_set_path(CaStore *store, const char *path) {
        if (!store)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (store->root)
                return -EBUSY;

        if (endswith(path, "/"))
                store->root = strdup(path);
        else
                store->root = strjoin(path, "/", NULL);
        if (!store->root)
                return -ENOMEM;

        return 0;
}

int ca_store_set_compression(CaStore *store, CaChunkCompression c) {
        if (!store)
                return -EINVAL;
        if (c < 0)
                return -EINVAL;
        if (c >= _CA_CHUNK_COMPRESSION_MAX)
                return -EINVAL;

        store->compression = c;
        return 0;
}

int ca_store_get(
                CaStore *store,
                const CaChunkID *chunk_id,
                CaChunkCompression desired_compression,
                const void **ret,
                size_t *ret_size,
                CaChunkCompression *ret_effective_compression) {

        int r;

        if (!store)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;
        if (!store->root)
                return -EUNATCH;

        realloc_buffer_empty(&store->buffer);

        r = ca_chunk_file_load(AT_FDCWD, store->root, chunk_id, desired_compression, &store->buffer, ret_effective_compression);
        if (r < 0)
                return r;

        *ret = realloc_buffer_data(&store->buffer);
        *ret_size = realloc_buffer_size(&store->buffer);

        return r;
}

int ca_store_has(CaStore *store, const CaChunkID *chunk_id) {

        if (!store)
                return -EINVAL;
        if (!store->root)
                return -EUNATCH;

        return ca_chunk_file_test(AT_FDCWD, store->root, chunk_id);
}

int ca_store_put(
                CaStore *store,
                const CaChunkID *chunk_id,
                CaChunkCompression effective_compression,
                const void *data,
                size_t size) {

        if (!store)
                return -EINVAL;
        if (!store->root)
                return -EUNATCH;

        if (mkdir(store->root, 0777) < 0 && errno != EEXIST)
                return -errno;

        return ca_chunk_file_save(AT_FDCWD, store->root, chunk_id, effective_compression, store->compression, data, size);
}
