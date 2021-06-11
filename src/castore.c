/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "castore.h"
#include "def.h"
#include "dirent-util.h"
#include "realloc-buffer.h"
#include "rm-rf.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef EBADMSG */
/* #define EBADMSG __LINE__ */

struct CaStore {
        char *root;
        bool is_cache:1;
        bool mkdir_done:1;
        ReallocBuffer buffer;

        CaDigestType digest_type;
        ReallocBuffer validate_buffer;
        CaDigest *validate_digest;

        CaChunkCompression compression;
        CaCompressionType compression_type;

        uint64_t n_requests;
        uint64_t n_request_bytes;
};

struct CaStoreIterator {
        CaStore *store;

        DIR *rootdir;
        struct dirent *subdir_de;
        DIR *subdir;
};

CaStore* ca_store_new(void) {
        CaStore *store;

        store = new0(CaStore, 1);
        if (!store)
                return NULL;

        store->digest_type = _CA_DIGEST_TYPE_INVALID;

        store->compression = CA_CHUNK_COMPRESSED;
        store->compression_type = CA_COMPRESSION_DEFAULT;

        return store;
}

CaStore *ca_store_new_cache(void) {
        CaStore *s;

        s = new0(CaStore, 1);
        if (!s)
                return NULL;

        s->is_cache = true;
        s->compression = CA_CHUNK_AS_IS;
        s->compression_type = CA_COMPRESSION_DEFAULT;

        return s;
}

CaStore* ca_store_unref(CaStore *store) {
        if (!store)
                return NULL;

        if (store->is_cache && store->root)
                (void) rm_rf(store->root, REMOVE_ROOT|REMOVE_PHYSICAL);

        free(store->root);
        realloc_buffer_free(&store->buffer);

        ca_digest_free(store->validate_digest);
        realloc_buffer_free(&store->validate_buffer);

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

int ca_store_set_compression_type(CaStore *store, CaCompressionType compression_type) {
        if (!store)
                return -EINVAL;
        if (compression_type < 0)
                return -EINVAL;
        if (compression_type >= _CA_COMPRESSION_TYPE_MAX)
                return -EOPNOTSUPP;

        store->compression_type = compression_type;
        return 0;
}

int ca_store_get(
                CaStore *store,
                const CaChunkID *chunk_id,
                CaChunkCompression desired_compression,
                const void **ret,
                uint64_t *ret_size,
                CaChunkCompression *ret_effective_compression) {

        CaChunkCompression effective;
        ReallocBuffer *v;
        CaChunkID actual;
        int r;

        if (!store)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;
        if (!store->root)
                return store->is_cache ? -ENOENT : -EUNATCH;

        realloc_buffer_empty(&store->buffer);

        r = ca_chunk_file_load(AT_FDCWD, store->root, chunk_id, desired_compression, store->compression_type, &store->buffer, &effective);
        if (r < 0)
                return r;

        if (effective == CA_CHUNK_COMPRESSED) {
                realloc_buffer_empty(&store->validate_buffer);

                r = ca_decompress(realloc_buffer_data(&store->buffer),
                                  realloc_buffer_size(&store->buffer),
                                  &store->validate_buffer);
                if (r < 0)
                        return r;

                v = &store->validate_buffer;
        } else
                v = &store->buffer;

        if (!store->validate_digest) {
                r = ca_digest_new(store->digest_type >= 0 ? store->digest_type : CA_DIGEST_DEFAULT, &store->validate_digest);
                if (r < 0)
                        return r;
        }

        r = ca_chunk_id_make(store->validate_digest, realloc_buffer_data(v), realloc_buffer_size(v), &actual);
        if (r < 0)
                return r;

        if (!ca_chunk_id_equal(chunk_id, &actual)) {
                CaDigestType old_type, i;
                bool good = false;
                /* If a digest is explicitly configured, only accept this digest */

                if (store->digest_type >= 0)
                        return -EBADMSG;

                old_type = ca_digest_get_type(store->validate_digest);
                if (old_type < 0)
                        return -EINVAL;

                for (i = 0; i < _CA_DIGEST_TYPE_MAX; i++) {

                        if (i == old_type)
                                continue;

                        r = ca_digest_set_type(store->validate_digest, i);
                        if (r < 0)
                                return r;

                        r = ca_chunk_id_make(store->validate_digest, realloc_buffer_data(v), realloc_buffer_size(v), &actual);
                        if (r < 0)
                                return r;

                        if (ca_chunk_id_equal(chunk_id, &actual)) {
                                good = true;
                                break;
                        }
                }

                if (!good)
                        return -EBADMSG;
        }

        *ret = realloc_buffer_data(&store->buffer);
        *ret_size = realloc_buffer_size(&store->buffer);

        if (ret_effective_compression)
                *ret_effective_compression = effective;

        store->n_requests++;
        store->n_request_bytes += realloc_buffer_size(&store->buffer);

        return r;
}

int ca_store_has(CaStore *store, const CaChunkID *chunk_id) {

        if (!store)
                return -EINVAL;
        if (!store->root)
                return store->is_cache ? -ENOENT : -EUNATCH;

        return ca_chunk_file_test(AT_FDCWD, store->root, chunk_id);
}

int ca_store_put(
                CaStore *store,
                const CaChunkID *chunk_id,
                CaChunkCompression effective_compression,
                const void *data,
                uint64_t size) {

        int r;

        if (!store)
                return -EINVAL;

        if (!store->root) {
                const char *d;

                if (!store->is_cache)
                        return -EUNATCH;

                r = var_tmp_dir(&d);
                if (r < 0)
                        return r;

                if (asprintf(&store->root, "%s/%" PRIx64 ".castr/", d, random_u64()) < 0)
                        return -ENOMEM;
        }

        if (!store->mkdir_done) {
                if (mkdir(store->root, 0777) < 0 && errno != EEXIST)
                        return -errno;

                store->mkdir_done = true;
        }

        return ca_chunk_file_save(
                        AT_FDCWD, store->root,
                        chunk_id,
                        effective_compression, store->compression,
                        store->compression_type,
                        data, size);
}

int ca_store_get_requests(CaStore *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = s->n_requests;
        return 0;
}

int ca_store_get_request_bytes(CaStore *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = s->n_request_bytes;
        return 0;
}

int ca_store_set_digest_type(CaStore *s, CaDigestType type) {
        int r;

        if (!s)
                return -EINVAL;
        if (type >= _CA_DIGEST_TYPE_MAX)
                return -EOPNOTSUPP;

        if (type < 0)
                s->digest_type = _CA_DIGEST_TYPE_INVALID;
        else {
                if (s->validate_digest) {
                        r = ca_digest_set_type(s->validate_digest, type);
                        if (r < 0)
                                return r;
                }

                s->digest_type = type;
        }

        return 0;
}

CaStoreIterator* ca_store_iterator_new(CaStore *store) {
        CaStoreIterator *it;

        it = new0(CaStoreIterator, 1);
        if (!it)
                return NULL;

        it->store = store;

        return it;
}

CaStoreIterator* ca_store_iterator_unref(CaStoreIterator *iter) {
        if (!iter)
                return NULL;

        if (iter->rootdir)
                closedir(iter->rootdir);
        if (iter->subdir)
                closedir(iter->subdir);
        return mfree(iter);
}

int ca_store_iterator_next(
                CaStoreIterator *iter,
                int *rootdir_fd,
                const char **subdir,
                int *subdir_fd,
                const char **chunk) {

        struct dirent *de;

        if (!iter->rootdir) {
                iter->rootdir = opendir(iter->store->root);
                if (!iter->rootdir)
                        return -errno;
        }

        for (;;) {
                if (!iter->subdir) {
                        int fd;

                        errno = 0;
                        iter->subdir_de = readdir(iter->rootdir);
                        if (!iter->subdir_de) {
                                if (errno > 0)
                                        return -errno;
                                return 0; /* done */
                        }

                        fd = openat(dirfd(iter->rootdir), iter->subdir_de->d_name,
                                    O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                        if (fd < 0) {
                                if (errno == EISDIR)
                                        continue;
                                return -errno;
                        }

                        iter->subdir = fdopendir(fd);
                        if (!iter->subdir) {
                                safe_close(fd);
                                return -errno;
                        }
                }

                FOREACH_DIRENT_ALL(de, iter->subdir, return -errno) {
                        if (!dirent_is_file_with_suffix(de, ".cacnk"))
                                continue;

                        if (rootdir_fd)
                                *rootdir_fd = dirfd(iter->rootdir);
                        if (subdir)
                                *subdir = iter->subdir_de->d_name;
                        if (subdir_fd)
                                *subdir_fd = dirfd(iter->subdir);
                        if (chunk)
                                *chunk = de->d_name;
                        return 1; /* success */
                }

                assert_se(closedir(iter->subdir) == 0);
                iter->subdir = NULL;
        }
}
