/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <fcntl.h>
#include <lzma.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "affinity-count.h"
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

#define WORKER_THREADS_MAX 64U

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

        pthread_t worker_threads[WORKER_THREADS_MAX];
        size_t n_worker_threads, n_worker_threads_max;
        int worker_thread_socket[2];
};

struct CaStoreIterator {
        CaStore *store;

        DIR *rootdir;
        struct dirent *subdir_de;
        DIR *subdir;
};

CaStore* ca_store_new(void) {
        CaStore *store;

        store = new(CaStore, 1);
        if (!store)
                return NULL;

        *store = (CaStore) {
                .digest_type = _CA_DIGEST_TYPE_INVALID,
                .compression = CA_CHUNK_COMPRESSED,
                .compression_type = CA_COMPRESSION_DEFAULT,
                .worker_thread_socket = { -1, -1},
                .n_worker_threads_max = (size_t) -1,
        };

        return store;
}

CaStore *ca_store_new_cache(void) {
        CaStore *s;

        s = new(CaStore, 1);
        if (!s)
                return NULL;

        *s = (CaStore) {
                .is_cache = true,
                .compression = CA_CHUNK_AS_IS,
                .compression_type = CA_COMPRESSION_DEFAULT,

                .worker_thread_socket = { -1, -1 },
                .n_worker_threads_max = (size_t) -1,
        };

        return s;
}

CaStore* ca_store_unref(CaStore *store) {
        if (!store)
                return NULL;

        (void) ca_store_finalize(store);

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

struct queue_entry {
        CaChunkID chunk_id;
        CaChunkCompression effective_compression;
        void *data;
        size_t size;
};

static void* worker_thread(void *p) {
        CaStore *store = p;
        int ret = 0, r;

        assert(store);
        assert(store->worker_thread_socket[1] >= 0);

        (void) pthread_setname_np(pthread_self(), "worker-thread");

        for (;;) {
                struct queue_entry e;
                ssize_t n;

                n = recv(store->worker_thread_socket[0], &e, sizeof(e), 0);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        log_debug_errno(errno, "Failed to read from thread pool socket: %m");
                        return INT_TO_PTR(errno);
                }
                if (n == 0) /* Either EOF or zero-sized datagram (Linux doesn't really allow us to
                             * distinguish that), we take both as an indication to exit the worker thread. */
                        break;

                assert(n == sizeof(e));

                r = ca_chunk_file_save(
                                AT_FDCWD, store->root,
                                &e.chunk_id,
                                e.effective_compression, store->compression,
                                store->compression_type,
                                e.data, e.size);
                free(e.data);

                if (r < 0) {
                        log_debug_errno(r, "Failed to store chunk in store: %m");

                        if (r != -EEXIST)
                                ret = r;
                }
        }

        return INT_TO_PTR(ret);
}

static int determine_worker_threads_max(CaStore *store) {
        const char *e;
        int r;

        assert(store);

        if (store->n_worker_threads_max != (size_t) -1)
                return 0;

        e = getenv("CASYNC_WORKER_THREADS");
        if (e) {
                unsigned u;

                r = safe_atou(e, &u);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse $CASYNC_WORKER_THREADS, ignoring: %s", e);
                else if (u > WORKER_THREADS_MAX) {
                        log_debug("$CASYNC_WORKER_THREADS out of range, clamping to %zu: %s", (size_t) WORKER_THREADS_MAX, e);
                        store->n_worker_threads_max = WORKER_THREADS_MAX;
                } else {
                        store->n_worker_threads_max = u;
                        return 0;
                }
        }

        r = cpus_in_affinity_mask();
        if (r < 0)
                return log_debug_errno(r, "Failed to determine CPUs in affinity mask: %m");

        store->n_worker_threads_max = MIN((size_t) r, WORKER_THREADS_MAX);
        return 0;
}

static int start_worker_thread(CaStore *store) {
        int r;

        assert(store);

        r = determine_worker_threads_max(store);
        if (r < 0)
                return r;

        if (store->n_worker_threads >= (size_t) store->n_worker_threads_max)
                return 0;

        if (store->worker_thread_socket[0] < 0)
                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, store->worker_thread_socket) < 0)
                        return -errno;

        r = pthread_create(store->worker_threads + store->n_worker_threads, NULL, worker_thread, store);
        if (r != 0)
                return -r;

        store->n_worker_threads++;

        log_debug("Started store worker thread %zu.", store->n_worker_threads);
        return 0;
}

static int submit_to_worker_thread(
                CaStore *store,
                const CaChunkID *chunkid,
                CaChunkCompression effective_compression,
                const void *p,
                uint64_t l) {

        struct queue_entry e;
        void *copy = NULL;
        ssize_t n;
        int r;

        assert(store);

        /* If there's no need to compress/decompress, then let's do things client side, since the operation
         * is likely IO bound, not CPU bound */
        if (store->compression == CA_CHUNK_AS_IS ||
            store->compression == effective_compression)
                return -ENOANO;

        /* Before we submit the chunk for compression, let's see if it exists already. If so, let's return
         * -EEXIST right away, so that the caller can count reused chunks. Note that this is a bit racy
         * currently, as submitted but not yet processed chunks are not considered. */
        r = ca_store_has(store, chunkid);
        if (r < 0)
                return r;
        if (r > 0)
                return -EEXIST;

        /* Let's start a new worker thread each time we have a new job to process, until we reached all
         * worker threads we need */
        (void) start_worker_thread(store);

        /* If there are no worker threads, do things client side */
        if (store->n_worker_threads <= 0 ||
            store->worker_thread_socket[1] < 0)
                return -ENETDOWN;

        copy = memdup(p, l);
        if (!copy)
                return -ENOMEM;

        e = (struct queue_entry) {
                .chunk_id = *chunkid,
                .effective_compression = effective_compression,
                .data = copy,
                .size = l,
        };

        n = send(store->worker_thread_socket[1], &e, sizeof(e), 0);
        if (n < 0) {
                free(copy);
                return -errno;
        }

        assert(n == sizeof(e));
        return 0;
}

int ca_store_finalize(CaStore *store) {
        int ret = 0, r;
        size_t i;

        assert(store);

        /* Trigger EOF in all worker threads */
        store->worker_thread_socket[1] = safe_close(store->worker_thread_socket[1]);

        for (i = 0; i < store->n_worker_threads; i++) {
                void *p;
                r = pthread_join(store->worker_threads[i], &p);
                if (r != 0)
                        ret = -r;
                if (p != NULL)
                        ret = -PTR_TO_INT(p);
        }

        store->n_worker_threads = 0;
        store->worker_thread_socket[0] = safe_close(store->worker_thread_socket[0]);

        /* Propagate errors we ran into while processing store requests. This is useful for callers to
         * determine whether the worker threads ran into any problems. */
        return ret;
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

        r = submit_to_worker_thread(
                        store,
                        chunk_id,
                        effective_compression,
                        data, size);
        if (r >= 0)
                return 0;

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
