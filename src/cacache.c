/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cacache.h"
#include "chattr.h"
#include "realloc-buffer.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

struct CaCache {
        unsigned n_ref;
        int fd;
        char *path;
        CaDigestType digest_type;
        CaDigest *digest;
};

static CaDigestType ca_cache_digest_type(CaCache *c) {
        assert_se(c);

        return c->digest_type >= 0 ? c->digest_type : CA_DIGEST_DEFAULT;
}

CaCache *ca_cache_new(void) {
        CaCache *c;

        c = new0(CaCache, 1);
        if (!c)
                return NULL;

        c->n_ref = 1;
        c->fd = -1;
        c->digest_type = _CA_DIGEST_TYPE_INVALID;

        return c;
}

CaCache *ca_cache_unref(CaCache *c) {
        if (!c)
                return NULL;

        assert_se(c->n_ref > 0);
        c->n_ref--;

        if (c->n_ref > 0)
                return NULL;

        free(c->path);
        safe_close(c->fd);
        ca_digest_free(c->digest);

        return mfree(c);
}

CaCache *ca_cache_ref(CaCache *c) {
        if (!c)
                return NULL;

        assert_se(c->n_ref > 0);
        c->n_ref++;

        return c;
}

int ca_cache_set_digest_type(CaCache *c, CaDigestType type) {
        if (!c)
                return -EINVAL;
        if (type < 0)
                return -EINVAL;
        if (type >= _CA_DIGEST_TYPE_MAX)
                return -EINVAL;

        if (c->digest)
                return -EBUSY;

        c->digest_type = type;
        return 0;
}

int ca_cache_set_fd(CaCache *c, int fd) {
        if (!c)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (c->fd >= 0)
                return -EBUSY;
        if (c->path)
                return -EBUSY;

        c->fd = fd;
        return 0;
}

int ca_cache_set_path(CaCache *c, const char *path) {

        if (!c)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (c->fd >= 0)
                return -EBUSY;
        if (c->path)
                return -EBUSY;

        c->path = strdup(path);
        if (!c->path)
                return -ENOMEM;

        return 0;
}

static int ca_cache_open(CaCache *c) {
        int r;

        if (!c)
                return -EINVAL;
        if (c->fd >= 0)
                return 0;
        if (!c->path)
                return -EUNATCH;

        (void) mkdir(c->path, 0777);

        c->fd = open(c->path, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (c->fd < 0)
                return -errno;

        /* We never want the cache to be saved, it's entirely redundant after all, let's hence set the FS_NODUMP_FL
         * flag on it */
        r = mask_attr_fd(c->fd, FS_NODUMP_FL, FS_NODUMP_FL);
        if (r < 0)
                log_debug_errno(r, "Failed to set FS_NODUMP_PL flag on cache directory: %m");

        return 0;
}

int ca_cache_get(CaCache *c, CaLocation *location, CaChunkID *ret_chunk_id, CaOrigin **ret_origin) {
        _cleanup_(ca_location_unrefp) CaLocation *patched_location = NULL;
        _cleanup_(realloc_buffer_free) ReallocBuffer buffer = {};
        _cleanup_(ca_origin_unrefp) CaOrigin *origin = NULL;
        char path[CA_CHUNK_ID_PATH_SIZE(NULL, ".cachi")];
        _cleanup_free_ char *dest = NULL;
        _cleanup_(safe_closep) int fd = -1;
        CaChunkID key_id, chunk_id;
        int r;

        if (!c)
                return -EINVAL;
        if (!location)
                return -EINVAL;

        assert_se(location->mtime != UINT64_MAX);

        r = ca_cache_open(c);
        if (r < 0)
                return r;

        if (!c->digest) {
                r = ca_digest_new(ca_cache_digest_type(c), &c->digest);
                if (r < 0)
                        return r;
        }

        r = ca_location_id_make(c->digest, location, false, &key_id);
        if (r < 0)
                return r;

        ca_chunk_id_format_path(NULL, &key_id, ".cachi", path);

        r = readlinkat_malloc(c->fd, path, &dest);
        if (r == -EINVAL) {

                /* Not a symlink? read as file then */
                fd = openat(c->fd, path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd < 0)
                        return -errno;

                r = realloc_buffer_read_target(&buffer, fd, CA_CHUNK_ID_SIZE);
                if (r < 0)
                        return r;
                if (r == 0) /* file too short */
                        return -EINVAL;

                /* If this is a file, it begins with the binary chunk ID. Copy it out, and move ahead */
                memcpy(&chunk_id, realloc_buffer_data(&buffer), CA_CHUNK_ID_SIZE);
                r = realloc_buffer_advance(&buffer, CA_CHUNK_ID_SIZE);
                if (r < 0)
                        return r;

        } else if (r < 0) /* Any other error? */
                return r;
        else {
                const char *p, *q;

                /* A symlink? then add it to our buffer */
                if (!realloc_buffer_donate(&buffer, dest, strlen(dest)+1))
                        return -ENOMEM;
                dest = NULL;

                if (realloc_buffer_size(&buffer) < CA_CHUNK_ID_SIZE*2+1)
                        return -EINVAL;

                p = realloc_buffer_data(&buffer);
                if (p[CA_CHUNK_ID_SIZE*2] != ':')
                        return -EINVAL;

                /* If this is a symlink, its target begins with an ASCII formatted chunk ID. Copy it out, and move ahead */
                q = strndupa(p, CA_CHUNK_ID_SIZE*2);
                if (!ca_chunk_id_parse(q, &chunk_id))
                        return -EINVAL;

                r = realloc_buffer_advance(&buffer, CA_CHUNK_ID_SIZE*2+1);
                if (r < 0)
                        return r;
        }

        r = ca_origin_new(&origin);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(ca_location_unrefp) CaLocation *item = NULL;
                const char *p, *e;
                size_t l;

                l = realloc_buffer_size(&buffer);
                p = realloc_buffer_data(&buffer);

                e = memchr(p, 0, l);
                if (!e) {
                        /* No NUL byte? If we can read more, try to do so. Otherwise, the file is truncated */
                        if (fd >= 0) {
                                r = realloc_buffer_read(&buffer, fd);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        continue;
                        }

                        if (l == 0) /* EOF? */
                                break;

                        /* Truncated! */
                        return -EINVAL;
                }

                r = ca_location_parse(p, &item);
                if (r < 0)
                        return r;

                /* In locations from the cache both size and mtime must be initialized */
                if (item->size == UINT64_MAX)
                        return -EINVAL;
                if (item->mtime == UINT64_MAX)
                        return -EINVAL;

                r = realloc_buffer_advance(&buffer, e - p + 1);
                if (r < 0)
                        return r;

                r = ca_origin_put(origin, item);
                if (r < 0)
                        return r;
        }

        /* The origin we read from the cache can't be empty */
        if (ca_origin_bytes(origin) == 0)
                return -EINVAL;

        /* The first item of the origin must match our lookup key. If it doesn't something's bad. */
        if (!ca_location_equal(location, ca_origin_get(origin, 0), false))
                return -EINVAL;

        if (ret_chunk_id)
                *ret_chunk_id = chunk_id;

        if (ret_origin) {
                *ret_origin = origin;
                origin = NULL;
        }

        return 0;
}

int ca_cache_put(CaCache *c, CaOrigin *origin, const CaChunkID *chunk_id) {
        _cleanup_(realloc_buffer_free) ReallocBuffer buffer = {};
        char path[CA_CHUNK_ID_PATH_SIZE(NULL, ".cachi")];
        _cleanup_(unlink_and_freep) char *temp = NULL;
        _cleanup_(safe_closep) int fd = -1;
        CaLocation *first_location;
        CaChunkID key_id;
        const char *four;
        size_t i;
        int r;

        if (!c)
                return -EINVAL;
        if (!origin)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;

        first_location = ca_origin_get(origin, 0);
        if (!first_location)
                return -EINVAL;

        r = ca_cache_open(c);
        if (r < 0)
                return r;

        if (!c->digest) {
                r = ca_digest_new(ca_cache_digest_type(c), &c->digest);
                if (r < 0)
                        return r;
        }

        r = ca_location_id_make(c->digest, first_location, false, &key_id);
        if (r < 0)
                return r;

        ca_chunk_id_format_path(NULL, &key_id, ".cachi", path);

        four = strndupa(path, 4);
        (void) mkdirat(c->fd, four, 0755);

        if (ca_origin_items(origin) == 1) {
                const char *f;
                char *p;

                /* If there's only a single item, then let's try to create this as symlink, is it is the cheapest
                 * option */

                f = ca_location_format(first_location);
                if (!f)
                        return -ENOMEM;

                p = newa(char, CA_CHUNK_ID_SIZE*2 + 1 + strlen(f) + 1);

                ca_chunk_id_format(chunk_id, p);
                p[CA_CHUNK_ID_SIZE*2] = ':';
                strcpy(p + CA_CHUNK_ID_SIZE*2+1, f);

                if (symlinkat(p, c->fd, path) < 0) {
                        if (errno == EEXIST)
                                return 0;

                        if (errno != ENAMETOOLONG)
                                return -errno;
                } else
                        return 1;

        } else {
                /* Check if there's already a file for this, before we create one */
                if (faccessat(c->fd, path, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                        return 0;
        }

        r = tempfn_random(path, &temp);
        if (r < 0)
                return r;

        fd = openat(c->fd, temp, O_CREAT|O_WRONLY|O_CLOEXEC|O_EXCL|O_NOFOLLOW|O_EXCL, 0666);
        if (fd < 0)
                return -errno;

        if (!realloc_buffer_append(&buffer, chunk_id, sizeof(*chunk_id)))
                return -ENOMEM;

        for (i = 0; i < ca_origin_items(origin); i++) {
                CaLocation *l;
                const char *f;

                r = realloc_buffer_write_maybe(&buffer, fd);
                if (r < 0)
                        return r;

                l = ca_origin_get(origin, i);
                if (!l)
                        return -EINVAL;

                f = ca_location_format(l);
                if (!f)
                        return -ENOMEM;

                if (!realloc_buffer_append(&buffer, f, strlen(f) + 1))
                        return -ENOMEM;
        }

        r = realloc_buffer_write(&buffer, fd);
        if (r < 0)
                return r;

        if (renameat(c->fd, temp, c->fd, path) < 0)
                return -errno;

        temp = mfree(temp);
        return 1;
}

int ca_cache_remove(CaCache *c, CaLocation *location) {
        char path[CA_CHUNK_ID_PATH_SIZE(NULL, ".cachi")];
        CaChunkID key_id;
        const char *four;
        int r;

        if (!c)
                return -EINVAL;
        if (!location)
                return -EINVAL;

        r = ca_cache_open(c);
        if (r < 0)
                return r;

        if (!c->digest) {
                r = ca_digest_new(ca_cache_digest_type(c), &c->digest);
                if (r < 0)
                        return r;
        }

        r = ca_location_id_make(c->digest, location, false, &key_id);
        if (r < 0)
                return r;

        ca_chunk_id_format_path(NULL, &key_id, ".cachi", path);

        if (unlinkat(c->fd, path, 0) < 0)
                return -errno;

        four = strndupa(path, 4);
        (void) unlinkat(c->fd, four, AT_REMOVEDIR);

        return 0;
}
