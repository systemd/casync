/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/stat.h>
#include <fcntl.h>

#include "cachunk.h"
#include "cachunker.h"
#include "caencoder.h"
#include "cafileroot.h"
#include "caformat-util.h"
#include "caformat.h"
#include "calocation.h"
#include "caseed.h"
#include "def.h"
#include "realloc-buffer.h"
#include "rm-rf.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef ENXIO */
/* #define ENXIO __LINE__ */

/* #undef EUNATCH */
/* #define EUNATCH __LINE__ */

struct CaSeed {
        CaEncoder *encoder;
        int base_fd;
        int cache_fd;
        char *cache_path;

        CaChunker chunker;
        CaDigest *chunk_digest;

        bool ready:1;
        bool remove_cache:1;
        bool cache_hardlink:1;
        bool cache_chunks:1;

        ReallocBuffer buffer;
        CaLocation *buffer_location;

        CaFileRoot *root;

        uint64_t feature_flags;

        uint64_t n_requests;
        uint64_t n_request_bytes;
};

CaSeed *ca_seed_new(void) {
        CaSeed *s;

        s = new0(CaSeed, 1);
        if (!s)
                return NULL;

        s->cache_fd = -1;
        s->base_fd = -1;

        s->cache_chunks = true;

        s->chunker = (CaChunker) CA_CHUNKER_INIT;

        s->feature_flags = CA_FORMAT_DEFAULT & SUPPORTED_FEATURE_MASK;

        return s;
}

static void ca_seed_remove_and_close_cache(CaSeed *s) {
        assert(s);

        if (!s->remove_cache)
                return;

        if (s->cache_path) {
                (void) rm_rf(s->cache_path, REMOVE_ROOT|REMOVE_PHYSICAL);
                s->cache_path = mfree(s->cache_path);
                s->cache_fd = safe_close(s->cache_fd);
        } else if (s->cache_fd >= 0) {
                (void) rm_rf_children(s->cache_fd, REMOVE_PHYSICAL, NULL);
                s->cache_fd = -1;
        }
}

CaSeed *ca_seed_unref(CaSeed *s) {
        if (!s)
                return NULL;

        ca_file_root_invalidate(s->root);

        ca_seed_remove_and_close_cache(s);

        ca_encoder_unref(s->encoder);

        safe_close(s->base_fd);
        safe_close(s->cache_fd);
        free(s->cache_path);

        ca_digest_free(s->chunk_digest);

        realloc_buffer_free(&s->buffer);
        ca_location_unref(s->buffer_location);

        ca_file_root_unref(s->root);

        return mfree(s);
}

int ca_seed_set_base_fd(CaSeed *s, int fd) {
        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (s->base_fd >= 0)
                return -EBUSY;

        s->base_fd = fd;
        return 0;
}

int ca_seed_set_base_path(CaSeed *s, const char *path) {
        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (s->base_fd >= 0)
                return -EBUSY;

        s->base_fd = open(path, O_CLOEXEC|O_NOCTTY|O_RDONLY);
        if (s->base_fd < 0)
                return -errno;

        return 0;
}

int ca_seed_set_cache_fd(CaSeed *s, int fd) {
        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (s->cache_fd >= 0)
                return -EBUSY;
        if (s->cache_path)
                return -EBUSY;

        s->cache_fd = fd;
        return 0;
}

int ca_seed_set_cache_path(CaSeed *s, const char *path) {
        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (s->cache_fd >= 0)
                return -EBUSY;
        if (s->cache_path)
                return -EBUSY;

        s->cache_path = strdup(path);
        if (!s->cache_path)
                return -ENOMEM;

        return 0;
}

static int ca_seed_open(CaSeed *s) {
        int r;

        if (!s)
                return -EINVAL;

        if (!s->encoder) {
                if (s->base_fd < 0)
                        return -EUNATCH;

                s->encoder = ca_encoder_new();
                if (!s->encoder)
                        return -ENOMEM;

                r = ca_encoder_set_feature_flags(s->encoder, s->feature_flags);
                if (r < 0)
                        return r;

                r = ca_encoder_set_base_fd(s->encoder, s->base_fd);
                if (r < 0)
                        return r;

                r = ca_encoder_enable_hardlink_digest(s->encoder, s->cache_hardlink);
                if (r < 0)
                        return r;

                s->base_fd = -1;
        }

        if (s->cache_fd < 0) {
                if (!s->cache_path) {
                        const char *d;

                        r = var_tmp_dir(&d);
                        if (r < 0)
                                return r;

                        if (asprintf(&s->cache_path, "%s/%" PRIx64 ".cased", d, random_u64()) < 0)
                                return -ENOMEM;

                        s->remove_cache = true;
                }

                (void) mkdir(s->cache_path, 0777);

                s->cache_fd = open(s->cache_path, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (s->cache_fd < 0)
                        return -errno;
        }

        return 0;
}

static int ca_seed_make_chunk_id(CaSeed *s, const void *p, size_t l, CaChunkID *ret) {
        int r;

        if (!s)
                return -EINVAL;
        if (!p && l > 0)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->chunk_digest) {
                r = ca_digest_new(ca_feature_flags_to_digest_type(s->feature_flags), &s->chunk_digest);
                if (r < 0)
                        return r;
        }

        return ca_chunk_id_make(s->chunk_digest, p, l, ret);
}

static int ca_seed_write_cache_entry(CaSeed *s, CaLocation *location, const void *data, size_t l) {
        char ids[CA_CHUNK_ID_FORMAT_MAX];
        const char *t, *four, *combined;
        CaChunkID id;
        int r;

        assert(s);
        assert(location);
        assert(data);
        assert(l > 0);

        r = ca_location_patch_size(&location, l);
        if (r < 0)
                return r;

        t = ca_location_format_full(location, CA_LOCATION_WITH_ALL);
        if (!t)
                return -ENOMEM;

        r = ca_seed_make_chunk_id(s, data, l, &id);
        if (r < 0)
                return r;

        if (!ca_chunk_id_format(&id, ids))
                return -EINVAL;

        four = strndupa(ids, 4);
        combined = strjoina(four, "/", ids);

        (void) mkdirat(s->cache_fd, four, 0777);

        if (symlinkat(t, s->cache_fd, combined) < 0) {
                _cleanup_(unlink_and_freep) char *temp = NULL;
                _cleanup_(safe_closep) int fd = -1;
                ssize_t n;
                size_t k;

                if (errno == EEXIST)
                        return 0;

                if (errno != ENAMETOOLONG)
                        return log_debug_errno(errno, "Failed to create seed entry symlink %s → %s: %m", combined, t);

                r = tempfn_random(combined, &temp);
                if (r < 0)
                        return log_debug_errno(r, "Failed to allocate temporary path for %s: %m", combined);

                fd = openat(s->cache_fd, temp, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW, 0666);
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to create seed entry file %s: %m", combined);

                k = strlen(t);
                n = write(fd, t, k);
                if (n < 0)
                        return log_debug_errno(errno, "Failed to write seed entry file %s: %m", combined);
                if ((size_t) n != k) {
                        log_debug("Short write while writing seed entry file %s: %m", combined);
                        return -EIO;
                }

                if (renameat(s->cache_fd, temp, s->cache_fd, combined) < 0)
                        return log_debug_errno(errno, "Failed to move seed entry file %s into place: %m", combined);

                temp = mfree(temp);
        }

        return 1;
}

static int ca_seed_cache_chunks(CaSeed *s) {
        uint64_t offset = 0;
        const void *p;
        size_t l;
        int r;

        assert(s);

        r = ca_encoder_get_data(s->encoder, UINT64_MAX, &p, &l);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (!s->cache_chunks)
                return 0;

        while (l > 0) {
                const void *chunk;
                size_t chunk_size, k;

                if (!s->buffer_location) {
                        r = ca_encoder_current_location(s->encoder, offset, &s->buffer_location);
                        if (r < 0)
                                return r;
                }

                k = ca_chunker_scan(&s->chunker, p, l);
                if (k == (size_t) -1) {
                        if (!realloc_buffer_append(&s->buffer, p, l))
                                return -ENOMEM;

                        return 0;
                }

                if (realloc_buffer_size(&s->buffer) == 0) {
                        chunk = p;
                        chunk_size = k;
                } else {
                        if (!realloc_buffer_append(&s->buffer, p, k))
                                return -ENOMEM;

                        chunk = realloc_buffer_data(&s->buffer);
                        chunk_size = realloc_buffer_size(&s->buffer);
                }

                r = ca_seed_write_cache_entry(s, s->buffer_location, chunk, chunk_size);
                if (r < 0)
                        return r;

                realloc_buffer_empty(&s->buffer);
                s->buffer_location = ca_location_unref(s->buffer_location);

                p = (const uint8_t*) p + k;
                l -= k;

                offset += k;
        }

        return 0;
}

static int ca_seed_cache_final_chunk(CaSeed *s) {
        int r;

        assert(s);

        if (!s->cache_chunks)
                return 0;

        if (realloc_buffer_size(&s->buffer) == 0)
                return 0;

        if (!s->buffer_location)
                return 0;

        r = ca_seed_write_cache_entry(s, s->buffer_location, realloc_buffer_data(&s->buffer), realloc_buffer_size(&s->buffer));
        if (r < 0)
                return 0;

        realloc_buffer_empty(&s->buffer);
        s->buffer_location = ca_location_unref(s->buffer_location);

        return 0;
}

static int ca_seed_cache_hardlink(CaSeed *s) {
        const char *t, *four, *combined;
        char v[CA_CHUNK_ID_FORMAT_MAX];
        CaLocation *location = NULL;
        char *path = NULL;
        CaChunkID digest;
        mode_t mode;
        int r;

        assert(s);

        if (!s->cache_hardlink)
                return 0;
        if (!s->encoder)
                return -EUNATCH;

        r = ca_encoder_current_mode(s->encoder, &mode);
        if (r < 0)
                return r;
        if (!S_ISREG(mode))
                return 0;

        r = ca_encoder_get_hardlink_digest(s->encoder, &digest);
        if (r < 0)
                return r;

        r = ca_encoder_current_path(s->encoder, &path);
        if (r < 0)
                return r;

        r = ca_location_new(path, CA_LOCATION_ENTRY, 0, UINT64_MAX, &location);
        free(path);
        if (r < 0)
                return r;

        t = ca_location_format(location);
        if (!t) {
                r = -ENOMEM;
                goto finish;
        }

        if (!ca_chunk_id_format(&digest, v)) {
                r = -EINVAL;
                goto finish;
        }

        four = strndupa(v, 4);
        combined = strjoina(four, "/", v);

        (void) mkdirat(s->cache_fd, four, 0777);

        if (symlinkat(t, s->cache_fd, combined) < 0 && errno != EEXIST) {
                r = -errno;
                goto finish;
        }

        r = 0;

finish:
        ca_location_unref(location);
        return r;
}

int ca_seed_step(CaSeed *s) {
        int r;

        if (!s)
                return -EINVAL;

        if (s->ready)
                return -EALREADY;

        if (!s->cache_chunks && !s->cache_hardlink) {
                s->ready = true;
                return CA_SEED_READY;
        }

        r = ca_seed_open(s);
        if (r < 0)
                return r;

        for (;;) {
                int step;

                step = ca_encoder_step(s->encoder);
                if (step < 0)
                        return step;

                switch (step) {

                case CA_ENCODER_FINISHED:

                        r = ca_seed_cache_final_chunk(s);
                        if (r < 0)
                                return r;

                        s->ready = true;
                        return CA_SEED_READY;

                case CA_ENCODER_DATA:
                case CA_ENCODER_NEXT_FILE:
                case CA_ENCODER_DONE_FILE:
                case CA_ENCODER_PAYLOAD:

                        r = ca_seed_cache_chunks(s);
                        if (r < 0)
                                return r;

                        if (step == CA_ENCODER_DONE_FILE) {
                                r = ca_seed_cache_hardlink(s);
                                if (r < 0)
                                        return r;
                        }

                        return step == CA_ENCODER_NEXT_FILE ? CA_SEED_NEXT_FILE :
                                step == CA_ENCODER_DONE_FILE ? CA_SEED_DONE_FILE : CA_SEED_STEP;

                default:
                        assert(false);
                }
        }
}

int ca_seed_get(CaSeed *s,
                const CaChunkID *chunk_id,
                const void **ret,
                size_t *ret_size,
                CaOrigin **ret_origin) {

        char id[CA_CHUNK_ID_FORMAT_MAX], *target = NULL;
        const char *four, *combined;
        CaFileRoot *root = NULL;
        CaOrigin *origin = NULL;
        CaLocation *l = NULL;
        uint64_t size, n = 0;
        void *p = NULL;
        int r, step;

        if (!s)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;
        if (s->cache_fd < 0)
                return -EUNATCH;
        if (!s->cache_chunks)
                return -ENOMEDIUM;

        if (!ca_chunk_id_format(chunk_id, id))
                return -EINVAL;

        four = strndupa(id, 4);
        combined = strjoina(four, "/", id);

        r = readlinkat_malloc(s->cache_fd, combined, &target);
        if (r == -EINVAL) {
                _cleanup_(safe_closep) int fd = -1;
                ReallocBuffer buffer = {};

                fd = openat(s->cache_fd, combined, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to read from seed file %s: %m", combined);

                r = realloc_buffer_read_full(&buffer, fd, 1024U*1024U);
                if (r < 0)
                        return r;

                /* Safety check: let's make sure there's no embedded NUL byte */
                r = realloc_buffer_memchr(&buffer, 0);
                if (r >= 0)
                        return -EINVAL;
                if (r != -ENXIO)
                        return r;

                if (!realloc_buffer_append_byte(&buffer, 0))
                        return -ENOMEM;

                target = realloc_buffer_steal(&buffer);
        } else if (r < 0)
                return r;

        /* fprintf(stderr, "GOT %s → %s\n", combined, target); */

        r = ca_location_parse(target, &l);
        free(target);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse location '%s': %m", target);

        if (l->size == UINT64_MAX) /* If the size is not specified, then this is a hardlink entry */
                return -ENOENT;

        if (l->size > s->chunker.chunk_size_max) {
                ca_location_unref(l);
                log_debug("Location size is larger than what chunker says.");
                return -EINVAL;
        }
        size = l->size;

        step = ca_encoder_seek_location(s->encoder, l);
        l = ca_location_unref(l);
        if (step == -ENXIO) /* location doesn't exist anymore? Then the seed has been modified */
                return -ESTALE;
        if (step < 0)
                return log_debug_errno(step, "Failed to seek to seed location: %m");

        p = realloc_buffer_acquire(&s->buffer, size);
        if (!p)
                return -ENOMEM;

        if (ret_origin) {
                r = ca_seed_get_file_root(s, &root);
                if (r < 0)
                        return r;

                r = ca_origin_new(&origin);
                if (r < 0)
                        return r;
        }

        for (;;) {
                switch (step) {

                case CA_ENCODER_FINISHED:
                        /* Premature end? Then the seed has been modified */
                        return -ESTALE;

                case CA_ENCODER_DATA:
                case CA_ENCODER_NEXT_FILE:
                case CA_ENCODER_DONE_FILE:
                case CA_ENCODER_PAYLOAD: {
                        const void *q;
                        size_t w;
                        uint64_t m;

                        r = ca_encoder_get_data(s->encoder, UINT64_MAX, &q, &w);
                        if (r == -ENODATA)
                                break;
                        if (r < 0)
                                goto finish;

                        m = MIN(w, size - n);
                        memcpy((uint8_t*) p + n, q, m);
                        n += m;

                        if (origin) {
                                r = ca_encoder_current_location(s->encoder, 0, &l);
                                if (r < 0)
                                        goto finish;

                                r = ca_location_patch_size(&l, m);
                                if (r < 0) {
                                        l = ca_location_unref(l);
                                        goto finish;
                                }

                                r = ca_location_patch_root(&l, root);
                                if (r < 0) {
                                        l = ca_location_unref(l);
                                        goto finish;
                                }

                                r = ca_origin_put(origin, l);
                                l = ca_location_unref(l);
                                if (r < 0)
                                        goto finish;
                        }

                        if (n >= size) {
                                CaChunkID test_id;

                                r = ca_seed_make_chunk_id(s, p, size, &test_id);
                                if (r < 0)
                                        goto finish;

                                if (!ca_chunk_id_equal(chunk_id, &test_id)) {

                                        /* fprintf(stderr, "SEED CHUNK CORRUPTED (%" PRIu64 "):\n", size); */
                                        /* hexdump(stderr, p, MIN(1024U, size)); */

                                        r = -ESTALE;
                                        goto finish;
                                }

                                /* fprintf(stderr, "SEED CHUNK GOOD\n"); */

                                *ret = p;
                                *ret_size = size;

                                if (ret_origin)
                                        *ret_origin = origin;

                                s->n_requests++;
                                s->n_request_bytes += size;

                                return 0;
                        }
                        break;
                }

                default:
                        assert(false);
                }

                step = ca_encoder_step(s->encoder);
                if (step < 0) {
                        r = step;
                        goto finish;
                }
        }

finish:
        ca_origin_unref(origin);
        return r;
}

int ca_seed_has(CaSeed *s, const CaChunkID *chunk_id) {
        char id[CA_CHUNK_ID_FORMAT_MAX];
        const char *four, *combined;

        if (!s)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;
        if (s->cache_fd < 0)
                return -EUNATCH;
        if (!s->cache_chunks)
                return -ENOMEDIUM;

        if (!ca_chunk_id_format(chunk_id, id))
                return -EINVAL;

        four = strndupa(id, 4);
        combined = strjoina(four, "/", id);

        if (faccessat(s->cache_fd, combined, F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        return 1;
}

int ca_seed_get_hardlink_target(
                CaSeed *s,
                const CaChunkID *id,
                char **ret) {

        char v[CA_CHUNK_ID_FORMAT_MAX];
        const char *four, *combined;
        CaLocation *l = NULL;
        char *target;
        int r;

        if (!s)
                return -EINVAL;
        if (!id)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (s->cache_fd < 0)
                return -EUNATCH;
        if (!s->cache_hardlink)
                return -ENOMEDIUM;

        if (!ca_chunk_id_format(id, v))
                return -EINVAL;

        four = strndupa(v, 4);
        combined = strjoina(four, "/", v);

        r = readlinkat_malloc(s->cache_fd, combined, &target);
        if (r < 0)
                return r;

        r = ca_location_parse(target, &l);
        free(target);
        if (r < 0)
                return r;

        if (l->designator != CA_LOCATION_ENTRY ||
            l->offset != 0 ||
            l->size != UINT64_MAX) { /* If the size is specified, this this a normal chunk reference */
                r = -ENOENT;
                goto finish;
        }

        *ret = l->path;
        l->path = NULL;

        r = 0;

finish:
        ca_location_unref(l);
        return r;
}

int ca_seed_current_path(CaSeed *seed, char **ret) {
        if (!seed)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (seed->ready)
                return -EALREADY;

        return ca_encoder_current_path(seed->encoder, ret);
}

int ca_seed_current_mode(CaSeed *seed, mode_t *ret) {
        if (!seed)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (seed->ready)
                return -EALREADY;

        return ca_encoder_current_mode(seed->encoder, ret);
}

int ca_seed_set_feature_flags(CaSeed *s, uint64_t flags) {
        if (!s)
                return -EINVAL;

        return ca_feature_flags_normalize(flags, &s->feature_flags);
}

int ca_seed_set_chunk_size(CaSeed *s, size_t cmin, size_t cavg, size_t cmax) {
        if (!s)
                return -EINVAL;

        ca_chunker_set_size(&s->chunker, cmin, cavg, cmax);

        return 0;
}

int ca_seed_get_file_root(CaSeed *s, CaFileRoot **ret) {
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->root) {
                int base_fd;

                if (s->base_fd >= 0)
                        base_fd = s->base_fd;
                else if (s->encoder) {
                        base_fd = ca_encoder_get_base_fd(s->encoder);
                        if (base_fd < 0)
                                return base_fd;
                } else
                        return -EUNATCH;

                r = ca_file_root_new(NULL, base_fd, &s->root);
                if (r < 0)
                        return r;
        }

        *ret = s->root;
        return 0;
}

int ca_seed_set_hardlink(CaSeed *s, bool b) {
        int r;

        if (!s)
                return -EINVAL;

        if (s->cache_hardlink == b)
                return 0;

        if (s->encoder) {
                r = ca_encoder_enable_hardlink_digest(s->encoder, b);
                if (r < 0)
                        return r;
        }

        s->cache_hardlink = b;

        return 1;
}

int ca_seed_set_chunks(CaSeed *s, bool b) {

        if (!s)
                return -EINVAL;

        if (s->cache_chunks == b)
                return 0;

        s->cache_chunks = b;
        return 1;
}

int ca_seed_get_requests(CaSeed *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->cache_chunks)
                return -ENOTTY;

        *ret = s->n_requests;
        return 0;
}

int ca_seed_get_request_bytes(CaSeed *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->cache_chunks)
                return -ENOTTY;

        *ret = s->n_request_bytes;
        return 0;
}
