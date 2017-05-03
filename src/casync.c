#include <fcntl.h>
#include <gcrypt.h>
#include <sys/poll.h>
#include <sys/stat.h>

#include "cachunk.h"
#include "cachunker.h"
#include "cadecoder.h"
#include "caencoder.h"
#include "caformat-util.h"
#include "caformat.h"
#include "caindex.h"
#include "caprotocol.h"
#include "caremote.h"
#include "caseed.h"
#include "castore.h"
#include "casync.h"
#include "def.h"
#include "gcrypt-util.h"
#include "realloc-buffer.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef ENXIO */
/* #define ENXIO __LINE__ */

typedef enum CaDirection {
        CA_SYNC_ENCODE,
        CA_SYNC_DECODE,
} CaDirection;

typedef struct CaSync {
        CaDirection direction;
        bool started;

        CaEncoder *encoder;
        CaDecoder *decoder;

        CaChunker chunker;

        CaIndex *index;
        CaRemote *remote_index;

        CaRemote *remote_archive;

        CaChunkID next_chunk;
        size_t next_chunk_size;
        bool next_chunk_valid;

        CaStore *wstore;
        CaStore **rstores;
        size_t n_rstores;
        CaStore *cache_store;

        CaRemote *remote_wstore;
        CaRemote **remote_rstores;
        size_t n_remote_rstores;
        size_t current_remote;

        CaSeed **seeds;
        size_t n_seeds;
        size_t current_seed; /* The seed we are currently indexing */
        bool chunk_size_propagated;

        int base_fd;
        int boundary_fd;
        int archive_fd;

        char *base_path, *temporary_base_path;
        char *boundary_path;
        char *archive_path, *temporary_archive_path;

        mode_t base_mode;
        mode_t make_mode;

        ReallocBuffer buffer;
        ReallocBuffer index_buffer;
        ReallocBuffer archive_buffer;
        ReallocBuffer compress_buffer;

        gcry_md_hd_t chunk_digest;
        gcry_md_hd_t archive_digest;

        bool archive_eof;
        bool remote_index_eof;

        size_t rate_limit_bps;

        uint64_t feature_flags;

        uint64_t n_written_chunks;
        uint64_t n_prefetched_chunks;

        uint64_t archive_size;

        uint64_t chunk_skip;

        bool punch_holes:1;
        bool reflink:1;
        bool delete:1;

        CaFileRoot *archive_root;
} CaSync;

static CaSync *ca_sync_new(void) {
        CaSync *s;

        s = new0(CaSync, 1);
        if (!s)
                return NULL;

        s->base_fd = s->boundary_fd = s->archive_fd = -1;
        s->base_mode = (mode_t) -1;
        s->make_mode = (mode_t) -1;

        s->chunker = (CaChunker) CA_CHUNKER_INIT;

        s->archive_size = UINT64_MAX;
        s->punch_holes = true;
        s->reflink = true;

        return s;
}

CaSync *ca_sync_new_encode(void) {
        CaSync *s;

        s = ca_sync_new();
        if (!s)
                return NULL;

        s->direction = CA_SYNC_ENCODE;
        assert_se(ca_feature_flags_normalize(CA_FORMAT_WITH_BEST|CA_FORMAT_RESPECT_FLAG_NODUMP, &s->feature_flags) >= 0);

        return s;
}

CaSync *ca_sync_new_decode(void) {
        CaSync *s;

        s = ca_sync_new();
        if (!s)
                return NULL;

        s->direction = CA_SYNC_DECODE;
        return s;
}

int ca_sync_set_chunk_size_avg(CaSync *s, size_t avg) {
        if (!s)
                return -EINVAL;

        return ca_chunker_set_avg_size(&s->chunker, avg);
}

int ca_sync_get_chunk_size_avg(CaSync *s, size_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = s->chunker.chunk_size_avg;
        return 0;
}

int ca_sync_get_chunk_size_min(CaSync *s, size_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = s->chunker.chunk_size_min;
        return 0;
}

int ca_sync_get_chunk_size_max(CaSync *s, size_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = s->chunker.chunk_size_max;
        return 0;
}

int ca_sync_set_punch_holes(CaSync *s, bool enabled) {
        int r;

        if (!s)
                return -EINVAL;
        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (s->decoder) {
                r = ca_decoder_set_punch_holes(s->decoder, enabled);
                if (r < 0)
                        return r;
        }

        s->punch_holes = enabled;

        return 0;
}

int ca_sync_set_reflink(CaSync *s, bool enabled) {
        int r;

        if (!s)
                return -EINVAL;
        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (s->decoder) {
                r = ca_decoder_set_reflink(s->decoder, enabled);
                if (r < 0)
                        return r;
        }

        s->reflink = enabled;

        return 0;
}

int ca_sync_set_delete(CaSync *s, bool enabled) {
        int r;

        if (!s)
                return -EINVAL;
        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (s->decoder) {
                r = ca_decoder_set_delete(s->decoder, enabled);
                if (r < 0)
                        return r;
        }

        s->delete = enabled;

        return 0;
}

CaSync *ca_sync_unref(CaSync *s) {
        size_t i;

        if (!s)
                return NULL;

        ca_encoder_unref(s->encoder);
        ca_decoder_unref(s->decoder);

        ca_store_unref(s->wstore);
        for (i = 0; i < s->n_rstores; i++)
                ca_store_unref(s->rstores[i]);
        free(s->rstores);
        ca_store_unref(s->cache_store);

        ca_remote_unref(s->remote_wstore);
        for (i = 0; i < s->n_remote_rstores; i++)
                ca_remote_unref(s->remote_rstores[i]);
        free(s->remote_rstores);

        for (i = 0; i < s->n_seeds; i++)
                ca_seed_unref(s->seeds[i]);
        free(s->seeds);

        safe_close(s->base_fd);
        safe_close(s->boundary_fd);
        safe_close(s->archive_fd);

        free(s->base_path);
        free(s->archive_path);
        free(s->boundary_path);

        if (s->temporary_base_path) {
                (void) unlink(s->temporary_base_path);
                free(s->temporary_base_path);
        }
        if (s->temporary_archive_path) {
                (void) unlink(s->temporary_archive_path);
                free(s->temporary_archive_path);
        }

        ca_index_unref(s->index);
        ca_remote_unref(s->remote_index);

        ca_remote_unref(s->remote_archive);

        realloc_buffer_free(&s->buffer);
        realloc_buffer_free(&s->index_buffer);
        realloc_buffer_free(&s->archive_buffer);
        realloc_buffer_free(&s->compress_buffer);

        ca_file_root_unref(s->archive_root);

        gcry_md_close(s->chunk_digest);
        gcry_md_close(s->archive_digest);
        free(s);

        return NULL;
}

int ca_sync_set_rate_limit_bps(CaSync *s, size_t rate_limit_bps) {
        if (!s)
                return -EINVAL;

        s->rate_limit_bps = rate_limit_bps;

        return 0;
}

int ca_sync_set_feature_flags(CaSync *s, uint64_t flags) {
        if (!s)
                return -EINVAL;

        if (s->direction != CA_SYNC_ENCODE)
                return -ENOTTY;

        return ca_feature_flags_normalize(flags, &s->feature_flags);
}

int ca_sync_get_feature_flags(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;

        if (s->direction == CA_SYNC_ENCODE)
                *ret = s->feature_flags;
        else {
                if (!s->decoder)
                        return -ENODATA;

                return ca_decoder_get_feature_flags(s->decoder, ret);
        }

        return 0;
}

int ca_sync_get_covering_feature_flags(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;

        if (!s->encoder)
                return -ENODATA;

        return ca_encoder_get_covering_feature_flags(s->encoder, ret);
}

static int ca_sync_allocate_index(CaSync *s) {
        assert(s);

        if (s->index)
                return -EBUSY;
        if (s->remote_index)
                return -EBUSY;

        if (s->direction == CA_SYNC_ENCODE)
                s->index = ca_index_new_write();
        else if (s->direction == CA_SYNC_DECODE)
                s->index = ca_index_new_read();
        else
                assert(false);

        if (!s->index)
                return -ENOMEM;

        return 0;
}

int ca_sync_set_index_fd(CaSync *s, int fd) {
        int r;

        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        r = ca_sync_allocate_index(s);
        if (r < 0)
                return r;

        r = ca_index_set_fd(s->index, fd);
        if (r < 0) {
                s->index = ca_index_unref(s->index);
                return r;
        }

        return 0;
}

int ca_sync_set_index_path(CaSync *s, const char *path) {
        int r;

        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        r = ca_sync_allocate_index(s);
        if (r < 0)
                return r;

        r = ca_index_set_path(s->index, path);
        if (r < 0) {
                s->index = ca_index_unref(s->index);
                return r;
        }

        return 0;
}

int ca_sync_set_index_remote(CaSync *s, const char *url) {
        uint64_t flags;
        int r;

        if (!s)
                return -EINVAL;
        if (!url)
                return -EINVAL;

        if (s->index)
                return -EBUSY;
        if (s->remote_index)
                return -EBUSY;

        flags = s->direction == CA_SYNC_ENCODE ? CA_PROTOCOL_PUSH_INDEX : CA_PROTOCOL_PULL_INDEX;

        if (s->remote_wstore) {
                /* Try to reuse the main store remote for the index too, if it matches the same server */

                r = ca_remote_set_index_url(s->remote_wstore, url);
                if (r >= 0) {
                        r = ca_remote_add_local_feature_flags(s->remote_wstore, flags);
                        if (r < 0)
                                return r;

                        s->remote_index = ca_remote_ref(s->remote_wstore);
                        return 0;
                }
                if (r != -EBUSY) /* Fail, except when the reason is that it matches the same server. */
                        return r;
        }

        s->remote_index = ca_remote_new();
        if (!s->remote_index)
                return -ENOMEM;

        if (s->rate_limit_bps > 0) {
                r = ca_remote_set_rate_limit_bps(s->remote_index, s->rate_limit_bps);
                if (r < 0)
                        return r;
        }

        r = ca_remote_set_index_url(s->remote_index, url);
        if (r < 0)
                return r;

        r = ca_remote_set_local_feature_flags(s->remote_index, flags);
        if (r < 0)
                return r;

        return 0;
}

int ca_sync_set_index_auto(CaSync *s, const char *locator) {
        CaLocatorClass c;

        if (!s)
                return -EINVAL;
        if (!locator)
                return -EINVAL;

        c = ca_classify_locator(locator);
        if (c < 0)
                return -EINVAL;

        if (c == CA_LOCATOR_PATH)
                return ca_sync_set_index_path(s, locator);

        return ca_sync_set_index_remote(s, locator);
}

int ca_sync_set_base_fd(CaSync *s, int fd) {
        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (s->base_fd >= 0)
                return -EBUSY;
        if (s->base_mode != (mode_t) -1)
                return -EBUSY;
        if (s->base_path)
                return -EBUSY;
        if (s->boundary_fd >= 0)
                return -EBUSY;
        if (s->boundary_path)
                return -EBUSY;

        s->base_fd = fd;
        return 0;
}

int ca_sync_set_base_path(CaSync *s, const char *path) {
        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (s->base_fd >= 0)
                return -EBUSY;
        if (s->base_path)
                return -EBUSY;
        if (s->boundary_fd >= 0)
                return -EBUSY;
        if (s->boundary_path)
                return -EBUSY;

        if (s->base_mode == (mode_t) -1 || S_ISDIR(s->base_mode)) {

                s->base_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                if (s->base_fd >= 0) /* Base exists already and is a directory */
                        return 0;

                if (s->direction == CA_SYNC_ENCODE && errno != ENOTDIR)
                        return -errno;
        }

        if (s->direction == CA_SYNC_ENCODE) {

                s->base_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (s->base_fd < 0)
                        return -errno;

                return 0;
        }

        assert(s->direction == CA_SYNC_DECODE);

        s->base_path = strdup(path);
        if (!s->base_path)
                return -ENOMEM;

        return 0;
}

int ca_sync_set_make_mode(CaSync *s, mode_t m) {
        if (!s)
                return -EINVAL;
        if (m & ~0666)
                return -EINVAL;
        if (s->direction != CA_SYNC_ENCODE)
                return -ENOTTY;

        if (s->make_mode != (mode_t) -1)
                return -EBUSY;

        s->make_mode = m;
        return 0;
}

int ca_sync_set_base_mode(CaSync *s, mode_t m) {
        if (!s)
                return -EINVAL;
        if (m & ~(07777 | S_IFMT))
                return -EINVAL;
        if (!S_ISREG(m) && !S_ISDIR(m) && !S_ISBLK(m))
                return -ENOTTY;
        if (s->direction == CA_SYNC_ENCODE)
                return -ENOTTY;

        if (s->base_fd >= 0)
                return -EBUSY;
        if (s->base_mode != (mode_t) -1)
                return -EBUSY;
        if (s->boundary_fd >= 0)
                return -EBUSY;
        if (s->boundary_path)
                return -EBUSY;

        s->base_mode = m;
        return 0;
}

int ca_sync_set_boundary_fd(CaSync *s, int fd) {
        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (s->base_fd >= 0)
                return -EBUSY;
        if (s->base_mode != (mode_t) -1)
                return -EBUSY;
        if (s->base_path)
                return -EBUSY;
        if (s->boundary_fd >= 0)
                return -EBUSY;
        if (s->boundary_path)
                return -EBUSY;

        if (s->direction == CA_SYNC_ENCODE)
                return -ENOTTY;

        s->boundary_fd = fd;
        return 0;
}

int ca_sync_set_boundary_path(CaSync *s, const char *p) {
        if (!s)
                return -EINVAL;
        if (!p)
                return -EINVAL;

        if (s->base_fd >= 0)
                return -EBUSY;
        if (s->base_mode != (mode_t) -1)
                return -EBUSY;
        if (s->base_path)
                return -EBUSY;
        if (s->boundary_fd >= 0)
                return -EBUSY;
        if (s->boundary_path)
                return -EBUSY;

        if (s->direction == CA_SYNC_ENCODE)
                return -ENOTTY;

        s->boundary_fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
        if (s->boundary_fd >= 0) /* Base exists already is a directory, good */
                return 0;

        if (errno != ENOENT)
                return -errno;

        s->boundary_path = strdup(p);
        if (!s->boundary_path)
                return -ENOMEM;

        return 0;
}

int ca_sync_set_archive_fd(CaSync *s, int fd) {
        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (s->archive_fd >= 0)
                return -EBUSY;
        if (s->archive_path)
                return -EBUSY;
        if (s->remote_archive)
                return -EBUSY;

        s->archive_fd = fd;
        return 0;
}

int ca_sync_set_archive_path(CaSync *s, const char *path) {
        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (s->archive_fd >= 0)
                return -EBUSY;
        if (s->archive_path)
                return -EBUSY;
        if (s->remote_archive)
                return -EBUSY;

        if (s->direction == CA_SYNC_ENCODE) {
                s->archive_path = strdup(path);
                if (!s->archive_path)
                        return -ENOMEM;

                return 0;
        }

        assert(s->direction == CA_SYNC_DECODE);

        s->archive_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (s->archive_fd < 0)
                return -errno;

        return 0;
}

int ca_sync_set_archive_remote(CaSync *s, const char *url) {
        int r;

        if (!s)
                return -EINVAL;
        if (!url)
                return -EINVAL;

        if (s->archive_fd >= 0)
                return -EBUSY;
        if (s->archive_path)
                return -EBUSY;
        if (s->remote_archive)
                return -EBUSY;

        s->remote_archive = ca_remote_new();
        if (!s->remote_archive)
                return -ENOMEM;

        r = ca_remote_set_archive_url(s->remote_archive, url);
        if (r < 0)
                return r;

        r = ca_remote_set_local_feature_flags(s->remote_archive,
                                              s->direction == CA_SYNC_ENCODE ? CA_PROTOCOL_PUSH_ARCHIVE : CA_PROTOCOL_PULL_ARCHIVE);
        if (r < 0)
                return r;

        return 0;
}

int ca_sync_set_archive_auto(CaSync *s, const char *locator) {
        CaLocatorClass c;

        if (!s)
                return -EINVAL;
        if (!locator)
                return -EINVAL;

        c = ca_classify_locator(locator);
        if (c < 0)
                return -EINVAL;

        if (c == CA_LOCATOR_PATH)
                return ca_sync_set_archive_path(s, locator);

        return ca_sync_set_archive_remote(s, locator);
}

int ca_sync_set_store_path(CaSync *s, const char *path) {
        int r;

        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (s->wstore)
                return -EBUSY;
        if (s->remote_wstore)
                return -EBUSY;

        s->wstore = ca_store_new();
        if (!s->wstore)
                return -ENOMEM;

        r = ca_store_set_path(s->wstore, path);
        if (r < 0) {
                s->wstore = ca_store_unref(s->wstore);
                return r;
        }

        return 0;
}

int ca_sync_set_store_remote(CaSync *s, const char *url) {
        uint64_t flags;
        int r;

        if (!s)
                return -EINVAL;
        if (!url)
                return -EINVAL;

        if (s->wstore)
                return -EBUSY;
        if (s->remote_wstore)
                return -EBUSY;

        flags = s->direction == CA_SYNC_ENCODE ? CA_PROTOCOL_PUSH_CHUNKS : CA_PROTOCOL_PULL_CHUNKS;

        if (s->remote_index) {
                /* Try to reuse the index remote for the main store too, if it matches the same server */

                r = ca_remote_set_store_url(s->remote_index, url);
                if (r >= 0) {

                        r = ca_remote_add_local_feature_flags(s->remote_index, flags);
                        if (r < 0)
                                return r;

                        s->remote_wstore = ca_remote_ref(s->remote_index);
                        return 0;
                }
                if (r != -EBUSY)
                        return r;
        }

        s->remote_wstore = ca_remote_new();
        if (!s->remote_wstore)
                return -ENOMEM;

        if (s->rate_limit_bps > 0) {
                r = ca_remote_set_rate_limit_bps(s->remote_wstore, s->rate_limit_bps);
                if (r < 0)
                        return r;
        }

        r = ca_remote_set_store_url(s->remote_wstore, url);
        if (r < 0)
                return r;

        r = ca_remote_set_local_feature_flags(s->remote_wstore, flags);
        if (r < 0)
                return r;

        return 0;
}

int ca_sync_set_store_auto(CaSync *s, const char *locator) {
        CaLocatorClass c;

        if (!s)
                return -EINVAL;
        if (!locator)
                return -EINVAL;

        c = ca_classify_locator(locator);
        if (c < 0)
                return -EINVAL;

        if (c == CA_LOCATOR_PATH)
                return ca_sync_set_store_path(s, locator);

        return ca_sync_set_store_remote(s, locator);
}

int ca_sync_add_store_path(CaSync *s, const char *path) {
        CaStore **array, *store;
        int r;

        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        store = ca_store_new();
        if (!store)
                return -ENOMEM;

        r = ca_store_set_path(store, path);
        if (r < 0) {
                ca_store_unref(store);
                return r;
        }

        array = realloc_multiply(s->rstores, sizeof(CaStore*), s->n_rstores+1);
        if (!array) {
                ca_store_unref(store);
                return -ENOMEM;
        }

        s->rstores = array;
        s->rstores[s->n_rstores++] = store;

        return 0;
}

int ca_sync_add_store_remote(CaSync *s, const char *url) {
        CaRemote **array, *remote;
        int r;

        if (!s)
                return -EINVAL;
        if (!url)
                return -EINVAL;

        remote = ca_remote_new();
        if (!remote)
                return -ENOMEM;

        r = ca_remote_set_store_url(remote, url);
        if (r < 0) {
                ca_remote_unref(remote);
                return r;
        }

        array = realloc_multiply(s->remote_rstores, sizeof(CaRemote*),  s->n_remote_rstores+1);
        if (!array) {
                ca_remote_unref(remote);
                return -ENOMEM;
        }

        s->remote_rstores = array;
        s->remote_rstores[s->n_remote_rstores++] = remote;

        return 0;
}

int ca_sync_add_store_auto(CaSync *s, const char *locator) {
        CaLocatorClass c;

        if (!s)
                return -EINVAL;
        if (!locator)
                return -EINVAL;

        c = ca_classify_locator(locator);
        if (c < 0)
                return -EINVAL;

        if (c == CA_LOCATOR_PATH)
                return ca_sync_add_store_path(s, locator);

        return ca_sync_add_store_remote(s, locator);
}

static int ca_sync_extend_seeds_array(CaSync *s) {
        CaSeed **new_seeds;

        assert(s);

        new_seeds = realloc_multiply(s->seeds, sizeof(CaSeed*), s->n_seeds+1);
        if (!new_seeds)
                return -ENOMEM;

        s->seeds = new_seeds;
        return 0;
}

int ca_sync_add_seed_fd(CaSync *s, int fd) {
        CaSeed *seed;
        int r;

        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        r = ca_sync_extend_seeds_array(s);
        if (r < 0)
                return r;

        seed = ca_seed_new();
        if (!seed)
                return -ENOMEM;

        r = ca_seed_set_base_fd(seed, fd);
        if (r < 0) {
                ca_seed_unref(seed);
                return r;
        }

        s->seeds[s->n_seeds++] = seed;
        return 0;
}

int ca_sync_add_seed_path(CaSync *s, const char *path) {
        CaSeed *seed;
        int r;

        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        r = ca_sync_extend_seeds_array(s);
        if (r < 0)
                return r;

        seed = ca_seed_new();
        if (!seed)
                return -ENOMEM;

        r = ca_seed_set_base_path(seed, path);
        if (r < 0) {
                ca_seed_unref(seed);
                return r;
        }

        s->seeds[s->n_seeds++] = seed;
        return 0;
}

static int ca_sync_start(CaSync *s) {
        int r;

        assert(s);

        if (s->started)
                return 0;

        if (s->direction == CA_SYNC_ENCODE && s->archive_path && s->archive_fd < 0) {
                if (!s->temporary_archive_path) {
                        r = tempfn_random(s->archive_path, &s->temporary_archive_path);
                        if (r < 0)
                                return r;
                }

                s->archive_fd = open(s->temporary_archive_path, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_CREAT|O_EXCL, s->make_mode & 0666);
                if (s->archive_fd < 0) {
                        s->temporary_archive_path = mfree(s->temporary_archive_path);
                        return -errno;
                }
        }

        if (s->direction == CA_SYNC_ENCODE && !s->encoder) {

                if (s->base_fd < 0)
                        return -EUNATCH;

                s->encoder = ca_encoder_new();
                if (!s->encoder)
                        return -ENOMEM;

                r = ca_encoder_set_feature_flags(s->encoder, s->feature_flags);
                if (r < 0) {
                        s->encoder = ca_encoder_unref(s->encoder);
                        return r;
                }

                r = ca_encoder_set_base_fd(s->encoder, s->base_fd);
                if (r < 0) {
                        s->encoder = ca_encoder_unref(s->encoder);
                        return r;
                }

                s->base_fd = -1;
        }

        if (s->direction == CA_SYNC_DECODE && !s->decoder) {

                if (s->boundary_fd < 0 && s->boundary_path) {

                        if (mkdir(s->boundary_path, 0777) < 0 && errno != EEXIST)
                                return -errno;

                        s->boundary_fd = open(s->boundary_path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                        if (s->boundary_fd < 0)
                                return -errno;
                }

                if (s->base_fd < 0 && s->base_path) {

                        if (s->base_mode == (mode_t) -1)
                                return -EUNATCH;

                        if (S_ISDIR(s->base_mode)) {

                                if (mkdir(s->base_path, 0777) < 0 && errno != EEXIST)
                                        return -errno;

                                s->base_fd = open(s->base_path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                                if (s->base_fd < 0)
                                        return -errno;

                        } else if (S_ISREG(s->base_mode)) {

                                if (!s->temporary_base_path) {
                                        r = tempfn_random(s->base_path, &s->temporary_base_path);
                                        if (r < 0)
                                                return r;
                                }

                                s->base_fd = open(s->temporary_base_path, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_CREAT|O_EXCL, 0666);
                                if (s->base_fd < 0) {
                                        s->temporary_base_path = mfree(s->temporary_base_path);
                                        return -errno;
                                }

                        } else {
                                assert(S_ISBLK(s->base_mode));

                                s->base_fd = open(s->base_path, O_WRONLY|O_CLOEXEC|O_NOCTTY);
                                if (s->base_fd < 0)
                                        return -errno;
                        }
                }

                s->decoder = ca_decoder_new();
                if (!s->decoder)
                        return -ENOMEM;

                /* There are three ways we can initialize the decoder:
                 *
                 * 1. We extract the whole archive. In this case we specify the "base" fd for the extraction, which is
                 *    going to be the top-level object we'll write to. If the archive is a directory tree, this needs
                 *    to be a directory fd, otherwise a regular file or block device.
                 *
                 * 2. We do not extract anything (i.e. only list the contents or such). In this case we don't specify
                 *    any fd, but we do specify the file type (directory or regular file/block device) of the top-level
                 *    object we'd extract to if we'd extract. This is necessary so that we know whether to simply
                 *    decode a raw file contents blob, or a full directory tree.
                 *
                 * 3. We extract a subtree of the whole archive. In this case we specify a "boundary" directory fd,
                 *    where to place the objected seeked to. Note that difference from the "base" fd: we'll always
                 *    extract the seeked to file as a subfile of the specified fd.
                 */

                if (s->boundary_fd >= 0) {

                        r = ca_decoder_set_boundary_fd(s->decoder, s->boundary_fd);
                        if (r < 0)
                                return r;

                        s->boundary_fd = -1;

                } else  if (s->base_fd >= 0) {

                        r = ca_decoder_set_base_fd(s->decoder, s->base_fd);
                        if (r < 0)
                                return r;

                        s->base_fd = -1;
                } else {

                        if (s->base_mode == (mode_t) -1)
                                return -EUNATCH;

                        r = ca_decoder_set_base_mode(s->decoder, s->base_mode);
                        if (r < 0)
                                return r;
                }

                if (s->archive_size != UINT64_MAX) {
                        r = ca_decoder_set_archive_size(s->decoder, s->archive_size);
                        if (r < 0)
                                return r;
                }

                r = ca_decoder_set_punch_holes(s->decoder, s->punch_holes);
                if (r < 0)
                        return r;

                r = ca_decoder_set_reflink(s->decoder, s->reflink);
                if (r < 0)
                        return r;
        }

        if (s->remote_index && !s->index) {
                if (s->direction == CA_SYNC_DECODE)
                        s->index = ca_index_new_incremental_read();
                else {
                        assert(s->direction == CA_SYNC_ENCODE);
                        s->index = ca_index_new_incremental_write();
                }
                if (!s->index)
                        return -ENOMEM;
        }

        if (s->remote_index &&
            s->remote_wstore == s->remote_index &&
            s->direction == CA_SYNC_ENCODE &&
            !s->cache_store) {

                /* If we use the same server for index and storage, then we can optimize things a bit, and make the
                 * server request what it is missing so far. */

                s->cache_store = ca_store_new_cache();
                if (!s->cache_store)
                        return -ENOMEM;

                r = ca_remote_add_local_feature_flags(s->remote_index, CA_PROTOCOL_PUSH_INDEX_CHUNKS);
                if (r < 0)
                        return r;
        }

        if (s->direction == CA_SYNC_ENCODE && s->index) {
                /* Propagate the chunk size to the index we generate */

                r = ca_index_set_chunk_size_min(s->index, s->chunker.chunk_size_min);
                if (r < 0)
                        return r;

                r = ca_index_set_chunk_size_avg(s->index, s->chunker.chunk_size_avg);
                if (r < 0)
                        return r;

                r = ca_index_set_chunk_size_max(s->index, s->chunker.chunk_size_max);
                if (r < 0)
                        return r;

                if (s->make_mode != (mode_t) -1) {
                        r = ca_index_set_make_mode(s->index, s->make_mode);
                        if (r < 0 && r != -ENOTTY)
                                return r;
                }
        }

        if (s->index) {
                r = ca_index_open(s->index);
                if (r < 0)
                        return r;
        }

        s->started = true;

        return 1;
}

static int ca_sync_write_archive(CaSync *s, const void *p, size_t l) {
        assert(s);
        assert(p || l == 0);

        if (s->archive_fd < 0)
                return 0;

        return loop_write(s->archive_fd, p, l);
}

static int ca_sync_write_remote_archive(CaSync *s, const void *p, size_t l) {
        assert(s);
        assert(p || l == 0);

        if (!s->remote_archive)
                return 0;

        return ca_remote_put_archive(s->remote_archive, p, l);
}

static int ca_sync_allocate_archive_digest(CaSync *s) {
        assert(s);

        if (s->archive_digest)
                return 0;

        initialize_libgcrypt();

        assert(gcry_md_get_algo_dlen(GCRY_MD_SHA256) == sizeof(CaChunkID));

        if (gcry_md_open(&s->archive_digest, GCRY_MD_SHA256, 0) != 0)
                return -EIO;

        return 0;
}

static int ca_sync_write_archive_digest(CaSync *s, const void *p, size_t l) {
        int r;

        assert(s);
        assert(p || l == 0);

        r = ca_sync_allocate_archive_digest(s);
        if (r < 0)
                return r;

        gcry_md_write(s->archive_digest, p, l);
        return 0;
}

static int ca_sync_write_one_chunk(CaSync *s, const void *p, size_t l) {
        CaChunkID id;
        int r;

        assert(s);
        assert(p || l == 0);

        r = ca_sync_make_chunk_id(s, p, l, &id);
        if (r < 0)
                return r;

        s->n_written_chunks++;

        if (s->wstore) {
                r = ca_store_put(s->wstore, &id, CA_CHUNK_UNCOMPRESSED, p, l);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        if (s->cache_store) {
                r = ca_store_put(s->cache_store, &id, CA_CHUNK_UNCOMPRESSED, p, l);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        if (s->index) {
                r = ca_index_write_chunk(s->index, &id, l);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ca_sync_write_chunks(CaSync *s, const void *p, size_t l) {
        int r;

        assert(s);
        assert(p || l == 0);

        if (!s->wstore && !s->cache_store && !s->index)
                return 0;

        while (l > 0) {
                const void *chunk;
                size_t chunk_size, k;

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

                r = ca_sync_write_one_chunk(s, chunk, chunk_size);
                if (r < 0)
                        return r;

                realloc_buffer_empty(&s->buffer);

                p = (const uint8_t*) p + k;
                l -= k;
        }

        return 0;
}

static int ca_sync_write_final_chunk(CaSync *s) {
        int r;

        assert(s);

        if (!s->wstore && !s->cache_store && !s->index)
                return 0;

        if (realloc_buffer_size(&s->buffer) == 0)
                return 0;

        r = ca_sync_write_one_chunk(s, realloc_buffer_data(&s->buffer), realloc_buffer_size(&s->buffer));
        if (r < 0)
                return r;

        if (s->index) {
                unsigned char *q;

                r = ca_sync_allocate_archive_digest(s);
                if (r < 0)
                        return r;

                q = gcry_md_read(s->archive_digest, GCRY_MD_SHA256);
                if (!q)
                        return -EIO;

                r = ca_index_set_digest(s->index, (CaChunkID*) q);
                if (r < 0)
                        return r;

                r = ca_index_write_eof(s->index);
                if (r < 0)
                        return r;

                r = ca_index_install(s->index);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ca_sync_install_archive(CaSync *s) {
        assert(s);

        if (!s->temporary_archive_path)
                return 0;

        if (!s->archive_path)
                return 0;

        if (rename(s->temporary_archive_path, s->archive_path) < 0)
                return -errno;

        s->temporary_archive_path = mfree(s->temporary_archive_path);
        return 0;
}

static int ca_sync_write_remote_archive_eof(CaSync *s) {
        assert(s);

        if (!s->remote_archive)
                return 0;

        return ca_remote_put_archive_eof(s->remote_archive);
}

static int ca_sync_step_encode(CaSync *s) {
        int r, step;

        assert(s);

        if (s->archive_eof)
                return CA_SYNC_POLL;

        if (!s->encoder)
                return CA_SYNC_POLL;

        if (s->remote_archive) {
                /* If we shall store the result remotely, wait until the remote side accepts more data */
                r = ca_remote_can_put_archive(s->remote_archive);
                if (r < 0)
                        return r;
                if (r == 0)
                        return CA_SYNC_POLL;
        }

        step = ca_encoder_step(s->encoder);
        if (step < 0)
                return step;

        switch (step) {

        case CA_ENCODER_FINISHED:

                r = ca_sync_write_final_chunk(s);
                if (r < 0)
                        return r;

                r = ca_sync_install_archive(s);
                if (r < 0)
                        return r;

                r = ca_sync_write_remote_archive_eof(s);
                if (r < 0)
                        return r;

                s->archive_eof = true;

                /* If we install an index or archive remotely, let's decide the peer when it's done */
                if (s->remote_index || s->remote_archive)
                        return CA_SYNC_STEP;

                return CA_SYNC_FINISHED;

        case CA_ENCODER_DATA:
        case CA_ENCODER_NEXT_FILE:
        case CA_ENCODER_PAYLOAD: {
                const void *p;
                size_t l;

                r = ca_encoder_get_data(s->encoder, &p, &l);
                if (r < 0)
                        return r;

                r = ca_sync_write_chunks(s, p, l);
                if (r < 0)
                        return r;

                r = ca_sync_write_archive(s, p, l);
                if (r < 0)
                        return r;

                r = ca_sync_write_remote_archive(s, p, l);
                if (r < 0)
                        return r;

                r = ca_sync_write_archive_digest(s, p, l);
                if (r < 0)
                        return r;

                return step == CA_ENCODER_NEXT_FILE ? CA_SYNC_NEXT_FILE :
                        step == CA_ENCODER_PAYLOAD ? CA_SYNC_PAYLOAD : CA_SYNC_STEP;
        }

        default:
                assert(false);
        }
}

static bool ca_sync_seed_ready(CaSync *s) {
        assert(s);

        return s->current_seed >= s->n_seeds;
}

static int ca_sync_process_decoder_request(CaSync *s) {
        int r;

        assert(s);
        assert(s->decoder);

        if (s->index)  {
                CaOrigin *origin = NULL;
                uint64_t chunk_size;
                const void *p;

                if (!s->next_chunk_valid) {
                        r = ca_index_read_chunk(s->index, &s->next_chunk, NULL, &s->next_chunk_size);
                        if (r == -EAGAIN) /* Not enough data */
                                return CA_SYNC_POLL;
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* EOF */
                                r = ca_decoder_put_eof(s->decoder);
                                if (r < 0)
                                        return r;

                                return CA_SYNC_STEP;
                        }

                        s->next_chunk_valid = true;
                }

                /* If we haven't indexed all seeds yet, then let's not start decoding yet. If we came this far, we know
                 * that the index header has been read at least, hence the seeders can be initialized with the index'
                 * chunk size, hence let's wait for them to complete. */
                if (!ca_sync_seed_ready(s))
                        return CA_SYNC_POLL;

                r = ca_sync_get(s, &s->next_chunk, CA_CHUNK_UNCOMPRESSED, &p, &chunk_size, NULL, &origin);
                if (r == -EAGAIN) /* Don't have this right now, but requested it now */
                        return CA_SYNC_STEP;
                if (r == -EALREADY) /* Don't have this right now, but it was already enqueued. */
                        return CA_SYNC_POLL;
                if (r < 0)
                        return r;
                if (s->next_chunk_size != UINT64_MAX && /* next_chunk_size will be -1 if we just seeked in the index file */
                    s->next_chunk_size != chunk_size) {
                        ca_origin_unref(origin);
                        return -EBADMSG;
                }

                s->next_chunk_valid = false;

                if (s->chunk_skip > 0) {
                        /* If we just seeked, then we might have seeked to a location inside of a chunk, hence skip as
                         * many bytes as necessary */
                        if (s->chunk_skip >= chunk_size) {
                                ca_origin_unref(origin);
                                return -EINVAL;
                        }

                        p = (const uint8_t*) p + s->chunk_skip;
                        chunk_size -= s->chunk_skip;

                        s->chunk_skip = 0;
                }

                r = ca_decoder_put_data(s->decoder, p, chunk_size, origin);
                ca_origin_unref(origin);
                if (r < 0)
                        return r;

                r = ca_sync_write_archive_digest(s, p, chunk_size);
                if (r < 0)
                        return r;

                return CA_SYNC_STEP;
        }

        if (s->archive_fd >= 0) {
                void *p;
                ssize_t n;

                p = realloc_buffer_acquire(&s->archive_buffer, BUFFER_SIZE);
                if (!p)
                        return -ENOMEM;

                n = read(s->archive_fd, p, BUFFER_SIZE);
                if (n < 0)
                        return -errno;

                assert((size_t) n <= BUFFER_SIZE);

                if (n == 0) {

                        r = ca_decoder_put_eof(s->decoder);
                        if (r < 0)
                                return r;

                } else {
                        CaOrigin *origin;
                        CaLocation *location;
                        uint64_t offset;

                        if (!s->archive_root) {
                                r = ca_file_root_new(s->archive_path, s->archive_fd, &s->archive_root);
                                if (r < 0)
                                        return r;
                        }

                        r = ca_decoder_get_request_offset(s->decoder, &offset);
                        if (r < 0)
                                return r;

                        r = ca_origin_new(&origin);
                        if (r < 0)
                                return r;

                        r = ca_location_new(NULL, CA_LOCATION_PAYLOAD, offset, n, &location);
                        if (r < 0) {
                                ca_origin_unref(origin);
                                return r;
                        }

                        location->root = ca_file_root_ref(s->archive_root);

                        r = ca_origin_put(origin, location);
                        ca_location_unref(location);
                        if (r < 0) {
                                ca_origin_unref(origin);
                                return r;
                        }

                        r = ca_decoder_put_data(s->decoder, p, n, origin);
                        ca_origin_unref(origin);
                        if (r < 0)
                                return r;

                        r = ca_sync_write_archive_digest(s, p, n);
                        if (r < 0)
                                return r;
                }

                realloc_buffer_empty(&s->archive_buffer);

                return CA_SYNC_STEP;
        }

        return CA_SYNC_POLL;
}

static int ca_sync_install_base(CaSync *s) {
        assert(s);

        if (!s->temporary_base_path)
                return 0;
        if (!s->base_path)
                return 0;

        if (rename(s->temporary_base_path, s->base_path) < 0)
                return -errno;

        s->temporary_base_path = mfree(s->temporary_base_path);
        return 0;
}

static int ca_sync_process_decoder_seek(CaSync *s) {
        uint64_t offset;
        int r;

        assert(s);
        assert(s->decoder);

        r = ca_decoder_get_seek_offset(s->decoder, &offset);
        if (r < 0)
                return r;

        if (s->index) {
                r = ca_index_seek(s->index, offset, &s->chunk_skip);
                if (r < 0)
                        return r;

        } else if (s->archive_fd >= 0) {
                off_t f;

                f = lseek(s->archive_fd, (off_t) offset, SEEK_SET);
                if (f == (off_t) -1)
                        return -errno;

                s->chunk_skip = 0;

        } else
                return -EOPNOTSUPP;

        s->archive_eof = false;
        s->remote_index_eof = false;
        s->next_chunk_valid = false;

        return CA_SYNC_STEP;
}

static int ca_sync_step_decode(CaSync *s) {
        int step, r;

        assert(s);

        if (!s->decoder)
                return CA_SYNC_POLL;

        if (s->archive_eof)
                return -EPIPE;

        step = ca_decoder_step(s->decoder);
        if (step < 0)
                return step;

        switch (step) {

        case CA_DECODER_FINISHED:

                r = ca_sync_install_base(s);
                if (r < 0)
                        return r;

                s->archive_eof = true;

                return CA_SYNC_FINISHED;

        case CA_DECODER_NEXT_FILE:
                return CA_SYNC_NEXT_FILE;

        case CA_DECODER_STEP:
                return CA_SYNC_STEP;

        case CA_DECODER_PAYLOAD:
                return CA_SYNC_PAYLOAD;

        case CA_DECODER_REQUEST:
                return ca_sync_process_decoder_request(s);

        case CA_DECODER_SEEK:
                return ca_sync_process_decoder_seek(s);

        case CA_DECODER_FOUND:
                if (s->archive_digest)
                        gcry_md_reset(s->archive_digest);

                return CA_SYNC_FOUND;

        case CA_DECODER_NOT_FOUND:
                return CA_SYNC_NOT_FOUND;

        default:
                assert(false);
        }
}

static int ca_sync_chunk_size_propagated(CaSync *s) {

        /* If we read the header of the index file, make sure to propagate the chunk size stored in it to the
         * seed. Return > 0 if we successfully propagated the chunk size, and thus can start running the seeds. */

        if (s->direction != CA_SYNC_DECODE)
                return 1;
        if (!s->index)
                return 1;
        if (s->n_seeds == 0)
                return 1;
        if (s->chunk_size_propagated)
                return 1;

        return 0;
}

static CaSeed *ca_sync_current_seed(CaSync *s) {
        assert(s);

        if (s->current_seed >= s->n_seeds)
                return NULL;

        return s->seeds[s->current_seed];
}

static int ca_sync_seed_step(CaSync *s) {
        int r;

        assert(s);

        r = ca_sync_chunk_size_propagated(s);
        if (r < 0)
                return r;
        if (r == 0) /* Chunk size not propagated to the seeds yet. Let's wait until then */
                return CA_SYNC_POLL;

        for (;;) {
                CaSeed *seed;

                seed = ca_sync_current_seed(s);
                if (!seed)
                        break;

                r = ca_seed_step(seed);
                if (r < 0)
                        return r;
                switch (r) {

                case CA_SEED_READY:
                        break;

                case CA_SEED_STEP:
                        return CA_SYNC_STEP;

                case CA_SEED_NEXT_FILE:
                        return CA_SYNC_SEED_NEXT_FILE;

                default:
                        assert(false);
                }

                s->current_seed++;
        }

        return CA_SYNC_POLL;
}

static size_t ca_sync_n_remotes(CaSync *s) {
        size_t n;

        assert(s);

        n = s->n_remote_rstores;

        if (s->remote_archive)
                n++;
        if (s->remote_index)
                n++;
        if (s->remote_wstore && s->remote_wstore != s->remote_index)
                n++;

        return n;
}

static CaRemote *ca_sync_current_remote(CaSync *s) {
        size_t c;

        assert(s);

        s->current_remote %= ca_sync_n_remotes(s);
        c = s->current_remote;

        if (s->remote_archive) {
                if (c == 0)
                        return s->remote_archive;
                c--;
        }

        if (s->remote_index) {
                if (c == 0)
                        return s->remote_index;
                c--;
        }

        if (s->remote_wstore && s->remote_wstore != s->remote_index) {
                if (c == 0)
                        return s->remote_wstore;
                c--;
        }

        return s->remote_rstores[c];
}

static int ca_sync_remote_prefetch(CaSync *s) {
        uint64_t available, saved, requested = 0;
        int r;

        assert(s);

        if (!s->index)
                return CA_SYNC_POLL;
        if (s->direction != CA_SYNC_DECODE)
                return CA_SYNC_POLL;
        if (!s->remote_wstore)
                return CA_SYNC_POLL;

        if (!ca_sync_seed_ready(s))
                return CA_SYNC_POLL;

        r = ca_index_get_available_chunks(s->index, &available);
        if (r == -ENODATA || r == -EAGAIN)
                return CA_SYNC_POLL;
        if (r < 0)
                return r;
        if (s->n_prefetched_chunks >= available) /* Already prefetched all we have */
                return CA_SYNC_POLL;

        r = ca_index_get_position(s->index, &saved);
        if (r < 0)
                return r;

        r = ca_index_set_position(s->index, s->n_prefetched_chunks);
        if (r < 0)
                return r;

        for (;;) {
                CaChunkID id;

                r = ca_index_read_chunk(s->index, &id, NULL, NULL);
                if (r == 0 || r == -EAGAIN)
                        break;
                if (r < 0)
                        return r;

                s->n_prefetched_chunks++;

                r = ca_sync_has_local(s, &id);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = ca_remote_request_async(s->remote_wstore, &id, false);
                if (r < 0)
                        return r;

                requested ++;
        }

        r = ca_index_set_position(s->index, saved);
        if (r < 0)
                return r;

        return requested > 0 ? CA_SYNC_STEP : CA_SYNC_POLL;
}

static int ca_sync_remote_push_index(CaSync *s) {
        int r;

        assert(s);

        if (!s->remote_index)
                return CA_SYNC_POLL;
        if (!s->index)
                return CA_SYNC_POLL;
        if (s->direction != CA_SYNC_ENCODE)
                return CA_SYNC_POLL;
        if (s->remote_index_eof)  /* Already fully written? */
                return CA_SYNC_POLL;

        r = ca_remote_can_put_index(s->remote_index);
        if (r < 0)
                return r;
        if (r == 0)
                return CA_SYNC_POLL;

        r = ca_index_incremental_read(s->index, &s->index_buffer);
        if (r == -EAGAIN)
                return CA_SYNC_POLL;
        if (r < 0)
                return r;
        if (r == 0) {
                r = ca_remote_put_index_eof(s->remote_index);
                if (r < 0)
                        return r;

                s->remote_index_eof = true;
                return CA_SYNC_STEP;
        }

        r = ca_remote_put_index(s->remote_index, realloc_buffer_data(&s->index_buffer), realloc_buffer_size(&s->index_buffer));
        if (r < 0)
                return r;

        return CA_SYNC_STEP;
}

static int ca_sync_remote_push_chunk(CaSync *s) {
        const void *p;
        CaChunkID id;
        size_t l;
        int r;

        assert(s);

        if (!s->remote_index)
                return CA_SYNC_POLL;
        if (!s->remote_wstore)
                return CA_SYNC_POLL;
        if (s->direction != CA_SYNC_ENCODE)
                return CA_SYNC_POLL;

        r = ca_remote_can_put_chunk(s->remote_wstore);
        if (r < 0)
                return r;
        if (r == 0)
                return CA_SYNC_POLL;

        r = ca_remote_next_request(s->remote_index, &id);
        if (r == -ENODATA)
                return CA_SYNC_POLL;
        if (r < 0)
                return r;

        r = ca_sync_get_local(s, &id, CA_CHUNK_COMPRESSED, &p, &l, NULL, NULL);
        if (r == -ENOENT) {
                r = ca_remote_put_missing(s->remote_wstore, &id);
                if (r < 0)
                        return r;

                return CA_SYNC_STEP;
        }
        if (r < 0)
                return r;

        r = ca_remote_put_chunk(s->remote_wstore, &id, CA_CHUNK_COMPRESSED, p, l);
        if (r < 0)
                return r;

        return CA_SYNC_STEP;
}

static int ca_sync_remote_step_one(CaSync *s, CaRemote *rr) {
        int r, step;

        assert(s);
        assert(rr);

        step = ca_remote_step(rr);
        switch (step) {

        case CA_REMOTE_READ_INDEX: {
                const void *data;
                size_t size;

                r = ca_remote_read_index(rr, &data, &size);
                if (r < 0)
                        return r;

                r = ca_index_incremental_write(s->index, data, size);
                if (r < 0)
                        return r;

                break;
        }

        case CA_REMOTE_READ_INDEX_EOF:
                r = ca_index_incremental_eof(s->index);
                if (r < 0)
                        return r;

                break;

        case CA_REMOTE_READ_ARCHIVE: {
                const void *data;
                size_t size;

                r = ca_remote_read_archive(rr, &data, &size);
                if (r < 0)
                        return r;

                r = ca_decoder_put_data(s->decoder, data, size, NULL);
                if (r < 0)
                        return r;

                r = ca_sync_write_archive_digest(s, data, size);
                if (r < 0)
                        return r;

                break;
        }

        case CA_REMOTE_READ_ARCHIVE_EOF:

                r = ca_decoder_put_eof(s->decoder);
                if (r < 0)
                        return r;
                break;
        }

        return step;
}

static int ca_sync_remote_step(CaSync *s) {
        size_t i;
        int r;

        assert(s);

        for (i = 0; i < ca_sync_n_remotes(s); i++) {
                CaRemote *remote;

                remote = ca_sync_current_remote(s);
                if (!remote)
                        continue;

                s->current_remote++;

                r = ca_sync_remote_step_one(s, remote);
                if (r < 0)
                        return r;

                switch (r) {

                case CA_REMOTE_POLL:
                case CA_REMOTE_WRITE_INDEX:
                case CA_REMOTE_WRITE_ARCHIVE:
                        break;

                case CA_REMOTE_STEP:
                case CA_REMOTE_REQUEST:
                case CA_REMOTE_CHUNK:
                case CA_REMOTE_READ_INDEX:
                case CA_REMOTE_READ_INDEX_EOF:
                case CA_REMOTE_READ_ARCHIVE:
                case CA_REMOTE_READ_ARCHIVE_EOF:
                        return CA_SYNC_STEP;

                case CA_REMOTE_FINISHED:
                        return CA_SYNC_FINISHED;

                default:
                        assert(false);
                }
        }

        return CA_SYNC_POLL;
}

static int ca_sync_propagate_chunk_size(CaSync *s) {
        uint64_t cmin, cavg, cmax;
        size_t i;
        int r;

        assert(s);

        /* If we read the header of the index file, make sure to propagate the chunk size stored in it to the seed. */

        r = ca_sync_chunk_size_propagated(s);
        if (r < 0)
                return r;
        if (r > 0) /* The chunk size is already propagated */
                return CA_SYNC_POLL;

        r = ca_index_get_chunk_size_min(s->index, &cmin);
        if (r == -ENODATA) /* haven't read enough from the index header yet, let's wait */
                return CA_SYNC_POLL;
        if (r < 0)
                return r;

        r = ca_index_get_chunk_size_avg(s->index, &cavg);
        if (r < 0)
                return r;

        r = ca_index_get_chunk_size_max(s->index, &cmax);
        if (r < 0)
                return r;

        for (i = 0; i < s->n_seeds; i++) {

                r = ca_seed_set_chunk_size_min(s->seeds[i], cmin);
                if (r < 0)
                        return r;

                r = ca_seed_set_chunk_size_avg(s->seeds[i], cavg);
                if (r < 0)
                        return r;

                r = ca_seed_set_chunk_size_max(s->seeds[i], cmax);
                if (r < 0)
                        return r;
        }

        s->chunk_size_propagated = true;
        return CA_SYNC_STEP;
}

int ca_sync_step(CaSync *s) {
        int r;

        if (!s)
                return -EINVAL;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        r = ca_sync_propagate_chunk_size(s);
        if (r != CA_SYNC_POLL)
                return r;

        r = ca_sync_seed_step(s);
        if (r != CA_SYNC_POLL)
                return r;

        r = ca_sync_remote_prefetch(s);
        if (r != CA_SYNC_POLL)
                return r;

        r = ca_sync_remote_push_index(s);
        if (r != CA_SYNC_POLL)
                return r;

        r = ca_sync_remote_push_chunk(s);
        if (r != CA_SYNC_POLL)
                return r;

        /* Try to decode as much as we already have received, before accepting new remote data */
        r = ca_sync_step_decode(s);
        if (r != CA_SYNC_POLL)
                return r;

        /* Then process any remote traffic and flush our own buffers */
        r = ca_sync_remote_step(s);
        if (r != CA_SYNC_POLL)
                return r;

        /* Finally, generate new data */
        return ca_sync_step_encode(s);
}

int ca_sync_get_local(
                CaSync *s,
                const CaChunkID *chunk_id,
                CaChunkCompression desired_compression,
                const void **ret,
                size_t *ret_size,
                CaChunkCompression *ret_effective_compression,
                CaOrigin **ret_origin) {

        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        for (i = 0; i < s->n_seeds; i++) {
                CaOrigin *origin = NULL;
                const void *p;
                size_t l;

                r = ca_seed_get(s->seeds[i], chunk_id, &p, &l, ret_origin ? &origin : NULL);
                if (r == -ESTALE) {
                        fprintf(stderr, "Chunk cache is not up-to-date, ignoring.\n");
                        continue;
                }
                if (r == -ENOLINK) {
                        fprintf(stderr, "Can't reproduce name table for GOODBYE record, ignoring.\n");
                        continue;
                }
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                if (desired_compression == CA_CHUNK_COMPRESSED) {
                        realloc_buffer_empty(&s->compress_buffer);

                        r = ca_compress(p, l, &s->compress_buffer);
                        if (r < 0) {
                                ca_origin_unref(origin);
                                return r;
                        }

                        *ret = realloc_buffer_data(&s->compress_buffer);
                        *ret_size = realloc_buffer_size(&s->compress_buffer);

                        if (ret_effective_compression)
                                *ret_effective_compression = CA_CHUNK_COMPRESSED;
                } else {
                        *ret = p;
                        *ret_size = l;

                        if (ret_effective_compression)
                                *ret_effective_compression = CA_CHUNK_UNCOMPRESSED;
                }

                if (ret_origin)
                        *ret_origin = origin;
                return r;
        }

        if (s->wstore) {
                r = ca_store_get(s->wstore, chunk_id, desired_compression, ret, ret_size, ret_effective_compression);
                if (r >= 0) {
                        if (ret_origin)
                                *ret_origin = NULL;
                        return r;
                }
                if (r != -ENOENT)
                        return r;
        }

        if (s->cache_store) {
                r = ca_store_get(s->cache_store, chunk_id, desired_compression, ret, ret_size, ret_effective_compression);
                if (r >= 0) {
                        if (ret_origin)
                                *ret_origin = NULL;
                        return r;
                }
                if (r != -ENOENT)
                        return r;
        }

        for (i = 0; i < s->n_rstores; i++) {
                r = ca_store_get(s->rstores[i], chunk_id, desired_compression, ret, ret_size, ret_effective_compression);
                if (r >= 0) {
                        if (ret_origin)
                                *ret_origin = NULL;
                        return r;
                }
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}

int ca_sync_get(CaSync *s,
                const CaChunkID *chunk_id,
                CaChunkCompression desired_compression,
                const void **ret,
                size_t *ret_size,
                CaChunkCompression *ret_effective_compression,
                CaOrigin **ret_origin) {

        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        r = ca_sync_get_local(s, chunk_id, desired_compression, ret, ret_size, ret_effective_compression, ret_origin);
        if (r != -ENOENT)
                return r;

        if (s->remote_wstore) {
                r = ca_remote_request(s->remote_wstore, chunk_id, true, desired_compression, ret, ret_size, ret_effective_compression);
                if (r >= 0) {
                        if (ret_origin)
                                *ret_origin = NULL;
                        return r;
                }
                if (r != -ENOENT)
                        return r;
        }

        for (i = 0; i < s->n_remote_rstores; i++) {
                r = ca_remote_request(s->remote_rstores[i], chunk_id, true, desired_compression, ret, ret_size, ret_effective_compression);
                if (r >= 0) {
                        if (ret_origin)
                                *ret_origin = NULL;
                        return r;
                }
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}

int ca_sync_has_local(CaSync *s, const CaChunkID *chunk_id) {

        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;

        for (i = 0; i < s->n_seeds; i++) {
                r = ca_seed_has(s->seeds[i], chunk_id);
                if (r != 0)
                        return r;
        }

        if (s->wstore) {
                r = ca_store_has(s->wstore, chunk_id);
                if (r != 0)
                        return r;
        }

        if (s->cache_store) {
                r = ca_store_has(s->cache_store, chunk_id);
                if (r != 0)
                        return r;
        }

        for (i = 0; i < s->n_rstores; i++) {
                r = ca_store_has(s->rstores[i], chunk_id);
                if (r != 0)
                        return r;
        }

        return 0;
}

int ca_sync_make_chunk_id(CaSync *s, const void *p, size_t l, CaChunkID *ret) {
        if (!s)
                return -EINVAL;
        if (!p && l > 0)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        return ca_chunk_id_make(&s->chunk_digest, p, l, ret);
}

int ca_sync_get_digest(CaSync *s, CaChunkID *ret) {
        unsigned char *q;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->archive_eof)
                return -EBUSY;

        r = ca_sync_allocate_archive_digest(s);
        if (r < 0)
                return r;

        q = gcry_md_read(s->archive_digest, GCRY_MD_SHA256);
        if (!q)
                return -EIO;

        memcpy(ret, q, sizeof(CaChunkID));

        return 0;
}

int ca_sync_current_path(CaSync *s, char **ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return ca_seed_current_path(seed, ret);

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_path(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_path(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_mode(CaSync *s, mode_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return ca_seed_current_mode(seed, ret);

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_mode(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_mode(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_target(CaSync *s, const char **ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_target(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_target(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_mtime(CaSync *s, uint64_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_mtime(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_mtime(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_size(CaSync *s, uint64_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_size(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_size(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_uid(CaSync *s, uid_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_uid(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_uid(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_gid(CaSync *s, gid_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_gid(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_gid(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_user(CaSync *s, const char **ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_user(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_user(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_group(CaSync *s, const char **ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_group(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_group(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_rdev(CaSync *s, dev_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_rdev(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_rdev(s->decoder, ret);

        return -ENOTTY;
}

static int ca_sync_add_pollfd(CaRemote *rr, struct pollfd *pollfd) {
        int r;

        assert(pollfd);

        if (!rr)
                return 0;

        r = ca_remote_get_io_fds(rr, &pollfd[0].fd, &pollfd[1].fd);
        if (r < 0)
                return r;

        r = ca_remote_get_io_events(rr, &pollfd[0].events, &pollfd[1].events);
        if (r < 0)
                return r;

        return 2;
}

int ca_sync_poll(CaSync *s, uint64_t timeout_usec) {
        struct pollfd *pollfd;
        size_t i, n = 0;
        int r;

        if (!s)
                return -EINVAL;

        if (!s->remote_archive &&
            !s->remote_index &&
            !s->remote_wstore &&
            s->n_remote_rstores == 0)
                return -EUNATCH;

        pollfd = newa(struct pollfd,
                      !!s->remote_archive +
                      !!s->remote_index +
                      !!s->remote_wstore +
                      s->n_remote_rstores);

        r = ca_sync_add_pollfd(s->remote_archive, pollfd);
        if (r < 0)
                return r;
        n += r;

        r = ca_sync_add_pollfd(s->remote_index, pollfd);
        if (r < 0)
                return r;
        n += r;

        r = ca_sync_add_pollfd(s->remote_wstore, pollfd + n);
        if (r < 0)
                return r;
        n += r;

        for (i = 0; i < s->n_remote_rstores; i++) {
                r = ca_sync_add_pollfd(s->remote_rstores[i], pollfd + n);
                if (r < 0)
                        return r;

                n += r;
        }

        if (poll(pollfd, n, timeout_usec == UINT64_MAX ? -1 : (int) ((timeout_usec + 999U)/1000U)) < 0)
                return -errno;

        return n;
}

int ca_sync_current_archive_chunks(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_ENCODE)
                return -ENODATA;

        *ret = s->n_written_chunks;
        return 0;
}

int ca_sync_current_archive_offset(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->encoder)
                return -ENODATA;

        return ca_encoder_current_archive_offset(s->encoder, ret);
}

int ca_sync_seek_offset(CaSync *s, uint64_t offset) {
        uint64_t chunk_skip = 0;
        int r;

        if (!s)
                return -EINVAL;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        if (!s->decoder)
                return -ESPIPE;

        if (s->index) {

                r = ca_index_seek(s->index, offset, &chunk_skip);
                if (r < 0)
                        return r;

        } else if (s->archive_fd >= 0) {
                off_t f;

                f = lseek(s->archive_fd, (off_t) offset, SEEK_SET);
                if (f == (off_t) -1)
                        return -errno;

        } else
                return -EOPNOTSUPP;

        r = ca_decoder_seek_offset(s->decoder, offset);
        if (r < 0)
                return r;

        s->archive_eof = false;
        s->remote_index_eof = false;
        s->next_chunk_valid = false;

        s->chunk_skip = chunk_skip;

        return 0;
}

int ca_sync_seek_path(CaSync *s, const char *path) {
        int r;

        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        if (!s->decoder)
                return -ESPIPE;

        if (s->archive_size == UINT64_MAX) {

                if (s->archive_fd >= 0) {
                        struct stat st;

                        if (fstat(s->archive_fd, &st) < 0)
                                return -errno;

                        if (S_ISREG(st.st_mode))
                                s->archive_size = st.st_size;

                } else if (s->index) {
                        r = ca_index_get_blob_size(s->index, &s->archive_size);
                        if (r < 0)
                                return r;
                } else
                        return -EOPNOTSUPP;

                r = ca_decoder_set_archive_size(s->decoder, s->archive_size);
                if (r < 0)
                        return r;
        }

        r = ca_decoder_seek_path(s->decoder, path);
        if(r < 0)
                return r;

        s->archive_eof = false;
        s->remote_index_eof = false;
        s->next_chunk_valid = false;
        s->chunk_skip = 0;

        return 0;
}

int ca_sync_get_payload(CaSync *s, const void **ret, size_t *ret_size) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        if (s->decoder)
                return ca_decoder_get_payload(s->decoder, ret, ret_size);
        else if (s->encoder)
                return ca_encoder_get_data(s->encoder, ret, ret_size);

        return -ENOTTY;
}

int ca_sync_get_archive_size(CaSync *s, uint64_t *ret_size) {
        int r;

        if (!s)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        if (!s->decoder)
                return -EINVAL;

        if (s->index)
                return ca_index_get_blob_size(s->index, ret_size);

        if (s->archive_fd >= 0) {
                struct stat st;

                if (s->archive_size != UINT64_MAX) {
                        *ret_size = s->archive_size;
                        return 0;
                }

                if (fstat(s->archive_fd, &st) < 0)
                        return -errno;

                if (!S_ISREG(st.st_mode))
                        return -ESPIPE;

                *ret_size = s->archive_size = st.st_size;
                return 0;
        }

        return -ENOTTY;
}

int ca_sync_get_punch_holes_bytes(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (!s->punch_holes)
                return -ENODATA;

        if (!s->decoder) {
                *ret = 0;
                return 0;
        }

        return ca_decoder_get_punch_holes_bytes(s->decoder, ret);
}

int ca_sync_get_reflink_bytes(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (!s->reflink)
                return -ENODATA;

        if (!s->decoder) {
                *ret = 0;
                return 0;
        }

        return ca_decoder_get_reflink_bytes(s->decoder, ret);
}
