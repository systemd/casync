/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/poll.h>
#include <sys/stat.h>

#include "cacache.h"
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
#include "realloc-buffer.h"
#include "time-util.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef ENXIO */
/* #define ENXIO __LINE__ */

/* #undef EUNATCH */
/* #define EUNATCH __LINE__ */

typedef enum CaDirection {
        CA_SYNC_ENCODE,
        CA_SYNC_DECODE,
} CaDirection;

/* In which state regarding cache check and validation are we? */
typedef enum CaCacheState {
        CA_SYNC_CACHE_OFF,       /* Possibly write to the cache, but don't consult it */
        CA_SYNC_CACHE_CHECK,     /* We are at a position where it might make sense to check the cache */
        CA_SYNC_CACHE_VERIFY,    /* We found a chunk in the cache, and are validating if it still matches disk */
        CA_SYNC_CACHE_FAILED,    /* We found a chunk in the cache, but it turned out not to match disk, now seek back where the cache experiment started */
        CA_SYNC_CACHE_SUCCEEDED, /* We found a chunk in the cache, and it checked out */
        CA_SYNC_CACHE_IDLE,      /* We are not at a position where it might make sense to check the cache */
} CaCacheState;

struct CaSync {
        CaDirection direction;
        uint64_t start_nsec;

        CaEncoder *encoder;
        CaDecoder *decoder;

        CaChunker chunker;
        CaChunker original_chunker; /* A copy of the full chunker state from the beginning, which we can use when we need to reset things */

        CaIndex *index;
        CaRemote *remote_index;

        CaRemote *remote_archive;

        CaChunkID next_chunk;
        uint64_t next_chunk_size;
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
        bool index_flags_propagated;

        CaCache *cache;
        CaCacheState cache_state;
        CaChunkID current_cache_chunk_id;
        uint64_t current_cache_chunk_size;
        CaOrigin *current_cache_origin;
        CaLocation *current_cache_start_location;

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

        CaOrigin *buffer_origin;

        CaDigest *chunk_digest;

        bool archive_eof;
        bool remote_index_eof;

        int log_level;
        size_t rate_limit_bps;

        uint64_t feature_flags;
        uint64_t feature_flags_mask;

        uint64_t n_written_chunks;
        uint64_t n_reused_chunks;
        uint64_t n_prefetched_chunks;

        uint64_t n_cache_hits;
        uint64_t n_cache_misses;
        uint64_t n_cache_invalidated;
        uint64_t n_cache_added;

        uint64_t archive_size;

        uint64_t chunk_skip;

        bool punch_holes:1;
        bool reflink:1;
        bool hardlink:1;
        bool delete:1;
        bool payload:1;
        bool undo_immutable:1;

        bool archive_digest:1;
        bool hardlink_digest:1;
        bool payload_digest:1;

        CaFileRoot *archive_root;

        uid_t uid_shift;
        uid_t uid_range; /* uid_range == 0 means "full range" */

        uint64_t chunk_size_min;
        uint64_t chunk_size_avg;
        uint64_t chunk_size_max;

        CaCompressionType compression_type;

        uint64_t first_chunk_request_nsec;
        uint64_t last_chunk_request_nsec;
};

#define CA_SYNC_IS_STARTED(s) ((s)->start_nsec != 0)

static CaSync *ca_sync_new(void) {
        CaSync *s;

        s = new0(CaSync, 1);
        if (!s)
                return NULL;

        s->base_fd = s->boundary_fd = s->archive_fd = -1;
        s->base_mode = (mode_t) -1;
        s->make_mode = (mode_t) -1;

        s->chunker = (CaChunker) CA_CHUNKER_INIT;

        s->log_level = -1;
        s->archive_size = UINT64_MAX;
        s->punch_holes = true;
        s->reflink = true;
        s->delete = true;
        s->payload = true;

        s->feature_flags = s->feature_flags_mask = UINT64_MAX;

        s->compression_type = CA_COMPRESSION_DEFAULT;

        return s;
}

CaSync *ca_sync_new_encode(void) {
        CaSync *s;

        s = ca_sync_new();
        if (!s)
                return NULL;

        s->direction = CA_SYNC_ENCODE;
        s->feature_flags = CA_FORMAT_DEFAULT & SUPPORTED_FEATURE_MASK;

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

int ca_sync_set_chunk_size_min(CaSync *s, uint64_t v) {
        int r;

        if (!s)
                return -EINVAL;

        r = ca_chunker_set_size(&s->chunker, v, s->chunk_size_avg, s->chunk_size_max);
        if (r < 0)
                return r;

        s->chunk_size_min = v;
        return 0;
}

int ca_sync_set_chunk_size_avg(CaSync *s, uint64_t v) {
        int r;

        if (!s)
                return -EINVAL;

        r = ca_chunker_set_size(&s->chunker, s->chunk_size_min, v, s->chunk_size_max);
        if (r < 0)
                return r;

        s->chunk_size_avg = v;
        return 0;
}

int ca_sync_set_chunk_size_max(CaSync *s, uint64_t v) {
        int r;

        if (!s)
                return -EINVAL;

        r = ca_chunker_set_size(&s->chunker, s->chunk_size_min, s->chunk_size_avg, v);
        if (r < 0)
                return r;

        s->chunk_size_max = v;
        return 0;
}

int ca_sync_get_chunk_size_avg(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = s->chunker.chunk_size_avg;
        return 0;
}

int ca_sync_get_chunk_size_min(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = s->chunker.chunk_size_min;
        return 0;
}

int ca_sync_get_chunk_size_max(CaSync *s, uint64_t *ret) {
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

int ca_sync_set_hardlink(CaSync *s, bool enabled) {
        int r;

        if (!s)
                return -EINVAL;
        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (s->decoder) {
                r = ca_decoder_enable_hardlink_digest(s->decoder, s->hardlink_digest || enabled);
                if (r < 0)
                        return r;

                r = ca_decoder_set_hardlink(s->decoder, enabled);
                if (r < 0)
                        return r;
        }

        s->hardlink = enabled;

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

int ca_sync_set_payload(CaSync *s, bool enabled) {
        int r;

        if (!s)
                return -EINVAL;
        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (s->decoder) {
                r = ca_decoder_set_payload(s->decoder, enabled || s->remote_archive);
                if (r < 0)
                        return r;
        }

        s->payload = enabled;

        return 0;
}

int ca_sync_set_undo_immutable(CaSync *s, bool enabled) {
        int r;

        if (!s)
                return -EINVAL;
        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (s->decoder) {
                r = ca_decoder_set_undo_immutable(s->decoder, enabled);
                if (r < 0)
                        return r;
        }

        s->undo_immutable = enabled;

        return 0;
}

int ca_sync_set_uid_shift(CaSync *s, uid_t u) {
        int r;

        if (!s)
                return -EINVAL;

        if (s->decoder) {
                r = ca_decoder_set_uid_shift(s->decoder, u);
                if (r < 0)
                        return r;
        }

        if (s->encoder) {
                r = ca_encoder_set_uid_shift(s->encoder, u);
                if (r < 0)
                        return r;
        }

        s->uid_shift = u;
        return 0;
}

int ca_sync_set_uid_range(CaSync *s, uid_t u) {
        int r;

        if (!s)
                return -EINVAL;

        if (s->decoder) {
                r = ca_decoder_set_uid_range(s->decoder, u);
                if (r < 0)
                        return r;
        }

        if (s->encoder) {
                r = ca_encoder_set_uid_range(s->encoder, u);
                if (r < 0)
                        return r;
        }

        s->uid_range = u;
        return 0;
}

static void ca_sync_reset_cache_data(CaSync *s) {
        assert(s);

        /* Resets the cache data, i.e. the cached item we are currently processing. */
        s->current_cache_start_location = ca_location_unref(s->current_cache_start_location);
        s->current_cache_origin = ca_origin_unref(s->current_cache_origin);
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

        ca_sync_reset_cache_data(s);
        ca_cache_unref(s->cache);

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

        ca_origin_unref(s->buffer_origin);

        ca_file_root_unref(s->archive_root);

        ca_digest_free(s->chunk_digest);

        return mfree(s);
}

int ca_sync_set_log_level(CaSync *s, int log_level) {
        if (!s)
                return -EINVAL;

        s->log_level = log_level;

        return 0;
}

int ca_sync_set_rate_limit_bps(CaSync *s, uint64_t rate_limit_bps) {
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
        if (s->encoder)
                return -EBUSY;

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

        if (s->direction != CA_SYNC_ENCODE)
                return -ENOTTY;
        if (!s->encoder)
                return -ENODATA;

        return ca_encoder_get_covering_feature_flags(s->encoder, ret);
}

int ca_sync_set_feature_flags_mask(CaSync *s, uint64_t mask) {
        if (!s)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;
        if (s->decoder)
                return -EBUSY;

        return ca_feature_flags_normalize_mask(mask, &s->feature_flags_mask);
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

	if (s->log_level != -1) {
        	r = ca_remote_set_log_level(s->remote_index, s->log_level);
        	if (r < 0)
        		return r;
	}

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

int ca_sync_set_cache_fd(CaSync *s, int fd) {
        _cleanup_(ca_cache_unrefp) CaCache *cache = NULL;
        int r;

        if (!s)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (s->cache)
                return -EBUSY;

        cache = ca_cache_new();
        if (!cache)
                return -ENOMEM;

        r = ca_cache_set_fd(cache, fd);
        if (r < 0)
                return r;

        s->cache = cache;
        cache = NULL;

        return 0;
}

int ca_sync_set_cache_path(CaSync *s, const char *path) {

        _cleanup_(ca_cache_unrefp) CaCache *cache = NULL;
        int r;

        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (s->cache)
                return -EBUSY;

        cache = ca_cache_new();
        if (!cache)
                return -ENOMEM;

        r = ca_cache_set_path(cache, path);
        if (r < 0)
                return r;

        s->cache = cache;
        cache = NULL;

        return 0;
}

static bool ca_sync_use_cache(CaSync *s) {
        assert(s);

        /* Returns true if we can use the cache when reading. This only works if we don't generate an archive or
         * archive digest and if we actually have a cache configured. */

        if (s->direction != CA_SYNC_ENCODE)
                return false;

        if (s->archive_fd >= 0)
                return false;

        if (s->remote_archive)
                return false;

        if (s->archive_digest || s->payload_digest || s->hardlink_digest)
                return false;

        return !!s->cache;
}

static int ca_sync_start(CaSync *s) {
        size_t i;
        int r;

        assert(s);

        if (CA_SYNC_IS_STARTED(s))
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

                r = ca_encoder_set_uid_shift(s->encoder, s->uid_shift);
                if (r < 0)
                        return r;
                r = ca_encoder_set_uid_range(s->encoder, s->uid_range);
                if (r < 0)
                        return r;
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
                r = ca_decoder_set_hardlink(s->decoder, s->hardlink);
                if (r < 0)
                        return r;
                r = ca_decoder_set_delete(s->decoder, s->delete);
                if (r < 0)
                        return r;
                r = ca_decoder_set_payload(s->decoder, s->payload || s->remote_archive);
                if (r < 0)
                        return r;
                r = ca_decoder_set_undo_immutable(s->decoder, s->undo_immutable);
                if (r < 0)
                        return r;
                r = ca_decoder_set_uid_shift(s->decoder, s->uid_shift);
                if (r < 0)
                        return r;
                r = ca_decoder_set_uid_range(s->decoder, s->uid_range);
                if (r < 0)
                        return r;
                r = ca_decoder_set_feature_flags_mask(s->decoder, s->feature_flags_mask);
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

                r = ca_store_set_digest_type(s->cache_store, ca_feature_flags_to_digest_type(s->feature_flags));
                if (r < 0)
                        return r;

                (void) ca_store_set_compression_type(s->cache_store, s->compression_type);

                r = ca_remote_add_local_feature_flags(s->remote_index, CA_PROTOCOL_PUSH_INDEX_CHUNKS);
                if (r < 0)
                        return r;
        }

        if (s->encoder) {
                r = ca_encoder_enable_archive_digest(s->encoder, s->archive_digest);
                if (r < 0)
                        return r;

                r = ca_encoder_enable_payload_digest(s->encoder, s->payload_digest);
                if (r < 0)
                        return r;

                r = ca_encoder_enable_hardlink_digest(s->encoder, s->hardlink_digest);
                if (r < 0)
                        return r;

                s->original_chunker = s->chunker;
        }

        if (s->decoder) {
                r = ca_decoder_enable_archive_digest(s->decoder, s->archive_digest);
                if (r < 0)
                        return r;

                r = ca_decoder_enable_payload_digest(s->decoder, s->payload_digest);
                if (r < 0)
                        return r;

                r = ca_decoder_enable_hardlink_digest(s->decoder, s->hardlink_digest || s->hardlink);
                if (r < 0)
                        return r;
        }

        if (s->index) {

                if (s->direction == CA_SYNC_ENCODE) {
                        /* Propagate the chunk size to the index we generate */

                        r = ca_index_set_feature_flags(s->index, s->feature_flags);
                        if (r < 0)
                                return r;

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

                r = ca_index_open(s->index);
                if (r < 0)
                        return r;
        }

        for (i = 0; i < s->n_seeds; i++) {
                /* Tell seeders whether to calculate hardlink and/or chunk seeds */

                r = ca_seed_set_hardlink(s->seeds[i], s->hardlink);
                if (r < 0)
                        return r;

                r = ca_seed_set_chunks(s->seeds[i], !!s->index);
                if (r < 0)
                        return r;
        }

        /* Tell the wstore which compression algorithm to use */
        if (s->wstore) {
                r = ca_store_set_compression_type(s->wstore, s->compression_type);
                if (r < 0)
                        return r;
        }

        if (s->remote_wstore) {
                r = ca_remote_set_compression_type(s->remote_wstore, s->compression_type);
                if (r < 0)
                        return r;
        }

        if (s->cache) {
                r = ca_cache_set_digest_type(s->cache, ca_feature_flags_to_digest_type(s->feature_flags));
                if (r < 0)
                        return r;
        }

        s->cache_state = ca_sync_use_cache(s) ? CA_SYNC_CACHE_CHECK : CA_SYNC_CACHE_OFF;
        s->start_nsec = now(CLOCK_MONOTONIC);

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

static int ca_sync_write_one_chunk(CaSync *s, const void *p, size_t l, CaOrigin *origin) {
        CaChunkID id;
        int r;

        assert(s);
        assert(p || l == 0);
        assert(!origin || ca_origin_bytes(origin) == l);

        /* Processes a single chunk we just generated. Writes it to our wstore, our cache store, and our cache. Also
         * writes a record about it into the index. Note that if we hit the cache ca_sync_write_one_cached_chunk() is
         * called instead. */

        r = ca_sync_make_chunk_id(s, p, l, &id);
        if (r < 0)
                return r;

        s->n_written_chunks++;

        if (s->wstore) {
                r = ca_store_put(s->wstore, &id, CA_CHUNK_UNCOMPRESSED, p, l);
                if (r == -EEXIST)
                        s->n_reused_chunks++;
                else if (r < 0)
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

        if (s->cache) {
                log_debug("Adding cache entry %s.", ca_location_format(ca_origin_get(origin, 0)));

                r = ca_cache_put(s->cache, origin, &id);
                if (r < 0)
                        return r;
                if (r > 0)
                        s->n_cache_added++;
        }

        if (ca_sync_use_cache(s))
                s->cache_state = CA_SYNC_CACHE_CHECK;

        return 0;
}

static int ca_sync_write_chunks(CaSync *s, const void *p, size_t l, CaLocation *location) {
        int r;

        assert(s);
        assert(p || l == 0);

        /* Splits up the data that was just generated into chunks, and calls ca_sync_write_one_chunk() for it */

        if (!s->wstore && !s->cache_store && !s->index)
                return 0;

        if (location) {
                if (!s->buffer_origin) {
                        r = ca_origin_new(&s->buffer_origin);
                        if (r < 0)
                                return r;
                }

                r = ca_origin_put(s->buffer_origin, location);
                if (r < 0)
                        return r;
        }

        while (l > 0) {
                _cleanup_(ca_origin_unrefp) CaOrigin *chunk_origin = NULL;
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

                if (s->buffer_origin) {
                        if (chunk_size == ca_origin_bytes(s->buffer_origin)) {
                                chunk_origin = s->buffer_origin;
                                s->buffer_origin = NULL;
                        } else {
                                r = ca_origin_extract_bytes(s->buffer_origin, chunk_size, &chunk_origin);
                                if (r < 0)
                                        return r;

                                r = ca_origin_advance_bytes(s->buffer_origin, chunk_size);
                                if (r < 0)
                                        return r;
                        }
                }

                r = ca_sync_write_one_chunk(s, chunk, chunk_size, chunk_origin);
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

        if (realloc_buffer_size(&s->buffer) > 0) {
                r = ca_sync_write_one_chunk(s, realloc_buffer_data(&s->buffer), realloc_buffer_size(&s->buffer), s->buffer_origin);
                if (r < 0)
                        return r;
        }

        if (s->index) {
                r = ca_index_write_eof(s->index);
                if (r < 0)
                        return r;

                r = ca_index_install(s->index);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ca_sync_write_one_cached_chunk(CaSync *s, const CaChunkID *id, uint64_t size, CaLocation *location) {
        int r;

        assert(s);
        assert(id);

        /* Much like ca_sync_write_one_chunk(), but is called when we are using the cache and had a cache hit */

        s->n_written_chunks ++;

        if (s->index) {
                r = ca_index_write_chunk(s->index, id, size);
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

static int ca_sync_cache_get(CaSync *s, CaLocation *location) {
        int r;

        assert(s);
        assert(location);

        assert(s->cache);
        assert(!s->current_cache_start_location);
        assert(!s->current_cache_origin);

        r = ca_cache_get(s->cache, location, &s->current_cache_chunk_id, &s->current_cache_origin);
        if (r == -ENOENT) { /* No luck, no cached entry about this, let's generate new data then */
                log_debug("Cache miss at %s.", ca_location_format(location));
                s->n_cache_misses++;
                return r;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire item from cache: %m");

        log_debug("Yay, cache hit at %s.", ca_location_format(location));

        s->current_cache_start_location = ca_location_ref(location);
        s->current_cache_chunk_size = ca_origin_bytes(s->current_cache_origin);

        return r;
}

static int ca_sync_need_data(CaSync *s) {
        assert(s);

        /* Returns true if we actually need to generate any data, i.e. when we are supposed to write an index or
         * archive, or a store to write to is configured, or at least one form of digest is turned on. It neither is
         * the case (because we just want to list files/directories) then we can avoid generating data and speed things
         * up */

        return s->index || s->remote_index ||
                s->archive_fd >= 0 || s->remote_archive ||
                s->wstore || s->cache_store ||
                s->archive_digest || s->hardlink_digest || s->payload_digest;
}

static int ca_sync_step_encode(CaSync *s) {
        int r, step;
        bool next_step;

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

        switch (s->cache_state) {

        case CA_SYNC_CACHE_OFF:
        case CA_SYNC_CACHE_IDLE:
                next_step = true;
                break;

        case CA_SYNC_CACHE_CHECK: {
                CaLocation *location;

                assert(!s->current_cache_start_location);
                assert(!s->current_cache_origin);

                /* Let's see if there's already data in the buffer. If so, let's see if we have a cached entry for
                 * it. */
                if (realloc_buffer_size(&s->buffer) == 0) {
                        /* Nope, nothing new. Let's generate some new data then */
                        next_step = true;
                        break;
                }

                assert_se(location = ca_origin_get(s->buffer_origin, 0));

                /* A previous iteration already read stuff into the buffer, however it wasn't enough for a whole
                 * chunk. Let's see if instead of generating further data the cache can help us. */

                r = ca_sync_cache_get(s, location);
                if (r == -ENOENT) { /* No luck */
                        s->cache_state = CA_SYNC_CACHE_IDLE;
                        next_step = true;
                        break;
                }
                if (r < 0)
                        return r;

                /* Yippieh! */
                s->cache_state = CA_SYNC_CACHE_VERIFY;
                return CA_SYNC_STEP;
        }

        case CA_SYNC_CACHE_VERIFY: {
                CaLocation *a, *b;

                assert(s->current_cache_start_location);
                assert(s->current_cache_origin);

                if (ca_origin_bytes(s->current_cache_origin) == 0) {
                        /* Nice! All checked out! */
                        log_debug("Cached block checked out (on buffer).");
                        s->cache_state = CA_SYNC_CACHE_SUCCEEDED;
                        return CA_SYNC_STEP;
                }

                /* Let's see if there's data in the buffer we need to verify first. */
                if (realloc_buffer_size(&s->buffer) == 0) {
                        /* Nope there is not, let's generate some new data then */
                        next_step = true;
                        break;
                }

                assert_se(a = ca_origin_get(s->current_cache_origin, 0));
                assert_se(b = ca_origin_get(s->buffer_origin, 0));

                if (ca_location_equal(a, b, CA_LOCATION_WITH_MTIME|CA_LOCATION_WITH_FEATURE_FLAGS)) {
                        uint64_t sz;

                        /* Yay, this location checked out. Let's advance both our buffer (and its origin), and the
                         * cache origin. */

                        assert_se(a->size != UINT64_MAX);
                        assert_se(a->size != 0);

                        assert_se(b->size != UINT64_MAX);
                        assert_se(b->size != 0);

                        sz = MIN(a->size, b->size);

                        r = ca_origin_advance_bytes(s->current_cache_origin, sz);
                        if (r < 0)
                                return r;

                        r = ca_origin_advance_bytes(s->buffer_origin, sz);
                        if (r < 0)
                                return r;

                        r = realloc_buffer_advance(&s->buffer, sz);
                        if (r < 0)
                                return r;

                        return CA_SYNC_STEP;
                }

                /* Ah, dang, this didn't check out. Let's revert back. */
                log_debug("Cache item out of date, location didn't match (on buffer).");
                s->cache_state = CA_SYNC_CACHE_FAILED;
                return CA_SYNC_STEP;
        }

        case CA_SYNC_CACHE_SUCCEEDED:
                assert(s->current_cache_start_location);
                assert(s->current_cache_origin);

                /* In the previous iteration we tried to use the cache, and it did work out. Yay! Let's now
                 * write the cached item, and seek where we are supposed to continue */

                log_debug("Succeeded with cached block!");

                r = ca_sync_write_one_cached_chunk(s, &s->current_cache_chunk_id, s->current_cache_chunk_size, s->current_cache_start_location);
                if (r < 0)
                        return log_debug_errno(r, "Failed to write cached item to index: %m");

                s->n_cache_hits++;

                /* Reset the cached item we are operating on */
                ca_sync_reset_cache_data(s);
                s->cache_state = CA_SYNC_CACHE_CHECK;

                return CA_SYNC_STEP;

        case CA_SYNC_CACHE_FAILED:
                assert(s->current_cache_start_location);
                assert(s->current_cache_origin);

                /* In the previous iteration we tried to use the cache, but this didn't work out, the stuff on disk
                 * didn't match our cache anymore. In this iteration we'll hence seek back to where our cache adventure
                 * started, and read off disk again. But we'll remove the bogus cache entry first, so that this doesn't
                 * happen again, ever. */

                log_debug("Cached block didn't check out, seeking back to %s.", ca_location_format(s->current_cache_start_location));

                r = ca_cache_remove(s->cache, s->current_cache_start_location);
                if (r < 0 && r != -ENOENT)
                        return log_debug_errno(r, "Failed to remove cache item: %m");

                s->n_cache_invalidated++;

                step = ca_encoder_seek_location(s->encoder, s->current_cache_start_location);
                if (step < 0)
                        return log_debug_errno(step, "Failed to seek encoder: %m");

                /* Reset the cached item we are operating on */
                ca_sync_reset_cache_data(s);
                s->cache_state = CA_SYNC_CACHE_IDLE;

                /* Clear whatever is currently in the buffer */
                realloc_buffer_empty(&s->buffer);
                s->buffer_origin = ca_origin_unref(s->buffer_origin);

                s->chunker = s->original_chunker;

                next_step = false;
                break;
        }

        if (next_step) {
                step = ca_encoder_step(s->encoder);
                if (step < 0)
                        return log_debug_errno(step, "Failed to run encoder step: %m");
        }

        switch (step) {

        case CA_ENCODER_FINISHED:

                if (s->cache_state == CA_SYNC_CACHE_VERIFY) {
                        /* What? There's still a cache item pending that didn't finish yet? If so, it's invalid. Let's
                         * treat it as miss */

                        log_debug("Cache item out of date, reached EOF too early.");
                        s->cache_state = CA_SYNC_CACHE_FAILED;
                        return CA_SYNC_STEP;
                }

                assert(IN_SET(s->cache_state, CA_SYNC_CACHE_OFF, CA_SYNC_CACHE_CHECK, CA_SYNC_CACHE_IDLE));

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

        case CA_ENCODER_NEXT_FILE:
        case CA_ENCODER_PAYLOAD:
        case CA_ENCODER_DATA: {
                _cleanup_(ca_location_unrefp) CaLocation *location = NULL;
                size_t l, extra_offset = 0;
                const void *p = NULL;

                switch (s->cache_state) {

                case CA_SYNC_CACHE_OFF:
                case CA_SYNC_CACHE_IDLE:
                        break;

                case CA_SYNC_CACHE_CHECK: {
                        /* Let's check if the cache provides an item for our current location */

                        assert(!s->current_cache_start_location);
                        assert(!s->current_cache_origin);

                        assert(realloc_buffer_size(&s->buffer) == 0);
                        assert(ca_origin_bytes(s->buffer_origin) == 0);

                        /* Let's figure out the location we are at right now */
                        r = ca_encoder_current_location(s->encoder, 0, &location);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to acquire encoder location: %m");

                        /* Hmm, let's check the cache now then, maybe we can use that and avoid the disk accesses for
                           the new data? */
                        r = ca_sync_cache_get(s, location);
                        if (r == -ENOENT) { /* No luck, let's generate new data then. */
                                s->cache_state = CA_SYNC_CACHE_IDLE;
                                break;
                        }
                        if (r < 0)
                                return r;

                        /* This worked! Let's proceed with verifying what we just got. */
                        s->cache_state = CA_SYNC_CACHE_VERIFY;
                } _fallthrough_;

                case CA_SYNC_CACHE_VERIFY: {
                        CaLocation *cached_location;
                        uint64_t sz;
                        size_t data_size;

                        assert(s->current_cache_start_location);
                        assert(s->current_cache_origin);

                        assert(realloc_buffer_size(&s->buffer) == 0);
                        assert(ca_origin_bytes(s->buffer_origin) == 0);

                        if (!location) {
                                /* Let's figure out the location we are at right now */
                                r = ca_encoder_current_location(s->encoder, 0, &location);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to acquire encoder location: %m");
                        }

                        assert_se(cached_location = ca_origin_get(s->current_cache_origin, 0));

                        if (!ca_location_equal(location, cached_location, CA_LOCATION_WITH_MTIME|CA_LOCATION_WITH_FEATURE_FLAGS)) {
                                /* We are not where we should be. Bummer. */
                                log_debug("Cache item out of date, location didn't match (on encoder). %s != %s",
                                          ca_location_format(location), ca_location_format(cached_location));
                                s->cache_state = CA_SYNC_CACHE_FAILED;
                                return CA_SYNC_STEP;
                        }

                        assert_se(cached_location->size != UINT64_MAX);
                        assert_se(cached_location->size != 0);

                        /* Generate the data if necessary, but clarify that we are not actually interested, by passing NULL */
                        r = ca_encoder_get_data(s->encoder, cached_location->size, NULL, &data_size);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to skip initial data: %m");

                        for (;;) {
                                if (data_size <= cached_location->size) {

                                        /* Less or equal data than we expected was generated. Let's advance the cache origin,
                                         * and retry */

                                        r = ca_origin_advance_bytes(s->current_cache_origin, data_size);
                                        if (r < 0)
                                                return r;

                                        goto done;
                                }

                                /* Hmm, so more data than we expected was generated. When this happens in the middle of
                                 * our cache verification that's a problem, as in that case the cache data didn't match
                                 * reality. However, if that happens at the end of our validation, it's OK, however we
                                 * need to do something useful with the remainder. */

                                if (ca_origin_items(s->current_cache_origin) > 1) {
                                        /* Not at the end. Bummer. */
                                        log_debug("Cache item out of date, size didn't match.");
                                        s->cache_state = CA_SYNC_CACHE_FAILED;
                                        return CA_SYNC_STEP;
                                }

                                log_debug("Chunk matched, writing out.");

                                /* Yay, we are at the end of our cache entry. That's excellent! */

                                r = ca_sync_write_one_cached_chunk(s, &s->current_cache_chunk_id, s->current_cache_chunk_size, s->current_cache_start_location);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to write cached item to index: %m");

                                sz = cached_location->size;

                                s->n_cache_hits++;
                                ca_sync_reset_cache_data(s);

                                /* So we have some more data to handle. Let's see if we have a hit for that one too. */

                                r = ca_location_advance(&location, sz);
                                if (r < 0)
                                        return r;
                                data_size -= sz;

                                r = ca_sync_cache_get(s, location);
                                if (r == -ENOENT) {
                                        s->cache_state = CA_SYNC_CACHE_IDLE;

                                        /* So, this is available in the cache, we hence need to generate data here. Hence we
                                         * need to call ca_encoder_get_data() again, but this time ask for real data. And then
                                         * we need to skip what we already used. */
                                        extra_offset = sz;
                                        break;
                                }
                                if (r < 0)
                                        return r;

                                assert_se(cached_location = ca_origin_get(s->current_cache_origin, 0));
                        }

                        assert_se(extra_offset > 0);
                        break;
                }

                case CA_SYNC_CACHE_FAILED:
                case CA_SYNC_CACHE_SUCCEEDED:
                        assert_not_reached("Unexpected cache state");
                }

                if (ca_sync_need_data(s))
                        r = ca_encoder_get_data(s->encoder, UINT64_MAX, &p, &l);
                else
                        r = ca_encoder_get_data(s->encoder, UINT64_MAX, NULL, &l);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire data: %m");

                /* Apply the extra offset, if there's any */
                if (p)
                        p = (const uint8_t*) p + extra_offset;
                l -= extra_offset;

                if (s->cache) {
                        /* When caching enabled, query current encoder location, so that we can generate a cache entry
                         * for it. Note that the location might already be initialized, and if it is the 'extra_offset'
                         * is already applied to it.  */

                        if (!location) {
                                r = ca_encoder_current_location(s->encoder, 0, &location);
                                if (r < 0)
                                        return r;
                        }

                        r = ca_location_patch_size(&location, l);
                        if (r < 0)
                                return r;
                }

                if (p) {
                        r = ca_sync_write_chunks(s, p, l, location);
                        if (r < 0)
                                return r;

                        r = ca_sync_write_archive(s, p, l);
                        if (r < 0)
                                return r;

                        r = ca_sync_write_remote_archive(s, p, l);
                        if (r < 0)
                                return r;
                }

        done:
                return step == CA_ENCODER_NEXT_FILE ? CA_SYNC_NEXT_FILE :
                       step == CA_ENCODER_PAYLOAD   ? CA_SYNC_PAYLOAD   :
                                                      CA_SYNC_STEP;
        }

        case CA_ENCODER_DONE_FILE:
                return CA_SYNC_DONE_FILE;

        default:
                assert(false);
        }
}

static bool ca_sync_shall_seed(CaSync *s) {

        assert(s);

        if (s->direction != CA_SYNC_DECODE)
                return false;  /* only run the seeds when decoding */
        if (s->n_seeds == 0) /* no point in bothering if there are no seeds */
                return false;

        if (!s->index && !s->hardlink) /* If there's no chunk index and hardlinking is turned off, there's no point of managing seeds. */
                return false;

        return true;
}

static bool ca_sync_seed_ready(CaSync *s) {
        assert(s);

        if (!ca_sync_shall_seed(s))
                return true;

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

                for (;;) {
                        if (s->next_chunk_valid) {

                                if (s->chunk_skip < s->next_chunk_size)
                                        break;

                                s->chunk_skip -= s->next_chunk_size;
                                s->next_chunk_valid = false;
                        }

                        r = ca_index_read_chunk(s->index, &s->next_chunk, NULL, &s->next_chunk_size);
                        if (r == -EAGAIN) /* Not enough data */
                                return CA_SYNC_POLL;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to read index chunk: %m");
                        if (r == 0) {
                                /* EOF */
                                r = ca_decoder_put_eof(s->decoder);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to put decoder EOF: %m");

                                if (s->last_chunk_request_nsec == 0)
                                        s->last_chunk_request_nsec = now(CLOCK_MONOTONIC);

                                return CA_SYNC_STEP;
                        }

                        /* Let's check if the chunk size was properly determined. */
                        if (s->next_chunk_size == UINT64_MAX) {
                                log_debug("Couldn't determine chunk size.");
                                return -ESPIPE;
                        }

                        s->next_chunk_valid = true;
                }

                /* If we haven't indexed all seeds yet, then let's not start decoding yet. If we came this far, we know
                 * that the index header has been read at least, hence the seeders can be initialized with the index'
                 * chunk size, hence let's wait for them to complete. */
                if (!ca_sync_seed_ready(s))
                        return CA_SYNC_POLL;

                if (s->first_chunk_request_nsec == 0)
                        s->first_chunk_request_nsec = now(CLOCK_MONOTONIC);

                r = ca_sync_get(s, &s->next_chunk, CA_CHUNK_UNCOMPRESSED, &p, &chunk_size, NULL, &origin);
                if (r == -EAGAIN) /* Don't have this right now, but requested it now */
                        return CA_SYNC_STEP;
                if (r == -EALREADY) /* Don't have this right now, but it was already enqueued. */
                        return CA_SYNC_POLL;
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire chunk: %m");
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
                                log_debug("Skip size larger than chunk. (%" PRIu64 " vs. %" PRIu64 ")", s->chunk_skip, chunk_size);
                                return -EINVAL;
                        }

                        p = (const uint8_t*) p + s->chunk_skip;
                        chunk_size -= s->chunk_skip;

                        s->chunk_skip = 0;
                }

                r = ca_decoder_put_data(s->decoder, p, chunk_size, origin);
                ca_origin_unref(origin);
                if (r < 0)
                        return log_debug_errno(r, "Decoder didn't accept chunk: %m");

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
                        return log_debug_errno(errno, "Failed to read archive: %m");

                assert((size_t) n <= BUFFER_SIZE);

                if (n == 0) {

                        r = ca_decoder_put_eof(s->decoder);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to put decoder EOF: %m");

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

static void ca_sync_reset_seek(CaSync *s) {
        assert(s);

        s->archive_eof = false;
        s->remote_index_eof = false;
        s->next_chunk_valid = false;
        s->chunk_skip = 0;
}

static int ca_sync_process_decoder_seek(CaSync *s) {
        uint64_t offset;
        int r;

        assert(s);
        assert(s->decoder);

        ca_sync_reset_seek(s);

        r = ca_decoder_get_seek_offset(s->decoder, &offset);
        if (r < 0)
                return log_debug_errno(r, "Failed to get seek offset: %m");

        if (s->index) {
                r = ca_index_seek(s->index, offset, &s->chunk_skip);
                if (r < 0)
                        return log_debug_errno(r, "Failed to seek in index: %m");

        } else if (s->archive_fd >= 0) {
                off_t f;

                f = lseek(s->archive_fd, (off_t) offset, SEEK_SET);
                if (f == (off_t) -1)
                        return log_debug_errno(errno, "Failed to seek in archive: %m");

        } else
                return -EOPNOTSUPP;

        return CA_SYNC_STEP;
}

static int ca_sync_process_decoder_skip(CaSync *s) {
        uint64_t size;
        int r;

        assert(s);
        assert(s->decoder);

        r = ca_decoder_get_skip_size(s->decoder, &size);
        if (r < 0)
                return r;

        if (s->index) {

                if (s->chunk_skip + size < s->chunk_skip)
                        return -EOVERFLOW;

                s->chunk_skip += size;

        } else if (s->archive_fd >= 0) {

                r = skip_bytes_fd(s->archive_fd, size);
                if (r < 0)
                        return r;
        } else
                return -EOPNOTSUPP;

        return CA_SYNC_STEP;
}

static int ca_sync_try_hardlink(CaSync *s) {
        CaChunkID digest;
        mode_t mode;
        size_t i;
        int r;

        assert(s);

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;
        if (!s->hardlink)
                return 0;
        if (s->n_seeds == 0)
                return 0;

        r = ca_decoder_current_mode(s->decoder, &mode);
        if (r < 0)
                return r;
        if (!S_ISREG(mode))
                return r;

        r = ca_decoder_get_hardlink_digest(s->decoder, &digest);
        if (r < 0)
                return r;

        for (i = 0; i < s->n_seeds; i++) {
                CaFileRoot *root;
                char *p;

                r = ca_seed_get_hardlink_target(s->seeds[i], &digest, &p);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                r = ca_seed_get_file_root(s->seeds[i], &root);
                if (r < 0) {
                        free(p);
                        return r;
                }

                r = ca_decoder_try_hardlink(s->decoder, root, p);
                free(p);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
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
                return log_debug_errno(step, "Failed to run decoder step: %m");

        switch (step) {

        case CA_DECODER_FINISHED:

                r = ca_sync_install_base(s);
                if (r < 0)
                        return r;

                s->archive_eof = true;

                return CA_SYNC_FINISHED;

        case CA_DECODER_NEXT_FILE:
                return CA_SYNC_NEXT_FILE;

        case CA_DECODER_DONE_FILE:
                r = ca_sync_try_hardlink(s);
                if (r < 0)
                        return r;

                return CA_SYNC_DONE_FILE;

        case CA_DECODER_STEP:
                return CA_SYNC_STEP;

        case CA_DECODER_PAYLOAD:
                return CA_SYNC_PAYLOAD;

        case CA_DECODER_REQUEST:
                return ca_sync_process_decoder_request(s);

        case CA_DECODER_SEEK:
                return ca_sync_process_decoder_seek(s);

        case CA_DECODER_SKIP:
                return ca_sync_process_decoder_skip(s);

        case CA_DECODER_FOUND:
                return CA_SYNC_FOUND;

        case CA_DECODER_NOT_FOUND:
                return CA_SYNC_NOT_FOUND;

        default:
                assert(false);
        }
}

static CaSeed *ca_sync_current_seed(CaSync *s) {
        assert(s);

        if (!ca_sync_shall_seed(s))
                return NULL;

        if (s->current_seed >= s->n_seeds)
                return NULL;

        return s->seeds[s->current_seed];
}

static int ca_sync_seed_step(CaSync *s) {
        int r;

        assert(s);

        if (!ca_sync_shall_seed(s))
                return CA_SYNC_POLL;

        if (s->index && !s->index_flags_propagated) /* Index flags/chunk sizes not propagated to the seeds yet. Let's wait until then */
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

                case CA_SEED_DONE_FILE:
                        return CA_SYNC_SEED_DONE_FILE;

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

        if (saved > 0) {
                /* Let's not just seek back to where we came from, but one earlier, and read it again, so that the
                 * previous offset is known, so that the size of the next chunk can be determined properly */

                r = ca_index_set_position(s->index, saved-1);
                if (r < 0)
                        return r;

                r = ca_index_read_chunk(s->index, NULL, NULL, NULL);
        } else
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
        uint64_t l;
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

static int ca_sync_propagate_flags_to_stores(CaSync *s, uint64_t flags) {
        CaDigestType dtype;
        size_t i;
        int r;

        dtype = ca_feature_flags_to_digest_type(flags);
        if (dtype < 0)
                return -EINVAL;

        if (s->wstore) {
                r = ca_store_set_digest_type(s->wstore, dtype);
                if (r < 0)
                        return r;
        }

        for (i = 0; i < s->n_rstores; i++) {
                r = ca_store_set_digest_type(s->rstores[i], dtype);
                if (r < 0)
                        return r;
        }

        if (s->cache_store) {
                r = ca_store_set_digest_type(s->cache_store, dtype);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ca_sync_propagate_flags_to_seeds(CaSync *s, uint64_t flags, size_t cmin, size_t cavg, size_t cmax) {
        size_t i;
        int r;

        assert(s);

        for (i = 0; i < s->n_seeds; i++) {

                r = ca_seed_set_feature_flags(s->seeds[i], flags);
                if (r < 0)
                        return r;

                r = ca_seed_set_chunk_size(s->seeds[i], cmin, cavg, cmax);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ca_sync_propagate_flags_to_remotes(CaSync *s, uint64_t flags) {
        CaDigestType dtype;
        size_t i;
        int r;

        dtype = ca_feature_flags_to_digest_type(flags);
        if (dtype < 0)
                return -EINVAL;

        if (s->remote_archive) {
                r = ca_remote_set_digest_type(s->remote_archive, dtype);
                if (r < 0)
                        return r;
        }

        if (s->remote_index) {
                r = ca_remote_set_digest_type(s->remote_index, dtype);
                if (r < 0)
                        return r;
        }

        if (s->remote_wstore) {
                r = ca_remote_set_digest_type(s->remote_wstore, dtype);
                if (r < 0)
                        return r;
        }

        for (i = 0; i < s->n_remote_rstores; i++) {
                r = ca_remote_set_digest_type(s->remote_rstores[i], dtype);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ca_sync_propagate_flags_to_decoder(CaSync *s, uint64_t flags) {
        assert(s);

        if (!s->decoder)
                return 0;

        return ca_decoder_set_expected_feature_flags(s->decoder, flags);
}

static int ca_sync_propagate_index_flags(CaSync *s) {
        size_t cmin, cavg, cmax;
        uint64_t flags;
        int r;

        assert(s);

        /* If we read the header of the index file, make sure to propagate the flags and chunk size stored in it to the
         * seeds and remotes. */

        if (s->direction != CA_SYNC_DECODE)
                return CA_SYNC_POLL;

        if (!s->index || s->index_flags_propagated) /* The flags/chunk size is already propagated */
                return CA_SYNC_POLL;

        r = ca_index_get_feature_flags(s->index, &flags);
        if (r == -ENODATA) /* haven't read enough from the index header yet, let's wait */
                return CA_SYNC_POLL;

        r = ca_index_get_chunk_size_min(s->index, &cmin);
        if (r < 0)
                return r;

        r = ca_index_get_chunk_size_avg(s->index, &cavg);
        if (r < 0)
                return r;

        r = ca_index_get_chunk_size_max(s->index, &cmax);
        if (r < 0)
                return r;

        r = ca_sync_propagate_flags_to_stores(s, flags);
        if (r < 0)
                return r;

        r = ca_sync_propagate_flags_to_seeds(s, flags, cmin, cavg, cmax);
        if (r < 0)
                return r;

        r = ca_sync_propagate_flags_to_remotes(s, flags);
        if (r < 0)
                return r;

        r = ca_sync_propagate_flags_to_decoder(s, flags);
        if (r < 0)
                return r;

        s->index_flags_propagated = true;
        return CA_SYNC_STEP;
}

int ca_sync_step(CaSync *s) {
        int r;

        if (!s)
                return -EINVAL;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        r = ca_sync_propagate_index_flags(s);
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
                uint64_t *ret_size,
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
                        log_debug("Chunk cache is not up-to-date, ignoring.");
                        continue;
                }
                if (r == -ENOLINK) {
                        log_debug("Can't reproduce name table for GOODBYE record, ignoring.");
                        continue;
                }
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire chunk from seed: %m");

                if (desired_compression == CA_CHUNK_COMPRESSED) {
                        realloc_buffer_empty(&s->compress_buffer);

                        r = ca_compress(s->compression_type, p, l, &s->compress_buffer);
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
                uint64_t *ret_size,
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

int ca_sync_get_archive_digest(CaSync *s, CaChunkID *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->archive_digest)
                return -ENOMEDIUM;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_get_archive_digest(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_get_archive_digest(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_get_payload_digest(CaSync *s, CaChunkID *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->payload_digest)
                return -ENOMEDIUM;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_get_payload_digest(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_get_payload_digest(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_get_hardlink_digest(CaSync *s, CaChunkID *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!s->hardlink_digest)
                return -ENOMEDIUM;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_get_hardlink_digest(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_get_hardlink_digest(s->decoder, ret);

        return -ENOTTY;
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

int ca_sync_current_chattr(CaSync *s, unsigned *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_chattr(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_chattr(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_fat_attrs(CaSync *s, uint32_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_fat_attrs(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_fat_attrs(s->decoder, ret);

        return -ENOTTY;
}

int ca_sync_current_xattr(CaSync *s, CaIterate where, const char **ret_name, const void **ret_value, size_t *ret_size) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret_name)
                return -EINVAL;
        if (where < 0 || where > _CA_ITERATE_MAX)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_xattr(s->encoder, where, ret_name, ret_value, ret_size);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_xattr(s->decoder, where, ret_name, ret_value, ret_size);

        return -ENOTTY;
}

int ca_sync_current_quota_projid(CaSync *s, uint32_t *ret) {
        CaSeed *seed;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        seed = ca_sync_current_seed(s);
        if (seed)
                return -ENODATA;

        if (s->direction == CA_SYNC_ENCODE && s->encoder)
                return ca_encoder_current_quota_projid(s->encoder, ret);
        if (s->direction == CA_SYNC_DECODE && s->decoder)
                return ca_decoder_current_quota_projid(s->decoder, ret);

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

int ca_sync_poll(CaSync *s, uint64_t timeout_nsec, const sigset_t *ss) {
        struct pollfd *pollfd;
        size_t i, n = 0, n_pollfd;
        int r;

        if (!s)
                return -EINVAL;

        n_pollfd = (!!s->remote_archive
                    + !!s->remote_index
                    + !!s->remote_wstore
                    + s->n_remote_rstores) * 2;

        if (n_pollfd == 0)
                return -EUNATCH;

        pollfd = newa(struct pollfd, n_pollfd);

        r = ca_sync_add_pollfd(s->remote_archive, pollfd);
        if (r < 0)
                return r;
        n += r;

        r = ca_sync_add_pollfd(s->remote_index, pollfd + n);
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
        assert_se(n == n_pollfd);

        if (timeout_nsec != UINT64_MAX) {
                struct timespec ts;

                ts = nsec_to_timespec(timeout_nsec);

                r = ppoll(pollfd, n, &ts, ss);
        } else
                r = ppoll(pollfd, n, NULL, ss);
        if (r < 0)
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
        if (!s->wstore && !s->cache_store && !s->index)
                return -ENODATA;

        *ret = s->n_written_chunks;
        return 0;
}

int ca_sync_current_archive_reused_chunks(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_ENCODE)
                return -ENODATA;
        if (!s->wstore) /* we can count this only on local wstores */
                return -ENODATA;

        *ret = s->n_reused_chunks;
        return 0;
}

int ca_sync_current_archive_offset(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->encoder)
                return ca_encoder_current_archive_offset(s->encoder, ret);

        if (s->decoder)
                return ca_decoder_current_archive_offset(s->decoder, ret);

        return -ENOTTY;
}

static int ca_sync_acquire_archive_size(CaSync *s) {
        int r;

        assert(s);

        /* Makes sure the decoder knows how large the archive is. This is a requirement for working seeks, as the seek
         * tables are located at the end of archives */

        if (s->archive_size != UINT64_MAX)
                return 0;

        if (s->archive_fd >= 0) {
                struct stat st;

                if (fstat(s->archive_fd, &st) < 0)
                        return -errno;

                if (!S_ISREG(st.st_mode))
                        return -ESPIPE;

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

        return 1;
}

int ca_sync_seek_offset(CaSync *s, uint64_t offset) {
        int r;

        if (!s)
                return -EINVAL;
        if (offset == UINT64_MAX)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        if (!s->decoder)
                return -ESPIPE;

        r = ca_sync_acquire_archive_size(s);
        if (r < 0)
                return r;

        r = ca_decoder_seek_offset(s->decoder, offset);
        if (r < 0)
                return r;

        ca_sync_reset_seek(s);

        return 0;
}

int ca_sync_seek_path_offset(CaSync *s, const char *path, uint64_t offset) {
        int r;

        if (!s)
                return -EINVAL;
        if (!path)
                return -EINVAL;
        if (offset == UINT64_MAX)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        if (!s->decoder)
                return -ESPIPE;

        r = ca_sync_acquire_archive_size(s);
        if (r < 0)
                return r;

        r = ca_decoder_seek_path_offset(s->decoder, path, offset);
        if (r < 0)
                return r;

        ca_sync_reset_seek(s);

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

        r = ca_sync_acquire_archive_size(s);
        if (r < 0)
                return r;

        r = ca_decoder_seek_path(s->decoder, path);
        if(r < 0)
                return r;

        ca_sync_reset_seek(s);

        return 0;
}

int ca_sync_seek_next_sibling(CaSync *s) {
        int r;

        if (!s)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        if (!s->decoder)
                return -ESPIPE;

        r = ca_sync_acquire_archive_size(s);
        if (r < 0)
                return r;

        r = ca_decoder_seek_next_sibling(s->decoder);
        if(r < 0)
                return r;

        ca_sync_reset_seek(s);

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
                return ca_encoder_get_data(s->encoder, UINT64_MAX, ret, ret_size);

        return -ENOTTY;
}

int ca_sync_get_archive_size(CaSync *s, uint64_t *ret_size) {
        int r;

        if (!s)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        r = ca_sync_start(s);
        if (r < 0)
                return r;

        if (!s->decoder)
                return -ESPIPE;

        r = ca_sync_acquire_archive_size(s);
        if (r < 0)
                return r;

        *ret_size = s->archive_size;
        return 0;
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

int ca_sync_get_hardlink_bytes(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_DECODE)
                return -ENOTTY;

        if (!s->hardlink)
                return -ENODATA;

        if (!s->decoder) {
                *ret = 0;
                return 0;
        }

        return ca_decoder_get_hardlink_bytes(s->decoder, ret);
}

int ca_sync_enable_archive_digest(CaSync *s, bool b) {
        int r;

        if (!s)
                return -EINVAL;
        if (s->archive_digest == b)
                return 0;

        if (s->encoder) {
                r = ca_encoder_enable_archive_digest(s->encoder, b);
                if (r < 0)
                        return r;
        }

        if (s->decoder) {
                r = ca_decoder_enable_archive_digest(s->decoder, b);
                if (r < 0)
                        return r;
        }

        s->archive_digest = b;
        return 1;
}

int ca_sync_enable_payload_digest(CaSync *s, bool b) {
        int r;

        if (!s)
                return -EINVAL;

        if (s->payload_digest == b)
                return 0;

        if (s->encoder) {
                r = ca_encoder_enable_payload_digest(s->encoder, b);
                if (r < 0)
                        return r;
        }

        if (s->decoder) {
                r = ca_decoder_enable_payload_digest(s->decoder, b);
                if (r < 0)
                        return r;
        }

        s->payload_digest = b;
        return 1;
}

int ca_sync_enable_hardlink_digest(CaSync *s, bool b) {
        int r;

        if (!s)
                return -EINVAL;

        if (s->hardlink_digest == b)
                return 0;

        if (s->encoder) {
                r = ca_encoder_enable_hardlink_digest(s->encoder, b);
                if (r < 0)
                        return r;
        }

        if (s->decoder) {
                r = ca_decoder_enable_hardlink_digest(s->decoder, b || s->hardlink);
                if (r < 0)
                        return r;
        }

        s->hardlink_digest = b;
        return 1;
}

int ca_sync_get_seed_requests(CaSync *s, uint64_t *ret) {
        uint64_t sum = 0;
        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        for (i = 0; i < s->n_seeds; i++) {
                uint64_t x;

                r = ca_seed_get_requests(s->seeds[i], &x);
                if (r < 0)
                        return r;

                sum += x;
        }

        *ret = sum;
        return 0;
}

int ca_sync_get_seed_request_bytes(CaSync *s, uint64_t *ret) {
        uint64_t sum = 0;
        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        for (i = 0; i < s->n_seeds; i++) {
                uint64_t x;

                r = ca_seed_get_request_bytes(s->seeds[i], &x);
                if (r < 0)
                        return r;

                sum += x;
        }

        *ret = sum;
        return 0;
}

int ca_sync_get_seed_seeding_time_nsec(CaSync *s, uint64_t *ret) {
        uint64_t sum = 0;
        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        /* We can sum seeding times since seeds are processed one after another */
        for (i = 0; i < s->n_seeds; i++) {
                uint64_t x;

                r = ca_seed_get_seeding_time_nsec(s->seeds[i], &x);
                if (r < 0)
                        return r;

                sum += x;
        }

        *ret = sum;
        return 0;
}

int ca_sync_get_local_requests(CaSync *s, uint64_t *ret) {
        uint64_t sum;
        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->wstore) {
                r = ca_store_get_requests(s->wstore, &sum);
                if (r < 0)
                        return r;
        } else
                sum = 0;

        for (i = 0; i < s->n_rstores; i++) {
                uint64_t x;

                r = ca_store_get_requests(s->rstores[i], &x);
                if (r < 0)
                        return r;

                sum += x;
        }

        *ret = sum;
        return 0;
}

int ca_sync_get_local_request_bytes(CaSync *s, uint64_t *ret) {
        uint64_t sum;
        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->wstore) {
                r = ca_store_get_request_bytes(s->wstore, &sum);
                if (r < 0)
                        return r;
        } else
                sum = 0;

        for (i = 0; i < s->n_rstores; i++) {
                uint64_t x;

                r = ca_store_get_request_bytes(s->rstores[i], &x);
                if (r < 0)
                        return r;

                sum += x;
        }

        *ret = sum;
        return 0;
}

int ca_sync_get_remote_requests(CaSync *s, uint64_t *ret) {
        uint64_t sum;
        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->remote_wstore) {
                r = ca_remote_get_requests(s->remote_wstore, &sum);
                if (r < 0)
                        return r;
        } else
                sum = 0;

        for (i = 0; i < s->n_remote_rstores; i++) {
                uint64_t x;

                r = ca_remote_get_requests(s->remote_rstores[i], &x);
                if (r < 0)
                        return r;

                sum += x;
        }

        *ret = sum;
        return 0;
}

int ca_sync_get_remote_request_bytes(CaSync *s, uint64_t *ret) {
        uint64_t sum;
        size_t i;
        int r;

        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->remote_wstore) {
                r = ca_remote_get_request_bytes(s->remote_wstore, &sum);
                if (r < 0)
                        return r;
        } else
                sum = 0;

        for (i = 0; i < s->n_remote_rstores; i++) {
                uint64_t x;

                r = ca_remote_get_request_bytes(s->remote_rstores[i], &x);
                if (r < 0)
                        return r;

                sum += x;
        }

        *ret = sum;
        return 0;
}

int ca_sync_get_decoding_time_nsec(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->first_chunk_request_nsec == 0 || s->last_chunk_request_nsec == 0)
                return -ENODATA;
        if (s->first_chunk_request_nsec > s->last_chunk_request_nsec)
                return -ENODATA;

        *ret = s->last_chunk_request_nsec - s->first_chunk_request_nsec;
        return 0;
}

int ca_sync_get_runtime_nsec(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->start_nsec == 0)
                return -ENODATA;

        *ret = now(CLOCK_MONOTONIC) - s->start_nsec;
        return 0;
}

int ca_sync_set_compression_type(CaSync *s, CaCompressionType compression) {
        if (!s)
                return -EINVAL;
        if (compression < 0)
                return -EINVAL;
        if (compression >= _CA_COMPRESSION_TYPE_MAX)
                return -EOPNOTSUPP;
        if (CA_SYNC_IS_STARTED(s))
                return -EBUSY;

        s->compression_type = compression;
        return 0;
}

int ca_sync_current_cache_hits(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_ENCODE)
                return -ENODATA;
        if (!s->cache)
                return -ENODATA;

        *ret = s->n_cache_hits;
        return 0;
}

int ca_sync_current_cache_misses(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_ENCODE)
                return -ENODATA;
        if (!s->cache)
                return -ENODATA;

        *ret = s->n_cache_misses;
        return 0;
}

int ca_sync_current_cache_invalidated(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_ENCODE)
                return -ENODATA;
        if (!s->cache)
                return -ENODATA;

        *ret = s->n_cache_invalidated;
        return 0;
}

int ca_sync_current_cache_added(CaSync *s, uint64_t *ret) {
        if (!s)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (s->direction != CA_SYNC_ENCODE)
                return -ENODATA;
        if (!s->cache)
                return -ENODATA;

        *ret = s->n_cache_added;
        return 0;
}
