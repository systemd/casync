/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocaremotehfoo
#define foocaremotehfoo

#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>

#include "cachunk.h"
#include "cachunkid.h"

typedef struct CaRemote CaRemote;

enum {
        CA_REMOTE_POLL,             /* Nothing to do, sleep with ca_remote_poll() please! */
        CA_REMOTE_FINISHED,         /* Done! */
        CA_REMOTE_STEP,             /* Did something, call me again */
        CA_REMOTE_REQUEST,          /* push: Got a REQUEST message, please call ca_remote_next_request() to find out more */
        CA_REMOTE_WRITE_INDEX,      /* push: Please provide index data now, via ca_remote_write_index() */
        CA_REMOTE_WRITE_ARCHIVE,    /* push: Please provide archive data now, via ca_remote_write_archive() */
        CA_REMOTE_CHUNK,            /* pull: Got a CHUNK message, ask me if yours is now with ca_remote_request() */
        CA_REMOTE_READ_INDEX,       /* pull: Got more INDEX data, retrieve it via ca_remote_read_index() */
        CA_REMOTE_READ_INDEX_EOF,   /* pull: INDEX data is now complete */
        CA_REMOTE_READ_ARCHIVE,     /* pull: Got more ARCHIVE data, retrieve it via ca_remote_read_archive() */
        CA_REMOTE_READ_ARCHIVE_EOF, /* pull: ARCHIVE data is now complete */
};

enum {
        CA_REMOTE_ARG_OPERATION = 0,
        CA_REMOTE_ARG_BASE_URL,
        CA_REMOTE_ARG_ARCHIVE_URL,
        CA_REMOTE_ARG_INDEX_URL,
        CA_REMOTE_ARG_WSTORE_URL,   /* This should be last except MAX */
        _CA_REMOTE_ARG_MAX,
};

CaRemote* ca_remote_new(void);
CaRemote* ca_remote_ref(CaRemote *rr);
CaRemote* ca_remote_unref(CaRemote *rr);
static inline void ca_remote_unrefp(CaRemote **rr) {
        ca_remote_unref(*rr);
}

int ca_remote_set_local_feature_flags(CaRemote *rr, uint64_t flags);
int ca_remote_add_local_feature_flags(CaRemote *rr, uint64_t flags);
int ca_remote_get_local_feature_flags(CaRemote *rr, uint64_t* flags);
int ca_remote_get_remote_feature_flags(CaRemote *rr, uint64_t* flags);

int ca_remote_set_digest_type(CaRemote *rr, CaDigestType type);
int ca_remote_get_digest_type(CaRemote *rr, CaDigestType *ret);

int ca_remote_set_log_level(CaRemote *rr, int log_level);
int ca_remote_set_rate_limit_bps(CaRemote *rr, uint64_t rate_limit_bps);
int ca_remote_set_max_active_chunks(CaRemote *rr, unsigned max_active_chunks);

int ca_remote_set_io_fds(CaRemote *rr, int input_fd, int output_fd);
int ca_remote_get_io_fds(CaRemote *rr, int *ret_input_fd, int *ret_output_fd);
int ca_remote_get_io_events(CaRemote *rr, short *ret_input_events, short *ret_output_events);

/* int ca_remote_set_base_url(CaRemote *rr, const char *url); */
int ca_remote_set_archive_url(CaRemote *rr, const char *url);
int ca_remote_set_index_url(CaRemote *rr, const char *url);
int ca_remote_set_store_url(CaRemote *rr, const char *url);
int ca_remote_add_store_url(CaRemote *rr, const char *url);

int ca_remote_set_cache_path(CaRemote *rr, const char *path);
int ca_remote_set_cache_fd(CaRemote *rr, int fd);

int ca_remote_set_index_path(CaRemote *rr, const char *path);
int ca_remote_set_index_fd(CaRemote *rr, int fd);

int ca_remote_set_archive_path(CaRemote *rr, const char *path);
int ca_remote_set_archive_fd(CaRemote *rr, int fd);

int ca_remote_step(CaRemote *rr);

int ca_remote_poll(CaRemote *rr, uint64_t timeout_nsec, const sigset_t *ss);

/* When we are in "pull" mode, interfaces for retrieving chunks, or enqueing requests for them */
int ca_remote_request(CaRemote *rr, const CaChunkID *chunk_id, bool priority, CaChunkCompression desired_compression, const void **ret, uint64_t *ret_size, CaChunkCompression *ret_effective_compression);
int ca_remote_request_async(CaRemote *rr, const CaChunkID *chunk_id, bool priority);
int ca_remote_next_chunk(CaRemote *rr, CaChunkCompression desired_compression, CaChunkID *ret_id, const void **ret_data, size_t *ret_size, CaChunkCompression *ret_compression);

/* When we are in "push" mode, interfaces for processing requests and pushing chunks */
int ca_remote_next_request(CaRemote *rr, CaChunkID *ret);
int ca_remote_can_put_chunk(CaRemote *rr);
int ca_remote_put_chunk(CaRemote *rr, const CaChunkID *chunk_id, CaChunkCompression compression, const void *data, uint64_t size);
int ca_remote_put_missing(CaRemote *rr, const CaChunkID *chunk_id);

/* pull mode: Read index data */
int ca_remote_read_index(CaRemote *rr, const void **ret, size_t *ret_size);

/* pull mode: Read archive data */
int ca_remote_read_archive(CaRemote *rr, const void **ret, size_t *ret_size);

/* push mode: Write index data */
int ca_remote_can_put_index(CaRemote *rr);
int ca_remote_put_index(CaRemote *rr, const void *p, size_t size);
int ca_remote_put_index_eof(CaRemote *rr);

/* push mode: Write archive data */
int ca_remote_can_put_archive(CaRemote *rr);
int ca_remote_put_archive(CaRemote *rr, const void *p, size_t size);
int ca_remote_put_archive_eof(CaRemote *rr);

/* Enqueue a goodbye frame */
int ca_remote_goodbye(CaRemote *rr);
int ca_remote_abort(CaRemote *rr, int error, const char *message);

int ca_remote_has_pending_requests(CaRemote *rr);
int ca_remote_has_unwritten(CaRemote *rr);
int ca_remote_has_chunks(CaRemote *rr);

int ca_remote_forget_chunk(CaRemote *rr, const CaChunkID *id);

int ca_remote_get_requests(CaRemote *rr, uint64_t *ret);
int ca_remote_get_request_bytes(CaRemote *rr, uint64_t *ret);

int ca_remote_set_compression_type(CaRemote *rr, CaCompressionType ct);

#endif
