#ifndef fooca_synchfoo
#define fooca_synchfoo

#include <inttypes.h>
#include <signal.h>

#include "cachunk.h"
#include "cachunkid.h"
#include "caorigin.h"

typedef struct CaSync CaSync;

enum {
        CA_SYNC_FINISHED,        /* Synchronization is complete */
        CA_SYNC_STEP,            /* Did something, call me again soon! */
        CA_SYNC_PAYLOAD,         /* Did something, and there's payload you might want to read */
        CA_SYNC_NEXT_FILE,       /* Started synchronizing a new file, find out which one with ca_sync_current_path() */
        CA_SYNC_DONE_FILE,       /* Done synchronizing a file, find out which one with ca_sync_current_path() */
        CA_SYNC_SEED_NEXT_FILE,  /* Started indexing a new file as seed, find out which one with ca_sync_current_path() */
        CA_SYNC_SEED_DONE_FILE,  /* Finished indexing a file as seed, find out which one with ca_sync_current_path() */
        CA_SYNC_POLL,            /* Can't proceed with remote feedback, please use ca_sync_poll() to wait for it */
        CA_SYNC_FOUND,           /* Entry looked for was found and is read next */
        CA_SYNC_NOT_FOUND,       /* Entry you were looking for couldn't be found */
};

CaSync *ca_sync_new_encode(void);
CaSync *ca_sync_new_decode(void);
CaSync *ca_sync_unref(CaSync *sync);

int ca_sync_set_rate_limit_bps(CaSync *s, size_t rate_limit_bps);

int ca_sync_set_feature_flags(CaSync *s, uint64_t flags);
int ca_sync_get_feature_flags(CaSync *s, uint64_t *ret);
int ca_sync_get_covering_feature_flags(CaSync *s, uint64_t *ret);

int ca_sync_set_punch_holes(CaSync *s, bool enabled);
int ca_sync_set_reflink(CaSync *s, bool enabled);
int ca_sync_set_delete(CaSync *s, bool enabled);
int ca_sync_set_payload(CaSync *s, bool enabled);
int ca_sync_set_undo_immutable(CaSync *s, bool enabled);

int ca_sync_set_uid_shift(CaSync *s, uid_t uid);
int ca_sync_set_uid_range(CaSync *s, uid_t uid);

/* Mode mask to use for created archive or index files */
int ca_sync_set_make_mode(CaSync *sync, mode_t mode);

/* The index file, that contains the hashes + offsets */
int ca_sync_set_index_fd(CaSync *sync, int fd);
int ca_sync_set_index_path(CaSync *sync, const char *path);
int ca_sync_set_index_remote(CaSync *sync, const char *url);
int ca_sync_set_index_auto(CaSync *s, const char *locator);

/* The raw, unarchived ("user") tree */
int ca_sync_set_base_fd(CaSync *sync, int fd);
int ca_sync_set_base_path(CaSync *sync, const char *path);
int ca_sync_set_base_mode(CaSync *sync, mode_t mode);

/* The raw, unarchived ("user") "boundary" tree, in case seeking is used */
int ca_sync_set_boundary_fd(CaSync *sync, int fd);
int ca_sync_set_boundary_path(CaSync *sync, const char *path);

/* The serialization of the user tree */
int ca_sync_set_archive_fd(CaSync *sync, int fd);
int ca_sync_set_archive_path(CaSync *sync, const char *path);
int ca_sync_set_archive_remote(CaSync *sync, const char *url);
int ca_sync_set_archive_auto(CaSync *sync, const char *url);

/* The store to place data in (i.e. the "primary" store) */
int ca_sync_set_store_path(CaSync *sync, const char *path);
int ca_sync_set_store_remote(CaSync *sync, const char *url);
int ca_sync_set_store_auto(CaSync *s, const char *locator);

/* Additional stores to use */
int ca_sync_add_store_path(CaSync *sync, const char *path);
int ca_sync_add_store_remote(CaSync *sync, const char *url);
int ca_sync_add_store_auto(CaSync *sync, const char *locator);

/* Additional seeds to use */
int ca_sync_add_seed_fd(CaSync *sync, int fd);
int ca_sync_add_seed_path(CaSync *sync, const char *path);

int ca_sync_step(CaSync *sync);
int ca_sync_poll(CaSync *s, uint64_t timeout_nsec, const sigset_t *ss);

int ca_sync_current_path(CaSync *sync, char **ret);
int ca_sync_current_mode(CaSync *sync, mode_t *ret);
int ca_sync_current_target(CaSync *sync, const char **ret);
int ca_sync_current_uid(CaSync *sync, uid_t *ret);
int ca_sync_current_gid(CaSync *sync, gid_t *ret);
int ca_sync_current_user(CaSync *sync, const char **ret);
int ca_sync_current_group(CaSync *sync, const char **ret);
int ca_sync_current_mtime(CaSync *sync, uint64_t *nsec);
int ca_sync_current_size(CaSync *sync, uint64_t *ret);
int ca_sync_current_rdev(CaSync *sync, dev_t *ret);
int ca_sync_current_chattr(CaSync *sync, unsigned *ret);

int ca_sync_get_digest(CaSync *s, CaChunkID *ret);
int ca_sync_get_archive_size(CaSync *s, uint64_t *ret);

/* Low level chunk access */
int ca_sync_get_local(CaSync *s, const CaChunkID *chunk_id, CaChunkCompression desired_compression, const void **ret, size_t *ret_size, CaChunkCompression *ret_effective_compression, CaOrigin **ret_origin);
int ca_sync_get(CaSync *s, const CaChunkID *chunk_id, CaChunkCompression desired_compression, const void **ret, size_t *ret_size, CaChunkCompression *ret_effective_compression, CaOrigin **ret_origin);
int ca_sync_has_local(CaSync *s, const CaChunkID *chunk_id);

int ca_sync_make_chunk_id(CaSync *s, const void *p, size_t l, CaChunkID *ret);

int ca_sync_set_chunk_size_avg(CaSync *s, size_t avg);

int ca_sync_get_chunk_size_avg(CaSync *s, size_t *ret);
int ca_sync_get_chunk_size_min(CaSync *s, size_t *ret);
int ca_sync_get_chunk_size_max(CaSync *s, size_t *ret);

int ca_sync_current_archive_chunks(CaSync *s, uint64_t *ret);
int ca_sync_current_archive_reused_chunks(CaSync *s, uint64_t *ret);
int ca_sync_current_archive_offset(CaSync *s, uint64_t *ret);

int ca_sync_seek_offset(CaSync *s, uint64_t offset);
int ca_sync_seek_path(CaSync *s, const char *path);
int ca_sync_seek_path_offset(CaSync *s, const char *path, uint64_t offset);
int ca_sync_seek_next_sibling(CaSync *s);

int ca_sync_get_payload(CaSync *s, const void **ret, size_t *ret_size);

int ca_sync_get_punch_holes_bytes(CaSync *s, uint64_t *ret);
int ca_sync_get_reflink_bytes(CaSync *s, uint64_t *ret);

#endif
