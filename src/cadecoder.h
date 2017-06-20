#ifndef foocadecoderhfoo
#define foocadecoderhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "cachunkid.h"
#include "cacommon.h"
#include "calocation.h"
#include "caorigin.h"

typedef struct CaDecoder CaDecoder;

enum {
        /* Stream events */
        CA_DECODER_FINISHED,   /* The end of the stream has been reached */
        CA_DECODER_STEP,       /* We processed a bit, call us again */
        CA_DECODER_NEXT_FILE,  /* We started processing a new file */
        CA_DECODER_DONE_FILE,  /* We finished processing a file */
        CA_DECODER_PAYLOAD,    /* We have some payload data for you */

        /* Requests to the caller */
        CA_DECODER_REQUEST,    /* We need more data */
        CA_DECODER_SEEK,       /* Please seek */
        CA_DECODER_SKIP,       /* Please skip some bytes */

        /* Response to seeks */
        CA_DECODER_FOUND,      /* Seek completed successfully */
        CA_DECODER_NOT_FOUND,  /* Seek to file was requested, but file didn't exist */
};

CaDecoder *ca_decoder_new(void);
CaDecoder *ca_decoder_unref(CaDecoder *d);

/* The actual feature flags in effect if known */
int ca_decoder_get_feature_flags(CaDecoder *d, uint64_t *ret);

/* Various booleans to configure the mode of operation */
int ca_decoder_set_punch_holes(CaDecoder *d, bool enabled);
int ca_decoder_set_reflink(CaDecoder *d, bool enabled);
int ca_decoder_set_hardlink(CaDecoder *d, bool enabled);
int ca_decoder_set_delete(CaDecoder *d, bool enabled);
int ca_decoder_set_payload(CaDecoder *d, bool enabled);
int ca_decoder_set_undo_immutable(CaDecoder *d, bool enabled);

/* Apply UID shifting */
int ca_decoder_set_uid_shift(CaDecoder *e, uid_t u);
int ca_decoder_set_uid_range(CaDecoder *e, uid_t u);

/* Output: a file descriptor to a directory tree, block device node, or regular file */
int ca_decoder_set_base_fd(CaDecoder *d, int fd);
int ca_decoder_set_boundary_fd(CaDecoder *d, int fd);

/* Output: if no output to the file system is desired: specify instead what kind of object is to be read */
int ca_decoder_set_base_mode(CaDecoder *d, mode_t mode);

/* Input: set the archive size, to make this seekable */
int ca_decoder_set_archive_size(CaDecoder *d, uint64_t size);

/* The core of loop, returns one of the CA_DECODER_XYZ events defined above */
int ca_decoder_step(CaDecoder *d);

/* If ca_decoder_step() returned CA_DECODER_REQUEST, which offset we are at now */
int ca_decoder_get_request_offset(CaDecoder *d, uint64_t *offset);

/* If ca_decoder_step() returned CA_DECODER_SEEK, where are we supposed to seek now? (returns absolute position) */
int ca_decoder_get_seek_offset(CaDecoder *d, uint64_t *ret);

/* If ca_decoder_step() returned CA_DECODER_SKIP, how many bytes are we supposed to skip? (returns relative number of bytes) */
int ca_decoder_get_skip_size(CaDecoder *d, uint64_t *ret);

/* Input: archive stream data */
int ca_decoder_put_data(CaDecoder *d, const void *p, size_t size, CaOrigin *origin);
int ca_decoder_put_eof(CaDecoder *d);

/* Output: payload data */
int ca_decoder_get_payload(CaDecoder *d, const void **ret, size_t *ret_size);

/* Retrieve information about where we currently are */
int ca_decoder_current_path(CaDecoder *d, char **ret);
int ca_decoder_current_mode(CaDecoder *d, mode_t *ret);
int ca_decoder_current_target(CaDecoder *d, const char **ret);
int ca_decoder_current_mtime(CaDecoder *d, uint64_t *nsec);
int ca_decoder_current_size(CaDecoder *d, uint64_t *size);
int ca_decoder_current_uid(CaDecoder *d, uid_t *uid);
int ca_decoder_current_gid(CaDecoder *d, gid_t *gid);
int ca_decoder_current_user(CaDecoder *d, const char **user);
int ca_decoder_current_group(CaDecoder *d, const char **user);
int ca_decoder_current_rdev(CaDecoder *d, dev_t *ret);
int ca_decoder_current_offset(CaDecoder *d, uint64_t *ret);
int ca_decoder_current_chattr(CaDecoder *d, int *ret);
int ca_decoder_current_fat_attrs(CaDecoder *d, uint32_t *ret);
int ca_decoder_current_xattr(CaDecoder *d, CaIterate where, const char **ret_name, const void **ret_value, size_t *ret_size);

/* Seeking to positions */
int ca_decoder_seek_offset(CaDecoder *d, uint64_t offset);
int ca_decoder_seek_path(CaDecoder *d, const char *path);
int ca_decoder_seek_path_offset(CaDecoder *d, const char *path, uint64_t offset);
int ca_decoder_seek_next_sibling(CaDecoder *d);

/* Statistics */
int ca_decoder_get_punch_holes_bytes(CaDecoder *d, uint64_t *ret);
int ca_decoder_get_reflink_bytes(CaDecoder *d, uint64_t *ret);
int ca_decoder_get_hardlink_bytes(CaDecoder *d, uint64_t *ret);

int ca_decoder_current_archive_offset(CaDecoder *d, uint64_t *ret);

int ca_decoder_enable_archive_digest(CaDecoder *d, bool b);
int ca_decoder_enable_payload_digest(CaDecoder *d, bool b);
int ca_decoder_enable_hardlink_digest(CaDecoder *d, bool b);

int ca_decoder_get_archive_digest(CaDecoder *d, CaChunkID *ret);
int ca_decoder_get_hardlink_digest(CaDecoder *d, CaChunkID *ret);
int ca_decoder_get_payload_digest(CaDecoder *d, CaChunkID *ret);

int ca_decoder_try_hardlink(CaDecoder *d, CaFileRoot *root, const char *path);

#endif
