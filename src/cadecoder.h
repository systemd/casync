#ifndef foocadecoderhfoo
#define foocadecoderhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "calocation.h"
#include "caorigin.h"

typedef struct CaDecoder CaDecoder;

enum {
        CA_DECODER_FINISHED,   /* The end of the stream has been reached */
        CA_DECODER_STEP,       /* We processed a bit, call us again */
        CA_DECODER_REQUEST,    /* We need more data */
        CA_DECODER_NEXT_FILE,  /* We started processing a new file */
        CA_DECODER_PAYLOAD,    /* We have some payload data for you */
        CA_DECODER_SEEK,       /* Please seek */
        CA_DECODER_FOUND,      /* Seek completed successfully */
        CA_DECODER_NOT_FOUND,  /* Seek to file was requested, but file didn't exist */
};

CaDecoder *ca_decoder_new(void);
CaDecoder *ca_decoder_unref(CaDecoder *d);

int ca_decoder_get_feature_flags(CaDecoder *d, uint64_t *ret);

int ca_decoder_set_punch_holes(CaDecoder *d, bool enabled);
int ca_decoder_set_reflink(CaDecoder *d, bool enabled);

/* Output: a file descriptor to a directory tree, block device node, or regular file */
int ca_decoder_set_base_fd(CaDecoder *d, int fd);
int ca_decoder_set_boundary_fd(CaDecoder *d, int fd);

/* Output: if no output to the file system is desired: specify instead what kind of object is to be read */
int ca_decoder_set_base_mode(CaDecoder *d, mode_t mode);

/* Input: set the archive size, to make this seekable */
int ca_decoder_set_archive_size(CaDecoder *d, uint64_t size);

int ca_decoder_step(CaDecoder *d);

/* If ca_decoder_step() returned CA_DECODER_REQUEST, which offset it desired now */
int ca_decoder_get_request_offset(CaDecoder *d, uint64_t *offset);
int ca_decoder_get_seek_offset(CaDecoder *d, uint64_t *ret);

/* Input: archive stream data */
int ca_decoder_put_data(CaDecoder *d, const void *p, size_t size, CaOrigin *origin);
int ca_decoder_put_eof(CaDecoder *d);

/* Output: payload data */
int ca_decoder_get_payload(CaDecoder *d, const void **ret, size_t *ret_size);

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

int ca_decoder_seek_offset(CaDecoder *d, uint64_t offset);
int ca_decoder_seek_path(CaDecoder *d, const char *path);

#endif
