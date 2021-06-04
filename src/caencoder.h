/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocaencoderhfoo
#define foocaencoderhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "cachunkid.h"
#include "cacommon.h"
#include "calocation.h"

typedef struct CaEncoder CaEncoder;

enum {
        CA_ENCODER_FINISHED,  /* The end of the stream has been reached */
        CA_ENCODER_NEXT_FILE, /* We started with the next file, and we generated some data */
        CA_ENCODER_DONE_FILE, /* We finished with some file, and possibly generated some data */
        CA_ENCODER_PAYLOAD,   /* We just read some payload data, and we generated some data */
        CA_ENCODER_DATA,      /* We generated some data */
};

CaEncoder *ca_encoder_new(void);
CaEncoder *ca_encoder_unref(CaEncoder *e);

int ca_encoder_set_feature_flags(CaEncoder *e, uint64_t flags);
int ca_encoder_get_feature_flags(CaEncoder *e, uint64_t *ret);

int ca_encoder_get_covering_feature_flags(CaEncoder *e, uint64_t *ret);

int ca_encoder_set_uid_shift(CaEncoder *e, uid_t u);
int ca_encoder_set_uid_range(CaEncoder *e, uid_t u);

/* Input: a directory tree, block device node or regular file */
int ca_encoder_set_base_fd(CaEncoder *e, int fd);
int ca_encoder_get_base_fd(CaEncoder *e);

/* Path to exclude filter */
int ca_encoder_set_exclude_from(CaEncoder *e, const char *path);

int ca_encoder_step(CaEncoder *e);

/* Output: archive stream data */
int ca_encoder_get_data(CaEncoder *e, uint64_t suggested_size, const void **ret, size_t *ret_size);

int ca_encoder_current_path(CaEncoder *e, char **ret);
int ca_encoder_current_mode(CaEncoder *d, mode_t *ret);
int ca_encoder_current_target(CaEncoder *e, const char **ret);
int ca_encoder_current_mtime(CaEncoder *e, uint64_t *nsec);
int ca_encoder_current_size(CaEncoder *e, uint64_t *size);
int ca_encoder_current_uid(CaEncoder *e, uid_t *ret);
int ca_encoder_current_gid(CaEncoder *e, gid_t *ret);
int ca_encoder_current_user(CaEncoder *e, const char **ret);
int ca_encoder_current_group(CaEncoder *e, const char **ret);
int ca_encoder_current_rdev(CaEncoder *e, dev_t *ret);
int ca_encoder_current_chattr(CaEncoder *e, unsigned *ret);
int ca_encoder_current_fat_attrs(CaEncoder *e, uint32_t *ret);
int ca_encoder_current_xattr(CaEncoder *e, CaIterate where, const char **ret_name, const void **ret_value, size_t *ret_size);
int ca_encoder_current_quota_projid(CaEncoder *e, uint32_t *ret);

int ca_encoder_current_payload_offset(CaEncoder *e, uint64_t *ret);
int ca_encoder_current_archive_offset(CaEncoder *e, uint64_t *ret);

int ca_encoder_current_location(CaEncoder *e, uint64_t add, CaLocation **ret);

int ca_encoder_seek_location(CaEncoder *e, CaLocation *location);

int ca_encoder_enable_archive_digest(CaEncoder *e, bool b);
int ca_encoder_enable_payload_digest(CaEncoder *e, bool b);
int ca_encoder_enable_hardlink_digest(CaEncoder *e, bool b);

int ca_encoder_get_archive_digest(CaEncoder *e, CaChunkID *ret);
int ca_encoder_get_hardlink_digest(CaEncoder *e, CaChunkID *ret);
int ca_encoder_get_payload_digest(CaEncoder *e, CaChunkID *ret);

#endif
