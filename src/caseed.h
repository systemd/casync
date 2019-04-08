/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocaseedhfoo
#define foocaseedhfoo

#include <sys/types.h>

#include "cachunkid.h"
#include "caorigin.h"

typedef struct CaSeed CaSeed;

enum {
        CA_SEED_READY     = 0,
        CA_SEED_STEP      = 1,
        CA_SEED_NEXT_FILE = 2,
        CA_SEED_DONE_FILE = 3,
};

CaSeed *ca_seed_new(void);
CaSeed *ca_seed_unref(CaSeed *s);

int ca_seed_set_base_fd(CaSeed *s, int fd);
int ca_seed_set_base_path(CaSeed *s, const char *path);

int ca_seed_set_cache_fd(CaSeed *s, int fd);
int ca_seed_set_cache_path(CaSeed *s, const char *path);

int ca_seed_step(CaSeed *s);

int ca_seed_get(CaSeed *s, const CaChunkID *chunk_id, const void **ret, size_t *ret_size, CaOrigin **ret_origin);
int ca_seed_has(CaSeed *s, const CaChunkID *chunk_id);

int ca_seed_get_hardlink_target(CaSeed *s, const CaChunkID *id, char **ret);

int ca_seed_current_path(CaSeed *seed, char **ret);
int ca_seed_current_mode(CaSeed *seed, mode_t *ret);

int ca_seed_set_feature_flags(CaSeed *s, uint64_t flags);

int ca_seed_set_cache_only(CaSeed *s, bool cache_only);

int ca_seed_set_chunk_size(CaSeed *s, size_t cmin, size_t cavg, size_t cmax);

int ca_seed_set_hardlink(CaSeed *s, bool b);
int ca_seed_set_chunks(CaSeed *s, bool b);

int ca_seed_get_file_root(CaSeed *s, CaFileRoot **ret);

int ca_seed_get_requests(CaSeed *s, uint64_t *ret);
int ca_seed_get_request_bytes(CaSeed *s, uint64_t *ret);
int ca_seed_get_seeding_time_nsec(CaSeed *s, uint64_t *ret);

#endif
