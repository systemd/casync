#ifndef foocaseedhfoo
#define foocaseedhfoo

#include <sys/types.h>

#include "cachunkid.h"

typedef struct CaSeed CaSeed;

enum {
        CA_SEED_READY     = 0,
        CA_SEED_STEP      = 1,
        CA_SEED_NEXT_FILE = 2,
};

CaSeed *ca_seed_new(void);
CaSeed *ca_seed_unref(CaSeed *s);

int ca_seed_set_base_fd(CaSeed *s, int fd);
int ca_seed_set_base_path(CaSeed *s, const char *path);

int ca_seed_set_cache_fd(CaSeed *s, int fd);
int ca_seed_set_cache_path(CaSeed *s, const char *path);

int ca_seed_step(CaSeed *s);

int ca_seed_get(CaSeed *s, const CaChunkID *chunk_id, const void **ret, size_t *ret_size);

int ca_seed_current_path(CaSeed *seed, char **ret);
int ca_seed_current_mode(CaSeed *seed, mode_t *ret);

int ca_seed_set_chunk_size_min(CaSeed *s, size_t cmin);
int ca_seed_set_chunk_size_avg(CaSeed *s, size_t cavg);
int ca_seed_set_chunk_size_max(CaSeed *s, size_t cmax);

#endif
