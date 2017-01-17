#ifndef fooca_synchfoo
#define fooca_synchfoo

#include <inttypes.h>

#include "objectid.h"

typedef struct CaSync CaSync;

enum {
        CA_SYNC_FINISHED,
        CA_SYNC_STEP,
        CA_SYNC_NEXT_FILE,
        CA_SYNC_SEED_STEP,
        CA_SYNC_SEED_NEXT_FILE,
};

CaSync *ca_sync_new_encode(void);
CaSync *ca_sync_new_decode(void);
CaSync *ca_sync_unref(CaSync *sync);

/* The index file, that contains the hashes + offsets */
int ca_sync_set_index_fd(CaSync *sync, int fd);
int ca_sync_set_index_path(CaSync *sync, const char *path);

/* The raw, unarchived ("user") tree */
int ca_sync_set_base_fd(CaSync *sync, int fd);
int ca_sync_set_base_path(CaSync *sync, const char *path);
int ca_sync_set_base_mode(CaSync *sync, mode_t mode);

/* The serialization of the user tree */
int ca_sync_set_archive_fd(CaSync *sync, int fd);
int ca_sync_set_archive_path(CaSync *sync, const char *path);

/* The store to place data in */
int ca_sync_set_store_local(CaSync *sync, const char *path);

/* Additional seeds to use */
int ca_sync_add_seed_base_fd(CaSync *sync, int fd);
int ca_sync_add_seed_base_path(CaSync *sync, const char *path);
int ca_sync_add_seed_store_local(CaSync *sync, const char *path);

int ca_sync_step(CaSync *sync);

int ca_sync_current_path(CaSync *sync, char **ret);
int ca_sync_current_mode(CaSync *sync, mode_t *ret);

int ca_sync_get(CaSync *s, const ObjectID *object_id, void **ret, size_t *ret_size);
int ca_sync_put(CaSync *s, const ObjectID *object_id, const void *data, size_t size);

int ca_sync_make_object_id(CaSync *s, const void *p, size_t l, ObjectID *ret);

int ca_sync_get_digest(CaSync *s, ObjectID *ret);

#endif
