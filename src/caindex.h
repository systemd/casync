#ifndef foocaindexhfoo
#define foocaindexhfoo

#include "caobjectid.h"

typedef struct CaIndex CaIndex;

CaIndex *ca_index_new_write(void);
CaIndex *ca_index_new_read(void);
CaIndex *ca_index_unref(CaIndex *i);

int ca_index_set_fd(CaIndex *i, int fd);
int ca_index_set_path(CaIndex *i, const char *path);

int ca_index_open(CaIndex *i);
int ca_index_close(CaIndex *i);

int ca_index_write_object(CaIndex *i, const CaObjectID *id, uint64_t size);
int ca_index_write_eof(CaIndex *i);

int ca_index_read_object(CaIndex *i, CaObjectID *id, uint64_t *ret_size);
int ca_index_seek(CaIndex *i, uint64_t offset);

int ca_index_get_digest(CaIndex *i, CaObjectID *ret);
int ca_index_set_digest(CaIndex *i, const CaObjectID *id);

#endif
