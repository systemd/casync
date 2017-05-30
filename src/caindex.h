#ifndef foocaindexhfoo
#define foocaindexhfoo

#include "cachunkid.h"
#include "realloc-buffer.h"

typedef struct CaIndex CaIndex;

CaIndex *ca_index_new_write(void); /* only (cooked) writing */
CaIndex *ca_index_new_read(void); /* only (cooked) reading */
CaIndex *ca_index_new_incremental_write(void); /* incremental cooked writing + raw/byte-wise reading (for uploads) */
CaIndex *ca_index_new_incremental_read(void); /* incremental raw/byte-wise writing + cooked reading (for downloads) */
CaIndex *ca_index_unref(CaIndex *i);

int ca_index_set_fd(CaIndex *i, int fd);
int ca_index_set_path(CaIndex *i, const char *path);

int ca_index_set_make_mode(CaIndex *i, mode_t m);

int ca_index_open(CaIndex *i);

int ca_index_install(CaIndex *i);

int ca_index_write_chunk(CaIndex *i, const CaChunkID *id, uint64_t size);
int ca_index_write_eof(CaIndex *i);

int ca_index_read_chunk(CaIndex *i, CaChunkID *id, uint64_t *ret_offset_end, uint64_t *ret_size);

int ca_index_set_position(CaIndex *i, uint64_t position);
int ca_index_get_position(CaIndex *i, uint64_t *ret);
int ca_index_get_available_chunks(CaIndex *i, uint64_t *ret);

int ca_index_incremental_write(CaIndex *i, const void *data, size_t size);
int ca_index_incremental_eof(CaIndex *i);

int ca_index_incremental_read(CaIndex *i, ReallocBuffer *buffer);

int ca_index_get_digest(CaIndex *i, CaChunkID *ret);
int ca_index_set_digest(CaIndex *i, const CaChunkID *id);

int ca_index_set_feature_flags(CaIndex *i, uint64_t flags);
int ca_index_get_feature_flags(CaIndex *i, uint64_t *ret);

int ca_index_set_chunk_size_min(CaIndex *i, size_t cmin);
int ca_index_set_chunk_size_avg(CaIndex *i, size_t cavg);
int ca_index_set_chunk_size_max(CaIndex *i, size_t cmax);

int ca_index_get_chunk_size_min(CaIndex *i, size_t *ret);
int ca_index_get_chunk_size_avg(CaIndex *i, size_t *ret);
int ca_index_get_chunk_size_max(CaIndex *i, size_t *ret);

int ca_index_get_blob_size(CaIndex *i, uint64_t *ret);
int ca_index_get_index_size(CaIndex *i, uint64_t *ret);
int ca_index_get_total_chunks(CaIndex *i, uint64_t *ret);

int ca_index_seek(CaIndex *i, uint64_t offset, uint64_t *ret_skip);

#endif
