#ifndef foocachunkhfoo
#define foocachunkhfoo

#include "cachunkid.h"
#include "realloc-buffer.h"

typedef enum CaChunkCompression {
        CA_CHUNK_UNCOMPRESSED,
        CA_CHUNK_COMPRESSED,
        CA_CHUNK_AS_IS,
        _CA_CHUNK_COMPRESSION_MAX,
} CaChunkCompression;

int ca_load_fd(int fd, ReallocBuffer *buffer);
int ca_load_and_decompress_fd(int fd, ReallocBuffer *buffer);
int ca_load_and_compress_fd(int fd, ReallocBuffer *buffer);

int ca_save_fd(int fd, const void *data, size_t size);
int ca_save_and_decompress_fd(int fd, const void *data, size_t size);
int ca_save_and_compress_fd(int fd, const void *data, size_t size);

int ca_compress(const void *data, size_t size, ReallocBuffer *buffer);
int ca_decompress(const void *data, size_t size, ReallocBuffer *buffer);

int ca_chunk_file_open(int cache_fd, const char *prefix, const CaChunkID *chunkid, const char *suffix, int flags);

int ca_chunk_file_test(int cache_fd, const char *prefix, const CaChunkID *chunkid);
int ca_chunk_file_load(int cache_fd, const char *prefix, const CaChunkID *chunkid, CaChunkCompression desired_compression, ReallocBuffer *buffer, CaChunkCompression *ret_effective_compression);
int ca_chunk_file_save(int cache_fd, const char *prefix, const CaChunkID *chunkid, CaChunkCompression effective_compression, CaChunkCompression desired_compression, const void *p, size_t l);
int ca_chunk_file_mark_missing(int cache_fd, const char *prefix, const CaChunkID *chunkid);
int ca_chunk_file_remove(int chunk_fd, const char *prefix, const CaChunkID *chunkid);

#endif
