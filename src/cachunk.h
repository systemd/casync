#ifndef foocachunkhfoo
#define foocachunkhfoo

#include "cachunkid.h"
#include "cacompression.h"
#include "realloc-buffer.h"

/* The hardcoded, maximum chunk size, after which we refuse operation */
#define CA_CHUNK_SIZE_LIMIT_MAX ((size_t) (128U*1024U*1024U))
#define CA_CHUNK_SIZE_LIMIT_MIN ((size_t) 1)

typedef enum CaChunkCompression {
        CA_CHUNK_UNCOMPRESSED,
        CA_CHUNK_COMPRESSED,
        CA_CHUNK_AS_IS,
        _CA_CHUNK_COMPRESSION_MAX,
} CaChunkCompression;

int ca_load_fd(int fd, ReallocBuffer *buffer);
int ca_load_and_decompress_fd(int fd, ReallocBuffer *buffer);
int ca_load_and_compress_fd(int fd, CaCompressionType compression_type, ReallocBuffer *buffer);

int ca_save_fd(int fd, const void *data, size_t size);
int ca_save_and_decompress_fd(int fd, const void *data, size_t size);
int ca_save_and_compress_fd(int fd, CaCompressionType compression_type, const void *data, size_t size);

int ca_decompress(const void *data, size_t size, ReallocBuffer *buffer);
int ca_compress(CaCompressionType compression_type, const void *data, size_t size, ReallocBuffer *buffer);

int ca_chunk_file_open(int cache_fd, const char *prefix, const CaChunkID *chunkid, const char *suffix, int flags);

int ca_chunk_file_test(int cache_fd, const char *prefix, const CaChunkID *chunkid);
int ca_chunk_file_load(int cache_fd, const char *prefix, const CaChunkID *chunkid, CaChunkCompression desired_compression, CaCompressionType compression_type, ReallocBuffer *buffer, CaChunkCompression *ret_effective_compression);
int ca_chunk_file_save(int cache_fd, const char *prefix, const CaChunkID *chunkid, CaChunkCompression effective_compression, CaChunkCompression desired_compression, CaCompressionType compression_type, const void *p, uint64_t l);
int ca_chunk_file_mark_missing(int cache_fd, const char *prefix, const CaChunkID *chunkid);
int ca_chunk_file_remove(int chunk_fd, const char *prefix, const CaChunkID *chunkid);

#endif
