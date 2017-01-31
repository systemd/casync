#ifndef foocautilhfoo
#define foocautilhfoo

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

bool ca_is_url(const char *s);
bool ca_is_ssh_path(const char *s);

typedef enum CaLocatorClass {
        CA_LOCATOR_PATH,
        CA_LOCATOR_SSH,
        CA_LOCATOR_URL,
        _CA_LOCATOR_CLASS_INVALID = -1,
} CaLocatorClass;

CaLocatorClass ca_classify_locator(const char *s);

char *ca_strip_file_url(const char *p);
bool ca_locator_has_suffix(const char *p, const char *suffix);

#endif
