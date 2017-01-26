#ifndef foocautilhfoo
#define foocautilhfoo

#include "caobjectid.h"
#include "realloc-buffer.h"

int ca_open_chunk_file(int cache_fd, const char *prefix, const CaObjectID *objectid, const char *suffix, int flags);

int ca_load_fd(int fd, ReallocBuffer *buffer);
int ca_load_compressed_fd(int fd, ReallocBuffer *buffer);

int ca_test_chunk_file(int cache_fd, const char *prefix, const CaObjectID *objectid);
int ca_load_chunk_file(int cache_fd, const char *prefix, const CaObjectID *objectid, ReallocBuffer *buffer);
int ca_save_chunk_file(int cache_fd, const char *prefix, const CaObjectID *objectid, bool compressed, const void *p, size_t l);
int ca_save_chunk_missing(int cache_fd, const char *prefix, const CaObjectID *objectid);

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
