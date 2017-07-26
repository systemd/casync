#ifndef foocautilhfoo
#define foocautilhfoo

#include <stdbool.h>

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

bool ca_xattr_name_is_valid(const char *s);
bool ca_xattr_name_store(const char *p);

const char *ca_compressed_chunk_suffix(void);

int ca_locator_patch_last_component(const char *locator, const char *last_component, char **ret);

#endif
