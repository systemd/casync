#ifndef foocadigesthfoo
#define foocadigesthfoo

#include <stdbool.h>
#include <sys/types.h>

typedef struct CaDigest CaDigest;

typedef enum CaDigestType {
        CA_DIGEST_SHA256,
        CA_DIGEST_SHA512_256,
        _CA_DIGEST_TYPE_MAX,
        _CA_DIGEST_TYPE_INVALID = -1,
} CaDigestType;

int ca_digest_new(CaDigestType t, CaDigest **ret);
CaDigest *ca_digest_free(CaDigest *d);

int ca_digest_ensure_allocated(CaDigest **d, CaDigestType t);

void ca_digest_write(CaDigest *d, const void *p, size_t l);

const void* ca_digest_read(CaDigest *d);

void ca_digest_reset(CaDigest *d);

size_t ca_digest_get_size(CaDigest *d);
CaDigestType ca_digest_get_type(CaDigest *d);
const char *ca_digest_get_name(CaDigest *d);

size_t ca_digest_type_size(CaDigestType t);

const char *ca_digest_type_to_string(CaDigestType t);
CaDigestType ca_digest_type_from_string(const char *name);

int ca_digest_set_type(CaDigest *d, CaDigestType t);

#endif
