#include <openssl/sha.h>

#include "cadigest.h"
#include "util.h"

struct CaDigest {
        CaDigestType type;
        uint8_t result[CONST_MAX(SHA256_DIGEST_LENGTH, SHA512_DIGEST_LENGTH)];

        union {
                SHA256_CTX sha256;
                SHA512_CTX sha512;
        };
};

void ca_digest_reset(CaDigest *d) {
        if (!d)
                return;

        switch (d->type) {

        case CA_DIGEST_SHA256:
                SHA256_Init(&d->sha256);
                break;

        case CA_DIGEST_SHA512_256:

                /* SHA512/256 is identical to SHA512 truncated to 256 bit, except that the start values are slightly
                 * different. Since OpenSSL doesn't support them natively, let's hack them in here. As soon as OpenSSL
                 * learns SHA512/256 natively, let's switch over to that. */

                SHA512_Init(&d->sha512);
                d->sha512.h[0] = UINT64_C(0x22312194fc2bf72c);
                d->sha512.h[1] = UINT64_C(0x9f555fa3c84c64c2);
                d->sha512.h[2] = UINT64_C(0x2393b86b6f53b151);
                d->sha512.h[3] = UINT64_C(0x963877195940eabd);
                d->sha512.h[4] = UINT64_C(0x96283ee2a88effe3);
                d->sha512.h[5] = UINT64_C(0xbe5e1e2553863992);
                d->sha512.h[6] = UINT64_C(0x2b0199fc2c85b8aa);
                d->sha512.h[7] = UINT64_C(0x0eb72ddc81c52ca2);

                break;

        default:
                assert_not_reached("Unknown hash function");
        }
}

int ca_digest_new(CaDigestType t, CaDigest **ret) {
        CaDigest *d;

        if (t < 0)
                return -EINVAL;
        if (t >= _CA_DIGEST_TYPE_MAX)
                return -EOPNOTSUPP;
        if (!ret)
                return -EINVAL;

        d = new0(CaDigest, 1);
        if (!d)
                return -ENOMEM;

        d->type = t;

        ca_digest_reset(d);

        *ret = d;
        return 0;
}

CaDigest *ca_digest_free(CaDigest *d) {
        return mfree(d);
}

void ca_digest_write(CaDigest *d, const void *p, size_t l) {
        if (!d)
                return;
        if (l <= 0)
                return;

        assert(p);

        switch (d->type) {

        case CA_DIGEST_SHA256:
                SHA256_Update(&d->sha256, p, l);
                break;

        case CA_DIGEST_SHA512_256:
                SHA512_Update(&d->sha512, p, l);
                break;

        default:
                assert_not_reached("Unknown hash function");
        }
}

const void* ca_digest_read(CaDigest *d) {
        if (!d)
                return NULL;

        switch (d->type) {

        case CA_DIGEST_SHA256:
                assert(sizeof(d->result) >= SHA256_DIGEST_LENGTH);
                SHA256_Final(d->result, &d->sha256);
                break;

        case CA_DIGEST_SHA512_256:
                assert(sizeof(d->result) >= SHA512_DIGEST_LENGTH);
                SHA512_Final(d->result, &d->sha512);
                break;

        default:
                assert_not_reached("Unknown hash function");

        }

        return d->result;
}

size_t ca_digest_get_size(CaDigest *d) {
        if (!d)
                return (size_t) -1;

        return ca_digest_type_size(d->type);
}

CaDigestType ca_digest_get_type(CaDigest *d) {
        if (!d)
                return _CA_DIGEST_TYPE_INVALID;

        return d->type;
}

const char *ca_digest_get_name(CaDigest *d) {
        if (!d)
                return NULL;

        return ca_digest_type_to_string(d->type);
}

size_t ca_digest_type_size(CaDigestType t) {

        switch (t) {

        case CA_DIGEST_SHA256:
        case CA_DIGEST_SHA512_256:
                assert(SHA256_DIGEST_LENGTH == SHA512_DIGEST_LENGTH/2);
                return SHA256_DIGEST_LENGTH;

        default:
                return (size_t) -1;
        }
}

static const char *const table[_CA_DIGEST_TYPE_MAX] = {
        [CA_DIGEST_SHA256] = "sha256",
        [CA_DIGEST_SHA512_256] = "sha512-256",
};

const char *ca_digest_type_to_string(CaDigestType t) {
        if (t < 0 || t >= _CA_DIGEST_TYPE_MAX)
                return NULL;

        return table[t];
}

CaDigestType ca_digest_type_from_string(const char *name) {
        CaDigestType t;

        if (!name)
                return _CA_DIGEST_TYPE_INVALID;

        if (streq(name, "default"))
                return CA_DIGEST_DEFAULT;

        for (t = 0; t < _CA_DIGEST_TYPE_MAX; t++)
                if (streq(table[t], name))
                        return t;

        return _CA_DIGEST_TYPE_INVALID;
}

int ca_digest_ensure_allocated(CaDigest **d, CaDigestType t) {
        int r;

        if (!d)
                return -EINVAL;
        if (*d)
                return 0;

        r = ca_digest_new(t, d);
        if (r < 0)
                return r;

        return 1;
}

int ca_digest_set_type(CaDigest *d, CaDigestType t) {
        if (!d)
                return -EINVAL;
        if (t < 0)
                return -EINVAL;
        if (t >= _CA_DIGEST_TYPE_MAX)
                return -EOPNOTSUPP;

        d->type = t;
        ca_digest_reset(d);

        return 0;
}
