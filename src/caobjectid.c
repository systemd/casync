#include <assert.h>
#include <errno.h>

#include "gcrypt-util.h"
#include "caobjectid.h"

static char encode_char(uint8_t x) {
        x &= 0xF;
        return (x < 10 ? '0' : 'a' - 10) + x;
}

static int decode_char(char x) {
        if (x >= '0' && x <= '9')
                return x - '0';
        if (x >= 'a' && x <= 'f')
                return x - 'a' + 10;

        return -EINVAL;
}

CaObjectID* ca_object_id_parse(const char *v, CaObjectID *ret) {
        CaObjectID id;
        size_t i;

        assert(v);
        assert(ret);

        for (i = 0; i < sizeof(CaObjectID); i++) {
                int x, y;

                x = decode_char(v[i*2]);
                if (x < 0)
                        return NULL;
                y = decode_char(v[i*2+1]);
                if (y < 0)
                        return NULL;

                id.bytes[i] = (uint8_t) x << 4 | (uint8_t) y;
        }

        if (v[sizeof(CaObjectID)*2] != 0)
                return NULL;

        *ret = id;
        return ret;
}

char* ca_object_id_format(const CaObjectID *id, char v[CA_OBJECT_ID_FORMAT_MAX]) {
        size_t i;

        assert(id);
        assert(v);

        for (i = 0; i < sizeof(CaObjectID); i++) {
                v[i*2] = encode_char(id->bytes[i] >> 4);
                v[i*2+1] = encode_char(id->bytes[i] & 0xF);
        }

        v[sizeof(CaObjectID) * 2] = 0;
        return v;
}

int ca_object_id_make(gcry_md_hd_t *digest, const void *p, size_t l, CaObjectID *ret) {
        const void *q;

        assert(p || l == 0);
        assert(ret);

        if (*digest)
                gcry_md_reset(*digest);
        else {
                initialize_libgcrypt();

                assert(gcry_md_get_algo_dlen(GCRY_MD_SHA256) == sizeof(CaObjectID));

                if (gcry_md_open(digest, GCRY_MD_SHA256, 0) != 0)
                        return -EIO;
        }

        gcry_md_write(*digest, p, l);

        q = gcry_md_read(*digest, GCRY_MD_SHA256);
        if (!q)
                return -EIO;

        memcpy(ret, q, sizeof(CaObjectID));
        return 0;
}
