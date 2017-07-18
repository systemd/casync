#include <assert.h>
#include <errno.h>

#include "cachunk.h"
#include "cachunkid.h"

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

CaChunkID* ca_chunk_id_parse(const char *v, CaChunkID *ret) {
        CaChunkID id;
        size_t i;

        assert(v);
        assert(ret);

        for (i = 0; i < sizeof(CaChunkID); i++) {
                int x, y;

                x = decode_char(v[i*2]);
                if (x < 0)
                        return NULL;
                y = decode_char(v[i*2+1]);
                if (y < 0)
                        return NULL;

                id.bytes[i] = (uint8_t) x << 4 | (uint8_t) y;
        }

        if (v[sizeof(CaChunkID)*2] != 0)
                return NULL;

        *ret = id;
        return ret;
}

char* ca_chunk_id_format(const CaChunkID *id, char v[CA_CHUNK_ID_FORMAT_MAX]) {
        size_t i;

        assert(id);
        assert(v);

        for (i = 0; i < sizeof(CaChunkID); i++) {
                v[i*2] = encode_char(id->bytes[i] >> 4);
                v[i*2+1] = encode_char(id->bytes[i] & 0xF);
        }

        v[sizeof(CaChunkID) * 2] = 0;
        return v;
}

int ca_chunk_id_make(CaDigest *digest, const void *p, size_t l, CaChunkID *ret) {
        if (!digest)
                return -EINVAL;
        if (!p)
                return -EINVAL;
        if (l < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (l > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (ca_digest_get_size(digest) != sizeof(CaChunkID))
                return -EINVAL;

        ca_digest_reset(digest);
        ca_digest_write(digest, p, l);

        memcpy(ret, ca_digest_read(digest), sizeof(CaChunkID));
        return 0;
}
