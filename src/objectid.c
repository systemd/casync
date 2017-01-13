#include <assert.h>
#include <errno.h>

#include "objectid.h"

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

ObjectID* object_id_parse(const char *v, ObjectID *ret) {
        ObjectID id;
        size_t i;

        assert(v);
        assert(ret);

        for (i = 0; i < sizeof(ObjectID); i++) {
                int x, y;

                x = decode_char(v[i*2]);
                if (x < 0)
                        return NULL;
                y = decode_char(v[i*2+1]);
                if (y < 0)
                        return NULL;

                id.bytes[i] = (uint8_t) x << 4 | (uint8_t) y;
        }

        if (v[sizeof(ObjectID)*2] != 0)
                return NULL;

        *ret = id;
        return ret;
}

char* object_id_format(const ObjectID *id, char v[OBJECT_ID_FORMAT_MAX]) {
        size_t i;

        assert(id);
        assert(v);

        for (i = 0; i < sizeof(ObjectID); i++) {
                v[i*2] = encode_char(id->bytes[i] >> 4);
                v[i*2+1] = encode_char(id->bytes[i] & 0xF);
        }

        v[sizeof(ObjectID) * 2] = 0;
        return v;
}
