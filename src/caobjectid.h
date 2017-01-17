#ifndef foocaobjectidhfoo
#define foocaobjectidhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <gcrypt.h>

#define CA_OBJECT_ID_SIZE 32
#define CA_OBJECT_ID_FORMAT_MAX (CA_OBJECT_ID_SIZE*2+1)

typedef union CaObjectID {
        /* For now, a SHA256 sum */
        uint8_t bytes[CA_OBJECT_ID_SIZE];
        uint64_t u64[CA_OBJECT_ID_SIZE / sizeof(uint64_t)];
} CaObjectID;

CaObjectID* ca_object_id_parse(const char *v, CaObjectID *ret);
char *ca_object_id_format(const CaObjectID *id, char v[CA_OBJECT_ID_FORMAT_MAX]);

static inline bool ca_object_id_equal(const CaObjectID *a, const CaObjectID *b) {

        if (a == b)
                return true;

        return memcmp(a, b, sizeof(CaObjectID)) == 0;
}

static inline bool ca_object_id_is_null(const CaObjectID *a) {
        size_t i;

        for (i = 0; i < CA_OBJECT_ID_SIZE / sizeof(uint64_t); i++)
                if (a->u64[0] != 0)
                        return false;

        return true;
}

int ca_object_id_make(gcry_md_hd_t *digest, const void *p, size_t l, CaObjectID *ret);

#endif
