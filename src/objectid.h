#ifndef fooobjectidhfoo
#define fooobjectidhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <gcrypt.h>

#define OBJECT_ID_SIZE 32
#define OBJECT_ID_FORMAT_MAX (OBJECT_ID_SIZE*2+1)

typedef union ObjectID {
        /* For now, a SHA256 sum */
        uint8_t bytes[OBJECT_ID_SIZE];
        uint64_t u64[OBJECT_ID_SIZE / sizeof(uint64_t)];
} ObjectID;

ObjectID* object_id_parse(const char *v, ObjectID *ret);
char *object_id_format(const ObjectID *id, char v[OBJECT_ID_FORMAT_MAX]);

static inline bool object_id_equal(const ObjectID *a, const ObjectID *b) {

        if (a == b)
                return true;

        return memcmp(a, b, sizeof(ObjectID)) == 0;
}

static inline bool object_id_is_null(const ObjectID *a) {
        size_t i;

        for (i = 0; i < OBJECT_ID_SIZE / sizeof(uint64_t); i++)
                if (a->u64[0] != 0)
                        return false;

        return true;
}

int object_id_make(gcry_md_hd_t *digest, const void *p, size_t l, ObjectID *ret);

#endif
