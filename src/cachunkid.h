#ifndef foocaobjectidhfoo
#define foocaobjectidhfoo

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include "cadigest.h"

#define CA_CHUNK_ID_SIZE 32
#define CA_CHUNK_ID_FORMAT_MAX (CA_CHUNK_ID_SIZE*2+1)

typedef union CaChunkID {
        /* For now, a SHA256 sum */
        uint8_t bytes[CA_CHUNK_ID_SIZE];
        uint64_t u64[CA_CHUNK_ID_SIZE / sizeof(uint64_t)];
} CaChunkID;

CaChunkID* ca_chunk_id_parse(const char *v, CaChunkID *ret);
char *ca_chunk_id_format(const CaChunkID *id, char v[CA_CHUNK_ID_FORMAT_MAX]);

static inline bool ca_chunk_id_equal(const CaChunkID *a, const CaChunkID *b) {

        if (a == b)
                return true;

        return memcmp(a, b, sizeof(CaChunkID)) == 0;
}

static inline bool ca_chunk_id_is_null(const CaChunkID *a) {
        size_t i;

        for (i = 0; i < CA_CHUNK_ID_SIZE / sizeof(uint64_t); i++)
                if (a->u64[0] != 0)
                        return false;

        return true;
}

int ca_chunk_id_make(CaDigest *digest, const void *p, size_t l, CaChunkID *ret);

#endif
