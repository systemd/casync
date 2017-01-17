#ifndef foocalocationhfoo
#define foocalocationhfoo

#include <inttypes.h>
#include <stdbool.h>

#include "util.h"

/* Describes the location of some data in a directory hierarchy */

typedef enum CaLocationDesignator {
        CA_LOCATION_PAYLOAD = 'p',
        CA_LOCATION_HELLO = 'h',
        CA_LOCATION_ENTRY = 'e',
        CA_LOCATION_GOODBYE = 'g',
} CaLocationDesignator;

static inline bool CA_LOCATION_DESIGNATOR_VALID(CaLocationDesignator d) {
        return IN_SET(d,
                      CA_LOCATION_PAYLOAD,
                      CA_LOCATION_HELLO,
                      CA_LOCATION_ENTRY,
                      CA_LOCATION_GOODBYE);
}

/* A location in the serialization of a directory tree. This is considered immutable as soon as it was created
 * once. When we change it we make copies. */
typedef struct CaLocation {
        unsigned n_ref;
        CaLocationDesignator designator;
        char *path;
        uint64_t offset;
        uint64_t size; /* if unspecified, may be UINT64_MAX */
        char *formatted;
} CaLocation;

int ca_location_new(const char *path, CaLocationDesignator designator, uint64_t offset, uint64_t size, CaLocation **ret);
CaLocation* ca_location_unref(CaLocation *l);
CaLocation* ca_location_ref(CaLocation *l);

const char* ca_location_format(CaLocation *l);

int ca_location_parse(const char *text, CaLocation **ret);

int ca_location_patch_size(CaLocation **l, uint64_t size);

#endif
