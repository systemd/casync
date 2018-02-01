/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocalocationhfoo
#define foocalocationhfoo

#include <inttypes.h>
#include <stdbool.h>

#include "cachunkid.h"
#include "cadigest.h"
#include "cafileroot.h"
#include "canametable.h"
#include "util.h"

/* Describes the location of some data in a directory hierarchy. This is useful for cache management (i.e. remember
 * where to seek to in the directory hierarchy to generate a serialization matching a specific hash), but also for
 * tracking data origin for creating file system reflinks. */

typedef enum CaLocationDesignator {
        CA_LOCATION_ENTRY = 'e',
        CA_LOCATION_PAYLOAD = 'p',
        CA_LOCATION_FILENAME = 'n',
        CA_LOCATION_GOODBYE = 'g',
        CA_LOCATION_VOID = 'v', /* Used as placeholder if we have to describe a blob of data from no known location */
        _CA_LOCATION_DESIGNATOR_INVALID = -1,
} CaLocationDesignator;

static inline bool CA_LOCATION_DESIGNATOR_VALID(CaLocationDesignator d) {
        return IN_SET(d,
                      CA_LOCATION_ENTRY,
                      CA_LOCATION_PAYLOAD,
                      CA_LOCATION_FILENAME,
                      CA_LOCATION_GOODBYE,
                      CA_LOCATION_VOID);
}

typedef enum CaLocationWith {
        CA_LOCATION_WITH_SIZE           = 1U << 0,
        CA_LOCATION_WITH_MTIME          = 1U << 1,
        CA_LOCATION_WITH_FEATURE_FLAGS  = 1U << 2,
        CA_LOCATION_WITH_ARCHIVE_OFFSET = 1U << 3,
        CA_LOCATION_WITH_NAME_TABLE     = 1U << 4,

        CA_LOCATION_WITH_ALL = CA_LOCATION_WITH_SIZE|CA_LOCATION_WITH_MTIME|CA_LOCATION_WITH_FEATURE_FLAGS|CA_LOCATION_WITH_ARCHIVE_OFFSET|CA_LOCATION_WITH_NAME_TABLE,
} CaLocationWith;

/* A location in the serialization of a directory tree. This is considered immutable as soon as it was created
 * once. When we change it we make copies. */
typedef struct CaLocation {
        unsigned n_ref;

        /* The following three fields are unconditionally part of the location */
        CaLocationDesignator designator;
        char *path;
        uint64_t offset;

        /* The following two fields are optional */
        uint64_t size; /* if unspecified UINT64_MAX */
        CaFileRoot *root; /* if unspecified NULL */

        /* The following is used to detect file changes, and are optional too */
        uint64_t mtime; /* If no mtime is known set to UINT64_MAX */
        uint64_t inode; /* only set if mtime is != UINT64_MAX */
        int generation; /* only valid if generation_valid is true */
        bool generation_valid;

        /* The feature flags used for encoding, so that we don't use cached data created with different settings (if unspecified UINT64_MAX) */
        uint64_t feature_flags;

        /* The archive offset at this location, if that's useful (if unspecified is UINT64_MAX) */
        uint64_t archive_offset;

        /* The following encodes the file name tables so far built of for this node and all its parents, and is
         * optional (in which case it is NULL) */
        CaNameTable *name_table;

        /* The formatted version of this location, if requested before */
        char *formatted;
        CaLocationWith formatted_with;
} CaLocation;

int ca_location_new(const char *path, CaLocationDesignator designator, uint64_t offset, uint64_t size, CaLocation **ret);
#define ca_location_new_void(size, ret) ca_location_new(NULL, CA_LOCATION_VOID, 0, size, ret)
int ca_location_copy(CaLocation *l, CaLocation **ret);

CaLocation* ca_location_unref(CaLocation *l);
CaLocation* ca_location_ref(CaLocation *l);

DEFINE_TRIVIAL_CLEANUP_FUNC(CaLocation*, ca_location_unref);

const char* ca_location_format_full(CaLocation *l, CaLocationWith with);
#define ca_location_format(l) ca_location_format_full(l, CA_LOCATION_WITH_SIZE|CA_LOCATION_WITH_MTIME|CA_LOCATION_WITH_FEATURE_FLAGS)

int ca_location_parse(const char *text, CaLocation **ret);

int ca_location_patch_size(CaLocation **l, uint64_t size);
int ca_location_patch_root(CaLocation **l, CaFileRoot *root);

int ca_location_advance(CaLocation **l, uint64_t n_bytes);

int ca_location_merge(CaLocation **a, CaLocation *b);

int ca_location_open(CaLocation *l);

int ca_location_id_make(CaDigest *digest, CaLocation *l, bool include_size, CaChunkID *ret);

bool ca_location_equal(CaLocation *a, CaLocation *b, CaLocationWith with);

#endif
