/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocacachehfoo
#define foocacachehfoo

#include "cachunkid.h"
#include "calocation.h"
#include "caorigin.h"
#include "util.h"

/* Implements a cache, that given a location returns a chunk ID plus a matching origin object encoding where the chunk
 * is sourced from. This is used to speed up generation of chunks: when we looked at a specific chunk in an earlier
 * run, then there's no need to regenerate its hash again as long as the origin inodes haven't changed */

typedef struct CaCache CaCache;

CaCache *ca_cache_new(void);
CaCache *ca_cache_unref(CaCache *c);
CaCache *ca_cache_ref(CaCache *c);

int ca_cache_set_digest_type(CaCache *c, CaDigestType type);

int ca_cache_set_fd(CaCache *c, int fd);
int ca_cache_set_path(CaCache *c, const char *path);

int ca_cache_get(CaCache *c, CaLocation *location, CaChunkID *ret_chunk_id, CaOrigin **ret_origin);
int ca_cache_put(CaCache *c, CaOrigin *origin, const CaChunkID *chunk_id);
int ca_cache_remove(CaCache *c, CaLocation *location);

DEFINE_TRIVIAL_CLEANUP_FUNC(CaCache*, ca_cache_unref);

#endif
