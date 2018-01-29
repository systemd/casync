/* SPDX-License-Identifier: LGPL-2.1+ */

#include "cachunkid.h"
#include "cadigest.h"
#include "calocation.h"
#include "def.h"
#include "util.h"
#include "caformat.h"

int main(int argc, char *argv[]) {

        _cleanup_(ca_digest_freep) CaDigest *digest = NULL;
        _cleanup_(ca_location_unrefp) CaLocation *loc = NULL, *loc2 = NULL;
        CaChunkID id, id2;

        assert_se(ca_digest_new(CA_DIGEST_DEFAULT, &digest) >= 0);

        assert_se(ca_location_new("foo/quux", CA_LOCATION_PAYLOAD, 4711, 815, &loc) >= 0);

        loc->feature_flags = CA_FORMAT_WITH_BEST;
        loc->mtime = 1517231408U * NSEC_PER_SEC;
        loc->inode = 123456;
        loc->generation = 2345;
        loc->generation_valid = true;

        assert_se(ca_location_patch_size(&loc, 333) >= 0);
        assert_se(ca_location_advance(&loc, 7) >= 0);
        assert_se(ca_location_id_make(digest, loc, true, &id) >= 0);

        assert_se(ca_location_parse(ca_location_format(loc), &loc2) >= 0);

        assert_se(ca_location_equal(loc, loc2, true));
        assert_se(ca_location_id_make(digest, loc2, true, &id2) >= 0);
        assert_se(ca_chunk_id_equal(&id, &id2));

        assert_se(streq(loc2->path, "foo/quux"));
        assert_se(loc2->designator == CA_LOCATION_PAYLOAD);
        assert_se(loc2->offset == 4711 + 7);
        assert_se(loc2->size == 333 - 7);
        assert_se(loc2->feature_flags == CA_FORMAT_WITH_BEST);
        assert_se(loc2->mtime == 1517231408U * NSEC_PER_SEC);
        assert_se(loc2->inode == 123456);
        assert_se(loc2->generation == 2345);
        assert_se(loc2->generation_valid);

        return 0;
}
