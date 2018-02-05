/* SPDX-License-Identifier: LGPL-2.1+ */

#include "caformat-util.h"
#include "caformat.h"
#include "util.h"

int main(int argc, char *argv[]) {

        uint64_t i, normalized;
        int r;

        /* Make sure that the with mask is a subset of all currently defined bits */
        assert((CA_FORMAT_WITH_MASK & ~CA_FORMAT_FEATURE_FLAGS_MAX) == UINT64_C(0));

        /* Make sure that the various with flag subsets are actually subsets of the with mask */
        assert((CA_FORMAT_WITH_BEST & ~CA_FORMAT_WITH_MASK) == UINT64_C(0));
        assert((CA_FORMAT_WITH_UNIX & ~CA_FORMAT_WITH_MASK) == UINT64_C(0));
        assert((CA_FORMAT_WITH_FAT & ~CA_FORMAT_WITH_MASK) == UINT64_C(0));
        assert((CA_FORMAT_WITH_CHATTR & ~CA_FORMAT_WITH_MASK) == UINT64_C(0));
        assert((CA_FORMAT_WITH_FAT_ATTRS & ~CA_FORMAT_WITH_MASK) == UINT64_C(0));
        assert((CA_FORMAT_WITH_PRIVILEGED & ~CA_FORMAT_WITH_MASK) == UINT64_C(0));
        assert((CA_FORMAT_WITH_FUSE & ~CA_FORMAT_WITH_MASK) == UINT64_C(0));

        /* Make sure that if we normalize the full mask we arrive at the best mask (modulo the NODUMP flag, as that's
         * masked by CA_FORMAT_EXCLUDE_NODUMP) */
        assert_se(ca_feature_flags_normalize(CA_FORMAT_FEATURE_FLAGS_MAX, &normalized) >= 0);
        assert_se((normalized & CA_FORMAT_WITH_MASK) == (CA_FORMAT_WITH_BEST & ~CA_FORMAT_WITH_FLAG_NODUMP));

        for (i = 0; i < sizeof(uint64_t) * 8; i++) {
                uint64_t flag = UINT64_C(1) << i, flag2;
                _cleanup_free_ char *s = NULL;

                r = ca_with_feature_flags_format(flag, &s);

                /* This has to succeed whenever the bit is valid at all */
                assert_se((r >= 0) == !!(flag & CA_FORMAT_FEATURE_FLAGS_MAX));
                if (r < 0) {
                        assert_se(r == -EINVAL);
                        continue;
                }

                /* If this is not a with mask, the result should be the empty string, but only then */
                assert_se(!(flag & CA_FORMAT_WITH_MASK) == isempty(s));
                if (isempty(s))
                        continue;

                assert_se(ca_with_feature_flags_parse_one(s, &flag2) == 0);
                assert_se(flag2 == flag);
        }

        return 0;
}
