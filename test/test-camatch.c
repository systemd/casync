/* SPDX-License-Identifier: LGPL-2.1+ */

#include "camatch.h"
#include "util.h"

int main(int argc, char *argv[]) {
        _cleanup_(ca_match_unrefp) CaMatch *match = NULL, *subtree = NULL;

        assert_se(ca_match_new_from_strings(STRV_MAKE("*.txt",
                                                       "!foobar.txt",
                                                       "/quux",
                                                       "/miepf/mupf",
                                                       "/miepf/zumm*kuck",
                                                       "/miepf/miepf/miepf",
                                                       "!/knurx/knurx/",
                                                       "/*.puff/"), &match) >= 0);

        ca_match_dump(NULL, match, NULL);

        assert_se(match->n_children == 8);

        assert_se(streq(match->children[0]->name, "*.txt"));
        assert_se(match->children[0]->type == CA_MATCH_POSITIVE);
        assert_se(match->children[0]->anchored == false);
        assert_se(match->children[0]->directory_only == false);
        assert_se(match->children[0]->n_children == 0);

        assert_se(streq(match->children[1]->name, "foobar.txt"));
        assert_se(match->children[1]->type == CA_MATCH_NEGATIVE);
        assert_se(match->children[1]->anchored == false);
        assert_se(match->children[1]->directory_only == false);
        assert_se(match->children[1]->n_children == 0);

        assert_se(streq(match->children[2]->name, "quux"));
        assert_se(match->children[2]->type == CA_MATCH_POSITIVE);
        assert_se(match->children[2]->anchored == true);
        assert_se(match->children[2]->directory_only == false);
        assert_se(match->children[2]->n_children == 0);

        assert_se(streq(match->children[3]->name, "miepf"));
        assert_se(match->children[3]->type == CA_MATCH_INNER);
        assert_se(match->children[3]->anchored == true);
        assert_se(match->children[3]->directory_only == true);
        assert_se(match->children[3]->n_children == 1);

        assert_se(streq(match->children[3]->children[0]->name, "mupf"));
        assert_se(match->children[3]->children[0]->type == CA_MATCH_POSITIVE);
        assert_se(match->children[3]->children[0]->anchored == true);
        assert_se(match->children[3]->children[0]->directory_only == false);
        assert_se(match->children[3]->children[0]->n_children == 0);

        assert_se(streq(match->children[4]->name, "miepf"));
        assert_se(match->children[4]->type == CA_MATCH_INNER);
        assert_se(match->children[4]->anchored == true);
        assert_se(match->children[4]->directory_only == true);
        assert_se(match->children[4]->n_children == 1);

        assert_se(streq(match->children[4]->children[0]->name, "zumm*kuck"));
        assert_se(match->children[4]->children[0]->type == CA_MATCH_POSITIVE);
        assert_se(match->children[4]->children[0]->anchored == true);
        assert_se(match->children[4]->children[0]->directory_only == false);
        assert_se(match->children[4]->children[0]->n_children == 0);

        assert_se(streq(match->children[5]->name, "miepf"));
        assert_se(match->children[5]->type == CA_MATCH_INNER);
        assert_se(match->children[5]->anchored == true);
        assert_se(match->children[5]->directory_only == true);
        assert_se(match->children[5]->n_children == 1);

        assert_se(streq(match->children[5]->children[0]->name, "miepf"));
        assert_se(match->children[5]->children[0]->type == CA_MATCH_INNER);
        assert_se(match->children[5]->children[0]->anchored == true);
        assert_se(match->children[5]->children[0]->directory_only == true);
        assert_se(match->children[5]->children[0]->n_children == 1);

        assert_se(streq(match->children[5]->children[0]->children[0]->name, "miepf"));
        assert_se(match->children[5]->children[0]->children[0]->type == CA_MATCH_POSITIVE);
        assert_se(match->children[5]->children[0]->children[0]->anchored == true);
        assert_se(match->children[5]->children[0]->children[0]->directory_only == false);
        assert_se(match->children[5]->children[0]->children[0]->n_children == 0);

        assert_se(streq(match->children[6]->name, "knurx"));
        assert_se(match->children[6]->type == CA_MATCH_INNER);
        assert_se(match->children[6]->anchored == true);
        assert_se(match->children[6]->directory_only == true);
        assert_se(match->children[6]->n_children == 1);

        assert_se(streq(match->children[6]->children[0]->name, "knurx"));
        assert_se(match->children[6]->children[0]->type == CA_MATCH_NEGATIVE);
        assert_se(match->children[6]->children[0]->anchored == true);
        assert_se(match->children[6]->children[0]->directory_only == true);
        assert_se(match->children[6]->children[0]->n_children == 0);

        assert_se(streq(match->children[7]->name, "*.puff"));
        assert_se(match->children[7]->type == CA_MATCH_POSITIVE);
        assert_se(match->children[7]->anchored == true);
        assert_se(match->children[7]->directory_only == true);
        assert_se(match->children[7]->n_children == 0);

        assert_se(ca_match_normalize(&match) >= 0);

        ca_match_dump(NULL, match, NULL);

        assert_se(ca_match_test(match, "test1.txt", false, &subtree) > 0);
        assert_se(!subtree);

        assert_se(ca_match_test(match, "test1.txt", true, &subtree) > 0);
        assert_se(ca_match_children(subtree) == 2);
        assert_se(ca_match_equal(subtree->children[0], match->children[1]));
        assert_se(ca_match_equal(subtree->children[1], match->children[3]));
        subtree = ca_match_unref(subtree);

        assert_se(ca_match_test(match, "foobar.txt", false, &subtree) == 0);
        assert_se(!subtree);

        assert_se(ca_match_test(match, "huhu", false, &subtree) == 0);
        assert_se(!subtree);

        assert_se(ca_match_test(match, "quux", false, &subtree) > 0);
        assert_se(!subtree);

        assert_se(ca_match_test(match, "quux", true, &subtree) > 0);
        assert_se(ca_match_children(subtree) == 2);
        assert_se(ca_match_equal(subtree->children[0], match->children[1]));
        assert_se(ca_match_equal(subtree->children[1], match->children[3]));
        subtree = ca_match_unref(subtree);

        assert_se(ca_match_test(match, "miepf", true, &subtree) == 0);
        ca_match_dump(NULL, subtree, NULL);
        assert_se(ca_match_children(subtree) == 5);
        assert_se(ca_match_equal(subtree->children[0], match->children[1]));
        assert_se(ca_match_equal(subtree->children[1], match->children[5]->children[0]));
        assert_se(ca_match_equal(subtree->children[2], match->children[5]->children[1]));
        assert_se(ca_match_equal(subtree->children[3], match->children[3]));
        assert_se(ca_match_equal(subtree->children[4], match->children[5]->children[2]));
        subtree = ca_match_unref(subtree);

        return 0;
}
