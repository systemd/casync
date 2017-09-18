/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "util.h"
#include "caindex.h"

int main(int argc, char*argv[]) {
        _cleanup_(ca_index_unrefp) CaIndex* index = NULL;
        int r;

        if (argc != 2) {
                fprintf(stderr, "Expected an index file as argument.\n");
                return EXIT_FAILURE;
        }

        assert_se(index = ca_index_new_read());
        assert_se(ca_index_set_path(index, argv[1]) >= 0);
        assert_se(ca_index_open(index) >= 0);

        for (;;) {
                CaChunkID id;
                uint64_t size;
                char ids[CA_CHUNK_ID_FORMAT_MAX];

                r = ca_index_read_chunk(index, &id, NULL, &size);
                assert_se(r >= 0);

                if (r == 0)
                        break;

                printf("%s (%" PRIu64 ")\n", ca_chunk_id_format(&id, ids), size);
        }

        printf("EOF\n");
        return 0;
}
