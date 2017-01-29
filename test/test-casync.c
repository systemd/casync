#include <sys/stat.h>
#include <fcntl.h>

#include "casync.h"
#include "util.h"

int main(int argc, char *argv[]) {
        char *teststore, *testindex, *testtree;
        CaSync *s;
        int r, base_fd;
        CaChunkID digest;
        char t[CA_CHUNK_ID_FORMAT_MAX];

        assert_se(asprintf(&teststore, "/var/tmp/teststore.%" PRIx64, random_u64()) >= 0);
        assert_se(asprintf(&testindex, "/var/tmp/testindex.%" PRIx64, random_u64()) >= 0);
        assert_se(asprintf(&testtree, "/var/tmp/testtree.%" PRIx64, random_u64()) >= 0);

        assert_se(s = ca_sync_new_encode());

        base_fd = open(".", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        assert_se(base_fd >= 0);
        assert_se(ca_sync_set_base_fd(s, base_fd) >= 0);

        assert_se(ca_sync_set_store_path(s, teststore) >= 0);
        assert_se(ca_sync_set_index_path(s, testindex) >= 0);

        for (;;) {
                r = ca_sync_step(s);
                assert_se(r >= 0);

                switch (r) {

                case CA_SYNC_FINISHED: {
                        assert_se(ca_sync_get_digest(s, &digest) >= 0);
                        printf("%s\n", ca_chunk_id_format(&digest, t));
                        goto step2;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_NEXT_FILE:
                        break;
                }
        }

step2:
        ca_sync_unref(s);
        assert_se(s = ca_sync_new_decode());

        (void) mkdir(testtree, 0777);
        base_fd = open(testtree, O_RDONLY|O_CLOEXEC|O_DIRECTORY);

        assert_se(base_fd >= 0);
        assert_se(ca_sync_set_base_fd(s, base_fd) >= 0);

        assert_se(ca_sync_set_store_path(s, teststore) >= 0);
        assert_se(ca_sync_set_index_path(s, testindex) >= 0);

        for (;;) {
                r = ca_sync_step(s);
                assert_se(r >= 0);

                switch (r) {
                case CA_SYNC_FINISHED: {
                        assert_se(ca_sync_get_digest(s, &digest) >= 0);
                        printf("%s\n", ca_chunk_id_format(&digest, t));
                        goto finish;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_NEXT_FILE:
                        break;
                }
        }

finish:
        ca_sync_unref(s);

        return 0;
}
