#include <sys/stat.h>
#include <fcntl.h>

#include "caformat.h"
#include "casync.h"
#include "util.h"

int main(int argc, char *argv[]) {
        const char *d;
        char *teststore, *testindex, *testtree;
        CaSync *s;
        int r, base_fd;
        CaChunkID digest;
        char t[CA_CHUNK_ID_FORMAT_MAX];
        uint64_t flags;

        assert(var_tmp_dir(&d) >= 0);

        r = asprintf(&teststore, "%s/teststore.%" PRIx64, d, random_u64());
        assert_se(r >= 0);
        asprintf(&testindex, "%s/testindex.%" PRIx64, d, random_u64());
        assert_se(r >= 0);
        r = asprintf(&testtree, "%s/testtree.%" PRIx64, d, random_u64());
        assert_se(r >= 0);

        assert_se(s = ca_sync_new_encode());

        flags = CA_FORMAT_DEFAULT;

        if (geteuid() != 0)
                flags &= ~CA_FORMAT_WITH_PRIVILEGED;

        assert_se(ca_sync_set_feature_flags(s, flags) >= 0);

        base_fd = open(".", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        assert_se(base_fd >= 0);
        assert_se(ca_sync_set_base_fd(s, base_fd) >= 0);

        assert_se(ca_sync_enable_archive_digest(s, true) >= 0);
        assert_se(ca_sync_set_store_path(s, teststore) >= 0);
        assert_se(ca_sync_set_index_path(s, testindex) >= 0);

        for (;;) {
                r = ca_sync_step(s);
                assert_se(r >= 0);

                switch (r) {

                case CA_SYNC_FINISHED: {
                        assert_se(ca_sync_get_archive_digest(s, &digest) >= 0);
                        printf("%s\n", ca_chunk_id_format(&digest, t));
                        goto step2;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_NEXT_FILE:
                case CA_SYNC_DONE_FILE:
                        break;

                default:
                        assert_se(false);
                }
        }

step2:
        ca_sync_unref(s);
        assert_se(s = ca_sync_new_decode());

        (void) mkdir(testtree, 0777);
        base_fd = open(testtree, O_RDONLY|O_CLOEXEC|O_DIRECTORY);

        assert_se(base_fd >= 0);
        assert_se(ca_sync_set_base_fd(s, base_fd) >= 0);

        assert_se(ca_sync_enable_archive_digest(s, true) >= 0);
        assert_se(ca_sync_set_store_path(s, teststore) >= 0);
        assert_se(ca_sync_set_index_path(s, testindex) >= 0);

        for (;;) {
                r = ca_sync_step(s);
                assert_se(r >= 0);

                switch (r) {

                case CA_SYNC_FINISHED: {
                        assert_se(ca_sync_get_archive_digest(s, &digest) >= 0);
                        printf("%s\n", ca_chunk_id_format(&digest, t));
                        goto finish;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_NEXT_FILE:
                case CA_SYNC_DONE_FILE:
                        break;

                default:
                        assert_se(false);
                }
        }

finish:
        ca_sync_unref(s);

        free(teststore);
        free(testindex);
        free(testtree);

        return 0;
}
