#include "cafileroot.h"
#include "util.h"

int ca_file_root_new(const char *path, int fd, CaFileRoot **ret) {
        CaFileRoot *root;

        if (!path && fd < 0)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        root = new0(CaFileRoot, 1);
        if (!root)
                return -ENOMEM;

        root->n_ref = 1;
        root->fd = fd;

        if (path) {
                root->path = strdup(path);
                if (!root->path) {
                        free(root);
                        return -ENOMEM;
                }
        }

        *ret = root;
        return 0;
}

CaFileRoot* ca_file_root_ref(CaFileRoot *root) {
        if (!root)
                return NULL;

        assert_se(root->n_ref > 0);

        root->n_ref++;

        return root;
}

CaFileRoot* ca_file_root_unref(CaFileRoot *root) {
        if (!root)
                return NULL;

        assert_se(root->n_ref > 0);
        root->n_ref--;

        if (root->n_ref > 0)
                return NULL;

        root->fd = -1;
        free(root->path);

        return mfree(root);
}

void ca_file_root_invalidate(CaFileRoot *root) {
        if (!root)
                return;

        root->fd = -1;
        root->path = mfree(root->path);

        root->invalidated = true;
}
