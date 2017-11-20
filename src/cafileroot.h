/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocafileroothfoo
#define foocafileroothfoo

#include <stdbool.h>

typedef struct CaFileRoot {
        unsigned n_ref;
        char *path;
        int fd;
        bool invalidated;
} CaFileRoot;

int ca_file_root_new(const char *path, int fd, CaFileRoot **ret);

CaFileRoot* ca_file_root_ref(CaFileRoot *root);
CaFileRoot* ca_file_root_unref(CaFileRoot *root);

void ca_file_root_invalidate(CaFileRoot *root);

#endif
