#ifndef foormrfhfoo
#define foormrfhfoo

#include <sys/stat.h>

typedef enum RemoveFlags {
        REMOVE_ONLY_DIRECTORIES = 1,
        REMOVE_ROOT = 2,
        REMOVE_PHYSICAL = 4, /* if not set, only removes files on tmpfs, never physical file systems */
        REMOVE_SPAN_DEVICES = 8,
} RemoveFlags;

int rm_rf_children(int fd, RemoveFlags flags, struct stat *root_dev);
int rm_rf(const char *path, RemoveFlags flags);
int rm_rf_at(int dir_fd, const char *path, RemoveFlags flags);

#endif
