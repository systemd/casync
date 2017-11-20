/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "rm-rf.h"
#include "util.h"

static int unlinkat_immutable(int dir_fd, const char *name, int flags, RemoveFlags rflags) {
        unsigned attr;
        int r, fd;

        if (unlinkat(dir_fd, name, flags) >= 0)
                return 0;

        if (errno != EPERM)
                return -errno;
        if ((rflags & REMOVE_UNDO_IMMUTABLE) == 0)
                return -EPERM;

        fd = openat(dir_fd, name, O_CLOEXEC|O_RDONLY|O_NOFOLLOW|O_NOCTTY|(flags & AT_REMOVEDIR ? O_DIRECTORY : 0));
        if (fd < 0) {
                /* If we can't open the thing because it's a symlink, propagate the original EPERM error. (Except if we are supposed to remove a directory) */
                if (errno == ELOOP)
                        return (flags & AT_REMOVEDIR) == 0 ? -EPERM : -ENOTDIR;

                return -errno;
        }

        if ((flags & AT_REMOVEDIR) == 0) {
                struct stat st;

                if (fstat(fd, &st) < 0) {
                        r = -errno;
                        goto fail;
                }

                if (S_ISDIR(st.st_mode)) {
                        /* This is a directory, but AT_REMOVEDIR wasn't set? then report it with the right error */
                        r = -EISDIR;
                        goto fail;
                }

                if (!S_ISREG(st.st_mode)) {
                        r = -EPERM; /* chattr(1) flags not supported for anything not regular files or directories, propagate the original error */
                        goto fail;
                }
        }

        if (ioctl(fd, FS_IOC_GETFLAGS, &attr) < 0) {
                /* If chattr(1) flags are not supported, propagate the original error */
                r = IN_SET(errno, ENOTTY, ENOSYS, EBADF, EOPNOTSUPP) ? -EPERM : -errno;
                goto fail;
        }

        if ((attr & FS_IMMUTABLE_FL) == 0) {
                /* immutable flag isn't set, propagate original error */
                r = -EPERM;
                goto fail;
        }

        attr &= ~FS_IMMUTABLE_FL;

        if (ioctl(fd, FS_IOC_SETFLAGS, &attr) < 0) {
                r = -errno;
                goto fail;
        }

        fd = safe_close(fd);

        if (unlinkat(dir_fd, name, flags) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        safe_close(fd);
        return r;
}

int rm_rf_children(int fd, RemoveFlags flags, struct stat *root_dev) {
        struct statfs sfs;
        struct stat _root_dev;
        int ret = 0, r;
        DIR *d = NULL;

        assert(fd >= 0);

        /* This returns the first error we run into, but nevertheless tries to go on. This closes the passed fd, even
         * on error */

        if (!(flags & REMOVE_PHYSICAL)) {

                r = fstatfs(fd, &sfs);
                if (r < 0) {
                        safe_close(fd);
                        return -errno;
                }

                if (!is_temporary_fs(&sfs)) {
                        /* We refuse to clean physical file systems with this call, unless explicitly requested. This
                         * is extra paranoia just to be sure we never ever remove non-state data */

                        safe_close(fd);
                        return -EPERM;
                }
        }

        if (!(flags & REMOVE_SPAN_DEVICES) && !root_dev) {

                if (fstat(fd, &_root_dev) < 0) {
                        safe_close(fd);
                        return -errno;
                }

                root_dev = &_root_dev;
        }

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return errno == ENOENT ? 0 : -errno;
        }

        for (;;) {
                struct dirent *de;
                struct stat st;
                bool is_dir;

                errno = 0;
                de = readdir(d);
                if (!de) {
                        if (errno != 0) {
                                ret = -errno;
                                break;
                        }

                        break;
                }

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (de->d_type == DT_UNKNOWN || (de->d_type == DT_DIR && root_dev)) {
                        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                                continue;
                        }

                        is_dir = S_ISDIR(st.st_mode);
                } else
                        is_dir = de->d_type == DT_DIR;

                if (is_dir) {
                        int subdir_fd;

                        /* if root_dev is set, remove subdirectories only if device is same */
                        if (root_dev && st.st_dev != root_dev->st_dev)
                                continue;

                        subdir_fd = openat(fd, de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                        if (subdir_fd < 0) {
                                if (ret == 0 && errno != ENOENT)
                                        ret = -errno;
                                continue;
                        }

                        /* We pass REMOVE_PHYSICAL here, to avoid doing the fstatfs() to check the file system type
                         * again for each directory */
                        r = rm_rf_children(subdir_fd, flags | REMOVE_PHYSICAL, root_dev);
                        if (r < 0 && ret == 0)
                                ret = r;

                        r = unlinkat_immutable(fd, de->d_name, AT_REMOVEDIR, flags);
                        if (r < 0) {
                                if (ret == 0 && r != -ENOENT)
                                        ret = r;
                        }

                } else if (!(flags & REMOVE_ONLY_DIRECTORIES)) {

                        r = unlinkat_immutable(fd, de->d_name, 0, flags);
                        if (r < 0) {
                                if (ret == 0 && r != -ENOENT)
                                        ret = r;
                        }
                }
        }

        closedir(d);

        return ret;
}

int rm_rf_at(int dir_fd, const char *path, RemoveFlags flags) {
        struct statfs s;
        int fd, r;

        assert(dir_fd == AT_FDCWD || dir_fd >= 0);
        assert(path);

        /* We refuse to clean the root file system with this call. This is extra paranoia to never cause a really
         * seriously broken system. */
        if (streq(path, "/"))
                return -EPERM;

        fd = openat(dir_fd, path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
        if (fd < 0) {

                if (!IN_SET(errno, ENOTDIR, ELOOP))
                        return -errno;

                /* At this point we know it's not a directory. */

                if (!(flags & REMOVE_PHYSICAL)) {

                        fd = openat(dir_fd, path, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                        if (fd < 0)
                                return -errno;

                        r = fstatfs(fd, &s);
                        safe_close(fd);
                        if (r < 0)
                                return -errno;

                        if (!is_temporary_fs(&s))
                                return -EPERM;
                }

                if ((flags & REMOVE_ROOT) && !(flags & REMOVE_ONLY_DIRECTORIES)) {
                        r = unlinkat_immutable(dir_fd, path, 0, flags);
                        if (r < 0 && r != -ENOENT)
                                return r;
                }

                return 0;
        }

        r = rm_rf_children(fd, flags, NULL);

        if (flags & REMOVE_ROOT) {
                r = unlinkat_immutable(dir_fd, path, AT_REMOVEDIR, flags);
                if (r < 0) {
                        if (r == 0 && r != -ENOENT)
                                r = r;
                }
        }

        return r;
}

int rm_rf(const char *path, RemoveFlags flags) {
        return rm_rf_at(AT_FDCWD, path, flags);
}
