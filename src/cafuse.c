/* SPDX-License-Identifier: LGPL-2.1+ */

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <linux/fs.h>
#include <linux/msdos_fs.h>

#include "caformat-util.h"
#include "caformat.h"
#include "cafuse.h"
#include "notify.h"
#include "signal-handler.h"
#include "util.h"

static CaSync *instance = NULL;
static struct fuse *fuse = NULL;

static void fuse_exit_signal_handler(int signo) {

        /* Call our own generic handler */
        exit_signal_handler(signo);

        /* Let FUSE know we are supposed to quit */
        if (fuse)
                fuse_exit(fuse);
}

static int iterate_until_file(CaSync *s) {
        int r;

        assert(s);

        for (;;) {
                int step;

                step = ca_sync_step(s);
                if (step < 0)
                        return log_error_errno(step, "Failed to run synchronizer: %m");

                switch (step) {

                case CA_SYNC_FINISHED:
                        log_error("Premature end of file.");
                        return -EIO;

                case CA_SYNC_NEXT_FILE:
                        return 0; /* Gotcha! */

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_DONE_FILE:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_FOUND:
                        break;

                case CA_SYNC_POLL:
                        r = sync_poll_sigset(s);
                        if (r == -ESHUTDOWN) /* Quit */
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to poll: %m");

                        break;

                case CA_SYNC_NOT_FOUND:
                        /* fprintf(stderr, "Not found.\n"); */
                        return -ENOENT;
                }
        }
}

static int seek_to_path(CaSync *s, const char *path) {
        int r;

        assert(s);
        assert(path);

        r = ca_sync_seek_path(s, path);
        if (r < 0)
                return log_error_errno(r, "Failed to seek for stat to %s: %m", path);

        return iterate_until_file(s);
}

static int fill_stat(CaSync *s, struct stat *stbuf) {
        mode_t mode;
        uid_t uid = 0;
        gid_t gid = 0;
        uint64_t mtime = 0;
        uint64_t size = 0;
        dev_t rdev = 0;
        int r;

        assert(s);
        assert(stbuf);

        r = ca_sync_current_mode(s, &mode);
        if (r < 0)
                return log_error_errno(r, "Failed to get current mode: %m");

        (void) ca_sync_current_uid(s, &uid);
        (void) ca_sync_current_gid(s, &gid);
        (void) ca_sync_current_mtime(s, &mtime);

        if (S_ISREG(mode))
                (void) ca_sync_current_size(s, &size);
        if (S_ISBLK(mode) || S_ISCHR(mode))
                (void) ca_sync_current_rdev(s, &rdev);

        *stbuf = (struct stat) {
                .st_mode = mode,
                .st_nlink = S_ISDIR(mode) ? 2 : 1,
                .st_size = size,
                .st_rdev = rdev,
                .st_uid = uid,
                .st_gid = gid,
                .st_mtim = NSEC_TO_TIMESPEC_INIT(mtime),
                .st_ctim = NSEC_TO_TIMESPEC_INIT(mtime),
                .st_atim = NSEC_TO_TIMESPEC_INIT(mtime),
        };

        return 0;
}

static void *casync_init(struct fuse_conn_info *conn) {
        return NULL;
}

static int casync_getattr(
                const char *path,
                struct stat *stbuf) {

        int r;

        assert(path);
        assert(stbuf);
        assert(instance);

        /* fprintf(stderr, "Got request for stat(%s).\n", path); */

        r = seek_to_path(instance, path);
        if (r < 0)
                return r;

        r = fill_stat(instance, stbuf);
        if (r < 0)
                return r;

        /* fprintf(stderr, "stat(%s) successful!\n", path); */

        return 0;
}

static int casync_readlink(
                const char *path,
                char *ret,
                size_t size) {

        const char *target;
        int r;

        assert(path);
        assert(ret);
        assert(size);

        /* fprintf(stderr, "Got request for readlink(%s).\n", path); */

        r = seek_to_path(instance, path);
        if (r < 0)
                return r;

        r = ca_sync_current_target(instance, &target);
        if (r < 0)
                return log_error_errno(r, "Failed to get symlink target: %m");

        strncpy(ret, target, size);

        /* fprintf(stderr, "readlink(%s) successful!\n", path); */

        return 0;
}

static int casync_readdir(
                const char *path,
                void *buf,
                fuse_fill_dir_t filler,
                off_t offset,
                struct fuse_file_info *info) {

        bool seen_toplevel = false;
        int r;

        /* fprintf(stderr, "Got request for readdir(%s).\n", path); */

        if (filler(buf, ".", NULL, 0) != 0)
                return -ENOBUFS;

        if (filler(buf, "..", NULL, 0) != 0)
                return -ENOBUFS;

        r = ca_sync_set_payload(instance, false);
        if (r < 0)
                return log_error_errno(r, "Failed to turn off payload: %m");

        r = ca_sync_seek_path(instance, path);
        if (r < 0)
                return log_error_errno(r, "Failed to seek to path %s: %m", path);

        for (;;) {
                int step;

                step = ca_sync_step(instance);
                if (step < 0)
                        return log_error_errno(step, "Failed to run synchronizer: %m");

                switch (step) {

                case CA_SYNC_FINISHED:
                        return 0;

                case CA_SYNC_NEXT_FILE: {
                        struct stat stbuf;
                        char *name;

                        if (!seen_toplevel) {
                                seen_toplevel = true;
                                break;
                        }

                        r = ca_sync_current_path(instance, &name);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get current path: %m");

                        r = fill_stat(instance, &stbuf);
                        if (r < 0) {
                                free(name);
                                return r;
                        }

                        if (filler(buf, basename(name), &stbuf, 0) != 0) {
                                free(name);
                                return -ENOBUFS;
                        }

                        free(name);

                        r = ca_sync_seek_next_sibling(instance);
                        if (r < 0)
                                return log_error_errno(r, "Failed to seek to next sibling: %m");

                        break;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_DONE_FILE:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_FOUND:
                        break;

                case CA_SYNC_POLL:
                        r = sync_poll_sigset(instance);
                        if (r == -ESHUTDOWN) /* Quit */
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to poll: %m");

                        break;

                case CA_SYNC_NOT_FOUND:
                        /* fprintf(stderr, "Not found: %s\n", path); */
                        return -ENOENT;
                }
        }

        /* fprintf(stderr, "readdir(%s) successful!\n", path); */

        return 0;
}
static int casync_open(const char *path, struct fuse_file_info *fi) {
        int r;

        assert(path);
        assert(fi);

        /* fprintf(stderr, "Got request for open(%s).\n", path); */

        r = seek_to_path(instance, path);
        if (r < 0)
                return r;

        if ((fi->flags & O_ACCMODE) != O_RDONLY)
                return -EACCES;

        fi->keep_cache = 1;

        /* fprintf(stderr, "open(%s) successful!\n", path); */

        return 0;
}
static int casync_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
        int r, sum = 0;

        assert(path);
        assert(buf);
        assert(size > 0);
        assert(fi);

        /* fprintf(stderr, "Got request for read(%s@%" PRIu64 ").\n", path, (uint64_t) offset); */

        r = ca_sync_set_payload(instance, true);
        if (r < 0)
                return log_error_errno(r, "Failed to turn on payload: %m");

        r = ca_sync_seek_path_offset(instance, path, offset);
        if (r < 0)
                return log_error_errno(r, "Failed to seek to path %s@%" PRIu64 ": %m", path, (uint64_t)offset);

        for (;;) {
                bool eof = false;
                int step;

                if (size == 0)
                        break;

                step = ca_sync_step(instance);
                if (step < 0)
                        return log_error_errno(step, "Failed to run synchronizer: %m");

                switch (step) {

                case CA_SYNC_FINISHED:
                        eof = true;
                        break;

                case CA_SYNC_PAYLOAD: {
                        const void *p;
                        size_t n;

                        r = ca_sync_get_payload(instance, &p, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to acquire payload: %m");

                        if (n > size)
                                n = size;

                        memcpy(buf, p, n);

                        buf += n;
                        size -= n;
                        sum += n;

                        break;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_NEXT_FILE:
                case CA_SYNC_DONE_FILE:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_FOUND:
                        break;

                case CA_SYNC_POLL:
                        r = sync_poll_sigset(instance);
                        if (r == -ESHUTDOWN) /* Quit */
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to poll: %m");

                        break;

                case CA_SYNC_NOT_FOUND:
                        /* fprintf(stderr, "Not found: %s@%" PRIu64 "\n", path, (uint64_t) offset); */
                        return -ENOENT;
                }

                if (eof)
                        break;
        }

        /* fprintf(stderr, "read(%s@%" PRIu64 ") successful!\n", path, (uint64_t) offset); */

        return sum;
}

static int casync_statfs(const char *path, struct statvfs *sfs) {
        uint64_t size = UINT64_MAX;
        int r;

        /* fprintf(stderr, "Got request for stats().\n"); */

        for (;;) {
                int step;

                r = ca_sync_get_archive_size(instance, &size);
                if (r >= 0)
                        break;
                if (r != -EAGAIN)
                        return log_error_errno(r, "Failed to acquire archive size: %m");

                step = ca_sync_step(instance);
                if (step < 0)
                        return log_error_errno(step, "Failed to run synchronizer: %m");

                switch (step) {

                case CA_SYNC_FINISHED:
                        log_error("Premature end of file.");
                        return -EIO;

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_NEXT_FILE:
                case CA_SYNC_DONE_FILE:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_FOUND:
                case CA_SYNC_NOT_FOUND:
                        break;

                case CA_SYNC_POLL:
                        r = sync_poll_sigset(instance);
                        if (r == -ESHUTDOWN) /* Quit */
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to poll: %m");
                        break;

                default:
                        assert(false);
                }
        }

        *sfs = (struct statvfs) {
                .f_namemax = CA_FORMAT_FILENAME_SIZE_MAX - offsetof(CaFormatFilename, name) - 1,
                .f_bsize = 4096,
                .f_blocks = (size + 4095) / 4096,
        };

        /* fprintf(stderr, "statfs() successful!\n"); */

        return 0;
}

static int casync_ioctl(
                const char *path,
                int cmd,
                void *arg,
                struct fuse_file_info *fi,
                unsigned int flags,
                void *data) {

        int r;

        if (flags & FUSE_IOCTL_COMPAT)
                return -ENOSYS;

        if (!IN_SET(cmd, FS_IOC_GETFLAGS, FAT_IOCTL_GET_ATTRIBUTES))
                return -ENOTTY;

        r = seek_to_path(instance, path);
        if (r < 0)
                return r;

        switch (cmd) {

        case FS_IOC_GETFLAGS: {
                unsigned chattr;

                r = ca_sync_current_chattr(instance, &chattr);
                if (r < 0)
                        return r;

                *(unsigned long*) data = chattr;
                break;
        }

        case FAT_IOCTL_GET_ATTRIBUTES: {
                uint32_t fat_attrs;

                r = ca_sync_current_fat_attrs(instance, &fat_attrs);
                if (r < 0)
                        return r;

                *(uint32_t*) data = fat_attrs;
                break;
        }

        default:
                assert(false);
        }

        return 0;
}

static int casync_getxattr(const char *path, const char *name, char *buffer, size_t size) {
        const char *n;
        const void *v;
        size_t l;
        int r;

        assert(path);
        assert(name);
        assert(buffer || size == 0);

        r = seek_to_path(instance, path);
        if (r < 0)
                return r;

        r = ca_sync_current_xattr(instance, CA_ITERATE_FIRST, &n, &v, &l);
        for (;;) {
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (streq(name, n)) {

                        if (size == 0)
                                return (int) l;
                        if (size < l)
                                return -ERANGE;

                        memcpy(buffer, v, l);
                        return (int) l;
                }

                r = ca_sync_current_xattr(instance, CA_ITERATE_NEXT, &n, &v, &l);
        }

        return -ENODATA;
}

static int casync_listxattr(const char *path, char *list, size_t size) {
        const char *n;
        size_t k = 0;
        char *p;
        int r;

        assert(path);
        assert(list || size == 0);

        r = seek_to_path(instance, path);
        if (r < 0)
                return r;

        r = ca_sync_current_xattr(instance, CA_ITERATE_FIRST, &n, NULL, NULL);
        for (;;) {
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                k += strlen(n) + 1;

                r = ca_sync_current_xattr(instance, CA_ITERATE_NEXT, &n, NULL, NULL);
        }

        if (size == 0)
                return (int) k;
        if (size < k)
                return -ERANGE;

        p = list;
        r = ca_sync_current_xattr(instance, CA_ITERATE_FIRST, &n, NULL, NULL);
        for (;;) {
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = stpcpy(p, n) + 1;

                r = ca_sync_current_xattr(instance, CA_ITERATE_NEXT, &n, NULL, NULL);
        }

        return (int) k;
}

static const struct fuse_operations ops = {
        .init      = casync_init,
        .getattr   = casync_getattr,
        .readlink  = casync_readlink,
        .readdir   = casync_readdir,
        .open      = casync_open,
        .read      = casync_read,
        .statfs    = casync_statfs,
        .ioctl     = casync_ioctl,
        .getxattr  = casync_getxattr,
        .listxattr = casync_listxattr,
};

static int feature_flags_warning(CaSync *s) {
        uint64_t ff, unsupported;
        char *t;
        int r;

        for (;;) {
                int step;

                r = ca_sync_get_feature_flags(s, &ff);
                if (r >= 0)
                        break;
                if (r != -ENODATA)
                        return log_error_errno(r, "Failed to retrieve feature flags: %m");

                step = ca_sync_step(instance);
                if (step < 0)
                        return log_error_errno(step, "Failed to run synchronizer: %m");

                switch (step) {

                case CA_SYNC_FINISHED:
                        log_error("Premature end of file.");
                        return -EIO;

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_NEXT_FILE:
                case CA_SYNC_DONE_FILE:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_FOUND:
                case CA_SYNC_NOT_FOUND:
                        break;

                case CA_SYNC_POLL:
                        r = sync_poll_sigset(s);
                        if (r == -ESHUTDOWN) /* Quit */
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to poll: %m");
                        break;

                default:
                        assert(false);
                }
        }

        unsupported = ff & ~(CA_FORMAT_WITH_FUSE|CA_FORMAT_SHA512_256|CA_FORMAT_EXCLUDE_SUBMOUNTS|CA_FORMAT_EXCLUDE_NODUMP);
        if (unsupported == 0)
                return 0;

        r = ca_with_feature_flags_format(unsupported, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to format feature flags: %m");

        log_error("The following feature flags are not exposed in the mounted file system: %s", t);
        free(t);

        return 0;
}

int ca_fuse_run(CaSync *s, const char *what, const char *where, bool do_mkdir) {
        struct fuse_chan *fc = NULL;
        const char * arguments[] = {
                "casync",
                NULL, /* -o ... */
                NULL
        };
        const char *opts;

        struct fuse_args args = {
                .argc = 2,
                .argv = (char **) arguments,
        };
        bool updated_signal_handlers = false;
        int r;

        assert(s);
        assert(where);

        assert(!fuse);
        assert(!instance);

        opts = "-oro,default_permissions,kernel_cache,subtype=casync";
        if (geteuid() == 0)
                opts = strjoina(opts, ",allow_other");
        if (what)
                opts = strjoina(opts, ",fsname=", what); /* FIXME: needs escaping */
        arguments[1] = opts;

        instance = s;

        errno = 0;
        fc = fuse_mount(where, &args);
        if (!fc) {
                r = errno != 0 ? -abs(errno) : -EIO;

                if (r == -ENOENT && do_mkdir) {
                        if (mkdir(where, 0777) < 0) {
                                r = -errno;
                                log_error("Failed to create mount directory %s: %m", where);
                                goto finish;
                        }

                        errno = 0;
                        fc = fuse_mount(where, &args);
                        r = fc ? 0 : (errno != 0 ? -abs(errno) : -EIO);
                }

                if (r < 0) {
                        log_error_errno(r, "Failed to establish FUSE mount: %m");
                        goto finish;
                }
        }

        errno = 0;
        fuse = fuse_new(fc, NULL, &ops, sizeof(ops), s);
        if (!fuse) {
                r = errno != 0 ? -abs(errno) : -ENOMEM;
                log_error_errno(r, "Failed to allocate FUSE object: %m");
                goto finish;
        }

        /* Update signal handler: in addition to our generic logic, we now also need to tell FUSE to quit */
        install_exit_handler(fuse_exit_signal_handler);
        updated_signal_handlers = true;

        printf("Mounted: %s\n", where);

        r = feature_flags_warning(s);
        if (r < 0)
                goto finish;

        if (quit) {
                r = 0;
                goto finish;
        }

        (void) send_notify("READY=1");

        r = fuse_loop(fuse);
        if (IN_SET(r, -ESHUTDOWN, -EINTR) && quit)
                r = 0;
        if (r < 0) {
                log_error_errno(r, "Failed to run FUSE loop: %m");
                goto finish;
        }

finish:
        if (updated_signal_handlers)
                install_exit_handler(NULL);

        if (fc)
                fuse_unmount(where, fc);

        if (fuse) {
                fuse_destroy(fuse);
                fuse = NULL;
        }

        instance = NULL;

        return r;
}
