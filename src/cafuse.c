#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <linux/fs.h>

#include "caformat.h"
#include "cafuse.h"
#include "util.h"

static CaSync *instance = NULL;

static int iterate_until_file(CaSync *s) {
        int r;

        assert(s);

        for (;;) {
                int step;

                step = ca_sync_step(s);
                if (step < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-step));
                        return step;
                }

                switch (step) {

                case CA_SYNC_FINISHED:
                        fprintf(stderr, "Premature end of file.\n");
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
                        r = ca_sync_poll(s, UINT64_MAX, NULL);
                        if (r < 0) {
                                fprintf(stderr, "Failed to poll: %s\n", strerror(-r));
                                return r;
                        }

                        return 0;

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
        if (r < 0) {
                fprintf(stderr, "Failed to seek for stat to %s: %s\n", path, strerror(-r));
                return r;
        }

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
        if (r < 0) {
                fprintf(stderr, "Failed to get current mode: %s\n", strerror(-r));
                return r;
        }

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
        if (r < 0) {
                fprintf(stderr, "failed to get symlink target: %s\n", strerror(-r));
                return r;
        }

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
        if (r < 0) {
                fprintf(stderr, "Failed to turn off payload: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_seek_path(instance, path);
        if (r < 0) {
                fprintf(stderr, "Failed to seek to path %s: %s\n", path, strerror(-r));
                return r;
        }

        for (;;) {
                int step;

                step = ca_sync_step(instance);
                if (step < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-step));
                        return step;
                }

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
                        if (r < 0) {
                                fprintf(stderr, "Failed to get current path: %s\n", strerror(-r));
                                return r;
                        }

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
                        if (r < 0) {
                                fprintf(stderr, "Failed to seek to next sibling: %s\n", strerror(-r));
                                return r;
                        }

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
                        r = ca_sync_poll(instance, UINT64_MAX, NULL);
                        if (r < 0) {
                                fprintf(stderr, "Failed to poll: %s\n", strerror(-r));
                                return r;
                        }

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
        if (r < 0) {
                fprintf(stderr, "Failed to turn on payload: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_seek_path_offset(instance, path, offset);
        if (r < 0) {
                fprintf(stderr, "Failed to seek to path %s@%" PRIu64 ": %s\n", path, (uint64_t) offset, strerror(-r));
                return r;
        }

        for (;;) {
                bool eof = false;
                int step;

                if (size == 0)
                        break;

                step = ca_sync_step(instance);
                if (step < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-step));
                        return step;
                }

                switch (step) {

                case CA_SYNC_FINISHED:
                        eof = true;
                        break;

                case CA_SYNC_PAYLOAD: {
                        const void *p;
                        size_t n;

                        r = ca_sync_get_payload(instance, &p, &n);
                        if (r < 0) {
                                fprintf(stderr, "Failed to acquire payload: %s\n", strerror(-r));
                                return r;
                        }

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
                        r = ca_sync_poll(instance, UINT64_MAX, NULL);
                        if (r < 0) {
                                fprintf(stderr, "Failed to poll: %s\n", strerror(-r));
                                return r;
                        }

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
                if (r != -EAGAIN) {
                        fprintf(stderr, "Failed to acquire archive size: %s\n", strerror(-r));
                        return r;
                }

                step = ca_sync_step(instance);
                if (step < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-step));
                        return step;
                }

                switch (step) {

                case CA_SYNC_FINISHED:
                        fprintf(stderr, "Premature end of file.\n");
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
                        r = ca_sync_poll(instance, UINT64_MAX, NULL);
                        if (r < 0) {
                                fprintf(stderr, "Failed to poll: %s\n", strerror(-r));
                                return r;
                        }
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

        int r, gf;

        if (flags & FUSE_IOCTL_COMPAT)
                return -ENOSYS;

        gf = FS_IOC_GETFLAGS;
        if (cmd != gf)
                return -ENOTTY;

        r = seek_to_path(instance, path);
        if (r < 0)
                return r;

        r = ca_sync_current_chattr(instance, &flags);
        if (r < 0)
                return r;

        *(unsigned long*) data = flags;
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

static struct fuse_operations ops = {
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

int ca_fuse_run(CaSync *s, const char *what, const char *where, bool do_mkdir) {
        struct fuse_chan *fc = NULL;
        struct fuse *f = NULL;
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
        int r;

        assert(s);
        assert(where);

        opts = "-oro,default_permissions,kernel_cache,subtype=casync";
        if (geteuid() == 0)
                opts = strjoina(opts, ",allow_other");
        if (what)
                opts = strjoina(opts, ",fsname=", what); /* FIXME: needs escaping */
        arguments[1] = opts;

        assert(!instance);
        instance = s;

        errno = 0;
        fc = fuse_mount(where, &args);
        if (!fc) {
                r = errno != 0 ? -abs(errno) : -EIO;

                if (r == -ENOENT && do_mkdir) {
                        if (mkdir(where, 0777) < 0) {
                                r = -errno;
                                fprintf(stderr, "Failed to create mount directory %s: %s\n", where, strerror(-r));
                                goto finish;
                        }

                        errno = 0;
                        fc = fuse_mount(where, &args);
                        r = fc ? 0 : (errno != 0 ? -abs(errno) : -EIO);
                }

                if (r < 0) {
                        fprintf(stderr, "Failed to establish FUSE mount: %s\n", strerror(-r));
                        goto finish;
                }
        }

        errno = 0;
        f = fuse_new(fc, NULL, &ops, sizeof(ops), s);
        if (!f) {
                r = errno != 0 ? -abs(errno) : -ENOMEM;
                fprintf(stderr, "Failed to allocate FUSE object: %s\n", strerror(-r));
                goto finish;
        }

        r = fuse_loop(f);
        if (r < 0) {
                fprintf(stderr, "Failed to run FUSE loop: %s\n", strerror(-r));
                goto finish;
        }

        r = 0;

finish:
        if (fc)
                fuse_unmount(where, fc);

        if (f)
                fuse_destroy(f);

        instance = NULL;

        return r;
}
