#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/fs.h>
#include <linux/magic.h>

#include "caencoder.h"
#include "caformat-util.h"
#include "caformat.h"
#include "def.h"
#include "realloc-buffer.h"
#include "util.h"

typedef struct CaEncoderNode {
        int fd;
        struct stat stat;

        /* For S_ISDIR */
        struct dirent **dirents;
        size_t n_dirents;
        size_t dirent_idx;

        /* For S_ISLNK */
        char *symlink_target;

        /* For S_ISBLK */
        uint64_t device_size;

        /* chattr(1) flags */
        unsigned chattr_flags;
} CaEncoderNode;

typedef enum CaEncoderState {
        CA_ENCODER_INIT,
        CA_ENCODER_HELLO,
        CA_ENCODER_ENTRY,
        CA_ENCODER_POST_CHILD,
        CA_ENCODER_GOODBYE,
        CA_ENCODER_EOF,
} CaEncoderState;

struct CaEncoder {
        CaEncoderState state;

        uint64_t feature_flags;

        uint64_t time_granularity;

        CaEncoderNode nodes[NODES_MAX];
        size_t n_nodes;
        size_t node_idx;

        ReallocBuffer buffer;

        uint64_t archive_offset;
        uint64_t payload_offset;
        uint64_t step_size;

        uid_t cached_uid;
        gid_t cached_gid;

        char *cached_user_name;
        char *cached_group_name;
};

CaEncoder *ca_encoder_new(void) {
        CaEncoder *e;

        e = new0(CaEncoder, 1);
        if (!e)
                return NULL;

        e->feature_flags = CA_FORMAT_WITH_BEST;
        e->time_granularity = 1;

        return e;
}

static void ca_encoder_node_free(CaEncoderNode *n) {
        size_t i;

        assert(n);

        if (n->fd >= 3)
                n->fd = safe_close(n->fd);
        else
                n->fd = -1;

        for (i = 0; i < n->n_dirents; i++)
                free(n->dirents[i]);
        n->dirents = mfree(n->dirents);
        n->n_dirents = 0;

        n->symlink_target = mfree(n->symlink_target);

        n->device_size = UINT64_MAX;

        n->stat.st_mode = 0;
}

CaEncoder *ca_encoder_unref(CaEncoder *e) {
        size_t i;

        if (!e)
                return NULL;

        for (i = 0; i < e->n_nodes; i++)
                ca_encoder_node_free(e->nodes + i);

        free(e->cached_user_name);
        free(e->cached_group_name);

        realloc_buffer_free(&e->buffer);
        free(e);

        return NULL;
}

int ca_encoder_set_feature_flags(CaEncoder *e, uint64_t flags) {
        int r;

        if (!e)
                return -EINVAL;

        r = ca_feature_flags_normalize(flags, &flags);
        if (r < 0)
                return r;

        r = ca_feature_flags_time_granularity_nsec(flags, &e->time_granularity);
        if (r == -ENODATA)
                e->time_granularity = UINT64_MAX;
        else if (r < 0)
                return r;

        e->feature_flags = flags;

        return 0;
}

int ca_encoder_get_feature_flags(CaEncoder *e, uint64_t *ret) {
        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = e->feature_flags;
        return 0;
}

int ca_encoder_set_base_fd(CaEncoder *e, int fd) {
        struct stat st;

        if (!e)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;
        if (e->n_nodes > 0)
                return -EBUSY;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISBLK(st.st_mode))
                return -ENOTTY;

        e->nodes[0] = (struct CaEncoderNode) {
                .fd = fd,
                .stat = st,
                .device_size = UINT64_MAX,
        };

        e->n_nodes = 1;

        return 0;
}

static CaEncoderNode* ca_encoder_current_node(CaEncoder *e) {
        assert(e);

        if (e->node_idx >= e->n_nodes)
                return NULL;

        return e->nodes + e->node_idx;
}

static CaEncoderNode* ca_encoder_current_child_node(CaEncoder *e) {
        assert(e);

        if (e->node_idx+1 >= e->n_nodes)
                return NULL;

        return e->nodes + e->node_idx + 1;
}

static CaEncoderNode *ca_encoder_node_child_of(CaEncoder *e, CaEncoderNode *n) {

        size_t idx;

        assert(n >= e->nodes);
        idx = n - e->nodes;
        assert(idx < e->n_nodes);

        if (idx+1 >= e->n_nodes)
                return NULL;

        return e->nodes + idx + 1;
}

static const struct dirent *ca_encoder_node_current_dirent(CaEncoderNode *n) {
        assert(n);

        if (n->n_dirents <= 0)
                return NULL;
        if (n->dirent_idx >= n->n_dirents)
                return NULL;

        return n->dirents[n->dirent_idx];
}

static int scandir_filter(const struct dirent *de) {
        assert(de);

        /* Filter out "." and ".." */

        return !dot_or_dot_dot(de->d_name);
}

static int scandir_compare(const struct dirent **a, const struct dirent **b) {
        assert(a);
        assert(b);

        /* We don't use alphasort() here, as we want locale-independent ordering */

        return strcmp((*a)->d_name, (*b)->d_name);
}

static int ca_encoder_node_read_dirents(CaEncoderNode *n) {
        int r;

        assert(n);

        if (n->dirents)
                return 0;
        if (!S_ISDIR(n->stat.st_mode))
                return -ENOTDIR;
        if (n->fd < 0)
                return -EBADFD;

        r = scandirat(n->fd, ".", &n->dirents, scandir_filter, scandir_compare);
        if (r < 0)
                return -errno;

        n->n_dirents = (size_t) r;
        n->dirent_idx = 0;

        return 1;
}

#define _ANDROID_BOOTIMG_MAGIC_1 0x52444e41
#define _ANDROID_BOOTIMG_MAGIC_2 0x2144494f

static int ca_encoder_node_read_device_size(CaEncoderNode *n) {
        unsigned long u = 0;
        le32_t magic;
        int r;

        struct {
                le32_t magic;

                union {
                        struct {
                                /* unsigned int   s_magic; */
                                unsigned int   inodes;
                                int            mkfs_time;
                                unsigned int   block_size;
                                unsigned int   fragments;
                                unsigned short compression;
                                unsigned short block_log;
                                unsigned short flags;
                                unsigned short no_ids;
                                unsigned short s_major;
                                unsigned short s_minor;
                                long long      root_inode;
                                le64_t         bytes_used;
                                /* ignore the rest */
                        } _packed_ squashfs;

                        struct {
                                le32_t magic2;

                                le32_t kernel_size;
                                unsigned int kernel_addr;

                                le32_t initrd_size;
                                unsigned int initrd_addr;

                                le32_t second_size;
                                unsigned int second_addr;

                                /* ignore the rest */
                        } _packed_ android_bootimg;
                };
        } _packed_ superblock;

        assert(n);

        if (n->device_size != (uint64_t) -1)
                return 0;
        if (!S_ISBLK(n->stat.st_mode))
                return -ENOTTY;
        if (n->fd < 0)
                return -EBADFD;

        r = pread(n->fd, &superblock, sizeof(superblock), 0);
        if (r == sizeof(magic))
                return -EIO;

        switch(le32toh(superblock.magic)) {
                case SQUASHFS_MAGIC:
                        n->device_size = le64toh(superblock.squashfs.bytes_used);
                        return 1;

                case _ANDROID_BOOTIMG_MAGIC_1:
                        if (le32toh(superblock.android_bootimg.magic2) == _ANDROID_BOOTIMG_MAGIC_2) {
                                n->device_size = 608 /* header size */ +
                                                 le32toh(superblock.android_bootimg.kernel_size) +
                                                 le32toh(superblock.android_bootimg.initrd_size) +
                                                 le32toh(superblock.android_bootimg.second_size);
                                return 1;
                        }

                        break;
        }

        if (ioctl(n->fd, BLKGETSIZE, &u) < 0)
                return -errno;

        n->device_size = (uint64_t) u * 512;

        return 1;
}

static int ca_encoder_node_read_symlink(
                CaEncoderNode *n,
                const struct dirent *de,
                CaEncoderNode *symlink) {

        int r;

        assert(n);
        assert(de);
        assert(symlink);

        if (!S_ISDIR(n->stat.st_mode))
                return -ENOTDIR;
        if (n->fd < 0)
                return -EBADFD;

        if (!S_ISLNK(symlink->stat.st_mode))
                return 0;
        if (symlink->symlink_target)
                return 0;

        r = readlinkat_malloc(n->fd, de->d_name, &symlink->symlink_target);
        if (r < 0)
                return r;

        return 1;
}

static int ca_encoder_node_read_chattr(
                CaEncoder *e,
                CaEncoderNode *n,
                const struct dirent *de,
                CaEncoderNode *child) {

        int fd, r;

        assert(e);
        assert(n);
        assert(de);
        assert(child);

        if (!S_ISDIR(n->stat.st_mode))
                return -ENOTDIR;
        if (n->fd < 0)
                return -EBADFD;

        if ((e->feature_flags & CA_FORMAT_WITH_CHATTR) == 0)
                return 0;

        if (child->fd < 0) {
                fd = openat(n->fd, de->d_name, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (fd < 0)
                        return -errno;
        } else
                fd = child->fd;

        r = ioctl(fd, FS_IOC_GETFLAGS, &n->chattr_flags);
        if (fd != child->fd)
                safe_close(fd);

        if (r < 0) {
                /* If a file system or node type doesn't support chattr flags, then initialize things to zero */
                if (!IN_SET(errno, ENOTTY, EBADF, EOPNOTSUPP))
                        return -errno;

                n->chattr_flags = 0;
        }

        return 0;
}

static int uid_to_name(CaEncoder *e, uid_t uid, char **ret) {
        long bufsize;
        int r;

        assert(e);
        assert(ret);

        if (uid == 0) {
                /* Don't store name for root, it's clear anyway */
                *ret = NULL;
                return 0;
        }

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize <= 0)
                bufsize = 4096;

        for (;;) {
                struct passwd pwbuf, *pw = NULL;
                char *buf;

                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;

                r = getpwuid_r(uid, &pwbuf, buf, (size_t) bufsize, &pw);
                if (r == 0 && pw) {
                        char *n;

                        n = strdup(pw->pw_name);
                        free(buf);

                        *ret = n;
                        return 1;
                }
                free(buf);
                if (r != ERANGE) {
                        /* User name cannot be retrieved */

                        if (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) {
                                *ret = NULL;
                                return 0;
                        }

                        if (asprintf(ret, UID_FMT, uid) < 0)
                                return -ENOMEM;

                        return 1;
                }

                bufsize *= 2;
        }
}

static int gid_to_name(CaEncoder *e, gid_t gid, char **ret) {
        long bufsize;
        int r;

        assert(e);
        assert(ret);

        if (gid == 0) {
                *ret = NULL;
                return 0;
        }

        bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (bufsize <= 0)
                bufsize = 4096;

        for (;;) {
                struct group grbuf, *gr = NULL;
                char *buf;

                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;

                r = getgrgid_r(gid, &grbuf, buf, (size_t) bufsize, &gr);
                if (r == 0 && gr) {
                        char *n;

                        n = strdup(gr->gr_name);
                        free(buf);

                        *ret = n;
                        return 1;
                }

                free(buf);
                if (r != ERANGE) {

                        if (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) {
                                *ret = NULL;
                                return 0;
                        }

                        if (asprintf(ret, GID_FMT, gid) < 0)
                                return -ENOMEM;

                        return 1;
                }

                bufsize *= 2;
        }
}

static int ca_encoder_node_read_user_group_names(
                CaEncoder *e,
                CaEncoderNode *n) {

        int r;

        assert(e);
        assert(n);

        if (!(e->feature_flags & CA_FORMAT_WITH_USER_NAMES))
                return 0;

        if (n->stat.st_mode == 0)
                return -EINVAL;

        /* We store the user/group name in a per-encoder variable instead of per-node, under the assumption that
         * there's a good chance we can reuse the once retrieved data between subsequent files. */

        if (!e->cached_user_name || e->cached_uid != n->stat.st_uid) {

                e->cached_user_name = mfree(e->cached_user_name);

                r = uid_to_name(e, n->stat.st_uid, &e->cached_user_name);
                if (r < 0)
                        return r;

                e->cached_uid = n->stat.st_uid;
        }

        if (!e->cached_group_name || e->cached_gid != n->stat.st_gid) {

                e->cached_group_name = mfree(e->cached_group_name);

                r = gid_to_name(e, n->stat.st_gid, &e->cached_group_name);
                if (r < 0)
                        return r;

                e->cached_gid = n->stat.st_gid;
        }

        return 0;
}

static void ca_encoder_forget_children(CaEncoder *e) {
        assert(e);

        while (e->n_nodes > e->node_idx+1)
                ca_encoder_node_free(e->nodes + --e->n_nodes);
}

static CaEncoderNode* ca_encoder_init_child(CaEncoder *e) {
        CaEncoderNode *n;

        assert(e);

        ca_encoder_forget_children(e);

        if (e->n_nodes >= NODES_MAX)
                return NULL;

        n = e->nodes + e->n_nodes++;

        *n = (CaEncoderNode) {
                .fd = -1,
                .device_size = UINT64_MAX,
        };

        return n;
}

static int ca_encoder_open_child(CaEncoder *e, const struct dirent *de) {
        CaEncoderNode *n, *child;
        int r, open_flags = O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW;
        bool shall_open, have_stat;

        assert(e);
        assert(de);

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!S_ISDIR(n->stat.st_mode))
                return -ENOTDIR;
        if (n->fd < 0)
                return -EBADFD;

        child = ca_encoder_init_child(e);
        if (!child)
                return -E2BIG;

        if (IN_SET(de->d_type, DT_DIR, DT_REG)) {
                shall_open = true;
                have_stat = false;

                if (de->d_type == DT_DIR)
                        open_flags |= O_DIRECTORY;
        } else {
                if (fstatat(n->fd, de->d_name, &child->stat, AT_SYMLINK_NOFOLLOW) < 0)
                        return -errno;

                have_stat = true;
                shall_open = S_ISREG(child->stat.st_mode) || S_ISDIR(child->stat.st_mode);

                if (S_ISDIR(child->stat.st_mode))
                        open_flags |= O_DIRECTORY;
        }

        if (shall_open) {
                child->fd = openat(n->fd, de->d_name, open_flags);
                if (child->fd < 0)
                        return -errno;

                if (!have_stat) {
                        if (fstat(child->fd, &child->stat) < 0)
                                return -errno;
                }
        }

        r = ca_encoder_node_read_symlink(n, de, child);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_chattr(e, n, de, child);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_user_group_names(e, child);
        if (r < 0)
                return r;

        return 0;
}

static int ca_encoder_enter_child(CaEncoder *e) {
        mode_t mode;

        assert(e);

        if (e->node_idx+1 >= e->n_nodes)
                return -EINVAL;
        mode = e->nodes[e->node_idx+1].stat.st_mode;
        if (mode == 0)
                return -EINVAL;
        if (!S_ISREG(mode) && !S_ISDIR(mode))
                return -ENOTTY;
        if (e->nodes[e->node_idx+1].fd < 0)
                return -EINVAL;

        e->node_idx++;
        return 0;
}

static int ca_encoder_leave_child(CaEncoder *e) {
        assert(e);

        if (e->node_idx <= 0)
                return 0;

        e->node_idx--;
        return 1;
}

static int ca_encoder_node_get_payload_size(CaEncoderNode *n, uint64_t *ret) {
        int r;

        assert(n);
        assert(ret);

        if (S_ISREG(n->stat.st_mode))
                *ret = n->stat.st_size;
        else if (S_ISBLK(n->stat.st_mode)) {
                r = ca_encoder_node_read_device_size(n);
                if (r < 0)
                        return r;

                *ret = n->device_size;
        } else
                return -ENOTTY;

        return 0;
}

static void ca_encoder_enter_state(CaEncoder *e, CaEncoderState state) {
        assert(e);

        e->state = state;

        realloc_buffer_empty(&e->buffer);

        e->payload_offset = 0;
        e->step_size = 0;
}

static int ca_encoder_step_regular(CaEncoder *e, CaEncoderNode *n) {
        uint64_t size;
        int r;

        assert(e);
        assert(n);
        assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));
        assert(e->state == CA_ENCODER_INIT);

        realloc_buffer_empty(&e->buffer);

        r = ca_encoder_node_get_payload_size(n, &size);
        if (r < 0)
                return r;

        if (e->payload_offset >= size) {
                ca_encoder_enter_state(e, CA_ENCODER_EOF);
                return CA_ENCODER_FINISHED;
        }

        return CA_ENCODER_DATA;
}

static int ca_encoder_step_directory(CaEncoder *e, CaEncoderNode *n) {
        int r;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));

        r = ca_encoder_node_read_dirents(n);
        if (r < 0)
                return r;

        switch (e->state) {

        case CA_ENCODER_INIT:
                ca_encoder_enter_state(e, CA_ENCODER_HELLO);
                return CA_ENCODER_DATA;

        case CA_ENCODER_ENTRY: {
                CaEncoderNode *child;

                child = ca_encoder_current_child_node(e);
                if (!child)
                        return -ENOTTY;

                if (S_ISDIR(child->stat.st_mode) || S_ISREG(child->stat.st_mode)) {

                        r = ca_encoder_enter_child(e);
                        if (r < 0)
                                return r;

                        ca_encoder_enter_state(e, CA_ENCODER_INIT);
                        return ca_encoder_step(e);
                }
        }

                /* Fall through */

        case CA_ENCODER_POST_CHILD:
                n->dirent_idx++;

                /* Fall through */

        case CA_ENCODER_HELLO: {
                const struct dirent *de;

                de = ca_encoder_node_current_dirent(n);
                if (!de) {
                        ca_encoder_enter_state(e, CA_ENCODER_GOODBYE);
                        return CA_ENCODER_DATA;
                }

                r = ca_encoder_open_child(e, de);
                if (r < 0)
                        return r;

                ca_encoder_enter_state(e, CA_ENCODER_ENTRY);
                return CA_ENCODER_NEXT_FILE;
        }

        case CA_ENCODER_GOODBYE:
                ca_encoder_enter_state(e, CA_ENCODER_EOF);
                return CA_ENCODER_FINISHED;

        default:
                assert(false);
        }

        assert(false);
}

int ca_encoder_step(CaEncoder *e) {
        int r;

        if (!e)
                return -EINVAL;

        if (e->state == CA_ENCODER_EOF)
                return CA_ENCODER_FINISHED;

        e->payload_offset += e->step_size;
        if (e->archive_offset != UINT64_MAX)
                e->archive_offset += e->step_size;
        e->step_size = 0;

        for (;;) {
                CaEncoderNode *n;

                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;

                if (S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode))
                        r = ca_encoder_step_regular(e, n);
                else if (S_ISDIR(n->stat.st_mode))
                        r = ca_encoder_step_directory(e, n);
                else
                        return -ENOTTY;
                if (r != CA_ENCODER_FINISHED)
                        return r;

                r = ca_encoder_leave_child(e);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                ca_encoder_enter_state(e, CA_ENCODER_POST_CHILD);
        }

        ca_encoder_forget_children(e);
        return CA_ENCODER_FINISHED;
}

static int ca_encoder_get_payload_data(CaEncoder *e, CaEncoderNode *n) {
        uint64_t size;
        ssize_t m;
        size_t k;
        void *p;
        int r;

        assert(e);
        assert(n);
        assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));
        assert(e->state == CA_ENCODER_INIT);

        r = ca_encoder_node_get_payload_size(n, &size);
        if (r < 0)
                return r;

        if (e->payload_offset >= size) /* at EOF? */
                return 0;

        if (e->buffer.size > 0) /* already in buffer? */
                return 1;

        k = (size_t) MIN(BUFFER_SIZE, size - e->payload_offset);

        p = realloc_buffer_acquire(&e->buffer, k);
        if (!p)
                return -ENOMEM;

        m = read(n->fd, p, k);
        if (m < 0) {
                r = -errno;
                goto fail;
        }
        if ((size_t) m != k) {
                r = -EIO;
                goto fail;
        }

        return 1;

fail:
        realloc_buffer_empty(&e->buffer);
        return r;
}

static int ca_encoder_get_hello_data(CaEncoder *e, CaEncoderNode *n) {
        CaFormatHello *h;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));
        assert(e->state == CA_ENCODER_HELLO);

        if (e->buffer.size > 0) /* Already generated */
                return 1;

        h = realloc_buffer_acquire(&e->buffer, sizeof(CaFormatHello));
        if (!h)
                return -ENOMEM;

        *h = (CaFormatHello) {
                .header.type = htole64(CA_FORMAT_HELLO),
                .header.size = htole64(sizeof(CaFormatHello)),
                .uuid_part2 = htole64(CA_FORMAT_HELLO_UUID_PART2),
                .feature_flags = htole64(e->feature_flags),
        };

        return 1;
}

static int ca_encoder_get_entry_data(CaEncoder *e, CaEncoderNode *n) {
        const struct dirent *de;
        CaFormatEntry *entry;
        CaEncoderNode *child;
        uint64_t mtime, mode, uid, gid, flags;
        size_t size;
        char *p;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));
        assert(e->state == CA_ENCODER_ENTRY);

        if (e->buffer.size > 0) /* Already generated */
                return 1;

        de = ca_encoder_node_current_dirent(n);
        if (!de)
                return -EILSEQ;

        child = ca_encoder_current_child_node(e);
        if (!child)
                return -EILSEQ;

        if (!uid_is_valid(child->stat.st_uid) ||
            !gid_is_valid(child->stat.st_gid))
                return -EINVAL;

        if ((e->feature_flags & CA_FORMAT_WITH_16BIT_UIDS) &&
            (child->stat.st_uid > UINT16_MAX ||
             child->stat.st_gid > UINT16_MAX))
                return -EPROTONOSUPPORT;

        if (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) {
                uid = child->stat.st_uid;
                gid = child->stat.st_gid;
        } else
                uid = gid = 0;

        if ((e->feature_flags & CA_FORMAT_WITH_SYMLINKS) == 0 &&
            S_ISLNK(child->stat.st_mode))
                return -EPROTONOSUPPORT;

        if ((e->feature_flags & CA_FORMAT_WITH_DEVICE_NODES) == 0 &&
            (S_ISBLK(child->stat.st_mode) || S_ISCHR(child->stat.st_mode)))
                return -EPROTONOSUPPORT;

        if ((e->feature_flags & CA_FORMAT_WITH_FIFOS) == 0 &&
            S_ISFIFO(child->stat.st_mode))
                return -EPROTONOSUPPORT;

        if ((e->feature_flags & CA_FORMAT_WITH_SOCKETS) == 0 &&
            S_ISSOCK(child->stat.st_mode))
                return -EPROTONOSUPPORT;

        if (e->time_granularity == UINT64_MAX)
                mtime = 0;
        else {
                mtime = timespec_to_nsec(child->stat.st_mtim);
                mtime = (mtime / e->time_granularity) * e->time_granularity;
        }

        mode = child->stat.st_mode;
        if (S_ISLNK(mode))
                mode = S_IFLNK | 0777;
        if (e->feature_flags & CA_FORMAT_WITH_PERMISSIONS)
                mode = mode & (S_IFMT|07777);
        else if (e->feature_flags & CA_FORMAT_WITH_READ_ONLY)
                mode = (mode & S_IFMT) | ((mode & 0222) ? (S_ISDIR(mode) ? 0777 : 0666) : (S_ISDIR(mode) ? 0555 : 0444));
        else
                mode &= S_IFMT;

        if ((e->feature_flags & CA_FORMAT_WITH_CHATTR) != 0)
                flags = ca_feature_flags_from_chattr(n->chattr_flags) & e->feature_flags;
        else
                flags = 0;

        size = offsetof(CaFormatEntry, name) + strlen(de->d_name) + 1;

        if (child->stat.st_uid == e->cached_uid && e->cached_user_name)
                size += offsetof(CaFormatUser, name) +
                        strlen(e->cached_user_name) + 1;
        if (child->stat.st_gid == e->cached_gid && e->cached_group_name)
                size += offsetof(CaFormatGroup, name) +
                        strlen(e->cached_group_name) + 1;

        if (S_ISREG(child->stat.st_mode))
                size += offsetof(CaFormatPayload, data);
        else if (S_ISLNK(child->stat.st_mode))
                size += offsetof(CaFormatSymlink, target) +
                        strlen(child->symlink_target) + 1;
        else if (S_ISBLK(child->stat.st_mode) || S_ISCHR(child->stat.st_mode))
                size += sizeof(CaFormatDevice);

        entry = realloc_buffer_acquire0(&e->buffer, size);
        if (!entry)
                return -ENOMEM;

        entry->header = (CaFormatHeader) {
                .type = htole64(CA_FORMAT_ENTRY),
                .size = htole64(offsetof(CaFormatEntry, name) + strlen(de->d_name) + 1),
        };
        entry->flags = htole64(flags);
        entry->mode = htole64(mode);
        entry->uid = htole64(uid);
        entry->gid = htole64(gid);
        entry->mtime = htole64(mtime);

        p = stpcpy(entry->name, de->d_name) + 1;

        /* Note that any follow-up structures from here are unaligned in memory! */

        if (child->stat.st_uid == e->cached_uid && e->cached_user_name) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_USER),
                        .size = htole64(offsetof(CaFormatUser, name) + strlen(e->cached_user_name) + 1),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = stpcpy(p, e->cached_user_name) + 1;
        }

        if (child->stat.st_gid == e->cached_gid && e->cached_group_name) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_GROUP),
                        .size = htole64(offsetof(CaFormatGroup, name) + strlen(e->cached_group_name) + 1),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = stpcpy(p, e->cached_group_name) + 1;
        }

        if (S_ISREG(child->stat.st_mode)) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_PAYLOAD),
                        .size = htole64(offsetof(CaFormatPayload, data) + child->stat.st_size),
                };

                memcpy(p, &header, sizeof(header));

        } else if (S_ISLNK(child->stat.st_mode)) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_SYMLINK),
                        .size = htole64(offsetof(CaFormatSymlink, target) + strlen(child->symlink_target) + 1),
                };

                p = mempcpy(p, &header, sizeof(header));
                strcpy(p, child->symlink_target);

        } else if (S_ISBLK(child->stat.st_mode) || S_ISCHR(child->stat.st_mode)) {
                CaFormatDevice device = {
                        .header.type = htole64(CA_FORMAT_DEVICE),
                        .header.size = htole64(sizeof(CaFormatDevice)),
                        .major = htole64(major(child->stat.st_rdev)),
                        .minor = htole64(minor(child->stat.st_rdev)),
                };

                memcpy(p, &device, sizeof(device));
        }

        /* fprintf(stderr, "entry at %" PRIu64 " (%s)\n", e->archive_offset, entry->name); */

        return 1;
}

static int ca_encoder_get_goodbye_data(CaEncoder *e, CaEncoderNode *n) {
        CaFormatGoodbye *g;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));
        assert(e->state == CA_ENCODER_GOODBYE);

        if (e->buffer.size > 0) /* Already generated */
                return 1;

        g = realloc_buffer_acquire0(&e->buffer,
                                   offsetof(CaFormatGoodbye, table) +
                                   sizeof(le64_t));
        if (!g)
                return -ENOMEM;

        g->header = (CaFormatHeader) {
                .type = htole64(CA_FORMAT_GOODBYE),
                .size = htole64(offsetof(CaFormatGoodbye, table) + sizeof(le64_t)),
        };

        memcpy(g->table, &g->header.size, sizeof(le64_t));
        return 1;
}

int ca_encoder_get_data(CaEncoder *e, const void **ret, size_t *ret_size) {
        CaEncoderNode *n;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode)) {

                if (e->state != CA_ENCODER_INIT)
                        return -ENOTTY;

                r = ca_encoder_get_payload_data(e, n);
                if (r < 0)
                        return r;

        } else if (S_ISDIR(n->stat.st_mode)) {

                switch (e->state) {

                case CA_ENCODER_HELLO:
                        r = ca_encoder_get_hello_data(e, n);
                        break;

                case CA_ENCODER_ENTRY:
                        r = ca_encoder_get_entry_data(e, n);
                        break;

                case CA_ENCODER_GOODBYE:
                        r = ca_encoder_get_goodbye_data(e, n);
                        break;

                default:
                        return -ENOTTY;
                }
                if (r < 0)
                        return r;

                if (r > 0) {
                        /* When we got here due to a seek, there might be an additional offset set, simply drop it form our generated buffer. */
                        r = realloc_buffer_advance(&e->buffer, e->payload_offset);
                        if (r < 0)
                                return r;

                        r = 1;
                }

        } else
                return -ENOTTY;
        if (r == 0) {
                /* EOF */
                *ret = NULL;
                *ret_size = 0;

                e->step_size = 0;
                return 0;
        }

        *ret = e->buffer.data;
        *ret_size = e->buffer.size;
        e->step_size = e->buffer.size;

        return 1;
}

static int ca_encoder_node_path(CaEncoder *e, CaEncoderNode *node, char **ret) {
        char *p = NULL;
        size_t n = 0, i;
        bool found = false;

        if (!e)
                return -EINVAL;
        if (!node)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        for (i = 0; i <= e->n_nodes; i++) {
                CaEncoderNode *in;
                const struct dirent *de;
                char *np, *q;
                size_t k, nn;

                in = e->nodes + i;

                if (in == node) {
                        found = true;
                        break;
                }

                de = ca_encoder_node_current_dirent(in);
                if (!de)
                        break;

                k = strlen(de->d_name);
                nn = n + (n > 0) + k;

                np = realloc(p, nn+1);
                if (!np) {
                        free(p);
                        return -ENOMEM;
                }

                q = np + n;
                if (n > 0)
                        *(q++) = '/';

                strcpy(q, de->d_name);

                p = np;
                n = nn;
        }

        if (!found) {
                free(p);
                return -EINVAL;
        }

        if (!p)
                return -ENOTDIR;

        *ret = p;
        return 0;
}

int ca_encoder_current_path(CaEncoder *e, char **ret) {
        CaEncoderNode *node;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        node = ca_encoder_current_child_node(e);
        if (!node) {
                node = ca_encoder_current_node(e);
                if (!node)
                        return -EUNATCH;
        }

        return ca_encoder_node_path(e, node, ret);
}

int ca_encoder_current_mode(CaEncoder *e, mode_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_child_node(e);
        if (!n) {
                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;
        }

        *ret = n->stat.st_mode;
        return 0;
}

int ca_encoder_current_payload_offset(CaEncoder *e, uint64_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!S_ISREG(n->stat.st_mode) && !S_ISBLK(n->stat.st_mode))
                return -EISDIR;

        *ret = e->payload_offset;
        return 0;
}

int ca_encoder_current_archive_offset(CaEncoder *e, uint64_t *ret) {
        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (e->archive_offset == UINT64_MAX)
                return -ENODATA;

        *ret = e->archive_offset;
        return 0;
}

int ca_encoder_current_location(CaEncoder *e, uint64_t add, CaLocation **ret) {
        CaLocationDesignator designator;
        CaEncoderNode *node;
        char *path = NULL;
        CaLocation *l;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        node = ca_encoder_current_node(e);
        if (!node)
                return -EUNATCH;

        if (S_ISREG(node->stat.st_mode) || S_ISBLK(node->stat.st_mode)) {

                if (e->state != CA_ENCODER_INIT)
                        return -ENOTTY;

                designator = CA_LOCATION_PAYLOAD;

        } else if (S_ISDIR(node->stat.st_mode)) {

                switch (e->state) {

                case CA_ENCODER_HELLO:
                        designator = CA_LOCATION_HELLO;
                        break;

                case CA_ENCODER_ENTRY:
                        node = ca_encoder_current_child_node(e);
                        if (!node)
                                return -EUNATCH;

                        designator = CA_LOCATION_ENTRY;
                        break;

                case CA_ENCODER_GOODBYE:
                        designator = CA_LOCATION_GOODBYE;
                        break;

                default:
                        return -ENOTTY;
                }
        } else
                return -ENOTTY;

        r = ca_encoder_node_path(e, node, &path);
        if (r < 0 && r != -ENOTDIR)
                return r;

        r = ca_location_new(path, designator, e->payload_offset + add, UINT64_MAX, &l);
        free(path);
        if (r < 0)
                return r;

        *ret = l;
        return 0;
}

static int dirent_bsearch_func(const void *key, const void *member) {
        const char *k = key;
        const struct dirent ** const m = (const struct dirent ** const) member;

        return strcmp(k, (*m)->d_name);
}

static int ca_encoder_node_seek_child(CaEncoder *e, CaEncoderNode *n, const char *name) {
        const struct dirent *de;
        int r;

        assert(n);

        if (!S_ISDIR(n->stat.st_mode))
                return -ENOTDIR;

        r = ca_encoder_node_read_dirents(n);
        if (r < 0)
                return r;

        de = ca_encoder_node_current_dirent(n);
        if (de && streq(name, de->d_name)) {
                CaEncoderNode *child;

                child = ca_encoder_node_child_of(e, n);
                if (child && child->stat.st_mode != 0)
                        return 0;

        } else {
                struct dirent **found;

                found = bsearch(name, n->dirents, n->n_dirents, sizeof(struct dirent*), dirent_bsearch_func);
                if (!found)
                        return -ENOENT;

                assert(found >= n->dirents);
                assert((size_t) (found - n->dirents) < n->n_dirents);
                n->dirent_idx = found - n->dirents;

                de = *found;
        }

        return ca_encoder_open_child(e, de);
}

static int ca_encoder_seek_path(CaEncoder *e, const char *path) {
        CaEncoderNode *node;
        int r;

        assert(e);
        assert(path);

        /* fprintf(stderr, "seeking to: %s\n", path); */

        node = ca_encoder_current_node(e);
        if (!node)
                return -EUNATCH;

        for (;;) {
                size_t l = strcspn(path, "/");
                char name[l + 1];

                if (l <= 0)
                        return -EINVAL;

                if (!S_ISDIR(node->stat.st_mode))
                        return -ENOTDIR;

                memcpy(name, path, l);
                name[l] = 0;

                r = ca_encoder_node_seek_child(e, node, name);
                if (r < 0)
                        return r;

                path += l;
                if (*path == 0)
                        break;
                path++;

                r = ca_encoder_enter_child(e);
                if (r < 0)
                        return r;

                node = ca_encoder_current_node(e);
                assert(node);
        }

        return 0;
}

static int ca_encoder_seek_path_and_enter(CaEncoder *e, const char *path) {
        int r;

        assert(e);

        if (isempty(path))
                return 0;

        r = ca_encoder_seek_path(e, path);
        if (r < 0)
                return r;

        return ca_encoder_enter_child(e);
}

int ca_encoder_seek(CaEncoder *e, CaLocation *location) {
        CaEncoderNode *node;
        int r;

        if (!e)
                return -EINVAL;
        if (!location)
                return -EINVAL;
        if (location->size == 0)
                return -EINVAL;
        if (!CA_LOCATION_DESIGNATOR_VALID(location->designator))
                return -EINVAL;

        if (e->n_nodes == 0)
                return -EUNATCH;

        e->node_idx = 0;

        switch (location->designator) {

        case CA_LOCATION_PAYLOAD: {
                uint64_t size;

                r = ca_encoder_seek_path_and_enter(e, location->path);
                if (r < 0)
                        return r;

                node = ca_encoder_current_node(e);
                assert(node);

                if (!S_ISREG(node->stat.st_mode) && !S_ISBLK(node->stat.st_mode))
                        return -EISDIR;

                r = ca_encoder_node_get_payload_size(node, &size);
                if (r < 0)
                        return r;

                if (location->offset >= size)
                        return -ENXIO;

                if (lseek(node->fd, location->offset, SEEK_SET) == (off_t) -1)
                        return -errno;

                ca_encoder_enter_state(e, CA_ENCODER_INIT);
                e->payload_offset = location->offset;

                if (e->node_idx == 0)
                        e->archive_offset = location->offset;
                else
                        e->archive_offset = UINT64_MAX;

                return CA_ENCODER_DATA;
        }

        case CA_LOCATION_HELLO:

                r = ca_encoder_seek_path_and_enter(e, location->path);
                if (r < 0)
                        return r;

                node = ca_encoder_current_node(e);
                assert(node);

                if (!S_ISDIR(node->stat.st_mode))
                        return -ENOTDIR;

                node->dirent_idx = 0;
                ca_encoder_enter_state(e, CA_ENCODER_HELLO);

                e->payload_offset = location->offset;
                e->archive_offset = UINT64_MAX;

                return CA_ENCODER_DATA;

        case CA_LOCATION_ENTRY:

                if (isempty(location->path))
                        return -ENOTDIR;

                r = ca_encoder_seek_path(e, location->path);
                if (r < 0)
                        return r;

                node = ca_encoder_current_node(e);
                assert(node);

                if (!S_ISDIR(node->stat.st_mode))
                        return -ENOTDIR;

                ca_encoder_enter_state(e, CA_ENCODER_ENTRY);

                e->payload_offset = location->offset;
                e->archive_offset = UINT64_MAX;

                return CA_ENCODER_DATA;

        case CA_LOCATION_GOODBYE:

                r = ca_encoder_seek_path_and_enter(e, location->path);
                if (r < 0)
                        return r;

                node = ca_encoder_current_node(e);
                assert(node);

                if (!S_ISDIR(node->stat.st_mode))
                        return -ENOTDIR;

                r = ca_encoder_node_read_dirents(node);
                if (r < 0)
                        return r;

                node->dirent_idx = node->n_dirents;
                ca_encoder_enter_state(e, CA_ENCODER_GOODBYE);

                e->payload_offset = location->offset;
                e->archive_offset = UINT64_MAX;

                return CA_ENCODER_DATA;

        default:
                return -EINVAL;
        }

        return 0;
}
