#include <acl/libacl.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/msdos_fs.h>

#include "caencoder.h"
#include "caformat-util.h"
#include "caformat.h"
#include "cautil.h"
#include "def.h"
#include "fssize.h"
#include "realloc-buffer.h"
#include "siphash24.h"
#include "util.h"
#include "camakebst.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef ENXIO */
/* #define ENXIO __LINE__ */

typedef struct CaEncoderExtendedAttribute {
        char *name;
        void *data;
        size_t data_size;
} CaEncoderExtendedAttribute;

typedef struct CaEncoderACLEntry {
        char *name;
        uint64_t permissions;
        union {
                uid_t uid;
                gid_t gid;
                uint32_t generic_id;
        };
} CaEncoderACLEntry;

typedef struct CaEncoderNameTable {
        uint64_t hash;
        uint64_t start_offset;
        uint64_t end_offset;
} CaEncoderNameTable;

typedef struct CaEncoderNode {
        int fd;
        struct stat stat;
        statfs_f_type_t magic;

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
        bool chattr_flags_valid;

        /* FAT_IOCTL_GET_ATTRIBUTES flags */
        uint32_t fat_attrs;
        bool fat_attrs_valid;

        /* xattrs */
        CaEncoderExtendedAttribute *xattrs;
        size_t n_xattrs;
        bool xattrs_valid;

        /* ACLs */
        CaEncoderACLEntry *acl_user;
        size_t n_acl_user;
        CaEncoderACLEntry *acl_group;
        size_t n_acl_group;
        CaEncoderACLEntry *acl_default_user;
        size_t n_acl_default_user;
        CaEncoderACLEntry *acl_default_group;
        size_t n_acl_default_group;
        uint64_t acl_group_obj_permissions;
        uint64_t acl_default_user_obj_permissions;
        uint64_t acl_default_group_obj_permissions;
        uint64_t acl_default_other_permissions;
        uint64_t acl_default_mask_permissions;
        bool acl_valid;

        /* File system capabilities */
        void *fcaps;
        size_t fcaps_size;

        /* If this is a directory: file name lookup data */
        CaEncoderNameTable *name_table;
        size_t n_name_table;
        size_t n_name_table_allocated;
        uint64_t previous_name_table_offset;
        bool name_table_incomplete;
} CaEncoderNode;

typedef enum CaEncoderState {
        CA_ENCODER_INIT,
        CA_ENCODER_ENTERED,
        CA_ENCODER_ENTRY,
        CA_ENCODER_IN_PAYLOAD,
        CA_ENCODER_FIRST_DIRENT,
        CA_ENCODER_NEXT_DIRENT,
        CA_ENCODER_FILENAME,
        CA_ENCODER_GOODBYE,
        CA_ENCODER_EOF,
} CaEncoderState;

struct CaEncoder {
        CaEncoderState state;

        uint64_t feature_flags;
        uint64_t covering_feature_flags; /* feature flags the used file systems actually support */

        uint64_t time_granularity;

        CaEncoderNode nodes[NODES_MAX];
        size_t n_nodes;
        size_t node_idx;

        ReallocBuffer buffer;
        ReallocBuffer xattr_list_buffer;
        ReallocBuffer xattr_value_buffer;

        uint64_t archive_offset;
        uint64_t payload_offset;

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

        assert_se(ca_feature_flags_normalize(CA_FORMAT_WITH_BEST|CA_FORMAT_RESPECT_FLAG_NODUMP, &e->feature_flags) >= 0);
        e->time_granularity = 1;

        return e;
}

static CaEncoderACLEntry* ca_encoder_acl_entry_free(CaEncoderACLEntry *l, size_t n) {
        size_t i;

        for (i = 0; i < n; i++)
                free(l[i].name);

        return mfree(l);
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

        for (i = 0; i < n->n_xattrs; i++) {
                free(n->xattrs[i].name);
                free(n->xattrs[i].data);
        }
        n->xattrs = mfree(n->xattrs);
        n->n_xattrs = 0;

        n->acl_user = ca_encoder_acl_entry_free(n->acl_user, n->n_acl_user);
        n->acl_group = ca_encoder_acl_entry_free(n->acl_group, n->n_acl_group);
        n->acl_default_user = ca_encoder_acl_entry_free(n->acl_default_user, n->n_acl_default_user);
        n->acl_default_group = ca_encoder_acl_entry_free(n->acl_default_group, n->n_acl_default_group);

        n->n_acl_user = n->n_acl_group = n->n_acl_default_user = n->n_acl_default_group = 0;

        n->acl_group_obj_permissions = UINT64_MAX;
        n->acl_default_user_obj_permissions = UINT64_MAX;
        n->acl_default_group_obj_permissions = UINT64_MAX;
        n->acl_default_other_permissions = UINT64_MAX;
        n->acl_default_mask_permissions = UINT64_MAX;

        n->fcaps = mfree(n->fcaps);

        n->device_size = UINT64_MAX;

        n->stat.st_mode = 0;

        n->name_table = mfree(n->name_table);
        n->n_name_table = n->n_name_table_allocated = 0;
        n->previous_name_table_offset = UINT64_MAX;
        n->name_table_incomplete = false;
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
        realloc_buffer_free(&e->xattr_list_buffer);
        realloc_buffer_free(&e->xattr_value_buffer);

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

int ca_encoder_get_covering_feature_flags(CaEncoder *e, uint64_t *ret) {
        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = e->covering_feature_flags;
        return 0;
}

int ca_encoder_set_base_fd(CaEncoder *e, int fd) {
        struct stat st;
        struct statfs sfs;

        if (!e)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;
        if (e->n_nodes > 0)
                return -EBUSY;

        if (fstat(fd, &st) < 0)
                return -errno;
        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISBLK(st.st_mode))
                return -ENOTTY;

        e->nodes[0] = (struct CaEncoderNode) {
                .fd = fd,
                .stat = st,
                .device_size = UINT64_MAX,
                .magic = sfs.f_type,
                .acl_group_obj_permissions = UINT64_MAX,
                .acl_default_user_obj_permissions = UINT64_MAX,
                .acl_default_group_obj_permissions = UINT64_MAX,
                .acl_default_other_permissions = UINT64_MAX,
                .acl_default_mask_permissions = UINT64_MAX,
                .previous_name_table_offset = UINT64_MAX,
        };

        e->n_nodes = 1;

        return 0;
}

int ca_encoder_get_base_fd(CaEncoder *e) {
        if (!e)
                return -EINVAL;
        if (e->n_nodes == 0)
                return -EUNATCH;
        if (e->nodes[0].fd < 0)
                return -EUNATCH;

        return e->nodes[0].fd;
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

static CaEncoderNode *ca_encoder_node_parent_of(CaEncoder *e, CaEncoderNode *n) {

        size_t idx;

        assert(n >= e->nodes);
        idx = n - e->nodes;
        assert(idx < e->n_nodes);

        if (idx == 0)
                return NULL;

        return e->nodes + idx - 1;
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

static int ca_encoder_node_read_device_size(CaEncoderNode *n) {
        unsigned long u = 0;
        uint64_t fs_size;
        int r;

        assert(n);

        if (n->device_size != (uint64_t) -1)
                return 0;
        if (!S_ISBLK(n->stat.st_mode))
                return -ENOTTY;
        if (n->fd < 0)
                return -EBADFD;

        if (ioctl(n->fd, BLKGETSIZE, &u) < 0)
                return -errno;

        n->device_size = (uint64_t) u * 512;

        r = read_file_system_size(n->fd, &fs_size);
        if (r < 0)
                return r;
        if (r > 0) {
                /* The actual superblock claims a smaller size, let's fix this up. */

                if (n->device_size > fs_size)
                        n->device_size = fs_size;
        }

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
                CaEncoderNode *n) {
        int r;

        assert(e);
        assert(n);

        if (!S_ISDIR(n->stat.st_mode) && !S_ISREG(n->stat.st_mode))
                return 0;
        if (n->fd < 0)
                return -EBADFD;
        if (n->chattr_flags_valid)
                return 0;
        if ((e->feature_flags & (CA_FORMAT_WITH_CHATTR|CA_FORMAT_RESPECT_FLAG_NODUMP)) == 0)
                return 0;

        r = ioctl(n->fd, FS_IOC_GETFLAGS, &n->chattr_flags);
        if (r < 0) {
                /* If a file system or node type doesn't support chattr flags, then initialize things to zero */
                if (!IN_SET(errno, ENOTTY, EBADF, EOPNOTSUPP))
                        return -errno;

                n->chattr_flags = 0;
        }

        n->chattr_flags_valid = true;

        return 0;
}

static int ca_encoder_node_read_fat_attrs(
                CaEncoder *e,
                CaEncoderNode *n) {

        assert(e);
        assert(n);

        if (!S_ISDIR(n->stat.st_mode) && !S_ISREG(n->stat.st_mode))
                return 0;
        if (n->fd < 0)
                return -EBADFD;
        if (n->fat_attrs_valid)
                return 0;
        if ((e->feature_flags & CA_FORMAT_WITH_FAT_ATTRS) == 0)
                return 0;

        if (n->magic == MSDOS_SUPER_MAGIC) {
                if (ioctl(n->fd, FAT_IOCTL_GET_ATTRIBUTES, &n->fat_attrs) < 0)
                        return -errno;
        } else
                n->fat_attrs = 0;

        n->fat_attrs_valid = true;

        return 0;
}

static int compare_xattr(const void *a, const void *b) {
        const CaEncoderExtendedAttribute *x = a, *y = b;

        assert(x);
        assert(y);
        assert(x->name);
        assert(y->name);

        return strcmp(x->name, y->name);
}

static int ca_encoder_node_read_xattrs(
                CaEncoder *e,
                CaEncoderNode *n) {

        size_t space = 256, left, count = 0;
        bool has_fcaps = false;
        int path_fd = -1, r;
        char *q;

        assert(e);
        assert(n);

        if ((e->feature_flags & (CA_FORMAT_WITH_XATTRS|CA_FORMAT_WITH_FCAPS)) == 0)
                return 0;

        if (n->xattrs_valid)
                return 0;

        if (S_ISLNK(n->stat.st_mode))
                return 0;

        assert(!n->xattrs);
        assert(n->n_xattrs == 0);
        assert(!n->fcaps);
        assert(n->fcaps_size == 0);

        if (n->fd < 0) {
                const struct dirent *de;
                CaEncoderNode *parent;

                parent = ca_encoder_node_parent_of(e, n);
                if (!parent) {
                        r = -EUNATCH;
                        goto finish;
                }

                de = ca_encoder_node_current_dirent(parent);
                if (!de) {
                        r = -EUNATCH;
                        goto finish;
                }

                /* There's no listxattrat() unfortunately, we fake it via openat() with O_PATH */
                path_fd = openat(parent->fd, de->d_name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_PATH);
                if (path_fd < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        for (;;) {
                ssize_t l;
                char *p;

                p = realloc_buffer_acquire(&e->xattr_list_buffer, space);
                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                l = flistxattr(n->fd < 0 ? path_fd : n->fd, p, space);
                if (l < 0) {
                        /* If xattrs aren't supported there are none. EOPNOTSUPP is returned by file systems that do
                         * not support xattrs, and EBADF is returned on nodes that cannot carry xattrs (such as
                         * symlinks). */
                        if (IN_SET(errno, EOPNOTSUPP, EBADF)) {
                                n->xattrs_valid = true;
                                r = 0;
                                goto finish;
                        }
                        if (errno != ERANGE) {
                                r = -errno;
                                goto finish;
                        }
                } else {
                        realloc_buffer_truncate(&e->xattr_list_buffer, l);
                        break;
                }

                if (space*2 <= space) {
                        r = -ENOMEM;
                        goto finish;
                }

                space *= 2;
        }

        q = realloc_buffer_data(&e->xattr_list_buffer);
        left = realloc_buffer_size(&e->xattr_list_buffer);

        /* Count the number of relevant extended attributes */
        while (left > 1) {
                size_t k;

                k = strlen(q);
                assert(left >= k + 1);

                if (ca_xattr_name_store(q))
                        count ++;
                else if (streq(q, "security.capability") && S_ISREG(n->stat.st_mode))
                        has_fcaps = true;

                q += k + 1;
                left -= k + 1;
        }

        if (count == 0 && !has_fcaps) { /* None set */
                n->xattrs_valid = true;
                r = 0;
                goto finish;
        }

        if (count > 0) {
                n->xattrs = new0(CaEncoderExtendedAttribute, count);
                if (!n->xattrs) {
                        r = -ENOMEM;
                        goto finish;
                }
        }

        q = realloc_buffer_data(&e->xattr_list_buffer);
        left = realloc_buffer_size(&e->xattr_list_buffer);

        while (left > 1) {
                size_t  k;

                k = strlen(q);
                assert(left >= k + 1);

                if (ca_xattr_name_store(q) ||
                    (streq(q, "security.capability") && S_ISREG(n->stat.st_mode))) {
                        bool good = false;

                        space = 256;

                        for (;;) {
                                ssize_t l;
                                char *p;

                                p = realloc_buffer_acquire(&e->xattr_value_buffer, space);
                                if (!p) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                l = fgetxattr(n->fd < 0 ? path_fd : n->fd, q, p, space);
                                if (l < 0) {
                                        if (errno == ENODATA) /* Went missing? That's fine */
                                                break;

                                        if (errno != ERANGE) {
                                                r = -errno;
                                                goto finish;
                                        }
                                } else {
                                        realloc_buffer_truncate(&e->xattr_value_buffer, l);
                                        good = true;
                                        break;
                                }

                                if (space*2 <= space) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                space *= 2;
                        }

                        if (good) {
                                if (streq(q, "security.capability") && S_ISREG(n->stat.st_mode)) {
                                        size_t z;

                                        assert(!n->fcaps);
                                        assert(n->fcaps_size == 0);

                                        z = realloc_buffer_size(&e->xattr_value_buffer);
                                        n->fcaps = realloc_buffer_steal(&e->xattr_value_buffer);
                                        if (!n->fcaps) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        n->fcaps_size = z;

                                } else {
                                        char *name;
                                        size_t z;
                                        void *d;

                                        assert(n->xattrs);
                                        assert(n->n_xattrs < count);

                                        name = strdup(q);
                                        if (!name) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        z = realloc_buffer_size(&e->xattr_value_buffer);
                                        d = realloc_buffer_steal(&e->xattr_value_buffer);
                                        if (!d) {
                                                free(name);
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        n->xattrs[n->n_xattrs++] = (CaEncoderExtendedAttribute) {
                                                .name = name,
                                                .data = d,
                                                .data_size = z,
                                        };
                                }
                        }
                }

                q += k + 1;
                left -= k + 1;
        }

        /* Bring extended attributes in a defined order */
        if (n->n_xattrs > 1)
                qsort(n->xattrs, n->n_xattrs, sizeof(CaEncoderExtendedAttribute), compare_xattr);

        n->xattrs_valid = true;

        r = 0;
finish:
        safe_close(path_fd);

        return r;
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

static int compare_acl_entry(const void *a, const void *b) {
        const CaEncoderACLEntry *x = a, *y = b;
        int r;

        assert(x);
        assert(y);

        if (x->generic_id < y->generic_id)
                return -1;
        if (x->generic_id > y->generic_id)
                return 1;

        if (!x->name && y->name)
                return -1;
        if (x->name && !y->name)
                return 1;
        if (x->name && y->name) {
                r = strcmp(x->name, y->name);
                if (r != 0)
                        return r;
        }

        if (x->permissions < y->permissions)
                return -1;
        if (x->permissions > y->permissions)
                return 1;

        return 0;
}

static int acl_entry_permissions(acl_entry_t entry, uint64_t *ret) {

        uint64_t permissions = 0;
        acl_permset_t permset;
        int r;

        assert(entry);

        if (acl_get_permset(entry, &permset) < 0)
                return -errno;

        r = acl_get_perm(permset, ACL_READ);
        if (r < 0)
                return -errno;
        if (r > 0)
                permissions |= CA_FORMAT_ACL_PERMISSION_READ;

        r = acl_get_perm(permset, ACL_WRITE);
        if (r < 0)
                return -errno;
        if (r > 0)
                permissions |= CA_FORMAT_ACL_PERMISSION_WRITE;

        r = acl_get_perm(permset, ACL_EXECUTE);
        if (r < 0)
                return -errno;
        if (r > 0)
                permissions |= CA_FORMAT_ACL_PERMISSION_EXECUTE;

        *ret = permissions;
        return 0;
}

static int ca_encoder_node_process_acl(
                CaEncoder *e,
                CaEncoderNode *n,
                acl_type_t type,
                acl_t acl) {

        size_t n_allocated_user = 0, n_allocated_group = 0;
        uint64_t user_obj_permissions = UINT64_MAX, group_obj_permissions = UINT64_MAX, other_permissions = UINT64_MAX, mask_permissions = UINT64_MAX;
        CaEncoderACLEntry **user_entries, **group_entries;
        size_t *n_user_entries, *n_group_entries;
        acl_entry_t entry;
        int r;

        switch (type) {

        case ACL_TYPE_ACCESS:
                user_entries = &n->acl_user;
                n_user_entries = &n->n_acl_user;

                group_entries = &n->acl_group;
                n_group_entries = &n->n_acl_group;
                break;

        case ACL_TYPE_DEFAULT:
                user_entries = &n->acl_default_user;
                n_user_entries = &n->n_acl_default_user;

                group_entries = &n->acl_default_group;
                n_group_entries = &n->n_acl_default_group;
                break;

        default:
                assert(false);
        }

        for (r = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
             r > 0;
             r = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry)) {

                uint64_t permissions;
                void *q;
                acl_tag_t tag;

                if (acl_get_tag_type(entry, &tag) < 0)
                        return -errno;

                r = acl_entry_permissions(entry, &permissions);
                if (r < 0)
                        return r;

                switch (tag) {

                case ACL_USER_OBJ:
                        user_obj_permissions = permissions;
                        break;

                case ACL_GROUP_OBJ:
                        group_obj_permissions = permissions;
                        break;

                case ACL_OTHER:
                        other_permissions = permissions;
                        break;

                case ACL_MASK:
                        mask_permissions = permissions;
                        break;

                case ACL_USER: {
                        uid_t uid;
                        char *name;

                        q = acl_get_qualifier(entry);
                        if (!q)
                                return -errno;

                        uid = *(uid_t*) q;
                        acl_free(q);

                        if (!uid_is_valid(uid))
                                return -EINVAL;

                        if ((e->feature_flags & CA_FORMAT_WITH_16BIT_UIDS) && uid > UINT16_MAX)
                                return -EPROTONOSUPPORT;

                        if (e->feature_flags & CA_FORMAT_WITH_USER_NAMES) {
                                r = uid_to_name(e, uid, &name);
                                if (r < 0)
                                        return r;
                        } else
                                name = NULL;

                        if (!GREEDY_REALLOC(*user_entries, n_allocated_user, *n_user_entries+1)) {
                                free(name);
                                return -ENOMEM;
                        }

                        (*user_entries)[(*n_user_entries)++] = (CaEncoderACLEntry) {
                                .name = name,
                                .permissions = permissions,
                                .uid = (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) ? uid : 0,
                        };
                        break;
                }

                case ACL_GROUP: {
                        gid_t gid;
                        char *name;

                        q = acl_get_qualifier(entry);
                        if (!q)
                                return -errno;

                        gid = *(gid_t*) q;
                        acl_free(q);

                        if (!gid_is_valid(gid))
                                return -EINVAL;

                        if ((e->feature_flags & CA_FORMAT_WITH_16BIT_UIDS) && gid > UINT16_MAX)
                                return -EPROTONOSUPPORT;

                        if (e->feature_flags & CA_FORMAT_WITH_USER_NAMES) {
                                r = gid_to_name(e, gid, &name);
                                if (r < 0)
                                        return r;
                        } else
                                name = NULL;

                        if (!GREEDY_REALLOC(*group_entries, n_allocated_group, *n_group_entries+1)) {
                                free(name);
                                return -ENOMEM;
                        }

                        (*group_entries)[(*n_group_entries)++] = (CaEncoderACLEntry) {
                                .name = name,
                                .permissions = permissions,
                                .gid = (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) ? gid : 0,
                        };
                        break;
                }

                default:
                        assert(false);
                }
        }
        if (r < 0)
                return -errno;

        if (*n_user_entries > 1)
                qsort(*user_entries, *n_user_entries, sizeof(CaEncoderACLEntry), compare_acl_entry);
        if (*n_group_entries > 1)
                qsort(*group_entries, *n_group_entries, sizeof(CaEncoderACLEntry), compare_acl_entry);

        switch (type) {

        case ACL_TYPE_ACCESS:

                /* We only store the group object if there's also a mask set. This is because on Linux the stat()
                 * reported group permissions map to the ACL mask if one is set and the group permissions otherwise. */

                if (group_obj_permissions != UINT64_MAX && mask_permissions != UINT64_MAX)
                        n->acl_group_obj_permissions = group_obj_permissions;

                break;

        case ACL_TYPE_DEFAULT:

                n->acl_default_user_obj_permissions = user_obj_permissions;
                n->acl_default_group_obj_permissions = group_obj_permissions;
                n->acl_default_other_permissions = other_permissions;
                n->acl_default_mask_permissions = mask_permissions;
                break;

        default:
                assert(false);
        }

        return 0;
}

static int ca_encoder_node_read_acl(
                CaEncoder *e,
                CaEncoderNode *n) {

        char proc_path[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
        int path_fd = -1, r;
        acl_t acl = NULL;

        if ((e->feature_flags & CA_FORMAT_WITH_ACL) == 0)
                return 0;

        if (n->acl_valid)
                return 0;

        assert(n->n_acl_user == 0);
        assert(!n->acl_user);
        assert(n->n_acl_group == 0);
        assert(!n->acl_group);

        assert(n->n_acl_default_user == 0);
        assert(!n->acl_default_user);
        assert(n->n_acl_default_group == 0);
        assert(!n->acl_default_group);

        assert(n->acl_group_obj_permissions == UINT64_MAX);
        assert(n->acl_default_user_obj_permissions == UINT64_MAX);
        assert(n->acl_default_group_obj_permissions == UINT64_MAX);
        assert(n->acl_default_other_permissions == UINT64_MAX);
        assert(n->acl_default_mask_permissions == UINT64_MAX);

        if (S_ISLNK(n->stat.st_mode))
                return 0;

        if (n->fd < 0) {
                CaEncoderNode *parent;
                const struct dirent *de;

                parent = ca_encoder_node_parent_of(e, n);
                if (!parent) {
                        r = -EUNATCH;
                        goto finish;
                }

                de = ca_encoder_node_current_dirent(parent);
                if (!de) {
                        r = -EUNATCH;
                        goto finish;
                }

                /* There's no acl_get_fdat() unfortunately, we fake it via openat() with O_PATH */
                path_fd = openat(parent->fd, de->d_name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_PATH);
                if (path_fd < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        sprintf(proc_path, "/proc/self/fd/%i", n->fd < 0 ? path_fd : n->fd);

        acl = acl_get_file(proc_path, ACL_TYPE_ACCESS);
        if (acl) {

                r = ca_encoder_node_process_acl(e, n, ACL_TYPE_ACCESS, acl);
                if (r < 0)
                        goto finish;

                acl_free(acl);
                acl = NULL;

        } else if (!IN_SET(errno, EOPNOTSUPP, EBADF, ENODATA)) {
                r = -errno;
                goto finish;
        }

        if (S_ISDIR(n->stat.st_mode)) {
                acl = acl_get_file(proc_path, ACL_TYPE_DEFAULT);
                if (acl) {

                        r = ca_encoder_node_process_acl(e, n, ACL_TYPE_DEFAULT, acl);
                        if (r < 0)
                                goto finish;

                        acl_free(acl);
                        acl = NULL;

                } else if (!IN_SET(errno, EOPNOTSUPP, EBADF, ENODATA)) {
                        r = -errno;
                        goto finish;
                }
        }

        n->acl_valid = true;
        r = 0;

finish:
        safe_close(path_fd);

        if (acl)
                acl_free(acl);

        return r;
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
                .acl_group_obj_permissions = UINT64_MAX,
                .acl_default_user_obj_permissions = UINT64_MAX,
                .acl_default_group_obj_permissions = UINT64_MAX,
                .acl_default_other_permissions = UINT64_MAX,
                .acl_default_mask_permissions = UINT64_MAX,
        };

        return n;
}

static int ca_encoder_open_child(CaEncoder *e, CaEncoderNode *n, const struct dirent *de) {
        int r, open_flags = O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW;
        bool shall_open, have_stat;
        CaEncoderNode *child;

        assert(e);
        assert(n);
        assert(de);

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

        if (child->stat.st_dev == n->stat.st_dev ||
            child->fd < 0)
                child->magic = n->magic;
        else {
                struct statfs sfs;

                if (fstatfs(child->fd, &sfs) < 0)
                        return -errno;

                child->magic = sfs.f_type;
        }

        r = ca_encoder_node_read_symlink(n, de, child);
        if (r < 0)
                return r;

        return 0;
}

static int ca_encoder_enter_child(CaEncoder *e) {
        assert(e);

        if (e->node_idx+1 >= e->n_nodes)
                return -EINVAL;
        if (e->nodes[e->node_idx+1].stat.st_mode == 0)
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

static int ca_encoder_shall_store_child_node(CaEncoder *e) {
        CaEncoderNode *child;
        int r;

        assert(e);

        /* Check whether this node is one we should care for or skip */

        child = ca_encoder_current_child_node(e);
        if (!child)
                return -EUNATCH;

        if (!(e->feature_flags & CA_FORMAT_WITH_SYMLINKS) && S_ISLNK(child->stat.st_mode))
                return false;
        if (!(e->feature_flags & CA_FORMAT_WITH_DEVICE_NODES) && (S_ISBLK(child->stat.st_mode) || S_ISCHR(child->stat.st_mode)))
                return false;
        if (!(e->feature_flags & CA_FORMAT_WITH_FIFOS) && S_ISFIFO(child->stat.st_mode))
                return false;
        if (!(e->feature_flags & CA_FORMAT_WITH_SOCKETS) && S_ISSOCK(child->stat.st_mode))
                return false;

        r = ca_encoder_node_read_chattr(e, child);
        if (r < 0)
                return r;

        if ((e->feature_flags & CA_FORMAT_RESPECT_FLAG_NODUMP) &&
            (child->chattr_flags & FS_NODUMP_FL))
                return false;

        return true;
}

static int ca_encoder_node_shall_enumerate(CaEncoder *e, CaEncoderNode *n) {
        assert(e);
        assert(n);

        /* Checks whether we shall enumerate the dirents inside the current node (or in case of a regular file, include
         * the file contents */

        if (!S_ISDIR(n->stat.st_mode) && !S_ISREG(n->stat.st_mode)) /* We only care for files and directories here */
                return false;

        /* Exclude all virtual API file systems */
        if (IN_SET(n->magic,
                   BINFMTFS_MAGIC,
                   CGROUP2_SUPER_MAGIC,
                   CGROUP_SUPER_MAGIC,
                   CONFIGFS_MAGIC,
                   DEBUGFS_MAGIC,
                   DEVPTS_SUPER_MAGIC,
                   EFIVARFS_MAGIC,
                   FUSE_CTL_SUPER_MAGIC,
                   HUGETLBFS_MAGIC,
                   MQUEUE_MAGIC,
                   NFSD_MAGIC,
                   PROC_SUPER_MAGIC,
                   PSTOREFS_MAGIC,
                   RPCAUTH_GSSMAGIC,
                   SECURITYFS_MAGIC,
                   SELINUX_MAGIC,
                   SMACK_MAGIC,
                   SYSFS_MAGIC))
                return false;

        return true;
}

static int ca_encoder_collect_covering_feature_flags(CaEncoder *e, CaEncoderNode *n) {
        assert(e);
        assert(n);

        /* Collect all feature flags that cover the complete feature set of the underlying file systems */
        e->covering_feature_flags |= ca_feature_flags_from_magic(n->magic);

        return 0;
}

static int ca_encoder_node_get_payload_size(CaEncoderNode *n, uint64_t *ret) {
        int r;

        assert(n);
        assert(ret);

        if (S_ISREG(n->stat.st_mode)) {
                *ret = n->stat.st_size;
                return 0;
        }

        if (S_ISBLK(n->stat.st_mode)) {
                r = ca_encoder_node_read_device_size(n);
                if (r < 0)
                        return r;

                *ret = n->device_size;
                return 0;
        }

        return -ENOTTY;
}

static void ca_encoder_enter_state(CaEncoder *e, CaEncoderState state) {
        assert(e);

        e->state = state;
        e->payload_offset = 0;
}

static int ca_encoder_step_node(CaEncoder *e, CaEncoderNode *n) {
        int r;

        assert(e);
        assert(n);

        switch (e->state) {

        case CA_ENCODER_INIT:

                if (S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode))
                        /* If we are just initializing and looking at a regular file/block device, then our top-level
                         * node is serialized as its contents, hence continue in payload mode. */
                        ca_encoder_enter_state(e, CA_ENCODER_IN_PAYLOAD);
                else
                        /* Otherwise, if we are initializing and looking at anything else, then start with an ENTRY
                         * record. */
                        ca_encoder_enter_state(e, CA_ENCODER_ENTERED);

                return ca_encoder_step_node(e, n);

        case CA_ENCODER_ENTERED:

                /* We just entered this node. In this case, generate the ENTRY record for it */

                r = ca_encoder_collect_covering_feature_flags(e, n);
                if (r < 0)
                        return r;

                ca_encoder_enter_state(e, CA_ENCODER_ENTRY);
                return CA_ENCODER_NEXT_FILE;

        case CA_ENCODER_ENTRY:

                /* The ENTRY record has been generated now, let's see if we now shall serialize the conents of the
                 * node, or go to the next one right-away */

                r = ca_encoder_node_shall_enumerate(e, n);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (S_ISREG(n->stat.st_mode)) {
                                /* The ENTRY record has been generated, now go for the payload. */
                                ca_encoder_enter_state(e, CA_ENCODER_IN_PAYLOAD);
                                return ca_encoder_step_node(e, n);
                        }

                        if (S_ISDIR(n->stat.st_mode)) {
                                /* The ENTRY record has been generated, now go for the first directory entry. */
                                ca_encoder_enter_state(e, CA_ENCODER_FIRST_DIRENT);
                                return ca_encoder_step_node(e, n);
                        }
                } else {

                        if (S_ISDIR(n->stat.st_mode)) {
                                /* We shall not enumerate the entry, hence go directly for the GOODBYE record. */

                                ca_encoder_enter_state(e, CA_ENCODER_GOODBYE);
                                return CA_ENCODER_DATA;
                        }
                }

                return CA_ENCODER_FINISHED;

        case CA_ENCODER_IN_PAYLOAD: {
                uint64_t size;

                assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));

                r = ca_encoder_node_get_payload_size(n, &size);
                if (r < 0)
                        return r;

                if (e->payload_offset >= size) {
                        ca_encoder_enter_state(e, CA_ENCODER_EOF);
                        return CA_ENCODER_FINISHED;
                }

                return CA_ENCODER_PAYLOAD;
        }

        case CA_ENCODER_NEXT_DIRENT:

                if (!n->name_table_incomplete) {
                        assert(n->n_name_table > 0);
                        n->name_table[n->n_name_table-1].end_offset = e->archive_offset;
                }

                n->dirent_idx++;

                /* Fall through */

        case CA_ENCODER_FIRST_DIRENT: {
                const struct dirent *de;

                assert(S_ISDIR(n->stat.st_mode));

                r = ca_encoder_node_read_dirents(n);
                if (r < 0)
                        return r;

                for (;;) {
                        de = ca_encoder_node_current_dirent(n);
                        if (!de) {
                                if (!n->name_table_incomplete && n->n_name_table > 0)
                                        n->name_table[n->n_name_table-1].end_offset = e->archive_offset;

                                ca_encoder_enter_state(e, CA_ENCODER_GOODBYE);
                                return CA_ENCODER_DATA;
                        }

                        r = ca_encoder_open_child(e, n, de);
                        if (r < 0)
                                return r;

                        /* Check if this child is relevant to us */
                        r = ca_encoder_shall_store_child_node(e);
                        if (r < 0)
                                return r;
                        if (r > 0) /* Yay, this one's relevant */
                                break;

                        /* Nope, not relevant to us, let's try the next one */
                        n->dirent_idx++;
                }

                if (!n->name_table_incomplete) {
                        if (!GREEDY_REALLOC(n->name_table, n->n_name_table_allocated, n->n_name_table+1))
                                return -ENOMEM;

                        n->name_table[n->n_name_table++] = (CaEncoderNameTable) {
                                .start_offset = e->archive_offset,
                                .hash = siphash24(de->d_name, strlen(de->d_name), (const uint8_t[16]) CA_FORMAT_GOODBYE_HASH_KEY),
                        };
                }

                ca_encoder_enter_state(e, CA_ENCODER_FILENAME);
                return CA_ENCODER_DATA;
        }

        case CA_ENCODER_FILENAME: {
                CaEncoderNode *child;

                /* The FILENAME record was written, now enter the child */

                r = ca_encoder_enter_child(e);
                if (r < 0)
                        return r;

                child = ca_encoder_current_node(e);
                if (!child)
                        return -EUNATCH;

                ca_encoder_enter_state(e, CA_ENCODER_ENTERED);
                return ca_encoder_step_node(e, child);
        }

        case CA_ENCODER_GOODBYE:

                ca_encoder_enter_state(e, CA_ENCODER_EOF);
                return CA_ENCODER_FINISHED;

        default:
                assert(false);
        }

        assert(false);
}

static void ca_encoder_advance_buffer(CaEncoder *e) {
        size_t sz;

        assert(e);

        sz = realloc_buffer_size(&e->buffer);

        e->payload_offset += sz;
        if (e->archive_offset != UINT64_MAX)
                e->archive_offset += sz;

        realloc_buffer_empty(&e->buffer);
}

int ca_encoder_step(CaEncoder *e) {
        int r;

        if (!e)
                return -EINVAL;

        if (e->state == CA_ENCODER_EOF)
                return CA_ENCODER_FINISHED;

        ca_encoder_advance_buffer(e);

        for (;;) {
                CaEncoderNode *n;

                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;

                r = ca_encoder_step_node(e, n);
                if (r != CA_ENCODER_FINISHED)
                        return r;

                r = ca_encoder_leave_child(e);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                ca_encoder_enter_state(e, CA_ENCODER_NEXT_DIRENT);
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
        assert(e->state == CA_ENCODER_IN_PAYLOAD);

        r = ca_encoder_node_get_payload_size(n, &size);
        if (r < 0)
                return r;

        if (e->payload_offset >= size) /* at EOF? */
                return 0;

        if (realloc_buffer_size(&e->buffer) > 0) /* already in buffer? */
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

static int ca_encoder_get_filename_data(CaEncoder *e, const struct dirent *de) {
        CaFormatFilename *filename;
        size_t size;

        assert(e);
        assert(de);

        if (realloc_buffer_size(&e->buffer) > 0)
                return 1;

        size = offsetof(CaFormatFilename, name) + strlen(de->d_name) + 1;

        filename = realloc_buffer_acquire(&e->buffer, size);
        if (!filename)
                return -ENOMEM;

        filename->header = (CaFormatHeader) {
                .type = htole64(CA_FORMAT_FILENAME),
                .size = htole64(size),
        };

        strcpy(filename->name, de->d_name);

        return 1;
}

static uint64_t ca_encoder_fixup_mtime(CaEncoder *e, CaEncoderNode *n) {
        uint64_t mtime;

        assert(e);
        assert(n);

        if (e->time_granularity == UINT64_MAX)
                mtime = 0;
        else {
                mtime = timespec_to_nsec(n->stat.st_mtim);
                mtime = (mtime / e->time_granularity) * e->time_granularity;
        }

        return mtime;
}

static mode_t ca_encoder_fixup_mode(CaEncoder *e, CaEncoderNode *n) {
        mode_t mode;

        assert(e);
        assert(n);

        mode = n->stat.st_mode;
        if (S_ISLNK(mode))
                mode = S_IFLNK | 0777;
        else if (e->feature_flags & (CA_FORMAT_WITH_PERMISSIONS|CA_FORMAT_WITH_ACL))
                mode = mode & (S_IFMT|07777);
        else if (e->feature_flags & CA_FORMAT_WITH_READ_ONLY)
                mode = (mode & S_IFMT) | ((mode & 0222) ? (S_ISDIR(mode) ? 0777 : 0666) : (S_ISDIR(mode) ? 0555 : 0444));
        else
                mode = (mode & S_IFMT) | (S_ISDIR(mode) ? 0777 : 0666);

        return mode;
}

static size_t ca_encoder_format_acl_user_size(CaEncoderACLEntry *l, size_t n) {
        size_t i, size = 0;

        for (i = 0; i < n; i++)
                size += offsetof(CaFormatACLUser, name) +
                        (l[i].name ? strlen(l[i].name) + 1 : 0);

        return size;
}

static size_t ca_encoder_format_acl_group_size(CaEncoderACLEntry *l, size_t n) {
        size_t i, size = 0;

        for (i = 0; i < n; i++)
                size += offsetof(CaFormatACLGroup, name) +
                        (l[i].name ? strlen(l[i].name) + 1 : 0);

        return size;
}

static void *ca_encoder_format_acl_user_append(CaEncoder *e, void *p, uint64_t type, CaEncoderACLEntry *l, size_t n) {
        CaFormatACLUser *acl_user;
        size_t i;

        assert(e);
        assert(p);

        acl_user = alloca0(offsetof(CaFormatACLUser, name));

        for (i = 0; i < n; i++) {

                acl_user->header = (CaFormatHeader) {
                        .type = htole64(type),
                        .size = htole64(offsetof(CaFormatACLUser, name) +
                                        (l[i].name ? strlen(l[i].name) + 1 : 0)),
                };

                acl_user->uid =
                        (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) ?
                        htole64(l[i].uid) : htole64(0);
                acl_user->permissions = htole64(l[i].permissions);

                p = mempcpy(p, acl_user, offsetof(CaFormatACLUser, name));
                if (l[i].name)
                        p = stpcpy(p, l[i].name) + 1;
        }

        return p;
}

static void *ca_encoder_format_acl_group_append(CaEncoder *e, void *p, uint64_t type, CaEncoderACLEntry *l, size_t n) {
        CaFormatACLGroup *acl_group;
        size_t i;

        assert(e);
        assert(p);

        acl_group = alloca0(offsetof(CaFormatACLGroup, name));

        for (i = 0; i < n; i++) {

                acl_group->header = (CaFormatHeader) {
                        .type = htole64(type),
                        .size = htole64(offsetof(CaFormatACLGroup, name) +
                                        (l[i].name ? strlen(l[i].name) + 1 : 0)),
                };

                acl_group->gid =
                        (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) ?
                        htole64(l[i].gid) : htole64(0);
                acl_group->permissions = htole64(l[i].permissions);

                p = mempcpy(p, acl_group, offsetof(CaFormatACLGroup, name));
                if (l[i].name)
                        p = stpcpy(p, l[i].name) + 1;
        }

        return p;
}

static int ca_encoder_get_entry_data(CaEncoder *e, CaEncoderNode *n) {
        uint64_t mtime, mode, uid, gid, flags = 0, fsize;
        CaFormatEntry *entry;
        size_t size, i;
        void *p;
        int r;

        assert(e);
        assert(n);
        assert(e->state == CA_ENCODER_ENTRY);

        if (realloc_buffer_size(&e->buffer) > 0) /* Already generated */
                return 1;

        r = ca_encoder_node_read_chattr(e, n);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_fat_attrs(e, n);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_xattrs(e, n);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_acl(e, n);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_user_group_names(e, n);
        if (r < 0)
                return r;

        if (!uid_is_valid(n->stat.st_uid) ||
            !gid_is_valid(n->stat.st_gid))
                return -EINVAL;

        if ((e->feature_flags & CA_FORMAT_WITH_16BIT_UIDS) &&
            (n->stat.st_uid > UINT16_MAX ||
             n->stat.st_gid > UINT16_MAX))
                return -EPROTONOSUPPORT;

        if (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) {
                uid = n->stat.st_uid;
                gid = n->stat.st_gid;
        } else
                uid = gid = 0;

        if ((e->feature_flags & CA_FORMAT_WITH_SYMLINKS) == 0 &&
            S_ISLNK(n->stat.st_mode))
                return -EPROTONOSUPPORT;

        if ((e->feature_flags & CA_FORMAT_WITH_DEVICE_NODES) == 0 &&
            (S_ISBLK(n->stat.st_mode) || S_ISCHR(n->stat.st_mode)))
                return -EPROTONOSUPPORT;

        if ((e->feature_flags & CA_FORMAT_WITH_FIFOS) == 0 &&
            S_ISFIFO(n->stat.st_mode))
                return -EPROTONOSUPPORT;

        if ((e->feature_flags & CA_FORMAT_WITH_SOCKETS) == 0 &&
            S_ISSOCK(n->stat.st_mode))
                return -EPROTONOSUPPORT;

        mtime = ca_encoder_fixup_mtime(e, n);
        mode = ca_encoder_fixup_mode(e, n);

        if (S_ISDIR(n->stat.st_mode) || S_ISREG(n->stat.st_mode)) {
                /* chattr(1) flags and FAT file flags are only defined for regular files and directories */

                if ((e->feature_flags & CA_FORMAT_WITH_CHATTR) != 0) {
                        assert(n->chattr_flags_valid);
                        flags |= ca_feature_flags_from_chattr(n->chattr_flags) & e->feature_flags;
                }

                if ((e->feature_flags & CA_FORMAT_WITH_FAT_ATTRS) != 0) {
                        assert(n->fat_attrs_valid);
                        flags |= ca_feature_flags_from_fat_attrs(n->fat_attrs) & e->feature_flags;
                }
        }

        r = ca_encoder_node_shall_enumerate(e, n);
        if (r < 0)
                return r;
        fsize = r > 0 ? n->stat.st_size : 0;

        size = sizeof(CaFormatEntry);

        if (n->stat.st_uid == e->cached_uid && e->cached_user_name)
                size += offsetof(CaFormatUser, name) +
                        strlen(e->cached_user_name) + 1;
        if (n->stat.st_gid == e->cached_gid && e->cached_group_name)
                size += offsetof(CaFormatGroup, name) +
                        strlen(e->cached_group_name) + 1;

        for (i = 0; i < n->n_xattrs; i++)
                size += offsetof(CaFormatXAttr, name_and_value) +
                        strlen(n->xattrs[i].name) + 1 +
                        n->xattrs[i].data_size;

        size += ca_encoder_format_acl_user_size(n->acl_user, n->n_acl_user);
        size += ca_encoder_format_acl_group_size(n->acl_group, n->n_acl_group);

        if (n->acl_group_obj_permissions != UINT64_MAX)
                size += sizeof(CaFormatACLGroupObj);

        if (n->acl_default_user_obj_permissions != UINT64_MAX ||
            n->acl_default_group_obj_permissions != UINT64_MAX ||
            n->acl_default_other_permissions != UINT64_MAX ||
            n->acl_default_mask_permissions != UINT64_MAX)
                size += sizeof(CaFormatACLDefault);

        size += ca_encoder_format_acl_user_size(n->acl_default_user, n->n_acl_default_user);
        size += ca_encoder_format_acl_group_size(n->acl_default_group, n->n_acl_default_group);

        if (n->fcaps)
                size += offsetof(CaFormatFCaps, data) + n->fcaps_size;

        if (S_ISREG(n->stat.st_mode))
                size += offsetof(CaFormatPayload, data);
        else if (S_ISLNK(n->stat.st_mode))
                size += offsetof(CaFormatSymlink, target) +
                        strlen(n->symlink_target) + 1;
        else if (S_ISBLK(n->stat.st_mode) || S_ISCHR(n->stat.st_mode))
                size += sizeof(CaFormatDevice);

        entry = realloc_buffer_acquire(&e->buffer, size);
        if (!entry)
                return -ENOMEM;

        *entry = (CaFormatEntry) {
                .header.type = htole64(CA_FORMAT_ENTRY),
                .header.size = htole64(sizeof(CaFormatEntry)),
                .feature_flags = htole64(e->feature_flags),
                .mode = htole64(mode),
                .flags = htole64(flags),
                .uid = htole64(uid),
                .gid = htole64(gid),
                .mtime = htole64(mtime),
        };

        p = (uint8_t*) entry + sizeof(CaFormatEntry);

        /* Note that any follow-up structures from here are unaligned in memory! */

        if (n->stat.st_uid == e->cached_uid && e->cached_user_name) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_USER),
                        .size = htole64(offsetof(CaFormatUser, name) + strlen(e->cached_user_name) + 1),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = stpcpy(p, e->cached_user_name) + 1;
        }

        if (n->stat.st_gid == e->cached_gid && e->cached_group_name) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_GROUP),
                        .size = htole64(offsetof(CaFormatGroup, name) + strlen(e->cached_group_name) + 1),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = stpcpy(p, e->cached_group_name) + 1;
        }

        for (i = 0; i < n->n_xattrs; i++) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_XATTR),
                        .size = htole64(offsetof(CaFormatXAttr, name_and_value) +
                                        strlen(n->xattrs[i].name) + 1 +
                                        n->xattrs[i].data_size),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = stpcpy(p, n->xattrs[i].name) + 1;
                p = mempcpy(p, n->xattrs[i].data, n->xattrs[i].data_size);
        }

        p = ca_encoder_format_acl_user_append(e, p, CA_FORMAT_ACL_USER, n->acl_user, n->n_acl_user);
        p = ca_encoder_format_acl_group_append(e, p, CA_FORMAT_ACL_GROUP, n->acl_group, n->n_acl_group);

        if (n->acl_group_obj_permissions != UINT64_MAX) {
                CaFormatACLGroupObj acl_group_obj = {
                        .header.type = htole64(CA_FORMAT_ACL_GROUP_OBJ),
                        .header.size = htole64(sizeof(CaFormatACLGroupObj)),
                        .permissions = htole64(n->acl_group_obj_permissions),
                };

                p = mempcpy(p, &acl_group_obj, sizeof(acl_group_obj));
        }

        if (n->acl_default_user_obj_permissions != UINT64_MAX ||
            n->acl_default_group_obj_permissions != UINT64_MAX ||
            n->acl_default_other_permissions != UINT64_MAX ||
            n->acl_default_mask_permissions != UINT64_MAX) {
                CaFormatACLDefault acl_default = {
                        .header.type = htole64(CA_FORMAT_ACL_DEFAULT),
                        .header.size = htole64(sizeof(CaFormatACLDefault)),
                        .user_obj_permissions = htole64(n->acl_default_user_obj_permissions),
                        .group_obj_permissions = htole64(n->acl_default_group_obj_permissions),
                        .other_permissions = htole64(n->acl_default_other_permissions),
                        .mask_permissions = htole64(n->acl_default_mask_permissions),
                };

                p = mempcpy(p, &acl_default, sizeof(acl_default));
        }

        p = ca_encoder_format_acl_user_append(e, p, CA_FORMAT_ACL_DEFAULT_USER, n->acl_default_user, n->n_acl_default_user);
        p = ca_encoder_format_acl_group_append(e, p, CA_FORMAT_ACL_DEFAULT_GROUP, n->acl_default_group, n->n_acl_default_group);

        if (n->fcaps) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_FCAPS),
                        .size = htole64(offsetof(CaFormatFCaps, data) + n->fcaps_size),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = mempcpy(p, n->fcaps, n->fcaps_size);
        }

        if (S_ISREG(n->stat.st_mode)) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_PAYLOAD),
                        .size = htole64(offsetof(CaFormatPayload, data) + fsize),
                };

                memcpy(p, &header, sizeof(header));

        } else if (S_ISLNK(n->stat.st_mode)) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_SYMLINK),
                        .size = htole64(offsetof(CaFormatSymlink, target) + strlen(n->symlink_target) + 1),
                };

                p = mempcpy(p, &header, sizeof(header));
                strcpy(p, n->symlink_target);

        } else if (S_ISBLK(n->stat.st_mode) || S_ISCHR(n->stat.st_mode)) {
                CaFormatDevice device = {
                        .header.type = htole64(CA_FORMAT_DEVICE),
                        .header.size = htole64(sizeof(CaFormatDevice)),
                        .major = htole64(major(n->stat.st_rdev)),
                        .minor = htole64(minor(n->stat.st_rdev)),
                };

                memcpy(p, &device, sizeof(device));
        }

        /* fprintf(stderr, "entry at %" PRIu64 " (%s)\n", e->archive_offset, entry->name); */

        return 1;
}

static int name_table_compare(const void *a, const void *b) {
        const CaEncoderNameTable *x = a, *y = b;

        if (x->hash < y->hash)
                return -1;
        if (x->hash > y->hash)
                return 1;

        if (x->start_offset < y->start_offset)
                return -1;
        if (x->start_offset > y->start_offset)
                return 1;

        return 0;
}

static int ca_encoder_get_goodbye_data(CaEncoder *e, CaEncoderNode *n) {
        const CaEncoderNameTable *table;
        CaEncoderNameTable *bst = NULL;
        CaFormatGoodbye *g;
        size_t size, i;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));
        assert(e->state == CA_ENCODER_GOODBYE);

        if (realloc_buffer_size(&e->buffer) > 0) /* Already generated */
                return 1;

        /* If we got here through a seek we don't know the correct addresses of the directory entries, hence can't
         * correctly generate the name GOODBYE record. */
        if (n->name_table_incomplete)
                return -ENOLINK;

        size = offsetof(CaFormatGoodbye, items) +
                sizeof(CaFormatGoodbyeItem) * n->n_name_table +
                sizeof(le64_t);

        g = realloc_buffer_acquire(&e->buffer, size);
        if (!g)
                return -ENOMEM;

        g->header = (CaFormatHeader) {
                .type = htole64(CA_FORMAT_GOODBYE),
                .size = htole64(size),
        };

        if (n->n_name_table <= 1)
                table = n->name_table;
        else {
                qsort(n->name_table, n->n_name_table, sizeof(CaEncoderNameTable), name_table_compare);

                bst = new(CaEncoderNameTable, n->n_name_table);
                if (!bst)
                        return -ENOMEM;

                ca_make_bst(n->name_table, n->n_name_table, sizeof(CaEncoderNameTable), bst);

                table = bst;
        }

        for (i = 0; i < n->n_name_table; i++) {
                assert(table[i].start_offset < e->archive_offset);
                assert(table[i].end_offset <= e->archive_offset);
                assert(table[i].start_offset < table[i].end_offset);

                g->items[i] = (CaFormatGoodbyeItem) {
                        .offset = htole64(e->archive_offset - table[i].start_offset),
                        .size = htole64(table[i].end_offset - table[i].start_offset),
                        .hash = htole64(table[i].hash),
                };
        }

        free(bst);

        memcpy(g->items + n->n_name_table, &g->header.size, sizeof(le64_t));
        return 1;
}

int ca_encoder_get_data(CaEncoder *e, const void **ret, size_t *ret_size) {
        bool skip_applied = false;
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

        switch (e->state) {

        case CA_ENCODER_ENTRY:
                r = ca_encoder_get_entry_data(e, n);
                if (r < 0)
                        return r;

                break;

        case CA_ENCODER_IN_PAYLOAD:
                assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));

                skip_applied = true;

                r = ca_encoder_get_payload_data(e, n);
                break;

        case CA_ENCODER_FILENAME: {
                const struct dirent *de;

                assert(S_ISDIR(n->stat.st_mode));

                de = ca_encoder_node_current_dirent(n);
                if (!de)
                        return -EUNATCH;

                r = ca_encoder_get_filename_data(e, de);
                break;
        }

        case CA_ENCODER_GOODBYE:
                assert(S_ISDIR(n->stat.st_mode));

                r = ca_encoder_get_goodbye_data(e, n);
                break;

        default:
                return -EUNATCH;
        }

        if (r < 0)
                return r;
        if (!skip_applied && r > 0) {
                /* When we got here due to a seek, there might be an additional offset set, simply drop it form our generated buffer. */
                r = realloc_buffer_advance(&e->buffer, e->payload_offset);
                if (r < 0)
                        return r;

                r = 1;
        }
        if (r == 0) {
                /* EOF */
                *ret = NULL;
                *ret_size = 0;
                return 0;
        }

        *ret = realloc_buffer_data(&e->buffer);
        *ret_size = realloc_buffer_size(&e->buffer);

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

        if (!p) {
                p = strdup("");
                if (!p)
                        return -ENOMEM;
        }

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

        *ret = ca_encoder_fixup_mode(e, n);
        return 0;
}

int ca_encoder_current_target(CaEncoder *e, const char **ret) {
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

        if (!S_ISLNK(n->stat.st_mode))
                return -ENOLINK;

        if (!n->symlink_target)
                return -ENODATA;

        *ret = n->symlink_target;
        return 0;
}

int ca_encoder_current_mtime(CaEncoder *e, uint64_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (e->time_granularity == UINT64_MAX)
                return -ENODATA;

        n = ca_encoder_current_child_node(e);
        if (!n) {
                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;
        }

        *ret = ca_encoder_fixup_mtime(e, n);
        return 0;
}

int ca_encoder_current_size(CaEncoder *e, uint64_t *ret) {
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

        if (!S_ISREG(n->stat.st_mode))
                return -ENODATA;

        *ret = n->stat.st_size;
        return 0;
}

int ca_encoder_current_uid(CaEncoder *e, uid_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)))
                return -ENODATA;

        n = ca_encoder_current_child_node(e);
        if (!n) {
                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;
        }

        *ret = n->stat.st_uid;
        return 0;
}

int ca_encoder_current_gid(CaEncoder *e, gid_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)))
                return -ENODATA;

        n = ca_encoder_current_child_node(e);
        if (!n) {
                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;
        }

        *ret = n->stat.st_gid;
        return 0;
}

int ca_encoder_current_user(CaEncoder *e, const char **ret) {
        CaEncoderNode *n;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & (CA_FORMAT_WITH_USER_NAMES)))
                return -ENODATA;

        n = ca_encoder_current_child_node(e);
        if (!n) {
                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;
        }

        r = ca_encoder_node_read_user_group_names(e, n);
        if (r < 0)
                return r;

        if (!e->cached_user_name || e->cached_uid != n->stat.st_uid)
                return -ENODATA;

        *ret = e->cached_user_name;
        return 0;
}

int ca_encoder_current_group(CaEncoder *e, const char **ret) {
        CaEncoderNode *n;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & (CA_FORMAT_WITH_USER_NAMES)))
                return -ENODATA;

        n = ca_encoder_current_child_node(e);
        if (!n) {
                n = ca_encoder_current_node(e);
                if (!n)
                        return -EUNATCH;
        }

        r = ca_encoder_node_read_user_group_names(e, n);
        if (r < 0)
                return r;

        if (!e->cached_group_name || e->cached_gid != n->stat.st_gid)
                return -ENODATA;

        *ret = e->cached_group_name;
        return 0;
}

int ca_encoder_current_rdev(CaEncoder *e, dev_t *ret) {
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

        if (!S_ISBLK(n->stat.st_mode) && !S_ISCHR(n->stat.st_mode))
                return -ENODATA;

        *ret = n->stat.st_rdev;
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

        switch (e->state) {

        case CA_ENCODER_ENTRY:
                designator = CA_LOCATION_ENTRY;
                break;

        case CA_ENCODER_IN_PAYLOAD:
                assert(S_ISREG(node->stat.st_mode) || S_ISBLK(node->stat.st_mode));

                designator = CA_LOCATION_PAYLOAD;
                break;

        case CA_ENCODER_FILENAME:
                assert(S_ISDIR(node->stat.st_mode));

                node = ca_encoder_current_child_node(e);
                if (!node)
                        return -EUNATCH;

                designator = CA_LOCATION_FILENAME;
                break;

        case CA_ENCODER_GOODBYE:
                assert(S_ISDIR(node->stat.st_mode));

                designator = CA_LOCATION_GOODBYE;
                break;

        default:
                return -ENOTTY;
        }

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

        n->name_table_incomplete = true;

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

        return ca_encoder_open_child(e, n, de);
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

int ca_encoder_seek_location(CaEncoder *e, CaLocation *location) {
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

        case CA_LOCATION_ENTRY:

                r = ca_encoder_seek_path_and_enter(e, location->path);
                if (r < 0)
                        return r;

                node = ca_encoder_current_node(e);
                assert(node);

                node->dirent_idx = 0;

                ca_encoder_enter_state(e, CA_ENCODER_ENTRY);

                e->payload_offset = location->offset;
                e->archive_offset = UINT64_MAX;

                realloc_buffer_empty(&e->buffer);

                return CA_ENCODER_DATA;

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

                ca_encoder_enter_state(e, CA_ENCODER_IN_PAYLOAD);
                e->payload_offset = location->offset;

                if (e->node_idx == 0)
                        e->archive_offset = location->offset;
                else
                        e->archive_offset = UINT64_MAX;

                realloc_buffer_empty(&e->buffer);

                return CA_ENCODER_PAYLOAD;
        }

        case CA_LOCATION_FILENAME:

                r = ca_encoder_seek_path(e, location->path);
                if (r < 0)
                        return r;

                node = ca_encoder_current_node(e);
                assert(node);

                if (!S_ISDIR(node->stat.st_mode))
                        return -ENOTDIR;

                ca_encoder_enter_state(e, CA_ENCODER_FILENAME);

                e->payload_offset = location->offset;
                e->archive_offset = UINT64_MAX;

                realloc_buffer_empty(&e->buffer);

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

                realloc_buffer_empty(&e->buffer);

                return CA_ENCODER_DATA;

        default:
                return -EINVAL;
        }

        return 0;
}
