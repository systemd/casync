/* SPDX-License-Identifier: LGPL-2.1+ */

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

#if HAVE_SELINUX
#  include <selinux/selinux.h>
#endif

#include "caencoder.h"
#include "caformat-util.h"
#include "caformat.h"
#include "camakebst.h"
#include "camatch.h"
#include "canametable.h"
#include "cautil.h"
#include "chattr.h"
#include "def.h"
#include "fssize.h"
#include "quota-projid.h"
#include "realloc-buffer.h"
#include "siphash24.h"
#include "time-util.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef ENXIO */
/* #define ENXIO __LINE__ */

/* Encodes whether we found a ".caexclude" file in this directory, and if we did, whether we loaded it */
typedef enum CaEncoderHasExcludeFile {
        CA_ENCODER_HAS_EXCLUDE_FILE_DONT_KNOW = -1,
        CA_ENCODER_HAS_EXCLUDE_FILE_NO = 0,
        CA_ENCODER_HAS_EXCLUDE_FILE_YES,
        CA_ENCODER_HAS_EXCLUDE_FILE_LOADED,
} CaEncoderHasExcludeFile;

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
        size_t xattrs_idx;

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

        /* btrfs subvolume flags */
        bool is_subvolume:1;
        bool is_subvolume_ro:1;
        bool subvolume_valid:1;

        /* SELinux label */
        bool selinux_label_valid:1;
        char *selinux_label;

        /* The FS_IOC_GETVERSION generation */
        int generation;
        int generation_valid; /* tri-state */

        /* The quota project ID, on file systems that support this (ext4, XFS) */
        uint32_t quota_projid;
        bool quota_projid_valid;

        /* If this is a directory: file name lookup data */
        CaNameTable *name_table;

        /* For detecting mount boundaries */
        int mount_id;

        /* Whether there's a ".caexclude" file in this directory, and whether it's loaded */
        CaEncoderHasExcludeFile has_exclude_file;
        CaMatch *exclude_match;
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
        CA_ENCODER_FINALIZE,
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
        uint64_t skipped_bytes;

        uid_t cached_uid;
        gid_t cached_gid;

        char *cached_user_name;
        char *cached_group_name;

        uid_t uid_shift;
        uid_t uid_range; /* uid_range == 0 means "full range" */

        CaDigest *archive_digest;
        CaDigest *payload_digest;
        CaDigest *hardlink_digest;

        bool payload_digest_invalid:1;
        bool hardlink_digest_invalid:1;

        bool want_archive_digest:1;
        bool want_payload_digest:1;
        bool want_hardlink_digest:1;
};

#define CA_ENCODER_AT_ROOT(e) ((e)->node_idx == 0)

static inline bool CA_ENCODER_IS_NAKED(CaEncoder *e) {
        assert(e);

        /* Returns true if we are encoding a naked blob, i.e. a top-level payload, in contrast to a directory tree */

        return e &&
                e->n_nodes == 1 &&
                e->nodes[0].stat.st_mode != 0 &&
                (S_ISREG(e->nodes[0].stat.st_mode) || S_ISBLK(e->nodes[0].stat.st_mode));
}

CaEncoder *ca_encoder_new(void) {
        CaEncoder *e;

        e = new0(CaEncoder, 1);
        if (!e)
                return NULL;

        e->feature_flags = CA_FORMAT_DEFAULT & SUPPORTED_FEATURE_MASK;
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
        n->xattrs_idx = (size_t) -1;

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
        n->quota_projid_valid = false;

#if HAVE_SELINUX
        if (n->selinux_label) {
                freecon(n->selinux_label);
                n->selinux_label = NULL;
        }
#endif

        n->device_size = UINT64_MAX;

        n->stat.st_mode = 0;

        n->name_table = ca_name_table_unref(n->name_table);

        n->mount_id = -1;
        n->generation_valid = 1;

        n->has_exclude_file = CA_ENCODER_HAS_EXCLUDE_FILE_DONT_KNOW;
        n->exclude_match = ca_match_unref(n->exclude_match);
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

        ca_digest_free(e->archive_digest);
        ca_digest_free(e->payload_digest);
        ca_digest_free(e->hardlink_digest);

        return mfree(e);
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
                .mount_id = -1,
                .generation_valid = -1,
                .has_exclude_file = CA_ENCODER_HAS_EXCLUDE_FILE_DONT_KNOW,
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

static const char *ca_encoder_node_current_child_name(CaEncoderNode *n) {
        const struct dirent *de;

        de = ca_encoder_node_current_dirent(n);
        if (!de)
                return NULL;

        return de->d_name;
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

static int dirent_bsearch_func(const void *key, const void *member) {
        const char *k = key;
        const struct dirent ** const m = (const struct dirent ** const) member;

        return strcmp(k, (*m)->d_name);
}

static int ca_encoder_node_load_exclude_file(CaEncoderNode *n) {
        int r;
        assert(n);

        if (!S_ISDIR(n->stat.st_mode))
                return -ENOTDIR;
        if (n->fd < 0)
                return -EBADFD;

        if (n->has_exclude_file == CA_ENCODER_HAS_EXCLUDE_FILE_DONT_KNOW) {
                struct dirent **found;

                r = ca_encoder_node_read_dirents(n);
                if (r < 0)
                        return r;

                found = bsearch(".caexclude", n->dirents, n->n_dirents, sizeof(struct dirent*), dirent_bsearch_func);
                n->has_exclude_file = found ? CA_ENCODER_HAS_EXCLUDE_FILE_YES : CA_ENCODER_HAS_EXCLUDE_FILE_NO;
        }

        if (n->has_exclude_file == CA_ENCODER_HAS_EXCLUDE_FILE_YES) {
                _cleanup_(ca_match_unrefp) CaMatch *match = NULL;

                r = ca_match_new_from_file(n->fd, ".caexclude", &match);
                if (r < 0)
                        return r;

                r = ca_match_merge(&n->exclude_match, match);
                if (r < 0)
                        return r;

                n->has_exclude_file = CA_ENCODER_HAS_EXCLUDE_FILE_LOADED;
        }

        return 0;
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
        if ((e->feature_flags & (CA_FORMAT_WITH_CHATTR|CA_FORMAT_EXCLUDE_NODUMP)) == 0)
                return 0;

        r = read_attr_fd(n->fd, &n->chattr_flags);
        if (r < 0)
                return r;

        n->chattr_flags_valid = true;

        return 0;
}

static int ca_encoder_node_read_fat_attrs(
                CaEncoder *e,
                CaEncoderNode *n) {

        int r;

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

        if (IN_SET(n->magic, MSDOS_SUPER_MAGIC, FUSE_SUPER_MAGIC)) {

                /* FUSE and true FAT file systems might implement this ioctl(), otherwise don't bother */
                r = read_fat_attr_fd(n->fd, &n->fat_attrs);
                if (r < 0)
                        return r;
        } else
                n->fat_attrs = 0;

        n->fat_attrs_valid = true;

        return 0;
}

static int ca_encoder_node_read_btrfs(
                CaEncoder *e,
                CaEncoderNode *n) {

        assert(e);
        assert(n);

        if (!S_ISDIR(n->stat.st_mode))
                return 0;
        if (n->fd < 0)
                return -EBADFD;
        if ((e->feature_flags & CA_FORMAT_WITH_SUBVOLUME) == 0)
                return 0;
        if (n->subvolume_valid)
                return 0;

        if (F_TYPE_EQUAL(n->magic, BTRFS_SUPER_MAGIC) &&
            n->stat.st_ino == 256) {

                uint64_t bflags;

                if (ioctl(n->fd, BTRFS_IOC_SUBVOL_GETFLAGS, &bflags) < 0)
                        return -errno;

                n->is_subvolume = true;
                n->is_subvolume_ro = !!(bflags & BTRFS_SUBVOL_RDONLY);

        } else {
                n->is_subvolume = false;
                n->is_subvolume_ro = false;
        }

        n->subvolume_valid = true;

        return 0;
}

static int ca_encoder_node_read_selinux_label(
                CaEncoder *e,
                CaEncoderNode *n) {

#if HAVE_SELINUX
        char *label;
        int r;
#endif

        assert(e);
        assert(n);

        if ((e->feature_flags & CA_FORMAT_WITH_SELINUX) == 0)
                return 0;
#if HAVE_SELINUX
        if (n->selinux_label_valid)
                return 0;

        if (n->fd >= 0)
                r = fgetfilecon(n->fd, &label) < 0 ? -errno : 0;
        else {
                const struct dirent *de;
                CaEncoderNode *parent;
                _cleanup_free_ char *subpath = NULL;

                parent = ca_encoder_node_parent_of(e, n);
                if (!parent)
                        return -EUNATCH;

                de = ca_encoder_node_current_dirent(parent);
                if (!de)
                        return -EUNATCH;

                if (asprintf(&subpath, "/proc/self/fd/%i/%s", parent->fd, de->d_name) < 0)
                        return -ENOMEM;

                r = lgetfilecon(subpath, &label) < 0 ? -errno : 0;
        }

        if (r < 0) {
                if (!IN_SET(-r, ENODATA, EOPNOTSUPP))
                        return r;

                if (n->selinux_label) {
                        freecon(n->selinux_label);
                        n->selinux_label = NULL;
                }
        } else {
                if (n->selinux_label)
                        freecon(n->selinux_label);

                n->selinux_label = label;
        }

        n->selinux_label_valid = true;
        return 0;

#else
        return -EOPNOTSUPP;
#endif
}

static int ca_encoder_node_read_generation(
                CaEncoder *e,
                CaEncoderNode *n) {

        assert(e);
        assert(n);

        if (!S_ISDIR(n->stat.st_mode) && !S_ISREG(n->stat.st_mode))
                return 0;
        if (n->fd < 0)
                return -EBADFD;
        if (n->generation_valid >= 0) /* Already read? */
                return 0;

        if (ioctl(n->fd, FS_IOC_GETVERSION, &n->generation) < 0) {

                if (!ERRNO_IS_UNSUPPORTED(errno))
                        return -errno;

                n->generation_valid = false;
        } else
                n->generation_valid = true;

        return 0;
}

static int ca_encoder_node_read_quota_projid(
                CaEncoder *e,
                CaEncoderNode *n) {

        int r;

        assert(e);
        assert(n);

        if (!S_ISDIR(n->stat.st_mode) && !S_ISREG(n->stat.st_mode))
                return 0;
        if (n->fd < 0)
                return -EBADFD;
        if (n->quota_projid_valid) /* Already read? */
                return 0;
        if (!(e->feature_flags & CA_FORMAT_WITH_QUOTA_PROJID))
                return 0;

        if (IN_SET(n->magic, EXT4_SUPER_MAGIC, XFS_SUPER_MAGIC, FUSE_SUPER_MAGIC)) {
                r = read_quota_projid(n->fd, &n->quota_projid);
                if (r < 0)
                        return r;
        } else
                n->quota_projid = 0;

        n->quota_projid_valid = true;
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
                                        _cleanup_free_ char *name = NULL;
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
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        n->xattrs[n->n_xattrs++] = (CaEncoderExtendedAttribute) {
                                                .name = name,
                                                .data = d,
                                                .data_size = z,
                                        };
                                        name = NULL;
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

static int ca_encoder_node_read_mount_id(
                CaEncoder *e,
                CaEncoderNode *n) {

        size_t line_allocated = 0;
        _cleanup_free_ char *line = NULL, *p = NULL;
        FILE *f;
        int r;

        assert(e);
        assert(n);

        if (!(e->feature_flags & CA_FORMAT_EXCLUDE_SUBMOUNTS))
                return 0;
        if (n->mount_id >= 0)
                return 0;
        if (n->fd < 0)
                return 0;

        if (asprintf(&p, "/proc/self/fdinfo/%i", n->fd) < 0)
                return -ENOMEM;

        f = fopen(p, "re");
        if (!f)
                return -errno;

        for (;;) {
                int mnt_id;
                ssize_t k;
                char *z;

                errno = 0;
                k = getline(&line, &line_allocated, f);
                if (k < 0) {
                        if (errno == 0) /* EOF? */
                                break;

                        r = -errno;
                        goto finish;
                }

                z = startswith(line, "mnt_id:");
                if (!z)
                        continue;

                z += strspn(z, WHITESPACE);
                truncate_nl(z);

                r = safe_atoi(z, &mnt_id);
                if (r < 0)
                        goto finish;

                if (mnt_id < 0) {
                        r = -EINVAL;
                        goto finish;
                }

                n->mount_id = mnt_id;
                break;
        }

        r = 0;

finish:
        fclose(f);

        return r;
}

static uid_t ca_encoder_shift_uid(CaEncoder *e, uid_t uid) {
        uid_t result;

        assert(e);

        if (!uid_is_valid(uid))
                return UID_INVALID;

        if (uid < e->uid_shift)
                return UID_INVALID;

        result = uid - e->uid_shift;

        if (e->uid_range != 0)
                result %= e->uid_range;

        return result;
}

static gid_t ca_encoder_shift_gid(CaEncoder *e, gid_t gid) {
        /* Let's rely on the fact that UIDs and GIDs have identical numeric behaviour */
        return (gid_t) ca_encoder_shift_uid(e, (uid_t) gid);
}

static int uid_to_name(CaEncoder *e, uid_t uid, char **ret) {
        long bufsize;
        int r;

        assert(e);
        assert(ret);

        if (!uid_is_valid(uid))
                return -EINVAL;

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
                _cleanup_free_ char *buf = NULL;

                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;

                r = getpwuid_r(uid, &pwbuf, buf, (size_t) bufsize, &pw);
                if (r == 0 && pw) {
                        char *n;

                        n = strdup(pw->pw_name);
                        if (!n)
                                return -ENOMEM;
                        *ret = n;
                        return 1;
                }
                if (r != ERANGE) {
                        uid_t shifted_uid;
                        /* User name cannot be retrieved */

                        if (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) {
                                *ret = NULL;
                                return 0;
                        }

                        shifted_uid = ca_encoder_shift_uid(e, uid);
                        if (!uid_is_valid(shifted_uid))
                                return -EINVAL;

                        if (asprintf(ret, UID_FMT, shifted_uid) < 0)
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
                _cleanup_free_ char *buf = NULL;

                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;

                r = getgrgid_r(gid, &grbuf, buf, (size_t) bufsize, &gr);
                if (r == 0 && gr) {
                        char *n;

                        n = strdup(gr->gr_name);
                        if (!n)
                                return -ENOMEM;

                        *ret = n;
                        return 1;
                }
                if (r != ERANGE) {
                        gid_t shifted_gid;

                        if (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) {
                                *ret = NULL;
                                return 0;
                        }

                        shifted_gid = ca_encoder_shift_gid(e, gid);
                        if (!gid_is_valid(shifted_gid))
                                return -EINVAL;

                        if (asprintf(ret, GID_FMT, shifted_gid) < 0)
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
                        uid_t uid, shifted_uid;
                        _cleanup_free_ char *name = NULL;

                        q = acl_get_qualifier(entry);
                        if (!q)
                                return -errno;

                        uid = *(uid_t*) q;
                        acl_free(q);

                        if (!uid_is_valid(uid))
                                return -EINVAL;

                        shifted_uid = ca_encoder_shift_uid(e, uid);
                        if (!uid_is_valid(shifted_uid))
                                return -EINVAL;

                        if ((e->feature_flags & CA_FORMAT_WITH_16BIT_UIDS) && shifted_uid > UINT16_MAX)
                                return -EPROTONOSUPPORT;

                        if (e->feature_flags & CA_FORMAT_WITH_USER_NAMES) {
                                r = uid_to_name(e, uid, &name);
                                if (r < 0)
                                        return r;
                        }

                        if (!GREEDY_REALLOC(*user_entries, n_allocated_user, *n_user_entries+1))
                                return -ENOMEM;

                        (*user_entries)[(*n_user_entries)++] = (CaEncoderACLEntry) {
                                .name = name,
                                .permissions = permissions,
                                .uid = (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) ? shifted_uid : 0,
                        };
                        name = NULL;
                        break;
                }

                case ACL_GROUP: {
                        gid_t gid, shifted_gid;
                        _cleanup_free_ char *name = NULL;

                        q = acl_get_qualifier(entry);
                        if (!q)
                                return -errno;

                        gid = *(gid_t*) q;
                        acl_free(q);

                        if (!gid_is_valid(gid))
                                return -EINVAL;

                        shifted_gid = ca_encoder_shift_gid(e, gid);
                        if (!gid_is_valid(shifted_gid))
                                return -EINVAL;

                        if ((e->feature_flags & CA_FORMAT_WITH_16BIT_UIDS) && shifted_gid > UINT16_MAX)
                                return -EPROTONOSUPPORT;

                        if (e->feature_flags & CA_FORMAT_WITH_USER_NAMES) {
                                r = gid_to_name(e, gid, &name);
                                if (r < 0)
                                        return r;
                        }

                        if (!GREEDY_REALLOC(*group_entries, n_allocated_group, *n_group_entries+1))
                                return -ENOMEM;

                        (*group_entries)[(*n_group_entries)++] = (CaEncoderACLEntry) {
                                .name = name,
                                .permissions = permissions,
                                .gid = (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) ? shifted_gid : 0,
                        };
                        name = NULL;
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
                .mount_id = -1,
                .generation_valid = -1,
                .has_exclude_file = CA_ENCODER_HAS_EXCLUDE_FILE_DONT_KNOW,
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

static int ca_encoder_shall_store_child_node(CaEncoder *e, CaEncoderNode *n) {
        _cleanup_(ca_match_unrefp) CaMatch *match = NULL;
        CaEncoderNode *child;
        int r;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));

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

        /* Check if the NODUMP flag is set */
        r = ca_encoder_node_read_chattr(e, child);
        if (r < 0)
                return r;
        if ((e->feature_flags & CA_FORMAT_EXCLUDE_NODUMP) &&
            (child->chattr_flags & FS_NODUMP_FL))
                return false;

        /* Check if we are crossing a mount point boundary */
        r = ca_encoder_node_read_mount_id(e, n);
        if (r < 0)
                return r;
        r = ca_encoder_node_read_mount_id(e, child);
        if (r < 0)
                return r;
        if ((e->feature_flags & CA_FORMAT_EXCLUDE_SUBMOUNTS) && child->mount_id >= 0 && n->mount_id >= 0 && child->mount_id != n->mount_id)
                return false;

        /* Load and check the child against our .caexclude file if we have one */
        r = ca_encoder_node_load_exclude_file(n);
        if (r < 0)
                return log_debug_errno(r, "Failed to load exclude file: %m");

        r = ca_match_test(n->exclude_match, ca_encoder_node_current_child_name(n), S_ISDIR(child->stat.st_mode), &match);
        if (r < 0)
                return log_debug_errno(r, "Failed to test child '%s' against exclude list: %m", ca_encoder_node_current_child_name(n));
        if (r > 0)
                return false;

        /* Merge the match calculated for this subtree into the child's match object */
        r = ca_match_merge(&child->exclude_match, match);
        if (r < 0)
                return log_debug_errno(r, "Failed to merge subtree match: %m");

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

static int ca_encoder_initialize_name_table(CaEncoder *e, CaEncoderNode *n, uint64_t sub) {
        CaEncoderNode *parent;

        assert(e);
        assert(n);
        assert(!n->name_table);

        /* Name tables only make sense for directories */
        if (!S_ISDIR(n->stat.st_mode))
                return 0;

        /* We can't set up a name table if we don't know our position */
        if (e->archive_offset == UINT64_MAX)
                return 0;
        if (e->archive_offset < sub)
                return -EINVAL;

        /* Link up parent's filename table */
        parent = ca_encoder_node_parent_of(e, n);
        if (parent && !parent->name_table)
                return 0; /* Parent has no name table, hence there's no point for us either */

        n->name_table = ca_name_table_new();
        if (!n->name_table)
                return -ENOMEM;

        n->name_table->entry_offset = e->archive_offset - sub;
        n->name_table->parent = parent ? ca_name_table_ref(parent->name_table) : NULL;

        return 1;
}

static int ca_encoder_add_name_table_item(CaEncoder *e, CaEncoderNode *n, const char *name) {
        CaNameItem *item;
        int r;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));
        assert(name);

        if (!n->name_table)
                return 0;

        if (e->archive_offset == UINT64_MAX) {
                n->name_table = ca_name_table_unref(n->name_table);
                return 0;
        }

        assert(ca_name_table_items(n->name_table) == 0 ||
               ca_name_table_last(n->name_table)->end_offset != UINT64_MAX);

        r = ca_name_table_add(&n->name_table, &item);
        if (r < 0)
                return r;

        *item = (CaNameItem) {
                .hash = siphash24(name, strlen(name), (const uint8_t[16]) CA_FORMAT_GOODBYE_HASH_KEY),
                .start_offset = e->archive_offset,
                .end_offset = UINT64_MAX,
        };

        return 0;
}

static int ca_encoder_update_name_table_end_offset(CaEncoder *e, CaEncoderNode *n) {
        CaNameItem *item;
        int r;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));

        if (!n->name_table)
                return 0;

        if (e->archive_offset == UINT64_MAX) {
                n->name_table = ca_name_table_unref(n->name_table);
                return 0;
        }

        if (ca_name_table_items(n->name_table) == 0)
                return 0;

        r = ca_name_table_make_writable(&n->name_table, 0);
        if (r < 0)
                return r;

        item = ca_name_table_last(n->name_table);
        assert(item);

        assert(item->start_offset != UINT64_MAX);
        assert(item->end_offset == UINT64_MAX);

        assert(item->start_offset <= e->archive_offset);
        item->end_offset = e->archive_offset;

        return 0;
}

static int ca_encoder_step_node(CaEncoder *e, CaEncoderNode *n) {
        int r;

        assert(e);
        assert(n);

        switch (e->state) {

        case CA_ENCODER_INIT:

                if (CA_ENCODER_IS_NAKED(e)) {
                        assert(CA_ENCODER_AT_ROOT(e));

                        /* If we are just initializing and looking at a regular file/block device, then our top-level
                         * node is serialized as its contents, hence continue in payload mode. */
                        ca_encoder_enter_state(e, CA_ENCODER_IN_PAYLOAD);
                } else
                        /* Otherwise, if we are initializing and looking at anything else, then start with an ENTRY
                         * record. */
                        ca_encoder_enter_state(e, CA_ENCODER_ENTERED);

                return ca_encoder_step_node(e, n);

        case CA_ENCODER_ENTERED:

                /* We just entered this node. In this case, generate the ENTRY record for it */

                if (e->want_payload_digest) {
                        ca_digest_reset(e->payload_digest);
                        e->payload_digest_invalid = false;
                }

                if (e->want_hardlink_digest) {
                        ca_digest_reset(e->hardlink_digest);
                        e->hardlink_digest_invalid = false;
                }

                r = ca_encoder_collect_covering_feature_flags(e, n);
                if (r < 0)
                        return r;

                r = ca_encoder_initialize_name_table(e, n, 0);
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

                ca_encoder_enter_state(e, CA_ENCODER_FINALIZE);
                return CA_ENCODER_DONE_FILE;

        case CA_ENCODER_IN_PAYLOAD: {
                uint64_t size;

                assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));

                r = ca_encoder_node_get_payload_size(n, &size);
                if (r < 0)
                        return r;

                if (e->payload_offset >= size) {
                        ca_encoder_enter_state(e, CA_ENCODER_FINALIZE);

                        /* If this is a blob archive (i.e. a top-level payload), then let's not generate the DONE_FILE
                         * event (because there is no entry) but let's shortcut to FINISHED. */
                        if (CA_ENCODER_IS_NAKED(e)) {
                                assert(CA_ENCODER_AT_ROOT(e));
                                return ca_encoder_step(e);
                        }

                        return CA_ENCODER_DONE_FILE;
                }

                return CA_ENCODER_PAYLOAD;
        }

        case CA_ENCODER_NEXT_DIRENT:

                r = ca_encoder_update_name_table_end_offset(e, n);
                if (r < 0)
                        return r;

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
                                ca_encoder_enter_state(e, CA_ENCODER_GOODBYE);
                                return CA_ENCODER_DATA;
                        }

                        r = ca_encoder_open_child(e, n, de);
                        if (r < 0)
                                return r;

                        /* Check if this child is relevant to us */
                        r = ca_encoder_shall_store_child_node(e, n);
                        if (r < 0)
                                return r;
                        if (r > 0) /* Yay, this one's relevant */
                                break;

                        /* Nope, not relevant to us, let's try the next one */
                        n->dirent_idx++;
                }

                r = ca_encoder_add_name_table_item(e, n, de->d_name);
                if (r < 0)
                        return r;

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

                ca_encoder_enter_state(e, CA_ENCODER_FINALIZE);
                return CA_ENCODER_DONE_FILE;

        case CA_ENCODER_FINALIZE:
                r = ca_encoder_leave_child(e);
                if (r < 0)
                        return r;
                if (r > 0) {
                        CaEncoderNode *parent;

                        parent = ca_encoder_current_node(e);
                        if (!parent)
                                return -EUNATCH;

                        ca_encoder_enter_state(e, CA_ENCODER_NEXT_DIRENT);
                        return ca_encoder_step_node(e, parent);
                }

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

        /* Flush generated buffer */
        sz = realloc_buffer_size(&e->buffer);

        e->payload_offset += sz;
        if (e->archive_offset != UINT64_MAX)
                e->archive_offset += sz;

        realloc_buffer_empty(&e->buffer);

        /* Flush skipped bytes */
        e->payload_offset += e->skipped_bytes;

        if (e->archive_offset != UINT64_MAX)
                e->archive_offset += e->skipped_bytes;

        e->skipped_bytes = 0;
}

int ca_encoder_step(CaEncoder *e) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;

        if (e->state == CA_ENCODER_EOF)
                return CA_ENCODER_FINISHED;

        ca_encoder_advance_buffer(e);

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        return ca_encoder_step_node(e, n);
}

static int ca_encoder_get_payload_data(CaEncoder *e, CaEncoderNode *n, uint64_t suggested_size) {
        uint64_t size;
        ssize_t m;
        size_t k;
        void *p;
        int r;

        assert(e);
        assert(n);
        assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));
        assert(e->state == CA_ENCODER_IN_PAYLOAD);
        assert(realloc_buffer_size(&e->buffer) == 0);
        assert(e->skipped_bytes == 0);

        r = ca_encoder_node_get_payload_size(n, &size);
        if (r < 0)
                return r;

        if (e->payload_offset >= size) /* at EOF? */
                return 0;

        k = (size_t) MIN(BUFFER_SIZE, size - e->payload_offset);
        if (suggested_size != UINT64_MAX && k > suggested_size)
                k = suggested_size;

        p = realloc_buffer_acquire(&e->buffer, k);
        if (!p)
                return -ENOMEM;

        m = pread(n->fd, p, k, e->payload_offset);
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

static int ca_encoder_skip_payload_data(CaEncoder *e, CaEncoderNode *n, uint64_t suggested_size) {
        uint64_t size, d;
        int r;

        assert(e);
        assert(n);
        assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));
        assert(e->state == CA_ENCODER_IN_PAYLOAD);
        assert(realloc_buffer_size(&e->buffer) == 0);
        assert(e->skipped_bytes == 0);

        /* Thisis much like ca_encoder_get_payload_data() but we don't actually try to read anything from disk, but
         * instead skip right to the end of the file we are currently looking at. This is used if the caller is not
         * actually interested in the payload, but just wants to proceed to whatever comes next. */

        r = ca_encoder_node_get_payload_size(n, &size);
        if (r < 0)
                return r;

        if (e->payload_offset >= size) /* at EOF? */
                return 0;

        d = size - e->payload_offset;
        if (suggested_size != UINT64_MAX && d > suggested_size)
                d = suggested_size;
        if (d > SIZE_MAX)
                d = SIZE_MAX;

        e->skipped_bytes = d;
        return 1;
}

static int ca_encoder_get_filename_data(CaEncoder *e, const struct dirent *de) {
        CaFormatFilename *filename;
        size_t size;

        assert(e);
        assert(de);
        assert(e->state == CA_ENCODER_FILENAME);
        assert(realloc_buffer_size(&e->buffer) == 0);
        assert(e->skipped_bytes == 0);

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
        assert(realloc_buffer_size(&e->buffer) == 0);
        assert(e->skipped_bytes == 0);

        r = ca_encoder_node_read_chattr(e, n);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_fat_attrs(e, n);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_btrfs(e, n);
        if (r < 0)
                return r;

        r = ca_encoder_node_read_selinux_label(e, n);
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

        r = ca_encoder_node_read_quota_projid(e, n);
        if (r < 0)
                return r;

        if (e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) {
                uid_t shifted_uid;
                gid_t shifted_gid;

                shifted_uid = ca_encoder_shift_uid(e, n->stat.st_uid);
                if (!uid_is_valid(shifted_uid))
                        return -EINVAL;

                shifted_gid = ca_encoder_shift_gid(e, n->stat.st_gid);
                if (!gid_is_valid(shifted_gid))
                        return -EINVAL;

                if ((e->feature_flags & CA_FORMAT_WITH_16BIT_UIDS) &&
                    (shifted_uid > UINT16_MAX || shifted_gid > UINT16_MAX))
                        return -EPROTONOSUPPORT;

                uid = shifted_uid;
                gid = shifted_gid;
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

        if (S_ISDIR(n->stat.st_mode) && (e->feature_flags & CA_FORMAT_WITH_SUBVOLUME)) {

                assert(n->subvolume_valid);

                flags |=
                        ((n->is_subvolume ? CA_FORMAT_WITH_SUBVOLUME : 0) |
                         (n->is_subvolume_ro ? CA_FORMAT_WITH_SUBVOLUME_RO : 0)) & e->feature_flags;
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

        if (e->feature_flags & CA_FORMAT_WITH_XATTRS)
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

        if (n->selinux_label_valid && n->selinux_label)
                size += offsetof(CaFormatSELinux, label) + strlen(n->selinux_label) + 1;

        if (n->fcaps && (e->feature_flags & CA_FORMAT_WITH_FCAPS))
                size += offsetof(CaFormatFCaps, data) + n->fcaps_size;

        if (n->quota_projid_valid && n->quota_projid != 0)
                size += sizeof(CaFormatQuotaProjID);

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

        if (e->feature_flags & CA_FORMAT_WITH_XATTRS) {
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

        if (n->selinux_label_valid && n->selinux_label) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_SELINUX),
                        .size = htole64(offsetof(CaFormatSELinux, label) + strlen(n->selinux_label) + 1),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = stpcpy(p, n->selinux_label) + 1;
        }

        if (n->fcaps && (e->feature_flags & CA_FORMAT_WITH_FCAPS)) {
                CaFormatHeader header = {
                        .type = htole64(CA_FORMAT_FCAPS),
                        .size = htole64(offsetof(CaFormatFCaps, data) + n->fcaps_size),
                };

                p = mempcpy(p, &header, sizeof(header));
                p = mempcpy(p, n->fcaps, n->fcaps_size);
        }

        if (n->quota_projid_valid && n->quota_projid != 0) {
                CaFormatQuotaProjID projid = {
                        .header.type = htole64(CA_FORMAT_QUOTA_PROJID),
                        .header.size = htole64(sizeof(CaFormatQuotaProjID)),
                        .projid = htole64(n->quota_projid),
                };

                p = mempcpy(p, &projid, sizeof(projid));
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

static int ca_encoder_get_goodbye_data(CaEncoder *e, CaEncoderNode *n) {
        _cleanup_(ca_name_table_unrefp) CaNameTable *bst = NULL;
        CaFormatGoodbye *g;
        CaFormatGoodbyeTail *tail;
        size_t size, i;
        uint64_t start_offset;
        int r;

        assert(e);
        assert(n);
        assert(S_ISDIR(n->stat.st_mode));
        assert(e->state == CA_ENCODER_GOODBYE);
        assert(realloc_buffer_size(&e->buffer) == 0);
        assert(e->skipped_bytes == 0);

        assert_cc(sizeof(CaFormatGoodbyeTail) == sizeof(CaFormatGoodbyeItem));

        /* If we got here through a seek we don't know the correct addresses of the directory entries, hence can't
         * correctly generate the name GOODBYE record. */
        if (!n->name_table)
                return -ENOLINK;

        if (e->archive_offset == UINT64_MAX)
                return -ENOLINK;

        size = offsetof(CaFormatGoodbye, items) +
                sizeof(CaFormatGoodbyeItem) * ca_name_table_items(n->name_table) +
                sizeof(CaFormatGoodbyeTail);

        g = realloc_buffer_acquire(&e->buffer, size);
        if (!g)
                return -ENOMEM;

        g->header = (CaFormatHeader) {
                .type = htole64(CA_FORMAT_GOODBYE),
                .size = htole64(size),
        };

        r = ca_name_table_make_bst(n->name_table, &bst);
        if (r < 0)
                return r;

        if (e->archive_offset < e->payload_offset)
                return -EINVAL;

        /* After seeking we might be pointing into the middle of a GOODBYE record. Let's calculate the actual start
         * position of the GOODBYE record by subtracting the offset into the record. */
        start_offset = e->archive_offset - e->payload_offset;

        for (i = 0; i < bst->n_items; i++) {
                assert(bst->items[i].start_offset < start_offset);
                assert(bst->items[i].end_offset <= start_offset);
                assert(bst->items[i].start_offset < bst->items[i].end_offset);

                g->items[i] = (CaFormatGoodbyeItem) {
                        .offset = htole64(start_offset - bst->items[i].start_offset),
                        .size = htole64(bst->items[i].end_offset - bst->items[i].start_offset),
                        .hash = htole64(bst->items[i].hash),
                };
        }

        assert(bst->entry_offset != UINT64_MAX);
        assert(bst->entry_offset < start_offset);

        /* Write the tail */
        tail = (CaFormatGoodbyeTail*) (g->items + bst->n_items);
        write_le64(&tail->entry_offset, start_offset - bst->entry_offset);
        write_le64(&tail->size, size);
        write_le64(&tail->marker, CA_FORMAT_GOODBYE_TAIL_MARKER);

        return 1;
}

static int ca_encoder_write_digest(CaEncoder *e, CaDigest **digest, const void *p, size_t l) {
        int r;

        if (!e)
                return -EINVAL;
        if (!digest)
                return -EINVAL;

        r = ca_digest_ensure_allocated(digest, ca_feature_flags_to_digest_type(e->feature_flags));
        if (r < 0)
                return r;

        ca_digest_write(*digest, p, l);
        return 0;
}

int ca_encoder_get_data(
                CaEncoder *e,
                uint64_t suggested_size,
                const void **ret,
                size_t *ret_size) {

        bool skip_applied = false;
        CaEncoderNode *n;
        bool really_want_hardlink_digest, really_want_payload_digest;
        int r;

        if (!e)
                return -EINVAL;

        /* A previous call in the same iteration was done with ret == NULL, and hence we decided to skip bytes, but the
         * new call wants to see data for the same iteration after all? That's not supported! */
        if (e->skipped_bytes > 0 && ret)
                return -EKEYREVOKED;

        if (realloc_buffer_size(&e->buffer) > 0 ||
            e->skipped_bytes > 0) /* already data in buffer, if so return it again? */
                goto done;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        really_want_hardlink_digest =
                e->want_hardlink_digest &&
                !e->hardlink_digest_invalid &&
                IN_SET(e->state, CA_ENCODER_ENTRY, CA_ENCODER_IN_PAYLOAD);

        really_want_payload_digest =
                e->want_payload_digest &&
                !e->payload_digest_invalid &&
                e->state == CA_ENCODER_IN_PAYLOAD;

        switch (e->state) {

        case CA_ENCODER_ENTRY:
                r = ca_encoder_get_entry_data(e, n);
                if (r < 0)
                        return r;

                break;

        case CA_ENCODER_IN_PAYLOAD:
                assert(S_ISREG(n->stat.st_mode) || S_ISBLK(n->stat.st_mode));

                if (!ret && !e->want_archive_digest && !really_want_hardlink_digest && !really_want_payload_digest)
                        /* OK, we can shortcut this, as neither the caller is interested in this data, nor do we need
                         * it for digest calculation. In this case let's just skip the whole shebang. */
                        r = ca_encoder_skip_payload_data(e, n, suggested_size);
                else
                        r = ca_encoder_get_payload_data(e, n, suggested_size);

                skip_applied = true;
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
                return -ENODATA;
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

                assert(realloc_buffer_size(&e->buffer) == 0);
                assert(e->skipped_bytes == 0);

                if (ret)
                        *ret = NULL;
                if (ret_size)
                        *ret_size = 0;
                return 0;
        }

        if (e->want_archive_digest)
                ca_encoder_write_digest(e, &e->archive_digest, realloc_buffer_data(&e->buffer), realloc_buffer_size(&e->buffer));
        if (really_want_hardlink_digest)
                ca_encoder_write_digest(e, &e->hardlink_digest, realloc_buffer_data(&e->buffer), realloc_buffer_size(&e->buffer));
        if (really_want_payload_digest)
                ca_encoder_write_digest(e, &e->payload_digest, realloc_buffer_data(&e->buffer), realloc_buffer_size(&e->buffer));

done:
        if (ret)
                *ret = realloc_buffer_data(&e->buffer);

        if (ret_size)
                *ret_size = realloc_buffer_size(&e->buffer) + e->skipped_bytes;

        return 1;
}

static int ca_encoder_node_path(CaEncoder *e, CaEncoderNode *node, char **ret) {
        _cleanup_free_ char *p = NULL;
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
                if (!np)
                        return -ENOMEM;

                q = np + n;
                if (n > 0)
                        *(q++) = '/';

                strcpy(q, de->d_name);

                p = np;
                n = nn;
        }

        if (!found)
                return -EINVAL;

        if (!p) {
                p = strdup("");
                if (!p)
                        return -ENOMEM;
        }

        *ret = p;
        p = NULL;

        return 0;
}

int ca_encoder_current_path(CaEncoder *e, char **ret) {
        CaEncoderNode *node;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        node = ca_encoder_current_node(e);
        if (!node)
                return -EUNATCH;

        return ca_encoder_node_path(e, node, ret);
}

int ca_encoder_current_mode(CaEncoder *e, mode_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        *ret = ca_encoder_fixup_mode(e, n);
        return 0;
}

int ca_encoder_current_target(CaEncoder *e, const char **ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

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

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        *ret = ca_encoder_fixup_mtime(e, n);
        return 0;
}

int ca_encoder_current_size(CaEncoder *e, uint64_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!S_ISREG(n->stat.st_mode))
                return -ENODATA;

        *ret = n->stat.st_size;
        return 0;
}

int ca_encoder_current_uid(CaEncoder *e, uid_t *ret) {
        CaEncoderNode *n;
        uid_t shifted_uid;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)))
                return -ENODATA;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        shifted_uid = ca_encoder_shift_uid(e, n->stat.st_uid);
        if (!uid_is_valid(shifted_uid))
                return -EINVAL;

        *ret = shifted_uid;
        return 0;
}

int ca_encoder_current_gid(CaEncoder *e, gid_t *ret) {
        CaEncoderNode *n;
        gid_t shifted_gid;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)))
                return -ENODATA;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        shifted_gid = ca_encoder_shift_gid(e, n->stat.st_gid);
        if (!gid_is_valid(shifted_gid))
                return -EINVAL;

        *ret = shifted_gid;
        return 0;
}

int ca_encoder_current_user(CaEncoder *e, const char **ret) {
        CaEncoderNode *n;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & CA_FORMAT_WITH_USER_NAMES))
                return -ENODATA;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        r = ca_encoder_node_read_user_group_names(e, n);
        if (r < 0)
                return r;

        if (e->cached_user_name && e->cached_uid == n->stat.st_uid)
                *ret = e->cached_user_name;
        else if (n->stat.st_uid == 0)
                *ret = "root";
        else
                return -ENODATA;

        return 0;
}

int ca_encoder_current_group(CaEncoder *e, const char **ret) {
        CaEncoderNode *n;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(e->feature_flags & CA_FORMAT_WITH_USER_NAMES))
                return -ENODATA;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        r = ca_encoder_node_read_user_group_names(e, n);
        if (r < 0)
                return r;

        if (e->cached_group_name && e->cached_gid == n->stat.st_gid)
                *ret = e->cached_group_name;
        else if (n->stat.st_gid == 0)
                *ret = "root";
        else
                return -ENODATA;

        return 0;
}

int ca_encoder_current_rdev(CaEncoder *e, dev_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!S_ISBLK(n->stat.st_mode) && !S_ISCHR(n->stat.st_mode))
                return -ENODATA;

        *ret = n->stat.st_rdev;
        return 0;
}

int ca_encoder_current_chattr(CaEncoder *e, unsigned *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!S_ISREG(n->stat.st_mode) && !S_ISDIR(n->stat.st_mode))
                return -ENODATA;

        if (!n->chattr_flags_valid)
                return -ENODATA;

        *ret = ca_feature_flags_to_chattr((ca_feature_flags_from_chattr(n->chattr_flags) & e->feature_flags));
        return 0;
}

int ca_encoder_current_fat_attrs(CaEncoder *e, uint32_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!S_ISREG(n->stat.st_mode) && !S_ISDIR(n->stat.st_mode))
                return -ENODATA;

        if (!n->fat_attrs_valid)
                return -ENODATA;

        *ret = ca_feature_flags_to_fat_attrs((ca_feature_flags_from_fat_attrs(n->fat_attrs) & e->feature_flags));
        return 0;
}

int ca_encoder_current_xattr(CaEncoder *e, CaIterate where, const char **ret_name, const void **ret_value, size_t *ret_size) {
        CaEncoderNode *n;
        size_t p;

        if (!e)
                return -EINVAL;
        if (!ret_name)
                return -EINVAL;
        if (where < 0)
                return -EINVAL;
        if (where >= _CA_ITERATE_MAX)
                return -EINVAL;
        if (!ret_name)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!n->xattrs_valid)
                return -ENODATA;

        switch (where) {

        case CA_ITERATE_NEXT:
                if (n->xattrs_idx == (size_t) -1)
                        goto eof;

                p = n->xattrs_idx + 1;
                break;

        case CA_ITERATE_PREVIOUS:
                if (n->xattrs_idx == (size_t) -1 ||
                    n->xattrs_idx == 0)
                        goto eof;

                p = n->xattrs_idx - 1;
                break;

        case CA_ITERATE_FIRST:
                p = 0;
                break;

        case CA_ITERATE_LAST:
                if (n->n_xattrs == 0)
                        goto eof;

                p = n->n_xattrs - 1;
                break;

        case CA_ITERATE_CURRENT:
                p = n->xattrs_idx;
                break;

        case _CA_ITERATE_MAX:
        case _CA_ITERATE_INVALID:
        default:
                assert(false);
        }

        if (p == (size_t) -1)
                goto eof;
        if (p >= n->n_xattrs)
                goto eof;

        n->xattrs_idx = p;

        *ret_name = n->xattrs[p].name;

        if (ret_value)
                *ret_value = n->xattrs[p].data;
        if (ret_size)
                *ret_size = n->xattrs[p].data_size;

        return 1;

eof:
        *ret_name = NULL;

        if (ret_value)
                *ret_value = NULL;
        if (ret_size)
                *ret_size = 0;

        return 0;
}

int ca_encoder_current_quota_projid(CaEncoder *e, uint32_t *ret) {
        CaEncoderNode *n;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (!n->quota_projid_valid)
                return -ENODATA;

        *ret = n->quota_projid;
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
        CaEncoderNode *node, *name_table_node;
        _cleanup_free_ char *path = NULL;
        CaLocationDesignator designator;
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
                /* In CA_ENCODER_ENTRY state, we add the parent's name table to the location. For two reasons: our own
                 * name table will be empty anyway this early. And we generate ENTRY records for all files not just
                 * directories, but name tables apply only to directories. By not encoding the name table here we can
                 * thus treat all file types the same way. */

                name_table_node = ca_encoder_node_parent_of(e, node);
                designator = CA_LOCATION_ENTRY;
                break;

        case CA_ENCODER_IN_PAYLOAD:
                assert(S_ISREG(node->stat.st_mode) || S_ISBLK(node->stat.st_mode));

                /* In CA_ENCODER_IN_PAYLOAD state we also use the parent's name table. Using our own makes no sense, as
                 * we won't have any name table on our own node, as only directories have that, and in this state we
                 * can't be in a directory */

                name_table_node = ca_encoder_node_parent_of(e, node);
                designator = CA_LOCATION_PAYLOAD;
                break;

        case CA_ENCODER_FILENAME:
                assert(S_ISDIR(node->stat.st_mode));

                name_table_node = node;

                /* Here's a tweak: in CA_ENCODER_FILENAME state we actually encode the child's data, as our
                 * current node might be the directory, but we need to serialize at which directory entry
                 * within it we currently are. */
                node = ca_encoder_current_child_node(e);
                if (!node)
                        return -EUNATCH;

                designator = CA_LOCATION_FILENAME;
                break;

        case CA_ENCODER_GOODBYE:
                assert(S_ISDIR(node->stat.st_mode));

                name_table_node = node;
                designator = CA_LOCATION_GOODBYE;
                break;

        default:
                return -ENOTTY;
        }

        r = ca_encoder_node_path(e, node, &path);
        if (r < 0 && r != -ENOTDIR)
                return r;

        r = ca_encoder_node_read_generation(e, node);
        if (r < 0)
                return r;

        r = ca_location_new(path, designator, e->payload_offset + add, UINT64_MAX, &l);
        if (r < 0)
                return r;

        l->mtime = MAX(timespec_to_nsec(node->stat.st_mtim),
                       timespec_to_nsec(node->stat.st_ctim));
        l->inode = node->stat.st_ino;
        l->generation_valid = node->generation_valid > 0;
        l->generation = node->generation;

        l->name_table = name_table_node ? ca_name_table_ref(name_table_node->name_table) : NULL;

        if (e->archive_offset != UINT64_MAX)
                l->archive_offset = e->archive_offset + add;

        l->feature_flags = e->feature_flags;

        *ret = l;
        return 0;
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

        n->name_table = ca_name_table_unref(n->name_table);

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

        if (isempty(path)) {
                CaEncoderNode *node;

                node = ca_encoder_current_node(e);
                if (!node)
                        return -EUNATCH;

                node->name_table = ca_name_table_unref(node->name_table);
                return 0;
        }

        r = ca_encoder_seek_path(e, path);
        if (r < 0)
                return r;

        return ca_encoder_enter_child(e);
}

static int ca_encoder_node_install_name_table(CaEncoder *e, CaEncoderNode *node, CaNameTable *t) {
        assert(e);
        assert(node);
        assert(S_ISDIR(node->stat.st_mode));
        assert(t);

        for (;;) {
                ca_name_table_unref(node->name_table);
                node->name_table = ca_name_table_ref(t);

                node = ca_encoder_node_parent_of(e, node);
                if (!node)
                        break;

                t = t->parent;
                if (!t) {
                        log_debug("Name table chain ended prematurely.");
                        return -ESPIPE;
                }
        }

        if (t->parent) {
                log_debug("Name table chain too long.");
                return -ESPIPE;
        }

        return 0;
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
                        return log_debug_errno(r, "Failed to seek to path %s and enter: %m", location->path);

                node = ca_encoder_current_node(e);
                assert(node);

                node->dirent_idx = 0;
                ca_encoder_enter_state(e, CA_ENCODER_ENTRY);
                e->payload_offset = location->offset;
                e->archive_offset = location->archive_offset;

                if (location->name_table) {
                        CaEncoderNode *parent;

                        parent = ca_encoder_node_parent_of(e, node);
                        if (!parent)
                                return -ENXIO;

                        /* Install the name table included in the location for our parents… */
                        r = ca_encoder_node_install_name_table(e, parent, location->name_table);
                        if (r < 0)
                                return r;
                }

                /* …and a new one for ourselves (if we are a directory that is). */
                node->name_table = ca_name_table_unref(node->name_table);
                r = ca_encoder_initialize_name_table(e, node, location->offset);
                if (r < 0)
                        return r;

                realloc_buffer_empty(&e->buffer);
                e->skipped_bytes = 0;

                ca_digest_reset(e->archive_digest);

                if (e->want_payload_digest) {
                        ca_digest_reset(e->payload_digest);
                        e->payload_digest_invalid = false;
                }

                e->hardlink_digest_invalid = location->offset > 0;
                if (e->want_hardlink_digest && !e->hardlink_digest_invalid)
                        ca_digest_reset(e->hardlink_digest);

                return location->offset > 0 ? CA_ENCODER_DATA : CA_ENCODER_NEXT_FILE;

        case CA_LOCATION_PAYLOAD: {
                uint64_t size;

                r = ca_encoder_seek_path_and_enter(e, location->path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to seek to path %s and enter: %m", location->path);

                node = ca_encoder_current_node(e);
                assert(node);

                if (!S_ISREG(node->stat.st_mode) && !S_ISBLK(node->stat.st_mode))
                        return -EISDIR;

                r = ca_encoder_node_get_payload_size(node, &size);
                if (r < 0)
                        return r;

                if (location->offset >= size)
                        return -ENXIO;

                ca_encoder_enter_state(e, CA_ENCODER_IN_PAYLOAD);
                e->payload_offset = location->offset;
                e->archive_offset = location->archive_offset;

                if (e->archive_offset == UINT64_MAX && CA_ENCODER_AT_ROOT(e))
                        e->archive_offset = location->offset;

                if (location->name_table) {
                        CaEncoderNode *parent;

                        parent = ca_encoder_node_parent_of(e, node);
                        if (!parent)
                                return -ENXIO;

                        r = ca_encoder_node_install_name_table(e, parent, location->name_table);
                        if (r < 0)
                                return r;
                }

                realloc_buffer_empty(&e->buffer);
                e->skipped_bytes = 0;

                ca_digest_reset(e->archive_digest);

                e->payload_digest_invalid = location->offset > 0;
                if (e->want_payload_digest && !e->payload_digest_invalid)
                        ca_digest_reset(e->payload_digest);

                e->hardlink_digest_invalid = true;
                return CA_ENCODER_PAYLOAD;
        }

        case CA_LOCATION_FILENAME:

                r = ca_encoder_seek_path(e, location->path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to seek to path %s: %m", location->path);

                node = ca_encoder_current_node(e);
                assert(node);

                if (!S_ISDIR(node->stat.st_mode))
                        return -ENOTDIR;

                ca_encoder_enter_state(e, CA_ENCODER_FILENAME);
                e->payload_offset = location->offset;
                e->archive_offset = location->archive_offset;

                if (location->name_table) {
                        r = ca_encoder_node_install_name_table(e, node, location->name_table);
                        if (r < 0)
                                return r;
                }

                realloc_buffer_empty(&e->buffer);
                e->skipped_bytes = 0;

                ca_digest_reset(e->archive_digest);

                return CA_ENCODER_DATA;

        case CA_LOCATION_GOODBYE:

                r = ca_encoder_seek_path_and_enter(e, location->path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to seek to path %s and enter: %m", location->path);

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
                e->archive_offset = location->archive_offset;

                if (location->name_table) {
                        r = ca_encoder_node_install_name_table(e, node, location->name_table);
                        if (r < 0)
                                return r;
                }

                realloc_buffer_empty(&e->buffer);
                e->skipped_bytes = 0;

                ca_digest_reset(e->archive_digest);

                return CA_ENCODER_DATA;

        default:
                return -EINVAL;
        }

        return 0;
}

int ca_encoder_set_uid_shift(CaEncoder *e, uid_t u) {
        if (!e)
                return -EINVAL;

        e->uid_shift = u;
        return 0;
}

int ca_encoder_set_uid_range(CaEncoder *e, uid_t u) {
        if (!e)
                return -EINVAL;

        e->uid_range = u;
        return 0;
}

int ca_encoder_enable_archive_digest(CaEncoder *e, bool b) {
        if (!e)
                return -EINVAL;

        e->want_archive_digest = b;
        return 0;
}

int ca_encoder_enable_payload_digest(CaEncoder *e, bool b) {
        if (!e)
                return -EINVAL;

        e->want_payload_digest = b;
        return 0;
}

int ca_encoder_enable_hardlink_digest(CaEncoder *e, bool b) {
        if (!e)
                return -EINVAL;

        e->want_hardlink_digest = b;
        return 0;
}

int ca_encoder_get_archive_digest(CaEncoder *e, CaChunkID *ret) {
        const void *q;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!e->want_archive_digest)
                return -ENOMEDIUM;
        if (e->state != CA_ENCODER_EOF)
                return -EBUSY;

        r = ca_digest_ensure_allocated(&e->archive_digest, ca_feature_flags_to_digest_type(e->feature_flags));
        if (r < 0)
                return r;

        q = ca_digest_read(e->archive_digest);
        if (!q)
                return -EIO;

        assert(ca_digest_get_size(e->archive_digest) == sizeof(CaChunkID));
        memcpy(ret, q, sizeof(CaChunkID));

        return 0;
}

int ca_encoder_get_payload_digest(CaEncoder *e, CaChunkID *ret) {
        CaEncoderNode *n;
        const void *q;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!e->want_payload_digest)
                return -ENOMEDIUM;
        if (e->state != CA_ENCODER_FINALIZE)
                return -EBUSY;
        if (e->payload_digest_invalid)
                return -ESTALE;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;
        if (!S_ISREG(n->stat.st_mode) && !S_ISBLK(n->stat.st_mode))
                return -ENOTTY;

        r = ca_digest_ensure_allocated(&e->payload_digest, ca_feature_flags_to_digest_type(e->feature_flags));
        if (r < 0)
                return r;

        q = ca_digest_read(e->payload_digest);
        if (!q)
                return -EIO;

        assert(ca_digest_get_size(e->payload_digest) == sizeof(CaChunkID));
        memcpy(ret, q, sizeof(CaChunkID));

        return 0;
}

int ca_encoder_get_hardlink_digest(CaEncoder *e, CaChunkID *ret) {
        CaEncoderNode *n;
        const void *q;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!e->want_hardlink_digest)
                return -ENOMEDIUM;
        if (e->state != CA_ENCODER_FINALIZE)
                return -EBUSY;
        if (e->hardlink_digest_invalid)
                return -ESTALE;

        n = ca_encoder_current_node(e);
        if (!n)
                return -EUNATCH;

        if (S_ISDIR(n->stat.st_mode))
                return -EISDIR;

        r = ca_digest_ensure_allocated(&e->hardlink_digest, ca_feature_flags_to_digest_type(e->feature_flags));
        if (r < 0)
                return r;

        q = ca_digest_read(e->hardlink_digest);
        if (!q)
                return -EIO;

        assert(ca_digest_get_size(e->hardlink_digest) == sizeof(CaChunkID));
        memcpy(ret, q, sizeof(CaChunkID));

        return 0;
}
