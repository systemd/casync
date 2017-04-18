#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <sys/acl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/fs.h>
#include <linux/msdos_fs.h>

#include "cadecoder.h"
#include "caformat-util.h"
#include "caformat.h"
#include "cautil.h"
#include "def.h"
#include "realloc-buffer.h"
#include "siphash24.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef EBADMSG */
/* #define EBADMSG __LINE__ */

/* #undef EBUSY */
/* #define EBUSY __LINE__ */

/* #undef ENOENT */
/* #define ENOENT __LINE__ */

#define APPLY_EARLY_FS_FL                       \
        (FS_NOATIME_FL|                         \
         FS_COMPR_FL|                           \
         FS_NOCOW_FL|                           \
         FS_NOCOMP_FL|                          \
         FS_PROJINHERIT_FL)

typedef struct CaDecoderExtendedAttribute {
        struct CaDecoderExtendedAttribute *next;
        CaFormatXAttr format;
} CaDecoderExtendedAttribute;

typedef struct CaDecoderACLEntry {
        struct CaDecoderACLEntry *next;
        union {
                CaFormatACLUser user;
                CaFormatACLGroup group;
        };
} CaDecoderACLEntry;

typedef struct CaDecoderNode {
        int fd;

        uint64_t entry_offset;
        uint64_t goodbye_offset;
        uint64_t end_offset;     /* offset of the byte behind the goodbye marker */

        char *name;
        CaFormatEntry *entry;
        CaFormatGoodbye *goodbye;

        mode_t mode;          /* Only relevant if entry == NULL */
        uint64_t size;        /* Only for S_ISREG() */

        char *user_name;
        char *group_name;
        char *symlink_target; /* Only for S_ISLNK() */
        dev_t rdev;           /* Only for S_ISCHR() and S_ISBLK() */

        CaDecoderExtendedAttribute *xattrs;

        bool have_fcaps;
        void *fcaps;
        size_t fcaps_size;

        bool have_acl;
        CaDecoderACLEntry *acl_user;
        CaDecoderACLEntry *acl_group;
        CaDecoderACLEntry *acl_default_user;
        CaDecoderACLEntry *acl_default_group;
        uint64_t acl_group_obj_permissions;
        uint64_t acl_default_user_obj_permissions;
        uint64_t acl_default_group_obj_permissions;
        uint64_t acl_default_other_permissions;
        uint64_t acl_default_mask_permissions;

        bool punch_holes;
} CaDecoderNode;

typedef enum CaDecoderState {
        CA_DECODER_INIT,
        CA_DECODER_ENTERED,
        CA_DECODER_ENTERED_FOR_SEEK,
        CA_DECODER_ENTRY,
        CA_DECODER_IN_PAYLOAD,
        CA_DECODER_IN_DIRECTORY,
        CA_DECODER_GOODBYE,
        CA_DECODER_EOF,
        CA_DECODER_PREPARING_SEEK_TO_FILENAME,
        CA_DECODER_SEEKING_TO_FILENAME,
        CA_DECODER_PREPARING_SEEK_TO_ENTRY,
        CA_DECODER_SEEKING_TO_ENTRY,
        CA_DECODER_PREPARING_SEEK_TO_GOODBYE,
        CA_DECODER_SEEKING_TO_GOODBYE,
        CA_DECODER_PREPARING_SEEK_TO_GOODBYE_SIZE,
        CA_DECODER_SEEKING_TO_GOODBYE_SIZE,
        CA_DECODER_NOWHERE,
} CaDecoderState;

struct CaDecoder {
        CaDecoderState state;

        uint64_t feature_flags;

        CaDecoderNode nodes[NODES_MAX];
        size_t n_nodes;
        size_t node_idx;
        size_t boundary_node_idx; /* Never go further up than this node. We set this in order to stop iteration above the point we seeked to */

        /* A buffer that automatically resizes, containing what we read most recently */
        ReallocBuffer buffer;

        /* An EOF was signalled to us */
        bool eof;

        /* Where we are from the stream start */
        uint64_t archive_offset;

        /* Where we are from the start of the current payload we are looking at */
        uint64_t payload_offset;

        /* How far cadecoder_step() will jump ahead */
        uint64_t step_size;

        /* If we are seeking, the path we are seeking to */
        char *seek_path; /* full */
        const char *seek_subpath; /* the subpath left to seek */
        uint64_t seek_idx; /* Current counter of filenames with the same hash value */
        uint64_t seek_offset; /* Where to seek to, if we already know */
        uint64_t seek_end_offset; /* If we are seeking somewhere and know the end of the object we seek into, we store it here*/

        /* Cached name → UID/GID translation */
        uid_t cached_uid;
        gid_t cached_gid;

        char *cached_user_name;
        char *cached_group_name;

        /* A cached pair of st_dev and magic, so that we don't have to call statfs() for each file */
        dev_t cached_st_dev;
        statfs_f_type_t cached_magic;

        int boundary_fd;

        bool punch_holes;
};

static inline bool CA_DECODER_IS_SEEKING(CaDecoder *d) {
        return IN_SET(d->state,
                      CA_DECODER_ENTERED_FOR_SEEK,
                      CA_DECODER_PREPARING_SEEK_TO_FILENAME,
                      CA_DECODER_SEEKING_TO_FILENAME,
                      CA_DECODER_PREPARING_SEEK_TO_ENTRY,
                      CA_DECODER_SEEKING_TO_ENTRY,
                      CA_DECODER_PREPARING_SEEK_TO_GOODBYE,
                      CA_DECODER_SEEKING_TO_GOODBYE,
                      CA_DECODER_PREPARING_SEEK_TO_GOODBYE_SIZE,
                      CA_DECODER_SEEKING_TO_GOODBYE_SIZE);
}

static mode_t ca_decoder_node_mode(CaDecoderNode *n) {
        assert(n);

        if (n->entry)
                return (mode_t) read_le64(&n->entry->mode);

        return n->mode;
}

CaDecoder *ca_decoder_new(void) {
        CaDecoder *d = NULL;

        d = new0(CaDecoder, 1);
        if (!d)
                return NULL;

        d->feature_flags = UINT64_MAX;

        d->seek_idx = UINT64_MAX;
        d->seek_offset = UINT64_MAX;
        d->seek_end_offset = UINT64_MAX;

        d->cached_uid = UID_INVALID;
        d->cached_gid = GID_INVALID;

        d->boundary_fd = -1;

        d->punch_holes = true;

        return d;
}

static void ca_decoder_node_free_xattrs(CaDecoderNode *n) {
        assert(n);

        while (n->xattrs) {
                CaDecoderExtendedAttribute *next;
                next = n->xattrs->next;
                free(n->xattrs);
                n->xattrs = next;
        }
}

static void ca_decoder_node_free_acl_entries(CaDecoderACLEntry **e) {

        while (*e) {
                CaDecoderACLEntry *next;

                next = (*e)->next;
                free(*e);
                *e = next;
        }
}

static void ca_decoder_node_free(CaDecoderNode *n) {
        assert(n);

        if (n->fd >= 3)
                n->fd = safe_close(n->fd);
        else
                n->fd = -1;

        n->name = mfree(n->name);
        n->entry = mfree(n->entry);
        n->user_name = mfree(n->user_name);
        n->group_name = mfree(n->group_name);
        n->symlink_target = mfree(n->symlink_target);
        n->size = UINT64_MAX;
        n->mode = (mode_t) -1;
        n->rdev = 0;
        n->fcaps = mfree(n->fcaps);
        n->fcaps_size = 0;
        n->have_fcaps = false;

        ca_decoder_node_free_xattrs(n);

        ca_decoder_node_free_acl_entries(&n->acl_user);
        ca_decoder_node_free_acl_entries(&n->acl_group);
        ca_decoder_node_free_acl_entries(&n->acl_default_user);
        ca_decoder_node_free_acl_entries(&n->acl_default_group);

        n->acl_group_obj_permissions =
                n->acl_default_user_obj_permissions =
                n->acl_default_group_obj_permissions =
                n->acl_default_other_permissions =
                n->acl_default_mask_permissions = UINT64_MAX;

        n->have_acl = false;

        n->entry_offset = UINT64_MAX;
        n->goodbye_offset = UINT64_MAX;
        n->end_offset = UINT64_MAX;
}

static void ca_decoder_flush_nodes(CaDecoder *d, size_t leave) {
        size_t i;

        assert(d);

        for (i = leave; i < d->n_nodes; i++)
                ca_decoder_node_free(d->nodes + i);

        if (d->n_nodes > leave)
                d->n_nodes = leave;
}

CaDecoder *ca_decoder_unref(CaDecoder *d) {
        if (!d)
                return NULL;

        ca_decoder_flush_nodes(d, 0);

        realloc_buffer_free(&d->buffer);

        free(d->cached_user_name);
        free(d->cached_group_name);

        free(d->seek_path);

        safe_close(d->boundary_fd);

        free(d);

        return NULL;
}

int ca_decoder_get_feature_flags(CaDecoder *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (d->feature_flags == UINT64_MAX)
                return -ENODATA;

        *ret = d->feature_flags;
        return 0;
}

int ca_decoder_set_base_fd(CaDecoder *d, int fd) {
        struct stat st;
        struct statfs sfs;

        if (!d)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;
        if (d->n_nodes > 0)
                return -EBUSY;
        if (d->boundary_fd >= 0)
                return -EBUSY;

        if (fstat(fd, &st) < 0)
                return -errno;
        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISBLK(st.st_mode))
                return -ENOTTY;

        d->nodes[0] = (CaDecoderNode) {
                .fd = fd,
                .entry_offset = S_ISDIR(st.st_mode) ? 0 : UINT64_MAX,
                .goodbye_offset = UINT64_MAX,
                .end_offset = UINT64_MAX,
                .mode = st.st_mode,
                .size = UINT64_MAX,
                .acl_group_obj_permissions = UINT64_MAX,
                .acl_default_user_obj_permissions = UINT64_MAX,
                .acl_default_group_obj_permissions = UINT64_MAX,
                .acl_default_other_permissions = UINT64_MAX,
                .acl_default_mask_permissions = UINT64_MAX,
        };

        d->n_nodes = 1;

        d->cached_magic = sfs.f_type;
        d->cached_st_dev = st.st_dev;

        return 0;
}

int ca_decoder_set_boundary_fd(CaDecoder *d, int fd) {
        struct stat st;

        if (!d)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (d->boundary_fd >= 0)
                return -EBUSY;
        if (d->n_nodes > 0 && d->nodes[0].fd >= 0)
                return -EBUSY;

        if (fstat(fd, &st) < 0)
                return -errno;
        if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;

        d->boundary_fd = fd;

        d->nodes[0] = (CaDecoderNode) {
                .fd = -1,
                .entry_offset = 0,
                .goodbye_offset = UINT64_MAX,
                .end_offset = UINT64_MAX,
                .mode = S_IFDIR,
                .size = UINT64_MAX,
                .acl_group_obj_permissions = UINT64_MAX,
                .acl_default_user_obj_permissions = UINT64_MAX,
                .acl_default_group_obj_permissions = UINT64_MAX,
                .acl_default_other_permissions = UINT64_MAX,
                .acl_default_mask_permissions = UINT64_MAX,
        };

        d->n_nodes = 1;

        return 0;
}

int ca_decoder_set_base_mode(CaDecoder *d, mode_t m) {
        if (!d)
                return -EINVAL;
        if (m & ~(07777 | S_IFMT))
                return -EINVAL;
        if (!S_ISREG(m) && !S_ISDIR(m) && !S_ISBLK(m))
                return -ENOTTY;

        if (d->n_nodes > 0)
                return -EBUSY;

        d->nodes[0] = (CaDecoderNode) {
                .fd = -1,
                .entry_offset = S_ISDIR(m) ? 0 : UINT64_MAX,
                .goodbye_offset = UINT64_MAX,
                .end_offset = UINT64_MAX,
                .mode = m,
                .size = UINT64_MAX,
                .acl_group_obj_permissions = UINT64_MAX,
                .acl_default_user_obj_permissions = UINT64_MAX,
                .acl_default_group_obj_permissions = UINT64_MAX,
                .acl_default_other_permissions = UINT64_MAX,
                .acl_default_mask_permissions = UINT64_MAX,
        };

        d->n_nodes = 1;

        return 0;
}

static CaDecoderNode* ca_decoder_current_node(CaDecoder *d) {
        assert(d);

        if (d->node_idx >= d->n_nodes)
                return NULL;

        return d->nodes + d->node_idx;
}

static CaDecoderNode* ca_decoder_current_parent_node(CaDecoder *d) {
        assert(d);

        if (d->node_idx == 0)
                return NULL;

        return d->nodes + d->node_idx - 1;
}

static CaDecoderNode* ca_decoder_current_child_node(CaDecoder *d) {
        assert(d);

        if (d->node_idx+1 >= d->n_nodes)
                return NULL;

        return d->nodes + d->node_idx + 1;
}

static void ca_decoder_forget_children(CaDecoder *d) {
        assert(d);

        while (d->n_nodes-1 > d->node_idx)
                ca_decoder_node_free(d->nodes + --d->n_nodes);
}

static CaDecoderNode* ca_decoder_init_child(CaDecoder *d) {
        CaDecoderNode *n;

        assert(d);

        ca_decoder_forget_children(d);

        if (d->n_nodes >= NODES_MAX)
                return NULL;

        n = d->nodes + d->n_nodes ++ ;

        *n = (CaDecoderNode) {
                .fd = -1,
                .entry_offset = UINT64_MAX,
                .goodbye_offset = UINT64_MAX,
                .end_offset = UINT64_MAX,
                .mode = (mode_t) -1,
                .size = UINT64_MAX,
                .acl_group_obj_permissions = UINT64_MAX,
                .acl_default_user_obj_permissions = UINT64_MAX,
                .acl_default_group_obj_permissions = UINT64_MAX,
                .acl_default_other_permissions = UINT64_MAX,
                .acl_default_mask_permissions = UINT64_MAX,
        };

        return n;
}

static int ca_decoder_enter_child(CaDecoder *d) {
        assert(d);

        if (d->node_idx+1 >= d->n_nodes)
                return -EINVAL;
        if (!d->nodes[d->node_idx+1].name)
                return -EINVAL;

        d->node_idx++;

        return 0;
}

static void ca_decoder_enter_state(CaDecoder *d, CaDecoderState state) {
        assert(d);

        d->state = state;
        d->payload_offset = 0;
        d->step_size = 0;
}

static int ca_decoder_leave_child(CaDecoder *d) {
        assert(d);

        if (d->node_idx <= d->boundary_node_idx)
                return 0;

        d->node_idx--;

        return 1;
}

static int ca_decoder_object_is_complete(const void *p, size_t size) {
        const CaFormatHeader *h;
        uint64_t k;

        if (size < sizeof(CaFormatHeader))
                return false;

        assert(p);

        h = p;
        k = read_le64(&h->size);
        if (k < sizeof(CaFormatHeader))
                return -EBADMSG;
        if (k == UINT64_MAX)
                return -EBADMSG;

        return size >= k;
}

static bool validate_filename(const char *name, size_t n) {
        const char *p;

        assert(name);

        if (n < 2)
                return false;

        if (name[n-1] != 0)
                return false;

        if (name[0] == '.') {
                if (name[1] == '.' && name[2] == 0)
                        return false;

                if (name[1] == 0)
                        return false;
        }

        for (p = name; p < name + n-1; p++)
                if (*p == 0 || *p == '/')
                        return false;

        return true;
}

static bool validate_mode(CaDecoder *d, uint64_t m) {
        assert(d);

        if ((m & ~(S_IFMT | UINT64_C(07777))) != 0)
                return false;

        switch (m & S_IFMT) {

        case S_IFREG:
        case S_IFDIR:
                break;

        case S_IFSOCK:
                if (!(d->feature_flags & CA_FORMAT_WITH_SOCKETS))
                        return false;
                break;

        case S_IFIFO:
                if (!(d->feature_flags & CA_FORMAT_WITH_FIFOS))
                        return false;
                break;

        case S_IFBLK:
        case S_IFCHR:
                if (!(d->feature_flags & CA_FORMAT_WITH_DEVICE_NODES))
                        return false;
                break;

        case S_IFLNK:
                if (!(d->feature_flags & CA_FORMAT_WITH_SYMLINKS))
                        return false;
                break;

        default:
                return false;
        }

        if (S_ISLNK(m) && ((m & 07777) != 0777))
                return false;

        if (d->feature_flags & (CA_FORMAT_WITH_PERMISSIONS|CA_FORMAT_WITH_ACL))
                return true;

        if ((m & 07777) == (S_ISDIR(m) ? 0777 : 0666))
                return true;

        if (d->feature_flags & CA_FORMAT_WITH_READ_ONLY) {
                if ((m & 07777) == (S_ISDIR(m) ? 0555 : 0444))
                        return true;
        }

        return false;
}

static bool validate_uid_gid(CaDecoder *d, uint64_t u) {
        /* Don't permit either (uid_t) -1 for 16bit nor 32bit uid_t. */

        assert(d);

        if (d->feature_flags & CA_FORMAT_WITH_16BIT_UIDS)
                return u < UINT16_MAX;

        if (d->feature_flags & CA_FORMAT_WITH_32BIT_UIDS)
                return u < UINT32_MAX && u != UINT16_MAX;

        return u == 0;
}

static bool validate_entry_flags(CaDecoder *d, uint64_t f) {
        assert(d);

        return (f & ~(d->feature_flags & (CA_FORMAT_WITH_FAT_ATTRS|CA_FORMAT_WITH_CHATTR))) == 0;
}

static bool validate_major(uint64_t m) {
        /* On Linux major numbers are 12bit */
        return m < (UINT64_C(1) << 12);
}

static bool validate_minor(uint64_t m) {
        /* On Linux minor numbers are 20bit */
        return m < (UINT64_C(1) << 20);
}

static bool validate_nsec(CaDecoder *d, uint64_t t) {

        assert(d);

        if (t == UINT64_MAX)
                return false;

        if (d->feature_flags & CA_FORMAT_WITH_NSEC_TIME)
                return true;

        if (d->feature_flags & CA_FORMAT_WITH_USEC_TIME)
                return (t % UINT64_C(1000000)) == 0;

        if (d->feature_flags & CA_FORMAT_WITH_SEC_TIME)
                return (t % UINT64_C(1000000000)) == 0;

        if (d->feature_flags & CA_FORMAT_WITH_2SEC_TIME)
                return (t % UINT64_C(2000000000)) == 0;

        return t == 0;
}

static bool validate_user_group_name(const char *name, size_t n) {
        const char *p;

        assert(name || n == 0);

        if (n < 2)
                return false;

        if (name[n-1] != 0)
                return false;

        if (!(name[0] >= 'a' && name[0] <= 'z') &&
            !(name[0] >= 'A' && name[0] <= 'Z') &&
            name[0] != '_')
                return false;

        for (p = name + 1; p < name + n-1; p++)
                if (!(*p >= 'a' && *p <= 'z') &&
                    !(*p >= 'A' && *p <= 'Z') &&
                    !(*p >= '0' && *p <= '9') &&
                    *p != '_' &&
                    *p != '-')
                        return false;

        if (n > 256) /* sysconf(_SC_LOGIN_NAME_MAX) on Linux is 256 */
                return false;

        /* If the user/group name is root, then it should be suppressed. Don't accept otherwise */
        if (n == 5 && memcmp(name, "root", 5) == 0)
                return false;
        if (n == 2 && memcmp(name, "0", 2) == 0)
                return false;

        return true;
}

static bool validate_symlink_target(const char *target, size_t n) {
        const char *p;

        assert(target || n == 0);

        if (n < 2)
                return false;

        if (target[n-1] != 0)
                return false;

        for (p = target; p < target + n - 1; p++)
                if (*p == 0)
                        return false;

        if (n > 4096) /* PATH_MAX is 4K on Linux */
                return false;

        return true;
}

static bool validate_feature_flags(CaDecoder *d, uint64_t flags) {
        assert(d);

        /* We use all bits on in the flags field as a special value, don't permit this in files */
        if (flags == UINT64_MAX)
                return false;

        if ((flags & CA_FORMAT_WITH_NSEC_TIME) &&
            (flags & (CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_2SEC_TIME)))
                return false;

        if ((flags & CA_FORMAT_WITH_USEC_TIME) &&
            (flags & (CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_2SEC_TIME)))
                return false;

        if ((flags & CA_FORMAT_WITH_SEC_TIME) &&
            (flags & CA_FORMAT_WITH_2SEC_TIME))
                return false;

        if ((flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) == (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS))
                return false;

        if ((flags & CA_FORMAT_WITH_PERMISSIONS) &&
            (flags & CA_FORMAT_WITH_READ_ONLY))
                return false;

        if ((flags & CA_FORMAT_WITH_ACL) &&
            (flags & (CA_FORMAT_WITH_PERMISSIONS|CA_FORMAT_WITH_READ_ONLY)))
                return false;

        if ((flags & CA_FORMAT_WITH_ACL) &&
            (flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS|CA_FORMAT_WITH_USER_NAMES)) == 0)
                return false;

        if ((flags & CA_FORMAT_RESPECT_FLAG_NODUMP) &&
            (flags & CA_FORMAT_WITH_FLAG_NODUMP))
                return false;

        if (d->feature_flags == UINT64_MAX)
                /* The first ENTRY record decides the flags for the whole archive */
                d->feature_flags = flags;
        else if (d->feature_flags != flags)
                return false;

        return true;
}

static const CaFormatEntry* validate_format_entry(CaDecoder *d, const void *p) {
        const CaFormatEntry *e = p;

        assert(d);
        assert(e);

        if (read_le64(&e->header.size) < sizeof(CaFormatEntry))
                return NULL;
        if (read_le64(&e->header.type) != CA_FORMAT_ENTRY)
                return NULL;

        if (!validate_feature_flags(d, read_le64(&e->feature_flags)))
                return NULL;
        if (!validate_mode(d, read_le64(&e->mode)))
                return NULL;
        if (!validate_entry_flags(d, read_le64(&e->flags)))
                return NULL;
        if (!validate_uid_gid(d, read_le64(&e->uid)))
                return NULL;
        if (!validate_uid_gid(d, read_le64(&e->gid)))
                return NULL;
        if (!validate_nsec(d, read_le64(&e->mtime)))
                return NULL;

        return e;
}

static const CaFormatUser* validate_format_user(CaDecoder *d, const void *p) {
        const CaFormatUser *u = p;

        assert(d);
        assert(u);

        if (read_le64(&u->header.size) < offsetof(CaFormatUser, name) + 1)
                return NULL;
        if (read_le64(&u->header.type) != CA_FORMAT_USER)
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_USER_NAMES))
                return NULL;

        if (!validate_user_group_name(u->name, read_le64(&u->header.size) - offsetof(CaFormatUser, name)))
                return NULL;

        return u;
}

static const CaFormatGroup* validate_format_group(CaDecoder *d, const void *p) {
        const CaFormatGroup *g = p;

        assert(d);
        assert(g);

        if (read_le64(&g->header.size) < offsetof(CaFormatGroup, name) + 1)
                return NULL;
        if (read_le64(&g->header.type) != CA_FORMAT_GROUP)
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_USER_NAMES))
                return NULL;

        if (!validate_user_group_name(g->name, read_le64(&g->header.size) - offsetof(CaFormatGroup, name)))
                return NULL;

        return g;
}

static const CaFormatXAttr* validate_format_xattr(CaDecoder *d, const void *p) {
        const CaFormatXAttr *x = p;
        char *n;

        assert(d);
        assert(x);

        if (read_le64(&x->header.size) < offsetof(CaFormatXAttr, name_and_value) + 4) /* namespace + "." + name + 0 */
                return NULL;
        if (read_le64(&x->header.type) != CA_FORMAT_XATTR)
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_XATTRS))
                return NULL;

        /* Make sure there's a NUL byte in the first 256 bytes, so that we have a properly bounded name */
        n = memchr(x->name_and_value, 0, MIN(256U, read_le64(&x->header.size) - offsetof(CaFormatXAttr, name_and_value)));
        if (!n)
                return NULL;

        if (!ca_xattr_name_is_valid((char*) x->name_and_value))
                return NULL;

        return x;
}

static bool validate_acl_permissions(uint64_t p) {
        return ((p & ~(CA_FORMAT_ACL_PERMISSION_READ|CA_FORMAT_ACL_PERMISSION_WRITE|CA_FORMAT_ACL_PERMISSION_EXECUTE)) == 0);
}

static const CaFormatACLUser* validate_format_acl_user(CaDecoder *d, const void *p) {
        const CaFormatACLUser *a = p;

        assert(d);
        assert(a);

        if (read_le64(&a->header.size) < offsetof(CaFormatACLUser, name))
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_ACL))
                return NULL;

        if (read_le64(&a->header.size) > offsetof(CaFormatACLUser, name)) {

                if ((d->feature_flags & CA_FORMAT_WITH_USER_NAMES) == 0)
                        return NULL;

                if (!validate_user_group_name(a->name, read_le64(&a->header.size) - offsetof(CaFormatACLUser, name)))
                        return NULL;
        }

        if (!validate_uid_gid(d, read_le64(&a->uid)))
                return NULL;

        if (!validate_acl_permissions(read_le64(&a->permissions)))
                return NULL;

        return a;
}

static const CaFormatACLGroup* validate_format_acl_group(CaDecoder *d, const void *p) {
        const CaFormatACLGroup *a = p;

        assert(d);
        assert(a);

        if (read_le64(&a->header.size) < offsetof(CaFormatACLGroup, name))
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_ACL))
                return NULL;

        if (read_le64(&a->header.size) > offsetof(CaFormatACLGroup, name)) {

                if ((d->feature_flags & CA_FORMAT_WITH_USER_NAMES) == 0)
                        return NULL;

                if (!validate_user_group_name(a->name, read_le64(&a->header.size) - offsetof(CaFormatACLGroup, name)))
                        return NULL;
        }

        if (!validate_uid_gid(d, read_le64(&a->gid)))
                return NULL;

        if (!validate_acl_permissions(read_le64(&a->permissions)))
                return NULL;

        return a;
}

static const CaFormatACLGroupObj* validate_format_acl_group_obj(CaDecoder *d, const void *p) {
        const CaFormatACLGroupObj *a = p;

        assert(d);
        assert(a);

        if (read_le64(&a->header.size) != sizeof(CaFormatACLGroupObj))
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_ACL))
                return NULL;

        if (!validate_acl_permissions(read_le64(&a->permissions)))
                return NULL;

        return a;
}

static const CaFormatACLDefault* validate_format_acl_default(CaDecoder *d, const void *p) {
        const CaFormatACLDefault *a = p;

        assert(d);
        assert(a);

        if (read_le64(&a->header.size) != sizeof(CaFormatACLDefault))
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_ACL))
                return NULL;

        /* An ACL must have USER_OBJ + GROUP_OBJ + OTHER to be valid, but MASK is optional. See acl(5), section "VALID
         * ACLS" for details */

        if (!validate_acl_permissions(read_le64(&a->user_obj_permissions)))
                return NULL;
        if (!validate_acl_permissions(read_le64(&a->group_obj_permissions)))
                return NULL;
        if (!validate_acl_permissions(read_le64(&a->other_permissions)))
                return NULL;
        if (read_le64(&a->mask_permissions) != UINT64_MAX &&
            !validate_acl_permissions(read_le64(&a->mask_permissions)))
                return NULL;

        return a;
}

static const CaFormatFCaps* validate_format_fcaps(CaDecoder *d, const void *p) {
        const CaFormatFCaps *f = p;

        assert(d);
        assert(f);

        if (read_le64(&f->header.size) < offsetof(CaFormatFCaps, data))
                return NULL;
        if (read_le64(&f->header.type) != CA_FORMAT_FCAPS)
                return NULL;

        return f;
}

static const CaFormatSymlink* validate_format_symlink(CaDecoder *d, const void *p) {
        const CaFormatSymlink *s = p;

        assert(d);
        assert(s);

        if (read_le64(&s->header.size) < offsetof(CaFormatSymlink, target) + 1)
                return NULL;
        if (read_le64(&s->header.type) != CA_FORMAT_SYMLINK)
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_SYMLINKS))
                return NULL;

        if (!validate_symlink_target(s->target, read_le64(&s->header.size) - offsetof(CaFormatSymlink, target)))
                return NULL;

        return s;
}

static const CaFormatDevice *validate_format_device(CaDecoder *d, const void *p) {
        const CaFormatDevice *dd = p;

        if (read_le64(&dd->header.size) != sizeof(CaFormatDevice))
                return NULL;
        if (read_le64(&dd->header.type) != CA_FORMAT_DEVICE)
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_DEVICE_NODES))
                return NULL;

        if (!validate_major(read_le64(&dd->major)))
                return NULL;

        if (!validate_minor(read_le64(&dd->minor)))
                return NULL;

        return dd;
}

static const CaFormatPayload* validate_format_payload(CaDecoder *d, const void *q) {
        const CaFormatPayload *p = q;

        if (read_le64(&p->header.size) < offsetof(CaFormatPayload, data))
                return NULL;
        if (read_le64(&p->header.type) != CA_FORMAT_PAYLOAD)
                return NULL;

        return p;
}

static const CaFormatFilename* validate_format_filename(CaDecoder *d, const void *p) {
        const CaFormatFilename *f = p;

        if (read_le64(&f->header.size) < offsetof(CaFormatFilename, name) + 1)
                return NULL;
        if (read_le64(&f->header.type) != CA_FORMAT_FILENAME)
                return NULL;

        if (!validate_filename(f->name, read_le64(&f->header.size) - offsetof(CaFormatFilename, name)))
                return NULL;

        return f;
}

static const CaFormatGoodbye *validate_format_goodbye(CaDecoder *d, const void *p) {
        const CaFormatGoodbye *g = p;
        uint64_t b, l;

        if (read_le64(&g->header.size) < offsetof(CaFormatGoodbye, items) + sizeof(le64_t))
                return NULL;
        if (read_le64(&g->header.type) != CA_FORMAT_GOODBYE)
                return NULL;

        l = read_le64(&g->header.size) - offsetof(CaFormatGoodbye, items) - sizeof(le64_t);

        if (l % sizeof(CaFormatGoodbyeItem) != 0)
                return NULL;

        b = read_le64((uint8_t*) p + read_le64(&g->header.size) - sizeof(le64_t));
        if (b != read_le64(&g->header.size))
                return NULL;

        return g;
}

static int compare_format_acl_user(const CaFormatACLUser *a, const CaFormatACLUser *b) {
        bool a_has_name, b_has_name;
        int r;

        assert(a);
        assert(b);

        if (read_le64(&a->uid) < read_le64(&b->uid))
                return -1;
        if (read_le64(&a->uid) > read_le64(&b->uid))
                return 1;

        a_has_name = read_le64(&a->header.size) > offsetof(CaFormatACLUser, name);
        b_has_name = read_le64(&b->header.size) > offsetof(CaFormatACLUser, name);

        if (!a_has_name && b_has_name)
                return -1;
        if (a_has_name && !b_has_name)
                return 1;
        if (a_has_name && b_has_name) {
                r = strcmp(a->name, b->name);
                if (r != 0)
                        return r;
        }

        if (read_le64(&a->permissions) < read_le64(&b->permissions))
                return -1;
        if (read_le64(&a->permissions) > read_le64(&b->permissions))
                return 1;

        return 0;
}

static int compare_format_acl_group(const CaFormatACLGroup *a, const CaFormatACLGroup *b) {
        bool a_has_name, b_has_name;
        int r;

        assert(a);
        assert(b);

        if (read_le64(&a->gid) < read_le64(&b->gid))
                return -1;
        if (read_le64(&a->gid) > read_le64(&b->gid))
                return 1;

        a_has_name = read_le64(&a->header.size) > offsetof(CaFormatACLGroup, name);
        b_has_name = read_le64(&b->header.size) > offsetof(CaFormatACLGroup, name);

        if (!a_has_name && b_has_name)
                return -1;
        if (a_has_name && !b_has_name)
                return 1;
        if (a_has_name && b_has_name) {
                r = strcmp(a->name, b->name);
                if (r != 0)
                        return r;
        }

        if (read_le64(&a->permissions) < read_le64(&b->permissions))
                return -1;
        if (read_le64(&a->permissions) > read_le64(&b->permissions))
                return 1;

        return 0;
}

static const CaFormatGoodbyeItem* format_goodbye_search_inner(
                const CaFormatGoodbyeItem *table,
                uint64_t n,
                uint64_t h,
                uint64_t i,
                uint64_t *idx) {

        const CaFormatGoodbyeItem *f;
        uint64_t p;

        assert(table);

        if (i >= n)
                return NULL;

        p = read_le64(&table[i].hash);

        if (p == h) {

                /* There might be multiple entries with the same hash value in the table. We'll skip *idx of those */
                if (*idx == 0)
                        return table + i;

                (*idx) --;
        }

        if (h <= p) {
                f = format_goodbye_search_inner(table, n, h, 2*i+1, idx);
                if (f)
                        return f;
        }

        if (h >= p) {
                f = format_goodbye_search_inner(table, n, h, 2*i+2, idx);
                if (f)
                        return f;
        }

        return NULL;
}

static const CaFormatGoodbyeItem* format_goodbye_search(
                const CaFormatGoodbye *g,
                const char *name,
                uint64_t idx) {

        uint64_t n, hash;

        assert(g);
        assert(name);

        hash = siphash24(name, strlen(name), (const uint8_t[16]) CA_FORMAT_GOODBYE_HASH_KEY);

        if (g->header.size < sizeof(CaFormatHeader) + sizeof(le64_t))
                return NULL;

        n = g->header.size - sizeof(CaFormatHeader) - sizeof(le64_t);
        if (n % sizeof(CaFormatGoodbyeItem) != 0)
                return NULL;

        n /= sizeof(CaFormatGoodbyeItem);

        return format_goodbye_search_inner(g->items, n, hash, 0, &idx);
}

static int path_get_component(const char **p, char **ret) {
        const char *q;
        char *copy;
        size_t n;

        assert(p);
        assert(*p);

        /* Skip initial slashes */
        q = *p + strspn(*p, "/");

        /* Figure out length of next component */
        n = strcspn(q, "/");
        if (n == 0) {
                /* There is no more component */
                *p = q;
                *ret = NULL;
                return 0;
        }

        if (ret) {
                copy = strndup(q, n);
                if (!copy)
                        return -ENOMEM;

                *ret = copy;
        }

        q += n;
        *p = q + strspn(q, "/");

        return 1;
}

enum {
        PATH_MATCH_NO = -1,
        PATH_MATCH_FINAL = 0,
        PATH_MATCH_MORE = 1,
};

static int path_match_component(const char *p, const char *component) {
        const char *q;
        size_t n;

        assert(p);
        assert(component);

        /* Matches a path component against the specified path.
         *
         * Returns < 0 if no match
         * Returns 0 if match and last component of path
         * Returns > 0 if match and more components are coming
         *
         */

        p += strspn(p, "/");

        n = strlen(component);

        if (strncmp(p, component, n) != 0)
                return PATH_MATCH_NO; /* No match */

        q = p + n;

        if (!IN_SET(*q, 0, '/'))
                return PATH_MATCH_NO; /* more text coming after the component */

        q += strspn(q, "/");

        if (*q == 0)
                return PATH_MATCH_FINAL; /* last component of path */

        return PATH_MATCH_MORE; /* more coming */
}

static int ca_decoder_do_seek(CaDecoder *d, CaDecoderNode *n) {
        char *child_name;
        const char *p;
        int r;

        if (!d)
                return -EINVAL;
        if (!n)
                return -EINVAL;

        if (!d->seek_subpath)
                return -EUNATCH;

        /* Seeking works like this: depending on how much information we have:
         *
         * - If we already are at the right place, return to the entry object
         * - If we know the goodbye object already, we use it and jump to the filename object
         * - If we know the offset of the goodbye object, we jump to it
         * - If we know the end offset, we jump to the last le64_t before it to read the goodbye offset
         * - Otherwise we fail, as we don't have enough information to execute the seek operation
         *
         * Each time, if we haven't reached the goal yet, we'll be invoked again with the relevant step executed.
         *
         */

        p = d->seek_subpath;
        r = path_get_component(&p, &child_name);
        if (r < 0)
                return r;
        if (r == 0) {
                /* We are already at the goal? If so, let's seek to the beginning of the entry */

                if (n->entry_offset == UINT64_MAX)
                        return -EUNATCH;

                d->seek_offset = n->entry_offset;
                d->seek_end_offset = n->end_offset;

                ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_ENTRY);

                return 1;
        }

        if (n->goodbye) {
                const CaFormatGoodbyeItem *item;
                uint64_t so;

                /* We already loaded the goodbye object for this entry. Use it for searching */
                if (n->goodbye_offset == UINT64_MAX ||
                    n->entry_offset == UINT64_MAX)
                        return -EUNATCH;

                item = format_goodbye_search(n->goodbye, child_name, d->seek_idx);
                free(child_name);

                if (!item) {
                        ca_decoder_enter_state(d, CA_DECODER_NOWHERE);
                        return 0;
                }

                if (read_le64(&item->size) > read_le64(&item->offset))
                        return -EBADMSG;

                if (read_le64(&item->offset) > n->goodbye_offset)
                        return -EBADMSG;
                so = n->goodbye_offset - read_le64(&item->offset);
                if (so < n->entry_offset)
                        return -EBADMSG;

                d->seek_offset = so;
                d->seek_end_offset = so + read_le64(&item->size);

                ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_FILENAME);

                return 1;
        }

        free(child_name);

        if (n->goodbye_offset != UINT64_MAX) {

                /* we know the offset of the GOODBYE object, but haven't loaded it yet. Do so now */

                d->seek_offset = n->goodbye_offset;
                d->seek_end_offset = UINT64_MAX;
                ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_GOODBYE);

                return 1;
        }

        if (n->end_offset != UINT64_MAX) {

                /* We know the end of the whole shebang, jump to its last le64_t to read the goodbye object offset */

                if (n->end_offset < sizeof(le64_t))
                        return -EBADMSG;

                d->seek_offset = n->end_offset - sizeof(le64_t);
                d->seek_end_offset = n->end_offset;
                ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_GOODBYE_SIZE);

                return 1;
        }

        return -ESPIPE;
}

static int ca_decoder_parse_entry(CaDecoder *d, CaDecoderNode *n) {
        const CaFormatEntry *entry = NULL;
        const CaFormatUser *user = NULL;
        const CaFormatGroup *group = NULL;
        const CaFormatSymlink *symlink = NULL;
        const CaFormatPayload *payload = NULL;
        const CaFormatDevice *device = NULL;
        const CaFormatFilename *filename = NULL;
        const CaFormatGoodbye *goodbye = NULL;
        const CaFormatACLGroupObj *acl_group_obj = NULL;
        const CaFormatACLDefault *acl_default = NULL;
        const CaFormatFCaps *fcaps = NULL;
        uint64_t offset = 0;
        bool done = false;
        mode_t mode;
        size_t sz;
        void *p;
        int r;

        assert(d);
        assert(n);
        assert(IN_SET(d->state, CA_DECODER_INIT, CA_DECODER_ENTERED, CA_DECODER_ENTERED_FOR_SEEK));

        ca_decoder_node_free_xattrs(n);

        p = realloc_buffer_data(&d->buffer);
        sz = realloc_buffer_size(&d->buffer);
        for (;;) {
                const CaFormatHeader *h;
                uint64_t t, l;

                if (sz < sizeof(CaFormatHeader)) /* Not read enough yet */
                        return CA_DECODER_REQUEST;

                h = p;
                l = read_le64(&h->size);

                if (l < sizeof(CaFormatHeader))
                        return -EBADMSG;
                if (l == UINT64_MAX)
                        return -EBADMSG;

                t = read_le64(&h->type);

                /* fprintf(stderr, "Got object: %016" PRIx64 " (%s) @%" PRIu64 "\n", */
                /*         t, */
                /*         strna(ca_format_type_name(t)), */
                /*         d->archive_offset + offset); */

                switch (t) {

                case CA_FORMAT_ENTRY:
                        if (entry)
                                return -EBADMSG;
                        if (l != sizeof(CaFormatEntry))
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        entry = validate_format_entry(d, p);
                        if (!entry)
                                return -EBADMSG;

                        /* Is this file too new for us? */
                        if ((entry->feature_flags & ~CA_FORMAT_FEATURE_FLAGS_MAX) != 0)
                                return -EPROTONOSUPPORT;

                        offset += l;
                        break;

                case CA_FORMAT_USER:
                        if (!entry)
                                return -EBADMSG;
                        if (user)
                                return -EBADMSG;
                        if (group)
                                return -EBADMSG;
                        if (n->xattrs)
                                return -EBADMSG;
                        if (n->have_acl)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (l > CA_FORMAT_USER_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        user = validate_format_user(d, p);
                        if (!user)
                                return -EBADMSG;

                        if ((d->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) &&
                            read_le64(&entry->uid) == 0)
                                return -EBADMSG;

                        offset += l;
                        break;

                case CA_FORMAT_GROUP:
                        if (!entry)
                                return -EBADMSG;
                        if (group)
                                return -EBADMSG;
                        if (n->xattrs)
                                return -EBADMSG;
                        if (n->have_acl)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (l > CA_FORMAT_GROUP_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        group = validate_format_group(d, p);
                        if (!group)
                                return -EBADMSG;

                        if ((d->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) &&
                            read_le64(&entry->gid) == 0)
                                return -EBADMSG;

                        offset += l;
                        break;

                case CA_FORMAT_XATTR: {
                        const struct CaFormatXAttr *x;
                        CaDecoderExtendedAttribute *u;

                        if (!entry)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (n->have_acl)
                                return -EBADMSG;
                        if (l > CA_FORMAT_XATTR_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        x = validate_format_xattr(d, p);
                        if (!x)
                                return -EBADMSG;

                        /* Check whether things are properly ordered */
                        if (n->xattrs && strcmp((char*) x->name_and_value, (char*) n->xattrs->format.name_and_value) <= 0)
                                return -EBADMSG;

                        /* Add to list of extended attributes */
                        u = malloc(offsetof(CaDecoderExtendedAttribute, format) + l);
                        if (!u)
                                return -ENOMEM;

                        memcpy(&u->format, x, l);
                        u->next = n->xattrs;
                        n->xattrs = u;

                        offset += l;

                        break;
                }

                case CA_FORMAT_ACL_USER:

                        if (n->acl_group)
                                return -EBADMSG;
                        if (acl_group_obj)
                                return -EBADMSG;
                        if (acl_default)
                                return -EBADMSG;
                        if (n->acl_default_user)
                                return -EBADMSG;

                        /* fall through */

                case CA_FORMAT_ACL_DEFAULT_USER: {
                        const struct CaFormatACLUser *u;
                        CaDecoderACLEntry *a;

                        if (!entry)
                                return -EBADMSG;
                        if (n->acl_default_group)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;

                        if (l > CA_FORMAT_ACL_USER_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        u = validate_format_acl_user(d, p);
                        if (!u)
                                return -EBADMSG;

                        if (t == CA_FORMAT_ACL_USER) {
                                if (n->acl_user && compare_format_acl_user(u, &n->acl_user->user) <= 0)
                                        return -EBADMSG;
                        } else {
                                if (n->acl_default_user && compare_format_acl_user(u, &n->acl_default_user->user) <= 0)
                                        return -EBADMSG;
                        }

                        a = malloc(offsetof(CaDecoderACLEntry, user) + l);
                        if (!a)
                                return -ENOMEM;

                        memcpy(&a->user, u, l);

                        if (t == CA_FORMAT_ACL_USER) {
                                a->next = n->acl_user;
                                n->acl_user = a;
                        } else {
                                a->next = n->acl_default_user;
                                n->acl_default_user = a;
                        }

                        n->have_acl = true;
                        offset += l;
                        break;
                }

                case CA_FORMAT_ACL_GROUP:

                        if (acl_group_obj)
                                return -EBADMSG;
                        if (acl_default)
                                return -EBADMSG;
                        if (n->acl_default_user || n->acl_default_group)
                                return -EBADMSG;

                        /* fall through */

                case CA_FORMAT_ACL_DEFAULT_GROUP: {
                        const struct CaFormatACLGroup *u;
                        CaDecoderACLEntry *a;

                        if (!entry)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;

                        if (l > CA_FORMAT_ACL_GROUP_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        u = validate_format_acl_group(d, p);
                        if (!u)
                                return -EBADMSG;

                        if (t == CA_FORMAT_ACL_GROUP) {
                                if (n->acl_group && compare_format_acl_group(u, &n->acl_group->group) <= 0)
                                        return -EBADMSG;
                        } else {
                                if (n->acl_default_group && compare_format_acl_group(u, &n->acl_default_group->group) <= 0)
                                        return -EBADMSG;
                        }

                        a = malloc(offsetof(CaDecoderACLEntry, group) + l);
                        if (!a)
                                return -ENOMEM;

                        memcpy(&a->group, u, l);

                        if (t == CA_FORMAT_ACL_GROUP) {
                                a->next = n->acl_group;
                                n->acl_group = a;
                        } else {
                                a->next = n->acl_default_group;
                                n->acl_default_group = a;
                        }

                        n->have_acl = true;
                        offset += l;
                        break;
                }

                case CA_FORMAT_ACL_GROUP_OBJ:
                        if (!entry)
                                return -EBADMSG;
                        if (acl_group_obj)
                                return -EBADMSG;
                        if (acl_default)
                                return -EBADMSG;
                        if (n->acl_default_user || n->acl_default_group)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;

                        if (l != sizeof(CaFormatACLGroupObj))
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        acl_group_obj = validate_format_acl_group_obj(d, p);
                        if (!acl_group_obj)
                                return -EBADMSG;

                        n->have_acl = true;

                        offset += l;
                        break;

                case CA_FORMAT_ACL_DEFAULT:
                        if (!entry)
                                return -EBADMSG;
                        if (acl_default)
                                return -EBADMSG;
                        if (n->acl_default_user || n->acl_default_group)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;

                        if (l != sizeof(CaFormatACLDefault))
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        acl_default = validate_format_acl_default(d, p);
                        if (!acl_default)
                                return -EBADMSG;

                        n->have_acl = true;

                        offset += l;
                        break;

                case CA_FORMAT_FCAPS:
                        if (!entry)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (l > CA_FORMAT_FCAPS_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        fcaps = validate_format_fcaps(d, p);
                        if (!fcaps)
                                return -EBADMSG;

                        offset += l;
                        break;

                case CA_FORMAT_SYMLINK:
                        if (!entry)
                                return -EBADMSG;
                        if (!S_ISLNK(read_le64(&entry->mode)))
                                return -EBADMSG;
                        if (l > CA_FORMAT_SYMLINK_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        symlink = validate_format_symlink(d, p);
                        if (!symlink)
                                return -EBADMSG;

                        offset += l;
                        done = true;
                        break;

                case CA_FORMAT_DEVICE:
                        if (!entry)
                                return -EBADMSG;
                        if (!S_ISCHR(read_le64(&entry->mode)) && !S_ISBLK(read_le64(&entry->mode)))
                                return -EBADMSG;
                        if (l != sizeof(CaFormatDevice))
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        device = validate_format_device(d, p);
                        if (!device)
                                return -EBADMSG;

                        offset += l;
                        done = true;
                        break;

                case CA_FORMAT_PAYLOAD:
                        if (!entry)
                                return -EBADMSG;
                        if (!S_ISREG(read_le64(&entry->mode)))
                                return -EBADMSG;
                        if (l < offsetof(CaFormatPayload, data))
                                return CA_DECODER_REQUEST;

                        payload = validate_format_payload(d, p);
                        if (!payload)
                                return -EBADMSG;

                        offset += offsetof(CaFormatPayload, data); /* only skip over the payload header, not the payload itself */

                        done = true;
                        break;

                case CA_FORMAT_FILENAME:
                        if (!entry)
                                return -EBADMSG;
                        if (l < offsetof(CaFormatFilename, name) + 1)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        filename = validate_format_filename(d, p);
                        if (!filename)
                                return -EBADMSG;

                        /* Note that we don't increase "offset" here, as we want to process it as part of the next
                         * state. */

                        done = true;
                        break;

                case CA_FORMAT_GOODBYE:
                        if (!entry)
                                return -EBADMSG;
                        if (!S_ISDIR(read_le64(&entry->mode)))
                                return -EBADMSG;
                        if (l < offsetof(CaFormatGoodbye, items) + sizeof(le64_t))
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        goodbye = validate_format_goodbye(d, p);
                        if (!goodbye)
                                return -EBADMSG;

                        /* Note that we don't increase "offset" here, as we want to process it as part of the next
                         * state */

                        done = true;
                        break;

                default:
                        fprintf(stderr, "Got unexpected object: %016" PRIx64 "\n", t);
                        return -EBADMSG;
                }

                if (done)
                        break;

                p = (uint8_t*) p + l;
                sz -= l;
        }

        if (!entry)
                return -EBADMSG;

        if (user && !(d->feature_flags & CA_FORMAT_WITH_USER_NAMES))
                return -EBADMSG;
        if (group && !(d->feature_flags & CA_FORMAT_WITH_USER_NAMES))
                return -EBADMSG;

        if ((d->feature_flags & CA_FORMAT_WITH_USER_NAMES) &&
            !(d->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) &&
            (!user || !group))
                return -EBADMSG;

        mode = (mode_t) read_le64(&entry->mode);

        if (S_ISREG(mode) && !payload)
                return -EBADMSG;
        if (S_ISDIR(mode) && !(filename || goodbye))
                return -EBADMSG;
        if (S_ISLNK(mode) && !symlink)
                return -EBADMSG;
        if ((S_ISBLK(mode) || S_ISCHR(mode)) && !device)
                return -EBADMSG;
        if (!S_ISREG(mode) && fcaps)
                return -EBADMSG;

        /* Both FAT and chattr(1) flags are only defined for regular files and directories */
        if (read_le64(&entry->flags) != 0 && !S_ISREG(mode) && !S_ISDIR(mode))
                return -EBADMSG;

        /* The top-level node must be a directory */
        if (d->node_idx == 0 && !S_ISDIR(mode))
                return -EBADMSG;

        /* xattrs/ALCs are not defined for symlinks */
        if (S_ISLNK(mode) && (n->xattrs || n->have_acl))
                return -EBADMSG;

        /* If there's at least one USER or GROUP entry in the access ACL, we also mus have a MASK entry (which is
         * stored in the stat() gid data) and hence a separate GROUP_OBJ */
        if ((n->acl_user || n->acl_group) && !acl_group_obj)
                return -EBADMSG;

        /* If there's at least one USER or GROUP entry in the default ACL, we also must have a default MASK entry */
        if ((n->acl_default_user || n->acl_default_group) &&
            (!acl_default ||
             read_le64(&acl_default->mask_permissions) == UINT64_MAX))
                return -EBADMSG;

        /* Default ACLs are only defined for directories */
        if ((n->acl_default_user || n->acl_default_group || acl_default) &&
            !S_ISDIR(mode))
                return -EBADMSG;

        assert(!n->entry);
        assert(!n->user_name);
        assert(!n->group_name);
        assert(!n->symlink_target);

        n->entry = memdup(entry, sizeof(CaFormatEntry));
        if (!n->entry)
                return -ENOMEM;

        if (user) {
                n->user_name = strdup(user->name);
                if (!n->user_name)
                        return -ENOMEM;
        }

        if (group) {
                n->group_name = strdup(group->name);
                if (!n->group_name)
                        return -ENOMEM;
        }

        if (acl_group_obj)
                n->acl_group_obj_permissions = read_le64(&acl_group_obj->permissions);

        if (acl_default) {
                n->acl_default_user_obj_permissions = read_le64(&acl_default->user_obj_permissions);
                n->acl_default_group_obj_permissions = read_le64(&acl_default->group_obj_permissions);
                n->acl_default_other_permissions = read_le64(&acl_default->other_permissions);
                n->acl_default_mask_permissions = read_le64(&acl_default->mask_permissions);
        }

        if (fcaps) {
                n->fcaps = memdup(fcaps->data, read_le64(&fcaps->header.size) - offsetof(CaFormatFCaps, data));
                if (!n->fcaps)
                        return -ENOMEM;

                n->fcaps_size = read_le64(&fcaps->header.size) - offsetof(CaFormatFCaps, data);
                n->have_fcaps = true;
        }

        if (symlink) {
                n->symlink_target = strdup(symlink->target);
                if (!n->symlink_target)
                        return -ENOMEM;
        }

        if (device)
                n->rdev = makedev(read_le64(&device->major), read_le64(&device->minor));

        if (payload)
                n->size = read_le64(&payload->header.size) - offsetof(CaFormatPayload, data);

        if (d->state == CA_DECODER_ENTERED_FOR_SEEK) {

                r = ca_decoder_do_seek(d, n);
                if (r < 0)
                        return r;

                if (r == 0)
                        return CA_DECODER_NOT_FOUND;

                return CA_DECODER_STEP;
        }

        ca_decoder_enter_state(d, CA_DECODER_ENTRY);
        d->step_size = offset;

        return CA_DECODER_NEXT_FILE;
}

static void ca_decoder_reset_seek(CaDecoder *d) {
        assert(d);

        d->seek_path = mfree(d->seek_path);
        d->seek_subpath = NULL;
        d->seek_idx = 0;
        d->seek_offset = UINT64_MAX;
        d->seek_end_offset = UINT64_MAX;
}

static int ca_decoder_parse_filename(CaDecoder *d, CaDecoderNode *n) {
        const CaFormatFilename *filename = NULL;
        const CaFormatGoodbye *goodbye = NULL;
        const CaFormatHeader *h;
        uint64_t l, t;
        size_t sz;
        int r;

        assert(d);
        assert(IN_SET(d->state, CA_DECODER_IN_DIRECTORY, CA_DECODER_SEEKING_TO_FILENAME, CA_DECODER_SEEKING_TO_GOODBYE));

        sz = realloc_buffer_size(&d->buffer);
        if (sz < sizeof(CaFormatHeader))
                return CA_DECODER_REQUEST;

        h = realloc_buffer_data(&d->buffer);
        l = read_le64(&h->size);
        if (l < sizeof(CaFormatHeader))
                return -EBADMSG;
        if (l == UINT64_MAX)
                return -EBADMSG;

        t = read_le64(&h->type);

        switch (t) {

        case CA_FORMAT_FILENAME: {
                CaDecoderNode *child;
                bool seek_continues = false, arrived = false;
                uint64_t end_offset = UINT64_MAX;

                if (!IN_SET(d->state, CA_DECODER_IN_DIRECTORY, CA_DECODER_SEEKING_TO_FILENAME))
                        return -EBADMSG;

                if (l < offsetof(CaFormatFilename, name) + 1)
                        return -EBADMSG;

                r = ca_decoder_object_is_complete(h, sz);
                if (r < 0)
                        return r;
                if (r == 0)
                        return CA_DECODER_REQUEST;

                filename = validate_format_filename(d, h);
                if (!filename)
                        return -EBADMSG;

                if (d->state == CA_DECODER_SEEKING_TO_FILENAME) {
                        int match;
                        assert(d->seek_path);

                        match = path_match_component(d->seek_subpath, filename->name);

                        if (match == PATH_MATCH_NO) {
                                /* We seeked to an incorrect entry. In that case we most likely had hash value
                                 * collision. Let's pick the next entry with the same hash value. */

                                d->seek_idx++;

                                r = ca_decoder_do_seek(d, n);
                                if (r < 0)
                                        return r;
                                if (r == 0) {
                                        ca_decoder_enter_state(d, CA_DECODER_NOWHERE);
                                        return CA_DECODER_NOT_FOUND;
                                }

                                return CA_DECODER_STEP;
                        }

                        end_offset = d->seek_end_offset;
                        d->seek_idx = 0;

                        if (match == PATH_MATCH_FINAL) {

                                /* We reached our goal, yay! */
                                ca_decoder_reset_seek(d);

                                /* Make sure that a later iteration won't go up from this */
                                d->boundary_node_idx = d->node_idx+1;

                                /* We arrived at the destination of the seek, report that */
                                arrived = true;

                        } else {
                                assert(match == PATH_MATCH_MORE);

                                /* This entry lies within our path, but the seek is not complete yet */
                                seek_continues = true;

                                /* Jump to component we need to process next. */
                                r = path_get_component(&d->seek_subpath, NULL);
                                if (r < 0)
                                        return r;

                                assert(r > 0);
                        }

                }

                child = ca_decoder_init_child(d);
                if (!child)
                        return -EFBIG;

                child->entry_offset = d->archive_offset + l;
                if (end_offset != UINT64_MAX)
                        child->end_offset = end_offset;

                child->name = strdup(filename->name);
                if (!child->name)
                        return -ENOMEM;

                r = ca_decoder_enter_child(d);
                if (r < 0)
                        return r;

                if (seek_continues)
                        ca_decoder_enter_state(d, CA_DECODER_ENTERED_FOR_SEEK);
                else
                        ca_decoder_enter_state(d, CA_DECODER_ENTERED);

                d->step_size = l;

                return arrived ? CA_DECODER_FOUND : CA_DECODER_STEP;
        }

        case CA_FORMAT_GOODBYE:

                if (!IN_SET(d->state, CA_DECODER_IN_DIRECTORY, CA_DECODER_SEEKING_TO_GOODBYE))
                        return -EBADMSG;

                if (l < offsetof(CaFormatGoodbye, items) + sizeof(le64_t))
                        return -EBADMSG;

                r = ca_decoder_object_is_complete(h, sz);
                if (r < 0)
                        return r;
                if (r == 0)
                        return CA_DECODER_REQUEST;

                goodbye = validate_format_goodbye(d, h);
                if (!goodbye)
                        return -EBADMSG;

                free(n->goodbye);
                n->goodbye = memdup(goodbye, sz);
                if (!n->goodbye)
                        return -ENOMEM;

                if (d->state == CA_DECODER_SEEKING_TO_GOODBYE) {

                        r = ca_decoder_do_seek(d, n);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_NOT_FOUND;

                        return CA_DECODER_STEP;
                }

                ca_decoder_enter_state(d, CA_DECODER_GOODBYE);
                d->step_size = l;

                return CA_DECODER_STEP;

        default:
                fprintf(stderr, "Got unexpected object: %016" PRIx64 "\n", t);
                return -EBADMSG;
        }
}

static int ca_decoder_parse_goodbye_size(CaDecoder *d, CaDecoderNode *n) {
        uint64_t l;
        size_t sz;
        void *p;
        int r;

        assert(d);
        assert(d->state == CA_DECODER_SEEKING_TO_GOODBYE_SIZE);
        assert(n);

        sz = realloc_buffer_size(&d->buffer);
        if (sz < sizeof(le64_t))
                return CA_DECODER_REQUEST;

        p = realloc_buffer_data(&d->buffer);
        l = read_le64(p);
        if (l < offsetof(CaFormatGoodbye, items) + sizeof(le64_t))
                return -EBADMSG;
        if ((l - offsetof(CaFormatGoodbye, items) - sizeof(le64_t)) % sizeof(CaFormatGoodbyeItem) != 0)
                return -EBADMSG;
        if (l > d->archive_offset + sizeof(le64_t))
                return -EBADMSG;

        n->goodbye_offset = d->archive_offset + sizeof(le64_t) - l;

        /* With the new information we acquired, try to seek to the right place now */
        r = ca_decoder_do_seek(d, n);
        if (r < 0)
                return r;
        if (r == 0)
                return CA_DECODER_NOT_FOUND;

        return CA_DECODER_STEP;
}

static int ca_decoder_node_get_fd(CaDecoder *d, CaDecoderNode *n) {
        assert(d);
        assert(n);

        /* Returns the fd of a node, if there's one set. If not, will return -1 except for the boundary node, if one is
         * configured, where the boundary fd is returned */

        if (n->fd >= 0)
                return n->fd;

        assert(n >= d->nodes && n < d->nodes + d->n_nodes);

        if ((size_t) (n - d->nodes) + 1 == d->boundary_node_idx)
                return d->boundary_fd;

        return -1;
}

static int ca_decoder_realize_child(CaDecoder *d, CaDecoderNode *n, CaDecoderNode *child) {
        mode_t mode;
        int dir_fd, r;

        assert(d);
        assert(n);
        assert(child);

        if (CA_DECODER_IS_SEEKING(d))
                return 0;

        if (child->fd >= 0)
                return 0;

        dir_fd = ca_decoder_node_get_fd(d, n);
        if (dir_fd < 0)
                return 0;

        assert(child->entry);
        assert(child->name);

        mode = read_le64(&child->entry->mode);

        switch (mode & S_IFMT) {

        case S_IFDIR:
                if (mkdirat(dir_fd, child->name, 0700) < 0) {

                        if (errno != EEXIST)
                                return -errno;
                }

                child->fd = openat(dir_fd, child->name, O_CLOEXEC|O_NOCTTY|O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
                if (child->fd < 0)
                        return -errno;

                break;

        case S_IFREG:
                child->fd = openat(dir_fd, child->name, O_CLOEXEC|O_NOCTTY|O_WRONLY|O_NOFOLLOW|O_CREAT|O_TRUNC, 0600 | mode);
                if (child->fd < 0) {
                        r = -errno;
                        if (r == -EACCES) {
                                /* If the file exists and is read-only, the open() will fail, in that case, remove it try again */
                                if (unlinkat(dir_fd, child->name, 0) >= 0)
                                        child->fd = openat(dir_fd, child->name, O_CLOEXEC|O_NOCTTY|O_WRONLY|O_NOFOLLOW|O_CREAT|O_TRUNC, 0600 | mode);
                        }

                        if (child->fd < 0)
                                return r;
                }

                break;

        case S_IFLNK:

                if (symlinkat(child->symlink_target, dir_fd, child->name) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        case S_IFIFO:

                if (mkfifoat(dir_fd, child->name, mode) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        case S_IFBLK:
        case S_IFCHR:

                if (mknodat(dir_fd, child->name, mode, child->rdev) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        case S_IFSOCK:

                if (mknodat(dir_fd, child->name, mode, 0) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        default:
                assert(false);
        }

        if (child->fd >= 0 && (read_le64(&child->entry->flags) & d->feature_flags & CA_FORMAT_WITH_CHATTR) != 0) {
                unsigned new_attr;

                /* A select few chattr() attributes need to be applied (or are better applied) on empty
                 * files/directories instead of the final result, do so here. */

                new_attr = ca_feature_flags_to_chattr(read_le64(&child->entry->flags) & d->feature_flags) & APPLY_EARLY_FS_FL;

                if (new_attr != 0) {
                        if (ioctl(child->fd, FS_IOC_SETFLAGS, &new_attr) < 0)
                                return -errno;
                }
        }

        return 0;
}

static int name_to_uid(CaDecoder *d, const char *name, uid_t *ret) {
        long bufsize;
        int r;

        assert(d);
        assert(name);
        assert(ret);

        if (streq_ptr(name, d->cached_user_name)) {
                *ret = d->cached_uid;
                return 1;
        }

        if (parse_uid(name, ret) >= 0)
                return 1;

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize <= 0)
                bufsize = 4096;

        for (;;) {
                struct passwd pwbuf, *pw = NULL;
                char *buf;

                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;

                r = getpwnam_r(name, &pwbuf, buf, (size_t) bufsize, &pw);
                if (r == 0 && pw) {

                        free(d->cached_user_name);
                        d->cached_user_name = strdup(pw->pw_name);
                        d->cached_uid = pw->pw_uid;

                        *ret = pw->pw_uid;
                        free(buf);
                        return 1;
                }
                free(buf);
                if (r != ERANGE)
                        return r > 0 ? -r : -ESRCH;

                bufsize *= 2;
        }
}

static int name_to_gid(CaDecoder *d, const char *name, gid_t *ret) {
        long bufsize;
        int r;

        assert(d);
        assert(name);
        assert(ret);

        if (streq_ptr(name, d->cached_group_name)) {
                *ret = d->cached_gid;
                return 1;
        }

        if (parse_gid(name, ret) >= 0)
                return 1;

        bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (bufsize <= 0)
                bufsize = 4096;

        for (;;) {
                struct group grbuf, *gr = NULL;
                char *buf;

                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;

                r = getgrnam_r(name, &grbuf, buf, (size_t) bufsize, &gr);
                if (r == 0 && gr) {

                        free(d->cached_group_name);
                        d->cached_group_name = strdup(gr->gr_name);
                        d->cached_gid = gr->gr_gid;

                        *ret = gr->gr_gid;
                        free(buf);
                        return 1;
                }
                free(buf);
                if (r != ERANGE)
                        return r > 0 ? -r : -ESRCH;

                bufsize *= 2;
        }
}

static int acl_add_entry_full(acl_t *acl, acl_tag_t tag, const void *qualifier, uint64_t permissions) {
        acl_permset_t permset;
        acl_entry_t entry;

        assert(acl);

        if (acl_create_entry(acl, &entry) < 0)
                return -errno;

        if (acl_set_tag_type(entry, tag) < 0)
                return -errno;

        if (qualifier)
                if (acl_set_qualifier(entry, qualifier) < 0)
                        return -errno;

        if (acl_get_permset(entry, &permset) < 0)
                return -errno;

        if (permissions & CA_FORMAT_ACL_PERMISSION_READ)
                if (acl_add_perm(permset, ACL_READ) < 0)
                        return -errno;
        if (permissions & CA_FORMAT_ACL_PERMISSION_WRITE)
                if (acl_add_perm(permset, ACL_WRITE) < 0)
                        return -errno;
        if (permissions & CA_FORMAT_ACL_PERMISSION_EXECUTE)
                if (acl_add_perm(permset, ACL_EXECUTE) < 0)
                        return -errno;

        return 0;
}

static int ca_decoder_acl_add_user_entries(CaDecoder *d, acl_t *acl, CaDecoderACLEntry *entries) {
        CaDecoderACLEntry *i;
        int r;

        assert(d);
        assert(acl);

        for (i = entries; i; i = i->next) {
                uid_t uid;

                if (read_le64(&i->user.header.size) > offsetof(CaFormatACLUser, name)) {
                        r = name_to_uid(d, i->user.name, &uid);
                        if (r < 0)
                                return r;
                } else
                        uid = read_le64(&i->user.uid);

                r = acl_add_entry_full(acl, ACL_USER, &uid, read_le64(&i->user.permissions));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ca_decoder_acl_add_group_entries(CaDecoder *d, acl_t* acl, CaDecoderACLEntry *entries) {
        CaDecoderACLEntry *i;
        int r;

        assert(d);
        assert(acl);

        for (i = entries; i; i = i->next) {
                gid_t gid;

                if (read_le64(&i->group.header.size) > offsetof(CaFormatACLGroup, name)) {
                        r = name_to_gid(d, i->group.name, &gid);
                        if (r < 0)
                                return r;
                } else
                        gid = read_le64(&i->group.gid);

                r = acl_add_entry_full(acl, ACL_GROUP, &gid, read_le64(&i->group.permissions));
                if (r < 0)
                        return r;
        }

        return 0;
}

static inline uint64_t mode_user_to_acl_permissions(mode_t m) {
        return (((uint64_t) m) >> 6) & 7;
}

static inline uint64_t mode_group_to_acl_permissions(mode_t m) {
        return (((uint64_t) m) >> 3) & 7;
}

static inline uint64_t mode_other_to_acl_permissions(mode_t m) {
        return ((uint64_t) m) & 7;
}

static int ca_decoder_child_to_acl(CaDecoder *d, CaDecoderNode *n, acl_t *ret) {
        mode_t mode;
        acl_t acl;
        int r;

        assert(d);
        assert(n);
        assert(ret);

        mode = read_le64(&n->entry->mode);

        acl = acl_init(5);
        if (!acl)
                return -ENOMEM;

        r = acl_add_entry_full(&acl, ACL_USER_OBJ, NULL, mode_user_to_acl_permissions(mode));
        if (r < 0)
                goto fail;

        r = acl_add_entry_full(&acl, ACL_OTHER, NULL, mode_other_to_acl_permissions(mode));
        if (r < 0)
                goto fail;

        if (n->acl_group_obj_permissions != UINT64_MAX) {
                /* The mask field is optional under certain conditions. If it is defined then the stat() data will
                 * report it instead of the group mask. */

                r = acl_add_entry_full(&acl, ACL_MASK, NULL, mode_group_to_acl_permissions(mode));
                if (r < 0)
                        goto fail;

                r = acl_add_entry_full(&acl, ACL_GROUP_OBJ, NULL, n->acl_group_obj_permissions);
        } else
                r = acl_add_entry_full(&acl, ACL_GROUP_OBJ, NULL, mode_group_to_acl_permissions(mode));
        if (r < 0)
                goto fail;

        r = ca_decoder_acl_add_user_entries(d, &acl, n->acl_user);
        if (r < 0)
                goto fail;

        r = ca_decoder_acl_add_group_entries(d, &acl, n->acl_group);
        if (r < 0)
                goto fail;

        *ret = acl;
        return 0;

fail:
        acl_free(acl);
        return r;
}

static int ca_decoder_child_to_default_acl(CaDecoder *d, CaDecoderNode *n, acl_t *ret) {
        acl_t acl;
        int r;

        assert(d);
        assert(n);
        assert(ret);

        acl = acl_init(5);
        if (!acl)
                return -ENOMEM;

        if (n->acl_default_user_obj_permissions != UINT64_MAX) {

                r = acl_add_entry_full(&acl, ACL_USER_OBJ, NULL, n->acl_default_user_obj_permissions);
                if (r < 0)
                        goto fail;

                r = acl_add_entry_full(&acl, ACL_GROUP_OBJ, NULL, n->acl_default_group_obj_permissions);
                if (r < 0)
                        goto fail;

                r = acl_add_entry_full(&acl, ACL_OTHER, NULL, n->acl_default_other_permissions);
                if (r < 0)
                        goto fail;

                if (n->acl_default_mask_permissions != UINT64_MAX) {
                        r = acl_add_entry_full(&acl, ACL_MASK, NULL, n->acl_default_mask_permissions);
                        if (r < 0)
                                goto fail;
                }

                r = ca_decoder_acl_add_user_entries(d, &acl, n->acl_default_user);
                if (r < 0)
                        goto fail;

                r = ca_decoder_acl_add_group_entries(d, &acl, n->acl_default_group);
                if (r < 0)
                        goto fail;
        }

        *ret = acl;
        return 0;

fail:
        acl_free(acl);
        return r;
}

static int ca_decoder_finalize_child(CaDecoder *d, CaDecoderNode *n, CaDecoderNode *child) {
        statfs_f_type_t magic = 0;
        struct stat st;
        mode_t mode;
        int r, dir_fd;

        assert(d);
        assert(child);

        /* Finalizes the file attributes on the specified child node. 'n' specifies it's parent, except for the special
         * case where we are processing the root direction of the serialization, where it is NULL. */

        if (n)
                dir_fd = ca_decoder_node_get_fd(d, n);
        else
                dir_fd = -1;

        if (dir_fd < 0 && child->fd < 0)
                return 0; /* Nothing to do if no fds are opened */

        /* If this is a top-level blob, then don't do anything */
        mode = ca_decoder_node_mode(child);
        if ((S_ISREG(mode) || S_ISBLK(mode)) && !n)
                return 0;

        assert(child->entry);

        if (child->fd >= 0)
                r = fstat(child->fd, &st);
        else {
                if (!n)
                        return -EINVAL;

                r = fstatat(dir_fd, child->name, &st, AT_SYMLINK_NOFOLLOW);
        }
        if (r < 0)
                return -errno;

        if (st.st_dev == d->cached_st_dev)
                magic = d->cached_st_dev;
        else if (child->fd >= 0) {
                struct statfs sfs;

                if (fstatfs(child->fd, &sfs) < 0)
                        return -errno;

                magic = d->cached_magic = sfs.f_type;
                d->cached_st_dev = st.st_dev;
        }

        if (((read_le64(&child->entry->mode) ^ st.st_mode) & S_IFMT) != 0)
                return -EEXIST;

        if ((S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) &&
            st.st_rdev != child->rdev)
                return -EEXIST;

        if (S_ISLNK(st.st_mode)) {
                size_t l;
                ssize_t z;
                char *buf;

                if (!n)
                        return -EINVAL;

                l = strlen(child->symlink_target);

                buf = newa(char, l+2);

                z = readlinkat(dir_fd, child->name, buf, l+1);
                if (z < 0)
                        return -errno;
                if ((size_t) z != l)
                        return -EEXIST;

                if (memcmp(child->symlink_target, buf, l) != 0)
                        return -EEXIST;
        }

        if (d->feature_flags & (CA_FORMAT_WITH_32BIT_UIDS|CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_USER_NAMES)) {
                uid_t uid;
                gid_t gid;

                if (child->user_name) {
                        r = name_to_uid(d, child->user_name, &uid);
                        if (r < 0)
                                return r;
                } else
                        uid = read_le64(&child->entry->uid);

                if (child->group_name) {
                        r = name_to_gid(d, child->group_name, &gid);
                        if (r < 0)
                                return r;
                } else
                        gid = read_le64(&child->entry->gid);

                if (st.st_uid != uid || st.st_gid != gid) {

                        if (child->fd >= 0)
                                r = fchown(child->fd, uid, gid);
                        else {
                                if (!n)
                                        return -EINVAL;

                                r = fchownat(dir_fd, child->name, uid, gid, AT_SYMLINK_NOFOLLOW);
                        }
                        if (r < 0)
                                return -errno;
                }
        }

        if (d->feature_flags & CA_FORMAT_WITH_READ_ONLY) {

                if ((st.st_mode & 0400) == 0 || /* not readable? */
                    (S_ISDIR(st.st_mode) && (st.st_mode & 0100) == 0) || /* a dir, but not executable? */
                    !(read_le64(&child->entry->mode) & 0222) != !(st.st_mode & 0200)) { /* writable bit doesn't match what it should be? */

                        mode_t new_mode;

                        new_mode = (st.st_mode & 0444) | 0400;

                        if (S_ISDIR(st.st_mode))
                                new_mode |= 0100;

                        if (read_le64(&child->entry->mode) & 0222)
                                new_mode |= 0200 |
                                        ((new_mode & 0040) ? 0020 : 0000) |
                                        ((new_mode & 0004) ? 0002 : 0000);
                        else
                                new_mode &= ~0444;

                        if (child->fd >= 0)
                                r = fchmod(child->fd, new_mode);
                        else {
                                if (!n)
                                        return -EINVAL;

                                r = fchmodat(dir_fd, child->name, new_mode, AT_SYMLINK_NOFOLLOW);
                        }
                        if (r < 0)
                                return -errno;
                }

        } else if (d->feature_flags & (CA_FORMAT_WITH_PERMISSIONS|CA_FORMAT_WITH_ACL)) {

                if ((st.st_mode & 07777) != (read_le64(&child->entry->mode) & 07777)) {

                        if (child->fd >= 0)
                                r = fchmod(child->fd, read_le64(&child->entry->mode) & 07777);
                        else {
                                if (!n)
                                        return -EINVAL;

                                r = fchmodat(dir_fd, child->name, read_le64(&child->entry->mode) & 07777, AT_SYMLINK_NOFOLLOW);
                        }
                        if (r < 0)
                                return -errno;
                }
        }

        if (d->feature_flags & CA_FORMAT_WITH_ACL) {
                char proc_path[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
                int path_fd = -1;
                acl_t new_acl;

                if (child->fd < 0) {
                        if (!n)
                                return -EINVAL;

                        path_fd = openat(dir_fd, child->name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_PATH);
                        if (path_fd < 0)
                                return -errno;
                }

                sprintf(proc_path, "/proc/self/fd/%i", child->fd < 0 ? path_fd : child->fd);

                r = ca_decoder_child_to_acl(d, child, &new_acl);
                if (r < 0) {
                        safe_close(path_fd);
                        return r;
                }

                if (acl_set_file(proc_path, ACL_TYPE_ACCESS, new_acl) < 0 &&
                    (!IN_SET(errno, EOPNOTSUPP, EBADF) || child->have_acl)) {
                        r = -errno;
                        safe_close(path_fd);
                        acl_free(new_acl);
                        return r;
                }

                acl_free(new_acl);

                if (S_ISDIR(st.st_mode)) {
                        acl_t new_default_acl;

                        r = ca_decoder_child_to_default_acl(d, child, &new_default_acl);
                        if (r < 0) {
                                safe_close(path_fd);
                                return r;
                        }

                        if (acl_set_file(proc_path, ACL_TYPE_DEFAULT, new_default_acl) < 0 &&
                            (!IN_SET(errno, EOPNOTSUPP, EBADF) || child->have_acl)) {
                                r = -errno;
                                safe_close(path_fd);
                                acl_free(new_default_acl);
                                return r;
                        }

                        acl_free(new_default_acl);
                }

                safe_close(path_fd);
        }

        if ((d->feature_flags & CA_FORMAT_WITH_XATTRS) && !S_ISLNK(st.st_mode) && child->fd >= 0) {
                CaDecoderExtendedAttribute *x;
                size_t space = 256;
                ssize_t l;
                char *p, *q;

                p = new(char, space);
                if (!p)
                        return -ENOMEM;

                for (;;) {
                        l = flistxattr(child->fd, p, space);
                        if (l < 0) {
                                if (IN_SET(errno, EOPNOTSUPP, EBADF)) {
                                        p = mfree(p);
                                        l = 0;
                                        break;
                                }

                                if (errno != ERANGE) {
                                        free(p);
                                        return -errno;
                                }
                        } else
                                break;

                        free(p);

                        if (space*2 <= space)
                                return -ENOMEM;

                        space *= 2;
                        p = new(char, space);
                        if (!p)
                                return -ENOMEM;
                }

                /* Remove xattrs set that don't appear in our list */
                q = p;
                for (;;) {
                        bool found = false;
                        size_t z;

                        if (l == 0)
                                break;

                        z = strlen(q);
                        assert(z + 1 <= (size_t) l);

                        /* Don't bother with xattrs we can't store in our archives anyway */
                        if (!ca_xattr_name_store(q))
                                goto next;

                        for (x = child->xattrs; x; x = x->next)
                                if (streq((char*) x->format.name_and_value, q)) {
                                        found = true;
                                        break;
                                }

                        if (found)
                                goto next;

                        if (fremovexattr(child->fd, q) < 0) {
                                r = -errno;
                                free(p);
                                return r;
                        }

                next:
                        q += z + 1;
                        l -= z + 1;
                }

                free(p);

                for (x = child->xattrs; x; x = x->next) {
                        size_t k;

                        k = strlen((char*) x->format.name_and_value);

                        if (fsetxattr(child->fd, (char*) x->format.name_and_value,
                                      x->format.name_and_value + k + 1,
                                      read_le64(&x->format.header.size) - offsetof(CaFormatXAttr, name_and_value) - k - 1,
                                      0) < 0)
                                return -errno;
                }
        }

        if ((d->feature_flags & CA_FORMAT_WITH_FCAPS) && S_ISREG(st.st_mode) && child->fd >= 0) {

                if (child->have_fcaps) {
                        if (fsetxattr(child->fd, "security.capability", child->fcaps, child->fcaps_size, 0) < 0)
                                return -errno;
                } else {
                        char v;

                        /* Before removing the caps we'll check if they aren't set anyway. That has the benefit that we
                         * don't run into EPERM here if we lack perms but the xattr isn't set anyway. */

                        if (fgetxattr(child->fd, "security.capability", &v, sizeof(v)) < 0) {

                                /* If the underlying file system doesn't do xattrs or caps, that's OK, if we shall set
                                 * them as empty anyway. */
                                if (!IN_SET(errno, EOPNOTSUPP, ENODATA))
                                        return -errno;
                        } else {
                                if (fremovexattr(child->fd, "security.capability") < 0)
                                        return -errno;
                        }
                }
        }

        if (d->feature_flags & (CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_NSEC_TIME|CA_FORMAT_WITH_2SEC_TIME)) {

                struct timespec ts[2] = {
                        { .tv_nsec = UTIME_OMIT },
                        nsec_to_timespec(read_le64(&child->entry->mtime)),
                };

                if (child->fd >= 0)
                        r = futimens(child->fd, ts);
                else {
                        if (!n)
                                return -EINVAL;

                        r = utimensat(dir_fd, child->name, ts, AT_SYMLINK_NOFOLLOW);
                }
                if (r < 0)
                        return -errno;
        }

        if ((d->feature_flags & CA_FORMAT_WITH_CHATTR) != 0 && child->fd >= 0) {
                unsigned new_attr, old_attr;

                new_attr = ca_feature_flags_to_chattr(read_le64(&child->entry->flags) & d->feature_flags);

                if (ioctl(child->fd, FS_IOC_GETFLAGS, &old_attr) < 0) {

                        if (new_attr != 0 || !IN_SET(errno, ENOTTY, EBADF, EOPNOTSUPP))
                                return -errno;

                } else if (old_attr != new_attr) {

                        if (ioctl(child->fd, FS_IOC_SETFLAGS, &new_attr) < 0)
                                return -errno;
                }
        }

        if ((d->feature_flags & CA_FORMAT_WITH_FAT_ATTRS) != 0 && child->fd >= 0) {
                uint32_t new_attr;

                new_attr = ca_feature_flags_to_fat_attrs(read_le64(&child->entry->flags) & d->feature_flags);

                if (magic == MSDOS_SUPER_MAGIC) {
                        uint32_t old_attr;

                        if (ioctl(child->fd, FAT_IOCTL_GET_ATTRIBUTES, &old_attr) < 0)
                                return -errno;

                        if ((old_attr & (ATTR_HIDDEN|ATTR_SYS|ATTR_ARCH)) != (new_attr & (ATTR_HIDDEN|ATTR_SYS|ATTR_ARCH))) {

                                new_attr |= old_attr & ~(ATTR_HIDDEN|ATTR_SYS|ATTR_ARCH);

                                if (ioctl(child->fd, FAT_IOCTL_SET_ATTRIBUTES, &new_attr) < 0)
                                        return -errno;
                        }
                } else {
                        if (new_attr != 0)
                                return -EOPNOTSUPP;
                }
        }

        return 0;
}

static void ca_decoder_apply_seek_offset(CaDecoder *d) {
        assert(d);

        d->archive_offset = d->seek_offset;
        d->step_size = 0;
        d->eof = false;

        realloc_buffer_empty(&d->buffer);
}

static int ca_decoder_step_node(CaDecoder *d, CaDecoderNode *n) {
        mode_t mode;
        int r;

        assert(d);
        assert(n);

        mode = ca_decoder_node_mode(n);

        switch (d->state) {

        case CA_DECODER_INIT:

                if (S_ISREG(mode) || S_ISBLK(mode)) {
                        assert(d->node_idx == 0);

                        /* A regular file or block device and we are at the top level, process this as payload */

                        ca_decoder_enter_state(d, CA_DECODER_IN_PAYLOAD);
                        return ca_decoder_step_node(d, n);
                }

                /* fall through */

        case CA_DECODER_ENTERED:
        case CA_DECODER_ENTERED_FOR_SEEK:
                return ca_decoder_parse_entry(d, n);

        case CA_DECODER_SEEKING_TO_ENTRY:

                /* If we enter the entry we reached our goal, and can flush out all seek info */
                ca_decoder_reset_seek(d);

                /* Make sure we never leave this node again through iteration */
                d->boundary_node_idx = d->node_idx;

                ca_decoder_enter_state(d, CA_DECODER_ENTERED);

                return CA_DECODER_FOUND;

        case CA_DECODER_ENTRY: {
                CaDecoderNode *parent;

                parent = ca_decoder_current_parent_node(d);
                if (parent) {
                        r = ca_decoder_realize_child(d, parent, n);
                        if (r < 0)
                                return r;
                }

                if (S_ISREG(mode)) {
                        ca_decoder_enter_state(d, CA_DECODER_IN_PAYLOAD);
                        return ca_decoder_step_node(d, n);
                }

                if (S_ISDIR(mode)) {
                        ca_decoder_enter_state(d, CA_DECODER_IN_DIRECTORY);
                        return ca_decoder_step_node(d, n);
                }

                ca_decoder_enter_state(d, CA_DECODER_FINISHED);
                return CA_DECODER_FINISHED;
        }

        case CA_DECODER_IN_PAYLOAD:
                assert(S_ISREG(mode) || S_ISBLK(mode));

                /* If the size of this payload is known, and we reached it, we are done */
                if (n->size != UINT64_MAX) {
                        assert(d->payload_offset <= n->size);

                        if (d->payload_offset == n->size) {
                                ca_decoder_enter_state(d, CA_DECODER_EOF);
                                return CA_DECODER_FINISHED;
                        }
                }

                if (realloc_buffer_size(&d->buffer) > 0) {
                        if (n->size == UINT64_MAX)
                                d->step_size = realloc_buffer_size(&d->buffer);
                        else
                                d->step_size = MIN(realloc_buffer_size(&d->buffer), n->size - d->payload_offset);

                        return CA_DECODER_PAYLOAD;
                }

                if (d->eof) {
                        /* EOF before the object was supposed to end? */
                        if (n->size != UINT64_MAX)
                                return -EPIPE;

                        /* There are still parent nodes around that wait for the GOODBYE object, and we got EOF inside this
                         * file? */
                        if (d->node_idx > 0)
                                return -EPIPE;

                        /* If we don't know the length and get an EOF, we are happy and just consider this the end of the payload */
                        ca_decoder_enter_state(d, CA_DECODER_EOF);
                        return CA_DECODER_FINISHED;
                }

                return CA_DECODER_REQUEST;

        case CA_DECODER_IN_DIRECTORY:
                assert(S_ISDIR(mode));

                return ca_decoder_parse_filename(d, n);

        case CA_DECODER_GOODBYE:
                assert(S_ISDIR(mode));

                ca_decoder_enter_state(d, CA_DECODER_EOF);
                return CA_DECODER_FINISHED;

        case CA_DECODER_PREPARING_SEEK_TO_FILENAME:
                assert(S_ISDIR(mode));

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_FILENAME);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_SEEKING_TO_FILENAME:
                assert(S_ISDIR(mode));
                return ca_decoder_parse_filename(d, n);

        case CA_DECODER_PREPARING_SEEK_TO_ENTRY:
                assert(S_ISDIR(mode));
                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_ENTRY);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_PREPARING_SEEK_TO_GOODBYE:
                assert(S_ISDIR(mode));
                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_GOODBYE);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_SEEKING_TO_GOODBYE:
                assert(S_ISDIR(mode));
                return ca_decoder_parse_filename(d, n);

        case CA_DECODER_PREPARING_SEEK_TO_GOODBYE_SIZE:
                assert(S_ISDIR(mode));
                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_GOODBYE_SIZE);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_SEEKING_TO_GOODBYE_SIZE:
                assert(S_ISDIR(mode));
                return ca_decoder_parse_goodbye_size(d, n);

        case CA_DECODER_NOWHERE:
                return CA_DECODER_NOT_FOUND;

        default:
                assert(false);
        }

        return 0;
}

static int ca_decoder_advance_buffer(CaDecoder *d, CaDecoderNode *n) {
        int r;

        assert(d);
        assert(n);

        if (d->step_size <= 0)
                return 0;

        if (d->state == CA_DECODER_IN_PAYLOAD) {

                if (n->fd >= 0) {

                        /* If hole punching is supported and we are writing to a regular file, use it */
                        if (d->punch_holes && S_ISREG(ca_decoder_node_mode(n)))
                                r = loop_write_with_holes(n->fd, realloc_buffer_data(&d->buffer), d->step_size);
                        else
                                r = loop_write(n->fd, realloc_buffer_data(&d->buffer), d->step_size);
                        if (r < 0)
                                return r;
                }

                d->payload_offset += d->step_size;
        }

        r = realloc_buffer_advance(&d->buffer, d->step_size);
        if (r < 0)
                return r;

        d->archive_offset += d->step_size;
        d->step_size = 0;

        return 0;
}

int ca_decoder_step(CaDecoder *d) {
        CaDecoderNode *n, *saved_child;
        int r;

        if (!d)
                return -EINVAL;

        if (d->state == CA_DECODER_EOF)
                return CA_DECODER_FINISHED;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        r = ca_decoder_advance_buffer(d, n);
        if (r < 0)
                return r;

        r = ca_decoder_step_node(d, n);
        if (r != CA_DECODER_FINISHED)
                return r;

        saved_child = n;

        r = ca_decoder_leave_child(d);
        if (r < 0)
                return r;
        if (r > 0) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;

                r = ca_decoder_finalize_child(d, n, saved_child);
                if (r < 0)
                        return r;

                ca_decoder_enter_state(d, CA_DECODER_IN_DIRECTORY);
                return CA_DECODER_STEP;
        }

        /* Also fix up the top-level entry */
        r = ca_decoder_finalize_child(d, ca_decoder_current_parent_node(d), n);
        if (r < 0)
                return r;

        ca_decoder_forget_children(d);

        return CA_DECODER_FINISHED;
}

int ca_decoder_get_request_offset(CaDecoder *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        return d->archive_offset;
}

int ca_decoder_put_data(CaDecoder *d, const void *p, size_t size) {
        if (!d)
                return -EINVAL;
        if (size == 0)
                return 0;
        if (!p)
                return -EINVAL;

        if (d->eof)
                return -EBUSY;

        if (size == 0)
                return 0;

        if (!realloc_buffer_append(&d->buffer, p, size))
                return -ENOMEM;

        return 0;
}

int ca_decoder_put_data_fd(CaDecoder *d, int fd, uint64_t offset, uint64_t size) {
        ssize_t l;
        void *m;
        int r;

        /* fprintf(stderr, "put data\n"); */

        if (!d)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (d->eof)
                return -EBUSY;

        if (size == 0)
                return 0;

        if (size == UINT64_MAX)
                size = BUFFER_SIZE;

        m = realloc_buffer_extend(&d->buffer, size);
        if (!m)
                return -ENOMEM;

        if (offset == UINT64_MAX)
                l = read(fd, m, size);
        else
                l = pread(fd, m, size, offset);
        if (l < 0) {
                r = -errno;
                (void) realloc_buffer_shorten(&d->buffer, size);
                return r;
        }
        if (l == 0)
                d->eof = true;

        assert((size_t) l <= size);
        realloc_buffer_shorten(&d->buffer, size - l);

        return 0;
}

int ca_decoder_put_eof(CaDecoder *d) {
        if (!d)
                return -EINVAL;

        d->eof = true;
        return 0;
}

int ca_decoder_get_payload(CaDecoder *d, const void **ret, size_t *ret_size) {
        CaDecoderNode *n;
        mode_t mode;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        mode = ca_decoder_node_mode(n);
        if (!S_ISREG(mode) && !S_ISBLK(mode))
                return -ENOTTY;

        if (d->state != CA_DECODER_IN_PAYLOAD)
                return -ENODATA;
        if (realloc_buffer_size(&d->buffer) == 0)
                return -ENODATA;
        if (d->step_size == 0)
                return -ENODATA;

        assert(d->step_size <= realloc_buffer_size(&d->buffer));

        *ret = realloc_buffer_data(&d->buffer);
        *ret_size = d->step_size;

        return 0;
}

int ca_decoder_current_path(CaDecoder *d, char **ret) {
        char *p = NULL;
        size_t n = 0, i;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (d->n_nodes <= 0)
                return -EUNATCH;

        for (i = 1; i < d->n_nodes; i++) {
                CaDecoderNode *node;
                size_t k, nn;
                char *np, *q;

                node = d->nodes + i;
                assert(node->entry);

                k = strlen(node->name);
                nn = n + (n > 0) + k;

                np = realloc(p, nn+1);
                if (!np) {
                        free(p);
                        return -ENOMEM;
                }

                q = np + n;
                if (n > 0)
                        *(q++) = '/';

                strcpy(q, node->name);
                p = np;
                n = nn;
        }

        if (!p) {
                p = strdup("");
                if (!p)
                        return -ENOMEM;
        }

        *ret = p;
        return 0;
}

int ca_decoder_current_mode(CaDecoder *d, mode_t *ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        *ret = ca_decoder_node_mode(n);
        return 0;
}

int ca_decoder_current_target(CaDecoder *d, const char **ret) {
        CaDecoderNode *n;
        mode_t mode;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        mode = ca_decoder_node_mode(n);
        if (!S_ISLNK(mode))
                return -ENODATA;
        if (!n->symlink_target)
                return -ENODATA;

        *ret = n->symlink_target;
        return 0;
}

int ca_decoder_current_mtime(CaDecoder *d, uint64_t *ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if ((d->feature_flags & (CA_FORMAT_WITH_NSEC_TIME|
                                 CA_FORMAT_WITH_USEC_TIME|
                                 CA_FORMAT_WITH_SEC_TIME|
                                 CA_FORMAT_WITH_2SEC_TIME)) == 0)
                return -ENODATA;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        if (!n->entry)
                return -ENODATA;

        *ret = read_le64(&n->entry->mtime);
        return 0;
}

int ca_decoder_current_size(CaDecoder *d, uint64_t *ret) {
        CaDecoderNode *n;
        mode_t mode;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        mode = ca_decoder_node_mode(n);
        if (!S_ISREG(mode))
                return -ENODATA;

        *ret = n->size;
        return 0;
}

int ca_decoder_current_uid(CaDecoder *d, uid_t *ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if ((d->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|
                                 CA_FORMAT_WITH_32BIT_UIDS)) == 0)
                return -ENODATA;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        if (!n->entry)
                return -ENODATA;

        *ret = (uid_t) read_le64(&n->entry->uid);
        return 0;
}

int ca_decoder_current_gid(CaDecoder *d, gid_t *ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if ((d->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|
                                 CA_FORMAT_WITH_32BIT_UIDS)) == 0)
                return -ENODATA;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        if (!n->entry)
                return -ENODATA;

        *ret = (uid_t) read_le64(&n->entry->gid);
        return 0;
}

int ca_decoder_current_user(CaDecoder *d, const char **ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if ((d->feature_flags & CA_FORMAT_WITH_USER_NAMES) == 0)
                return -ENODATA;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        if (!n->user_name)
                return -ENODATA;

        *ret = n->user_name;
        return 0;
}

int ca_decoder_current_group(CaDecoder *d, const char **ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if ((d->feature_flags & CA_FORMAT_WITH_USER_NAMES) == 0)
                return -ENODATA;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        if (!n->group_name)
                return -ENODATA;

        *ret = n->group_name;
        return 0;
}

int ca_decoder_current_rdev(CaDecoder *d, dev_t *ret) {
        CaDecoderNode *n;
        mode_t mode;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_decoder_current_child_node(d);
        if (!n) {
                n = ca_decoder_current_node(d);
                if (!n)
                        return -EUNATCH;
        }

        mode = ca_decoder_node_mode(n);
        if (!S_ISCHR(mode) && !S_ISBLK(mode))
                return -ENODATA;

        *ret = n->rdev;
        return 0;
}

int ca_decoder_current_offset(CaDecoder *d, uint64_t *ret) {
        CaDecoderNode *n;
        mode_t mode;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        mode = ca_decoder_node_mode(n);

        if (!S_ISREG(mode) && !S_ISBLK(mode))
                return -EISDIR;

        *ret = d->payload_offset;
        return 0;
}

int ca_decoder_seek_offset(CaDecoder *d, uint64_t offset) {
        CaDecoderNode *n;
        mode_t mode;

        if (!d)
                return -EINVAL;
        if (d->node_idx != 0)
                return -EINVAL;

        /* Only supported when we decode a naked file, i.e. not a directory tree serialization */

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        mode = ca_decoder_node_mode(n);
        if (!S_ISREG(mode) && !S_ISBLK(mode))
                return -EISDIR;

        d->archive_offset = d->payload_offset = offset;
        d->step_size = 0;
        d->eof = false;

        realloc_buffer_empty(&d->buffer);

        ca_decoder_enter_state(d, CA_DECODER_IN_PAYLOAD);

        return 0;
}

int ca_decoder_seek_path(CaDecoder *d, const char *path) {

        char *path_copy = NULL;
        const char *p;
        size_t new_idx;
        int r;

        if (!d)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (d->n_nodes <= 0)
                return -EUNATCH;
        if (d->nodes[0].end_offset == UINT64_MAX) /* The root directory must have a size set to be considered seekable */
                return -ESPIPE;
        if (!S_ISDIR(ca_decoder_node_mode(d->nodes)))
                return -ESPIPE;

        p = path + strspn(path, "/");
        new_idx = 0;

        for (;;) {
                char *child_name = NULL;
                CaDecoderNode *child;
                const char *q;
                bool match;

                /* Determine the name of the immediate child we are supposed to enter */
                q = p;
                r = path_get_component(&q, &child_name);
                if (r < 0)
                        return r;
                if (r == 0)  /* Yay, we already found where we were supposed to go */
                        break;

                if (new_idx + 1 >= d->n_nodes) {
                        free(child_name);
                        break; /* We can't descend any further because we haven't opened anything more so far. */
                }

                child = d->nodes + new_idx + 1;
                match = streq_ptr(child_name, child->name);
                free(child_name);

                if (!match)
                        break; /* The previously selected child doesn't match where we are supposed to go, let's stop here */

                if (child->end_offset == UINT64_MAX)
                        break; /* We don't know how large this child node is, probably because we are reading this
                                * iteratively so far. In that case, don't make use of this, and instead check the name
                                * table, so that we figure out the size. */

                /* The name we are looking for matches the child already selected. In that case reuse it. */
                p = q;
                new_idx ++;
        }

        path_copy = strdup(path);
        if (!path_copy)
                return -ENOMEM;

        ca_decoder_reset_seek(d);

        d->seek_path = path_copy;
        d->seek_subpath = path_copy + (p - path);
        d->seek_idx = 0;

        d->node_idx = new_idx;
        ca_decoder_forget_children(d);

        return ca_decoder_do_seek(d, d->nodes + new_idx);
}

int ca_decoder_get_seek_offset(CaDecoder *d, uint64_t *ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        if (!IN_SET(d->state,
                    CA_DECODER_SEEKING_TO_FILENAME,
                    CA_DECODER_SEEKING_TO_ENTRY,
                    CA_DECODER_SEEKING_TO_GOODBYE,
                    CA_DECODER_SEEKING_TO_GOODBYE_SIZE))
                return -ENODATA;

        if (d->seek_offset == UINT64_MAX)
                return -EUNATCH;

        *ret = d->seek_offset;
        return 0;
}

int ca_decoder_set_archive_size(CaDecoder *d, uint64_t size) {

        if (!d)
                return -EINVAL;

        if (d->n_nodes <= 0)
                return -EUNATCH;

        d->nodes[0].end_offset = size;
        return 0;
}

int ca_decoder_set_punch_holes(CaDecoder *d, int enabled) {

        if (!d)
                return -EINVAL;

        d->punch_holes = enabled;
        return 0;
}
