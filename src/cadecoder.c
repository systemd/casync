/* SPDX-License-Identifier: LGPL-2.1+ */

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

#if HAVE_SELINUX
#  include <selinux/selinux.h>
#endif

#include "cadecoder.h"
#include "caformat-util.h"
#include "caformat.h"
#include "cautil.h"
#include "chattr.h"
#include "def.h"
#include "quota-projid.h"
#include "realloc-buffer.h"
#include "reflink.h"
#include "rm-rf.h"
#include "siphash24.h"
#include "time-util.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef EBADMSG */
/* #define EBADMSG __LINE__ */

/* #undef EBUSY */
/* #define EBUSY __LINE__ */

/* #undef ENOENT */
/* #define ENOENT __LINE__ */

/* #undef EUNATCH */
/* #define EUNATCH __LINE__ */

#define APPLY_EARLY_FS_FL                       \
        (FS_NOATIME_FL|                         \
         FS_COMPR_FL|                           \
         FS_NOCOW_FL|                           \
         FS_NOCOMP_FL|                          \
         FS_PROJINHERIT_FL)

typedef struct CaDecoderExtendedAttribute {
        struct CaDecoderExtendedAttribute *next;
        struct CaDecoderExtendedAttribute *previous;
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
        uint64_t payload_offset;
        uint64_t goodbye_offset;
        uint64_t end_offset;     /* offset of the byte behind the goodbye marker */

        char *name;
        char *temporary_name;
        CaFormatEntry *entry;
        CaFormatGoodbye *goodbye;

        mode_t mode;          /* Only relevant if entry == NULL */
        uint64_t size;        /* Only for S_ISREG() */

        char *user_name;
        char *group_name;
        char *symlink_target; /* Only for S_ISLNK() */
        dev_t rdev;           /* Only for S_ISCHR() and S_ISBLK() */

        char *selinux_label;

        CaDecoderExtendedAttribute *xattrs_first;
        CaDecoderExtendedAttribute *xattrs_last;
        CaDecoderExtendedAttribute *xattrs_current;

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

        bool have_quota_projid;
        uint32_t quota_projid;

        /* Only for S_ISREG(), the origin if we know it */
        CaOrigin *payload_origin;

        /* Only for S_ISDIR(), so that we can remove files that aren't there anymore */
        char **dirents;
        size_t n_dirents;
        size_t n_dirents_allocated;

        bool dirents_invalid;
        bool hardlinked;
} CaDecoderNode;

typedef enum CaDecoderState {
        CA_DECODER_INIT,
        CA_DECODER_ENTERED,
        CA_DECODER_ENTERED_FOR_SEEK,
        CA_DECODER_ENTRY,
        CA_DECODER_IN_PAYLOAD,
        CA_DECODER_IN_DIRECTORY,
        CA_DECODER_GOODBYE,
        CA_DECODER_FINALIZE,
        CA_DECODER_EOF,

        /* As the result of ca_decoder_seek_offset() we'll traverse through these two states ... */
        CA_DECODER_PREPARING_SEEK_TO_OFFSET,
        CA_DECODER_SEEKING_TO_OFFSET,

        /* As the result of ca_decoder_seek_path() we'll traverse through these eight states ... */
        CA_DECODER_PREPARING_SEEK_TO_FILENAME,
        CA_DECODER_SEEKING_TO_FILENAME,
        CA_DECODER_PREPARING_SEEK_TO_NEXT_SIBLING,
        CA_DECODER_SEEKING_TO_NEXT_SIBLING,
        CA_DECODER_PREPARING_SEEK_TO_ENTRY,
        CA_DECODER_SEEKING_TO_ENTRY,
        CA_DECODER_PREPARING_SEEK_TO_PAYLOAD,
        CA_DECODER_SEEKING_TO_PAYLOAD,
        CA_DECODER_PREPARING_SEEK_TO_GOODBYE,
        CA_DECODER_SEEKING_TO_GOODBYE,
        CA_DECODER_PREPARING_SEEK_TO_GOODBYE_TAIL,
        CA_DECODER_SEEKING_TO_GOODBYE_TAIL,

        CA_DECODER_NOWHERE,
        CA_DECODER_SKIPPING,
} CaDecoderState;

struct CaDecoder {
        CaDecoderState state;

        uint64_t feature_flags;          /* The actual feature flags in the archive */
        uint64_t replay_feature_flags;   /* The feature flags we shall restore and which are available in the archive */
        uint64_t expected_feature_flags; /* The feature flags we expect to be stored in the file, given what we learnt from the index file */
        uint64_t feature_flags_mask;     /* The mask of feature flags that the user asked for restoring */

        CaDecoderNode nodes[NODES_MAX];
        size_t n_nodes;
        size_t node_idx;
        size_t boundary_node_idx; /* Never go further up than this node. We set this in order to stop iteration above the point we seeked to */

        /* A buffer that automatically resizes, containing what we read most recently */
        ReallocBuffer buffer;
        CaOrigin *buffer_origin;

        /* An EOF was signalled to us */
        bool eof;

        /* Where we are from the stream start */
        uint64_t archive_offset;

        /* Only in CA_DECODER_IN_PAYLOAD: Where we are from the start of the current payload we are looking at */
        uint64_t payload_offset;

        /* How far cadecoder_step() will jump ahead */
        uint64_t step_size;

        /* If we are seeking, the path we are seeking to */
        char *seek_path; /* full */
        const char *seek_subpath; /* the subpath left to seek */
        bool seek_next_sibling; /* if true then we'll seek to the entry one after the specified path */
        uint64_t seek_idx; /* Current counter of filenames with the same hash value */
        uint64_t seek_offset; /* Where to seek to, if we already know */
        uint64_t seek_end_offset; /* If we are seeking somewhere and know the end of the object we seek into, we store it here */
        uint64_t seek_payload; /* Payload we shall seek to */

        uint64_t skip_bytes; /* How many bytes to skip if we are in CA_DECODER_SKIPPING state */

        /* Cached name → UID/GID translation */
        uid_t cached_uid;
        gid_t cached_gid;

        char *cached_user_name;
        char *cached_group_name;

        /* A cached pair of st_dev and magic, so that we don't have to call statfs() for each file */
        dev_t cached_st_dev;
        statfs_f_type_t cached_magic;

        int boundary_fd;

        bool punch_holes:1;
        bool reflink:1;
        bool hardlink:1;
        bool delete:1;
        bool payload:1;
        bool undo_immutable:1;

        uint64_t n_punch_holes_bytes;
        uint64_t n_reflink_bytes;
        uint64_t n_hardlink_bytes;

        uid_t uid_shift;
        uid_t uid_range; /* uid_range == 0 means "full range" */

        CaDigest *archive_digest;
        CaDigest *payload_digest;
        CaDigest *hardlink_digest;

        bool want_archive_digest:1;
        bool want_payload_digest:1;
        bool want_hardlink_digest:1;

        bool payload_digest_invalid:1;
        bool hardlink_digest_invalid:1;
};

static inline bool CA_DECODER_IS_SEEKING(CaDecoder *d) {
        return IN_SET(d->state,
                      CA_DECODER_ENTERED_FOR_SEEK,
                      CA_DECODER_PREPARING_SEEK_TO_OFFSET,
                      CA_DECODER_SEEKING_TO_OFFSET,
                      CA_DECODER_PREPARING_SEEK_TO_FILENAME,
                      CA_DECODER_SEEKING_TO_FILENAME,
                      CA_DECODER_PREPARING_SEEK_TO_NEXT_SIBLING,
                      CA_DECODER_SEEKING_TO_NEXT_SIBLING,
                      CA_DECODER_PREPARING_SEEK_TO_PAYLOAD,
                      CA_DECODER_SEEKING_TO_PAYLOAD,
                      CA_DECODER_PREPARING_SEEK_TO_ENTRY,
                      CA_DECODER_SEEKING_TO_ENTRY,
                      CA_DECODER_PREPARING_SEEK_TO_GOODBYE,
                      CA_DECODER_SEEKING_TO_GOODBYE,
                      CA_DECODER_PREPARING_SEEK_TO_GOODBYE_TAIL,
                      CA_DECODER_SEEKING_TO_GOODBYE_TAIL);
}

#define CA_DECODER_AT_ROOT(d) ((d)->node_idx == 0)

static inline bool CA_DECODER_IS_NAKED(CaDecoder *d) {
        assert(d);

        /* Returns true if we are decoding a naked blob, i.e. a top-level payload, in contrast to a directory tree */

        return d->n_nodes == 1 &&
                !d->nodes[0].entry &&
                (S_ISREG(d->nodes[0].mode) || S_ISBLK(d->nodes[0].mode));
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
        d->replay_feature_flags = UINT64_MAX;
        d->expected_feature_flags = UINT64_MAX;
        d->feature_flags_mask = UINT64_MAX;

        d->seek_idx = UINT64_MAX;
        d->seek_offset = UINT64_MAX;
        d->seek_end_offset = UINT64_MAX;

        d->cached_uid = UID_INVALID;
        d->cached_gid = GID_INVALID;

        d->boundary_fd = -1;

        d->punch_holes = true;
        d->reflink = true;
        d->delete = true;
        d->payload = true;

        return d;
}

static void ca_decoder_node_free_xattrs(CaDecoderNode *n) {
        CaDecoderExtendedAttribute *i;

        assert(n);

        i = n->xattrs_first;
        while (i) {
                CaDecoderExtendedAttribute *next;

                next = i->next;
                free(i);
                i = next;
        }

        n->xattrs_first = n->xattrs_last = n->xattrs_current = NULL;
}

static void ca_decoder_node_free_acl_entries(CaDecoderACLEntry **e) {

        while (*e) {
                CaDecoderACLEntry *next;

                next = (*e)->next;
                free(*e);
                *e = next;
        }
}

static void ca_decoder_node_flush_entry(CaDecoderNode *n) {
        assert(n);

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
        n->have_quota_projid = false;

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

        n->selinux_label = mfree(n->selinux_label);
}

static void ca_decoder_node_free(CaDecoderNode *n) {
        assert(n);

        if (n->fd >= 3)
                n->fd = safe_close(n->fd);
        else
                n->fd = -1;

        n->name = mfree(n->name);
        n->temporary_name = mfree(n->temporary_name);

        ca_decoder_node_flush_entry(n);

        n->goodbye = mfree(n->goodbye);

        n->entry_offset = UINT64_MAX;
        n->payload_offset = UINT64_MAX;
        n->goodbye_offset = UINT64_MAX;
        n->end_offset = UINT64_MAX;

        n->payload_origin = ca_origin_unref(n->payload_origin);

        n->dirents = strv_free(n->dirents);
        n->n_dirents = n->n_dirents_allocated = 0;
        n->dirents_invalid = false;

        n->hardlinked = false;
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
        ca_origin_unref(d->buffer_origin);

        free(d->cached_user_name);
        free(d->cached_group_name);

        free(d->seek_path);

        safe_close(d->boundary_fd);

        ca_digest_free(d->archive_digest);
        ca_digest_free(d->payload_digest);
        ca_digest_free(d->hardlink_digest);

        free(d);

        return NULL;
}

int ca_decoder_set_expected_feature_flags(CaDecoder *d, uint64_t flags) {
        if (!d)
                return -EINVAL;

        d->expected_feature_flags = flags;
        return 0;
}

int ca_decoder_set_feature_flags_mask(CaDecoder *d, uint64_t mask) {
        if (!d)
                return -EINVAL;

        if (d->replay_feature_flags != UINT64_MAX)
                return -EBUSY;

        return ca_feature_flags_normalize_mask(mask, &d->feature_flags_mask);
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
                .payload_offset = S_ISREG(st.st_mode) || S_ISBLK(st.st_mode) ? 0 : UINT64_MAX,
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
        struct statfs sfs;

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
        if (fstatfs(fd, &sfs) < 0)
                return -errno;
        if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;

        d->boundary_fd = fd;

        d->nodes[0] = (CaDecoderNode) {
                .fd = -1,
                .entry_offset = 0,
                .payload_offset = UINT64_MAX,
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
                .payload_offset = S_ISREG(m) || S_ISBLK(m) ? 0 : UINT64_MAX,
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

        n = d->nodes + d->n_nodes++;

        *n = (CaDecoderNode) {
                .fd = -1,
                .entry_offset = UINT64_MAX,
                .payload_offset = UINT64_MAX,
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
        if (k < sizeof(CaFormatHeader)) {
                log_debug("Object header too short");
                return -EBADMSG;
        }
        if (k == UINT64_MAX) {
                log_debug("Object header size invalid");
                return -EBADMSG;
        }

        return size >= k;
}

static int ca_decoder_determine_replay_feature_flags(CaDecoder *d) {
        uint64_t t;
        int r;

        assert(d);

        /* First, let's extend the stream's feature flags so that all redundant bits are set */
        r = ca_feature_flags_normalize_mask(d->feature_flags, &t);
        if (r < 0)
                return r;

        /* Then, mask away everything the user's feature flag mask (that got extended like this too) doesn't allow */
        t &= d->feature_flags_mask;

        /* Finally, let's normalize this to drop all redundant bits again */
        return ca_feature_flags_normalize(t, &d->replay_feature_flags);
}

static bool validate_filename(const char *name, size_t n) {
        const char *p;

        assert(name);

        if (n < 2)
                return false;

        if (name[n-1] != 0)
                return false;

        for (p = name; p < name + n-1; p++)
                if (*p == 0 || *p == '/')
                        return false;

        if (dot_or_dot_dot(name))
                return false;

        return true;
}

static bool validate_mode(CaDecoder *d, uint64_t m, uint64_t flags) {
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

        if (!S_ISDIR(m) && (flags & CA_FORMAT_WITH_SUBVOLUME))
                return false;

        if (S_ISLNK(m))
                return (m & 07777) == 0777;

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

        return (f & ~(d->feature_flags & (CA_FORMAT_WITH_FAT_ATTRS|CA_FORMAT_WITH_CHATTR|CA_FORMAT_WITH_SUBVOLUME|CA_FORMAT_WITH_SUBVOLUME_RO))) == 0;
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
        assert(target || n == 0);

        if (n < 2)
                return false;

        if (target[n-1] != 0)
                return false;

        if (memchr(target, 0, n - 1))
                return false;

        if (n > 4096) /* PATH_MAX is 4K on Linux */
                return false;

        return true;
}

static bool validate_feature_flags(CaDecoder *d, uint64_t flags) {
        int r;

        assert(d);

        /* We use all bits on in the flags field as a special value, don't permit this in files */
        if (flags == UINT64_MAX)
                return false;

        if (d->expected_feature_flags != UINT64_MAX &&
            flags != d->expected_feature_flags)
                return false;

        r = ca_feature_flags_are_normalized(flags);
        if (r <= 0 && r != -EOPNOTSUPP) /* we let unsupported flags pass here, and let the caller decide what he wants to do with that */
                return false;

        if (d->feature_flags == UINT64_MAX) {
                /* The first ENTRY record decides the flags for the whole archive */
                d->feature_flags = flags;

                r = ca_decoder_determine_replay_feature_flags(d);
                if (r < 0)
                        return false;

        } else if (d->feature_flags != flags)
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
        if (!validate_mode(d, read_le64(&e->mode), read_le64(&e->flags)))
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

static const CaFormatSELinux *validate_format_selinux(CaDecoder *d, const void *p) {
        const CaFormatSELinux *l = p;
        size_t n;

        if (read_le64(&l->header.size) < offsetof(CaFormatSELinux, label) + 2)
                return NULL;
        if (read_le64(&l->header.type) != CA_FORMAT_SELINUX)
                return NULL;

        if (!(d->feature_flags & CA_FORMAT_WITH_SELINUX))
                return NULL;

        n = read_le64(&l->header.size) - offsetof(CaFormatSELinux, label) - 1;
        if (l->label[n] != 0)
                return NULL;

        if (memchr(l->label, 0, n))
                return NULL;

        return l;
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

static const CaFormatQuotaProjID* validate_format_quota_projid(CaDecoder *d, const void *p) {
        const CaFormatQuotaProjID *q = p;

        assert(d);
        assert(q);

        if (read_le64(&q->header.size) != sizeof(CaFormatQuotaProjID))
                return NULL;
        if (read_le64(&q->header.type) != CA_FORMAT_QUOTA_PROJID)
                return NULL;

        if (read_le64(&q->projid) == 0)
                return NULL;
        if (read_le64(&q->projid) > 0xFFFFFFFF)
                return NULL;

        return q;
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

static inline const CaFormatGoodbyeTail* CA_FORMAT_GOODBYE_TO_TAIL(const CaFormatGoodbye *g) {
        return (const CaFormatGoodbyeTail*) ((uint8_t*) g + read_le64(&g->header.size) - sizeof(CaFormatGoodbyeTail));
}

static const CaFormatGoodbye *validate_format_goodbye(CaDecoder *d, const void *p) {
const CaFormatGoodbye *g = p;
        const CaFormatGoodbyeTail *t;
        uint64_t l;

        assert(sizeof(CaFormatGoodbyeTail) == sizeof(CaFormatGoodbyeItem));

        if (read_le64(&g->header.size) < offsetof(CaFormatGoodbye, items) + sizeof(CaFormatGoodbyeTail))
                return NULL;
        if (read_le64(&g->header.type) != CA_FORMAT_GOODBYE)
                return NULL;

        l = read_le64(&g->header.size) - offsetof(CaFormatGoodbye, items) - sizeof(CaFormatGoodbyeTail);
        if (l % sizeof(CaFormatGoodbyeItem) != 0)
                return NULL;

        t = CA_FORMAT_GOODBYE_TO_TAIL(g);
        if (read_le64(&t->marker) != CA_FORMAT_GOODBYE_TAIL_MARKER)
                return NULL;
        if (read_le64(&t->size) != read_le64(&g->header.size))
                return NULL;

        /* Here we only very superficially validate the validity of the entry offset, the caller has to add a more precise test */
        if (read_le64(&t->entry_offset) < read_le64(&g->header.size))
                return NULL;
        if (read_le64(&t->entry_offset) == UINT64_MAX)
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

static uint64_t format_goodbye_items(const CaFormatGoodbye *g) {
        uint64_t n;

        assert(g);

        if (g->header.size < offsetof(CaFormatGoodbye, items) + sizeof(CaFormatGoodbyeTail))
                return UINT64_MAX;

        n = g->header.size - offsetof(CaFormatGoodbye, items) - sizeof(CaFormatGoodbyeTail);
        if (n % sizeof(CaFormatGoodbyeItem) != 0)
                return UINT64_MAX;

        return n / sizeof(CaFormatGoodbyeItem);
}

static const CaFormatGoodbyeItem* format_goodbye_search(
                const CaFormatGoodbye *g,
                const char *name,
                uint64_t idx) {

        uint64_t n, hash;

        assert(g);
        assert(name);

        hash = siphash24(name, strlen(name), (const uint8_t[16]) CA_FORMAT_GOODBYE_HASH_KEY);

        n = format_goodbye_items(g);
        if (n == UINT64_MAX)
                return NULL;

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
        mode_t mode;
        int r;

        if (!d)
                return -EINVAL;
        if (!n)
                return -EINVAL;

        if (!d->seek_subpath)
                return -EUNATCH;
        if (n->entry_offset == UINT64_MAX)
                return -EUNATCH;

        /* Seeking works like this: depending on how much information we have:
         *
         * - If we already are at the right place, return to the entry object
         * - If we know the goodbye object already, we use it and jump to the filename object
         * - If we know the offset of the goodbye object, we jump to it
         * - If we know the end offset, we jump to the GOODBYE tail structure before it to read the GOODBYE start offset
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
                if (d->seek_next_sibling) {

                        /* We are at the entry whose next sibling we shall seek to? If so, do so */

                        if (n->end_offset == UINT64_MAX)
                                return -EUNATCH;

                        r = ca_decoder_leave_child(d);
                        if (r == 0) {
                                /* We are at the top already? */
                                ca_decoder_enter_state(d, CA_DECODER_NOWHERE);
                                return 0;
                        }

                        d->seek_offset = n->end_offset;
                        d->seek_end_offset = UINT64_MAX;
                        ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_NEXT_SIBLING);

                } else if (d->seek_payload != UINT64_MAX) {

                        /* We are at the entry we wanted to go to, but shall now proceed directly to an offset in the
                         * payload of it */

                        if (n->payload_offset == UINT64_MAX)
                                return -EUNATCH;

                        mode = ca_decoder_node_mode(n);
                        if (mode == (mode_t) -1)
                                return -EUNATCH;
                        if (!S_ISREG(mode)) {
                                ca_decoder_enter_state(d, CA_DECODER_NOWHERE);
                                return 0;
                        }

                        if (d->seek_payload > n->size) {
                                ca_decoder_enter_state(d, CA_DECODER_NOWHERE);
                                return 0;
                        }

                        d->seek_offset = n->payload_offset + d->seek_payload;
                        d->seek_end_offset = n->end_offset;
                        ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_PAYLOAD);

                } else {
                        /* We are already at the goal? If so, let's seek to the beginning of the entry */

                        d->seek_offset = n->entry_offset;
                        d->seek_end_offset = n->end_offset;
                        ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_ENTRY);
                }

                return 1;
        } else {

                /* If we are supposed to descend further, but this is not actually a directory, then complain immediately */
                mode = ca_decoder_node_mode(n);
                if (mode == (mode_t) -1)
                        return -EUNATCH;

                if (!S_ISDIR(mode)) {
                        ca_decoder_enter_state(d, CA_DECODER_NOWHERE);
                        return 0;
                }

                n->dirents_invalid = true;
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

                if (read_le64(&item->size) > read_le64(&item->offset)) {
                        log_debug("GOODBYE item size larger than offset");
                        return -EBADMSG;
                }

                if (read_le64(&item->offset) > n->goodbye_offset) {
                        log_debug("GOODBYE item offset larger than GOODBYE start offset");
                        return -EBADMSG;
                }
                so = n->goodbye_offset - read_le64(&item->offset);
                if (so < n->entry_offset) {
                        log_debug("GOODBYE seek offset before entry offset");
                        return -EBADMSG;
                }

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

                if (n->end_offset < sizeof(CaFormatGoodbyeTail)) {
                        log_debug("GOODBYE end offset shorter than tail.");
                        return -EBADMSG;
                }

                d->seek_offset = n->end_offset - sizeof(CaFormatGoodbyeTail);
                d->seek_end_offset = n->end_offset;
                ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_GOODBYE_TAIL);

                return 1;
        }

        return -ESPIPE;
}

static int ca_decoder_write_digest(CaDecoder *d, CaDigest **digest, const void *p, size_t l) {
        int r;

        if (!d)
                return -EINVAL;
        if (!digest)
                return -EINVAL;

        r = ca_digest_ensure_allocated(digest, ca_feature_flags_to_digest_type(d->feature_flags));
        if (r < 0)
                return r;

        ca_digest_write(*digest, p, l);
        return 0;
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
        const CaFormatSELinux *selinux = NULL;
        const CaFormatFCaps *fcaps = NULL;
        const CaFormatQuotaProjID *quota_projid = NULL;
        uint64_t offset = 0;
        bool done = false;
        mode_t mode;
        size_t sz;
        void *p;
        int r;

        assert(d);
        assert(n);
        assert(IN_SET(d->state, CA_DECODER_INIT, CA_DECODER_ENTERED, CA_DECODER_ENTERED_FOR_SEEK));

        /* Make sure we flush out anything we might already have parsed */
        ca_decoder_node_flush_entry(n);

        p = realloc_buffer_data(&d->buffer);
        sz = realloc_buffer_size(&d->buffer);
        for (;;) {
                const CaFormatHeader *h;
                uint64_t t, l, flags;

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
                        flags = read_le64(&entry->feature_flags);
                        if ((flags & ~CA_FORMAT_FEATURE_FLAGS_MAX) != 0)
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
                        if (n->xattrs_first)
                                return -EBADMSG;
                        if (n->have_acl)
                                return -EBADMSG;
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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

                        /* If the UID is 0 then the user name should be supressed if "root". However, if it's anything
                         * else that's OK. The latter case happens in case UID shifting is used, as the user name
                         * always reflects the host system's user database (due to the nature of NSS), while the
                         * encoded numeric UID reflects the shifted one. */

                        if ((d->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) &&
                            read_le64(&entry->uid) == 0 &&
                            streq(user->name, "root"))
                                return -EBADMSG;

                        offset += l;
                        break;

                case CA_FORMAT_GROUP:
                        if (!entry)
                                return -EBADMSG;
                        if (group)
                                return -EBADMSG;
                        if (n->xattrs_first)
                                return -EBADMSG;
                        if (n->have_acl)
                                return -EBADMSG;
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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
                            read_le64(&entry->gid) == 0 &&
                            streq(group->name, "root"))
                                return -EBADMSG;

                        offset += l;
                        break;

                case CA_FORMAT_XATTR: {
                        const struct CaFormatXAttr *x;
                        CaDecoderExtendedAttribute *u;

                        if (!entry)
                                return -EBADMSG;
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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
                        if (!x) {
                                log_debug("Invalid XATTR record.");
                                return -EBADMSG;
                        }

                        /* Check whether things are properly ordered */
                        if (n->xattrs_last && strcmp((char*) x->name_and_value, (char*) n->xattrs_last->format.name_and_value) <= 0)
                                return -EBADMSG;

                        /* Add to list of extended attributes */
                        u = malloc(offsetof(CaDecoderExtendedAttribute, format) + l);
                        if (!u)
                                return -ENOMEM;

                        memcpy(&u->format, x, l);

                        u->next = NULL;
                        u->previous = n->xattrs_last;

                        if (n->xattrs_last)
                                n->xattrs_last->next = u;
                        else
                                n->xattrs_first = u;

                        n->xattrs_last = u;

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
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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

                case CA_FORMAT_SELINUX:
                        if (!entry)
                                return -EBADMSG;
                        if (selinux)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
                                return -EBADMSG;
                        if (l > CA_FORMAT_SELINUX_SIZE_MAX)
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        selinux = validate_format_selinux(d, p);
                        if (!selinux)
                                return -EBADMSG;

                        offset += l;
                        break;

                case CA_FORMAT_FCAPS:
                        if (!entry)
                                return -EBADMSG;
                        if (fcaps)
                                return -EBADMSG;
                        if (quota_projid)
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

                case CA_FORMAT_QUOTA_PROJID:
                        if (!entry)
                                return -EBADMSG;
                        if (quota_projid)
                                return -EBADMSG;
                        if (l != sizeof(CaFormatQuotaProjID))
                                return -EBADMSG;

                        r = ca_decoder_object_is_complete(p, sz);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return CA_DECODER_REQUEST;

                        quota_projid = validate_format_quota_projid(d, p);
                        if (!quota_projid)
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
                        if (l < offsetof(CaFormatGoodbye, items) + sizeof(CaFormatGoodbyeTail))
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
                        log_debug("Got unexpected object: %016" PRIx64, t);
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
        if (!(S_ISREG(mode) || S_ISDIR(mode)) && quota_projid)
                return -EBADMSG;

        /* Both FAT and chattr(1) flags are only defined for regular files and directories */
        if (read_le64(&entry->flags) != 0 && !S_ISREG(mode) && !S_ISDIR(mode))
                return -EBADMSG;

        /* The top-level node must be a directory */
        if (CA_DECODER_AT_ROOT(d) && !S_ISDIR(mode))
                return -EBADMSG;

        /* xattrs/ALCs are not defined for symlinks */
        if (S_ISLNK(mode) && (n->xattrs_first || n->have_acl))
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
        assert(!n->fcaps);
        assert(!n->symlink_target);
        assert(!n->selinux_label);
        assert(!n->have_quota_projid);

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

        if (selinux) {
                n->selinux_label = strdup(selinux->label);
                if (!n->selinux_label)
                        return -ENOMEM;
        }

        if (fcaps) {
                n->fcaps = memdup(fcaps->data, read_le64(&fcaps->header.size) - offsetof(CaFormatFCaps, data));
                if (!n->fcaps)
                        return -ENOMEM;

                n->fcaps_size = read_le64(&fcaps->header.size) - offsetof(CaFormatFCaps, data);
                n->have_fcaps = true;
        }

        if (quota_projid) {
                n->quota_projid = read_le64(&quota_projid->projid);
                n->have_quota_projid = true;
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

        if (S_ISREG(mode))
                n->payload_offset = d->archive_offset + offset;

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

        ca_decoder_write_digest(d, &d->archive_digest, realloc_buffer_data(&d->buffer), d->step_size);

        if (d->want_payload_digest) {
                ca_digest_reset(d->payload_digest);
                d->payload_digest_invalid = false;
        }
        if (d->want_hardlink_digest) {
                ca_digest_reset(d->hardlink_digest);
                ca_decoder_write_digest(d, &d->hardlink_digest, realloc_buffer_data(&d->buffer), d->step_size);
                d->hardlink_digest_invalid = false;
        }

        return CA_DECODER_NEXT_FILE;
}

static void ca_decoder_reset_seek(CaDecoder *d) {
        assert(d);

        d->seek_path = mfree(d->seek_path);
        d->seek_subpath = NULL;
        d->seek_idx = 0;
        d->seek_offset = UINT64_MAX;
        d->seek_end_offset = UINT64_MAX;
        d->seek_next_sibling = false;
        d->seek_payload = UINT64_MAX;
}

static int ca_decoder_parse_filename(CaDecoder *d, CaDecoderNode *n) {
        const CaFormatFilename *filename = NULL;
        const CaFormatGoodbye *goodbye = NULL;
        const CaFormatHeader *h;
        uint64_t l, t;
        size_t sz;
        int r;

        assert(d);
        assert(IN_SET(d->state,
                      CA_DECODER_IN_DIRECTORY,
                      CA_DECODER_SEEKING_TO_FILENAME,
                      CA_DECODER_SEEKING_TO_NEXT_SIBLING,
                      CA_DECODER_SEEKING_TO_GOODBYE));

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

                if (!IN_SET(d->state,
                            CA_DECODER_IN_DIRECTORY,
                            CA_DECODER_SEEKING_TO_FILENAME,
                            CA_DECODER_SEEKING_TO_NEXT_SIBLING))
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

                switch (d->state) {

                case CA_DECODER_IN_DIRECTORY:

                        if (d->delete && !n->dirents_invalid) {
                                _cleanup_free_ char *nd = NULL;

                                nd = strdup(filename->name);
                                if (!nd)
                                        return -ENOMEM;

                                if (!GREEDY_REALLOC(n->dirents, n->n_dirents_allocated, n->n_dirents + 2))
                                        return -ENOMEM;

                                n->dirents[n->n_dirents++] = nd;
                                nd = NULL;
                                n->dirents[n->n_dirents] = NULL;
                        }

                        break;

                case CA_DECODER_SEEKING_TO_FILENAME: {
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

                        if (match == PATH_MATCH_MORE || d->seek_next_sibling || d->seek_payload != UINT64_MAX) {
                                /* This entry lies within our path, but the seek is not complete yet */
                                seek_continues = true;

                                /* Move subpath ptr ahead to component we need to process next. */
                                r = path_get_component(&d->seek_subpath, NULL);
                                if (r < 0)
                                        return r;

                                assert(r > 0);

                        } else {
                                assert(match == PATH_MATCH_FINAL);

                                /* We reached our goal, yay! */
                                ca_decoder_reset_seek(d);

                                /* Make sure that a later iteration won't go up from this */
                                d->boundary_node_idx = d->node_idx+1;

                                /* We arrived at the destination of the seek, report that */
                                arrived = true;
                        }

                        break;
                }

                case CA_DECODER_SEEKING_TO_NEXT_SIBLING:

                        ca_decoder_reset_seek(d);
                        arrived = true;

                        break;

                default:
                        break;
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

                if (d->want_archive_digest) {
                        if (arrived)
                                ca_digest_reset(d->archive_digest);
                        else if (!seek_continues)
                                ca_decoder_write_digest(d, &d->archive_digest, realloc_buffer_data(&d->buffer), d->step_size);
                }

                return arrived ? CA_DECODER_FOUND : CA_DECODER_STEP;
        }

        case CA_FORMAT_GOODBYE:
                if (!IN_SET(d->state, CA_DECODER_IN_DIRECTORY, CA_DECODER_SEEKING_TO_GOODBYE, CA_DECODER_SEEKING_TO_NEXT_SIBLING))
                        return -EBADMSG;

                if (l < offsetof(CaFormatGoodbye, items) + sizeof(CaFormatGoodbyeTail))
                        return -EBADMSG;

                r = ca_decoder_object_is_complete(h, sz);
                if (r < 0)
                        return r;
                if (r == 0)
                        return CA_DECODER_REQUEST;

                goodbye = validate_format_goodbye(d, h);
                if (!goodbye)
                        return -EBADMSG;

                if (n->entry_offset != UINT64_MAX && d->archive_offset != UINT64_MAX) {
                        const CaFormatGoodbyeTail *tail;

                        tail = CA_FORMAT_GOODBYE_TO_TAIL(goodbye);
                        if (read_le64(&tail->entry_offset) != d->archive_offset - n->entry_offset)
                                return -EBADMSG;
                }

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

                ca_decoder_write_digest(d, &d->archive_digest, realloc_buffer_data(&d->buffer), d->step_size);

                return CA_DECODER_STEP;

        default:
                log_debug("Got unexpected object: %016" PRIx64, t);
                return -EBADMSG;
        }
}

static int ca_decoder_parse_goodbye_tail(CaDecoder *d, CaDecoderNode *n) {
        const CaFormatGoodbyeTail *tail;
        uint64_t l, q;
        size_t sz;
        int r;

        assert(d);
        assert(d->state == CA_DECODER_SEEKING_TO_GOODBYE_TAIL);
        assert(n);

        if (d->archive_offset == UINT64_MAX)
                return -ESPIPE;

        sz = realloc_buffer_size(&d->buffer);
        if (sz < sizeof(CaFormatGoodbyeTail))
                return CA_DECODER_REQUEST;

        tail = realloc_buffer_data(&d->buffer);
        if (read_le64(&tail->marker) != CA_FORMAT_GOODBYE_TAIL_MARKER)
                return -EBADMSG;

        l = read_le64(&tail->size);
        if (l < offsetof(CaFormatGoodbye, items) + sizeof(CaFormatGoodbyeTail))
                return -EBADMSG;
        if ((l - offsetof(CaFormatGoodbye, items) - sizeof(CaFormatGoodbyeTail)) % sizeof(CaFormatGoodbyeItem) != 0)
                return -EBADMSG;
        if (l > d->archive_offset + sizeof(CaFormatGoodbyeTail))
                return -EBADMSG;

        q = read_le64(&tail->entry_offset);
        if (q < sizeof(CaFormatEntry))
                return -EBADMSG;
        if (q > d->archive_offset + sizeof(CaFormatGoodbyeTail) - l)
                return -EBADMSG;

        /* The top-level ENTRY must be starting at offset 0 */
        if (d->nodes == n && d->archive_offset + sizeof(CaFormatGoodbyeTail) != l + q)
                return -EBADMSG;

        n->goodbye_offset = d->archive_offset + sizeof(CaFormatGoodbyeTail) - l;

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

static int mkdir_or_mksubvol(CaDecoder *d, int dir_fd, CaDecoderNode *n, const char *name) {
        int r;

        assert(dir_fd >= 0);
        assert(n);
        assert(name);

        if (d->replay_feature_flags & read_le64(&n->entry->flags) & CA_FORMAT_WITH_SUBVOLUME ) {
                struct btrfs_ioctl_vol_args args = {};
                mode_t saved;
                size_t l;

                l = strlen(name);
                if (l > sizeof(args.name))
                        return -EINVAL;

                memcpy(args.name, name, l);

                saved = umask(0077);
                r = ioctl(dir_fd, BTRFS_IOC_SUBVOL_CREATE, &args) < 0 ? -errno : 0;
                umask(saved);
        } else
                r = mkdirat(dir_fd, name, 0700) < 0 ? -errno : 0;

        return r;
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
        assert(!child->temporary_name);

        mode = read_le64(&child->entry->mode);

        switch (mode & S_IFMT) {

        case S_IFDIR:

                r = mkdir_or_mksubvol(d, dir_fd, child, child->name);
                if (r < 0 && r != -EEXIST)
                        return r;

                child->fd = openat(dir_fd, child->name, O_CLOEXEC|O_NOCTTY|O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
                if (child->fd < 0) {

                        /* If there's something else already in place, then let's create a temporary directory first */
                        if (!IN_SET(errno, ENOTDIR, ELOOP))
                                return -errno;

                        r = tempfn_random(child->name, &child->temporary_name);
                        if (r < 0)
                                return r;

                        r = mkdir_or_mksubvol(d, dir_fd, child, child->temporary_name);
                        if (r < 0)
                                return r;

                        child->fd = openat(dir_fd, child->temporary_name, O_CLOEXEC|O_NOCTTY|O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
                        if (child->fd < 0) {
                                r = -errno;
                                (void) unlinkat(dir_fd, child->temporary_name, AT_REMOVEDIR);
                                return r;
                        }
                }

                break;

        case S_IFREG:

                r = tempfn_random(child->name, &child->temporary_name);
                if (r < 0)
                        return r;

                child->fd = openat(dir_fd, child->temporary_name, O_CLOEXEC|O_NOCTTY|O_WRONLY|O_NOFOLLOW|O_CREAT|O_EXCL, 0600 | mode);
                if (child->fd < 0)
                        return -errno;

                break;

        case S_IFLNK:

                if ((d->replay_feature_flags & CA_FORMAT_WITH_SYMLINKS) == 0)
                        return 0;

                r = tempfn_random(child->name, &child->temporary_name);
                if (r < 0)
                        return r;

                if (symlinkat(child->symlink_target, dir_fd, child->temporary_name) < 0)
                        return -errno;

                break;

        case S_IFIFO:

                if ((d->replay_feature_flags & CA_FORMAT_WITH_FIFOS) == 0)
                        return 0;

                r = tempfn_random(child->name, &child->temporary_name);
                if (r < 0)
                        return r;

                if (mkfifoat(dir_fd, child->temporary_name, mode) < 0)
                        return -errno;
                break;

        case S_IFBLK:
        case S_IFCHR:

                if ((d->replay_feature_flags & CA_FORMAT_WITH_DEVICE_NODES) == 0)
                        return 0;

                r = tempfn_random(child->name, &child->temporary_name);
                if (r < 0)
                        return r;

                if (mknodat(dir_fd, child->temporary_name, mode, child->rdev) < 0)
                        return -errno;

                break;

        case S_IFSOCK:

                if ((d->replay_feature_flags & CA_FORMAT_WITH_SOCKETS) == 0)
                        return 0;

                r = tempfn_random(child->name, &child->temporary_name);
                if (r < 0)
                        return r;

                if (mknodat(dir_fd, child->temporary_name, mode, 0) < 0)
                        return -errno;

                break;

        default:
                assert(false);
        }

        if (child->fd >= 0) {
                /* A select few chattr() attributes need to be applied (or are better applied) on empty
                 * files/directories instead of the final result, do so here. */

                r = mask_attr_fd(child->fd,
                                 ca_feature_flags_to_chattr(read_le64(&child->entry->flags)),
                                 ca_feature_flags_to_chattr(d->replay_feature_flags) & APPLY_EARLY_FS_FL);
                if (r < 0)
                        return r;

                if (child->have_quota_projid &&
                    (d->replay_feature_flags & CA_FORMAT_WITH_QUOTA_PROJID)) {

                        r = write_quota_projid(child->fd, child->quota_projid);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static uid_t ca_decoder_shift_uid(CaDecoder *d, uid_t uid) {
        uid_t result;

        assert(d);

        if (!uid_is_valid(uid))
                return UID_INVALID;

        if (d->uid_range != 0)
                result = uid % d->uid_range;
        else
                result = uid;

        if (d->uid_shift + result < d->uid_shift)
                return UID_INVALID;

        result += d->uid_shift;

        return result;
}

static gid_t ca_decoder_shift_gid(CaDecoder *d, gid_t gid) {
        return (gid_t) ca_decoder_shift_uid(d, (uid_t) gid);
}

static int name_to_uid(CaDecoder *d, const char *name, uid_t *ret) {
        uid_t parsed_uid;
        long bufsize;
        int r;

        assert(d);
        assert(name);
        assert(ret);

        if (streq_ptr(name, d->cached_user_name)) {
                *ret = d->cached_uid;
                return 1;
        }

        if (parse_uid(name, &parsed_uid) >= 0) {
                uid_t shifted_uid;

                shifted_uid = ca_decoder_shift_uid(d, parsed_uid);
                if (!uid_is_valid(shifted_uid))
                        return -EINVAL;

                *ret = shifted_uid;
                return 1;
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

                r = getpwnam_r(name, &pwbuf, buf, (size_t) bufsize, &pw);
                if (r == 0 && pw) {

                        free(d->cached_user_name);
                        d->cached_user_name = strdup(pw->pw_name);
                        d->cached_uid = pw->pw_uid;

                        *ret = pw->pw_uid;
                        return 1;
                }
                if (r != ERANGE)
                        return r > 0 ? -r : -ESRCH;

                bufsize *= 2;
        }
}

static int name_to_gid(CaDecoder *d, const char *name, gid_t *ret) {
        gid_t parsed_gid;
        long bufsize;
        int r;

        assert(d);
        assert(name);
        assert(ret);

        if (streq_ptr(name, d->cached_group_name)) {
                *ret = d->cached_gid;
                return 1;
        }

        if (parse_gid(name, &parsed_gid) >= 0) {
                uid_t shifted_gid;

                shifted_gid = ca_decoder_shift_gid(d, parsed_gid);
                if (!gid_is_valid(shifted_gid))
                        return -EINVAL;

                *ret = shifted_gid;
                return 1;
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

                r = getgrnam_r(name, &grbuf, buf, (size_t) bufsize, &gr);
                if (r == 0 && gr) {

                        free(d->cached_group_name);
                        d->cached_group_name = strdup(gr->gr_name);
                        d->cached_gid = gr->gr_gid;

                        *ret = gr->gr_gid;
                        return 1;
                }
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
                } else {
                        uid = (uid_t) read_le64(&i->user.uid);

                        uid = ca_decoder_shift_uid(d, uid);
                        if (!uid_is_valid(uid))
                                return -EINVAL;
                }

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
                } else {
                        gid = (gid_t) read_le64(&i->group.gid);

                        gid = ca_decoder_shift_gid(d, gid);
                        if (!gid_is_valid(gid))
                                return -EINVAL;
                }

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

static int ca_decoder_node_reflink(CaDecoder *d, CaDecoderNode *n) {
        uint64_t offset = 0;
        mode_t mode;
        size_t i;
        int r;

        assert(d);
        assert(n);

        if (!d->reflink)
                return 0;

        if (n->fd < 0)
                return 0;

        mode = ca_decoder_node_mode(n);
        if (mode == (mode_t) -1)
                return -EUNATCH;
        if (!S_ISREG(mode))
                return 0;

        for (i = 0; i < ca_origin_items(n->payload_origin); i++) {

                CaLocation *l;

                l = ca_origin_get(n->payload_origin, i);
                assert(l);

                if (l->designator == CA_LOCATION_PAYLOAD) {
                        uint64_t reflinked;
                        int source_fd;

                        source_fd = ca_location_open(l);
                        if (source_fd == -ENOENT) {
                                log_debug_errno(source_fd, "Can't open reflink source %s: %m", ca_location_format(l));
                                goto next;
                        }
                        if (source_fd < 0)
                                return source_fd;

                        r = reflink_fd(source_fd, l->offset, n->fd, offset, l->size, &reflinked);
                        safe_close(source_fd);
                        if (r == -EBADR) /* the offsets are not multiples of 512 */
                                goto next;
                        if (r == -EXDEV) /* cross-device reflinks aren't supported */
                                goto next;
                        if (ERRNO_IS_UNSUPPORTED(-r)) /* reflinks not supported */
                                break;
                        if (r < 0)
                                return r;

                        d->n_reflink_bytes += reflinked;
                }

        next:
                offset += l->size;
        }

        return 0;
}

static int comparison_fn_strcmpp(const void *x, const void *y) {
        const char* const *a = x, * const* b = y;

        return strcmp(*a, *b);
}

static inline void* safe_bsearch(
                const void *key, const void *base,
                size_t nmemb, size_t size,
                comparison_fn_t fn) {

        /* A wrapper that makes sure we can bsearch and don't have to pass a non-NULL base for nmemb == 0 */

        if (nmemb == 0)
                return NULL;

        return bsearch(key, base, nmemb, size, fn);
}

static int ca_decoder_node_delete(CaDecoder *d, CaDecoderNode *n) {
        int r, fd_copy;
        mode_t mode;
        DIR *dd;

        assert(d);
        assert(n);

        /* If enabled, delete all files and directories below the selected directory that weren't listed in our
         * archive. */

        if (!d->delete)
                return 0;

        if (n->fd < 0)
                return 0;

        mode = ca_decoder_node_mode(n);
        if (mode == (mode_t) -1)
                return -EUNATCH;
        if (!S_ISDIR(mode))
                return 0;

        if (n->dirents_invalid)
                return -ENODATA;

        fd_copy = fcntl(n->fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0)
                return -errno;

        dd = fdopendir(fd_copy);
        if (!dd) {
                safe_close(fd_copy);
                return -errno;
        }

        for (;;) {
                struct dirent *de;
                const char *key;

                errno = 0;
                de = readdir(dd);
                if (!de) {
                        if (errno != 0) {
                                r = -errno;
                                goto finish;
                        }

                        break;
                }

                if (dot_or_dot_dot(de->d_name))
                        continue;

                key = de->d_name;

                if (safe_bsearch(&key, n->dirents, n->n_dirents, sizeof(char*), comparison_fn_strcmpp))
                        continue;

                r = rm_rf_at(n->fd, de->d_name, REMOVE_ROOT|REMOVE_PHYSICAL|(d->undo_immutable ? REMOVE_UNDO_IMMUTABLE : 0));
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        closedir(dd);
        return r;
}

static int drop_immutable(int dir_fd, const char *name) {
        _cleanup_(safe_closep) int fd = -1;
        struct stat st;

        if (dir_fd < 0)
                return -EBADF;
        if (!name)
                return -EINVAL;

        fd = openat(dir_fd, name, O_CLOEXEC|O_RDONLY|O_NOFOLLOW|O_NOCTTY|O_NONBLOCK);
        if (fd < 0) {
                if (errno == ELOOP) /* symlinks don't have an immutable bit */
                        return 0;

                return -errno;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Only regular files and directories have an immutable bit */
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
                return 0;

        return mask_attr_fd(fd, 0, FS_IMMUTABLE_FL);
}

static int ca_decoder_install_file(CaDecoder *d, int dir_fd, const char *temporary_name, const char *name) {
        int r;

        assert(d);
        assert(dir_fd >= 0);
        assert(temporary_name);
        assert(name);

        r = renameat(dir_fd, temporary_name, dir_fd, name) < 0 ? -errno : 0;
        if (r == -EPERM && d->undo_immutable) {
                /* Renaming the file failed. This could be because the "immutable" flag was set on the destination. Let's see if we can drop that */
                r = drop_immutable(dir_fd, name);
                if (r < 0)
                        return r;
                if (r == 0) /* Couldn't change? Then propagate the EPERM */
                        r = -EPERM;
                else /* try again... */
                        r = renameat(dir_fd, temporary_name, dir_fd, name) < 0 ? -errno : 0;
        }

        if (r < 0) {
                if (!IN_SET(r, -ENOTDIR, -EISDIR))
                        return r;

                /* The destination exists already, and we couldn't rename the file overriding it. This most likely
                 * happened because we tried to move a directory over a regular file or vice versa. Let's now try to
                 * swap the temporary file and the destination. If that works, we can remove the temporary file, and
                 * expose atomic behaviour to the outside. */

                r = renameat2(dir_fd, temporary_name, dir_fd, name, RENAME_EXCHANGE) < 0 ? -errno : 0;
                if (r == -EPERM && d->undo_immutable) {
                        /* EPERM could mean the immutable flag was set on the destination, let's see if we can drop that. */
                        r = drop_immutable(dir_fd, name);
                        if (r < 0)
                                return r;
                        if (r == 0) /* Couldn't change? */
                                r = -EPERM;
                        else
                                r = renameat2(dir_fd, temporary_name, dir_fd, name, RENAME_EXCHANGE) < 0 ? -errno : 0;
                }
                if (r < 0) {

                        /* If that didn't work (kernel too old?), then let's remove the destination first, and
                         * then try again. Of course in this mode we lose atomicity, but it's the best we can
                         * do */

                        (void) rm_rf_at(dir_fd, name, REMOVE_ROOT|REMOVE_PHYSICAL|(d->undo_immutable ? REMOVE_UNDO_IMMUTABLE : 0));

                        if (renameat(dir_fd, temporary_name, dir_fd, name) < 0)
                                return -errno;
                } else {
                        /* The exchange worked! In that case the temporary name is now the old version, let's remove it */

                        r = rm_rf_at(dir_fd, temporary_name, REMOVE_ROOT|REMOVE_PHYSICAL|(d->undo_immutable ? REMOVE_UNDO_IMMUTABLE : 0));
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int ca_decoder_finalize_child(CaDecoder *d, CaDecoderNode *n, CaDecoderNode *child) {
        statfs_f_type_t magic = 0;
        const char *name;
        struct stat st;
        mode_t mode;
        int r, dir_fd;

        assert(d);
        assert(child);

        /* If the child got replaced by a hardlink to a seed file we don't need to finalize it. */
        if (child->hardlinked)
                return 0;

        /* Finalizes the file attributes on the specified child node. 'n' specifies it's parent, except for the special
         * case where we are processing the root direction of the serialization, where it is NULL. */

        if (n)
                dir_fd = ca_decoder_node_get_fd(d, n);
        else
                dir_fd = -1;

        if (dir_fd < 0 && child->fd < 0)
                return 0; /* Nothing to do if no fds are opened */

        mode = ca_decoder_node_mode(child);
        if (mode == (mode_t) -1)
                return -EUNATCH;

        /* If this is a regular file, try to reflink everything. Note we do this both for naked files (unlike the rest
         * of the bits here) as well as for files in directory trees. */
        if (S_ISREG(mode)) {
                r = ca_decoder_node_reflink(d, child);
                if (r < 0)
                        return r;
        }

        /* If this is a naked file, then exit early, as we don't need to adjust metadata */
        if (CA_DECODER_IS_NAKED(d))
                return 0;

        /* Ignore entries we are not supposed to replay */
        if (S_ISLNK(mode) && (d->replay_feature_flags & CA_FORMAT_WITH_SYMLINKS) == 0)
                return 0;
        if (S_ISFIFO(mode) && (d->replay_feature_flags & CA_FORMAT_WITH_FIFOS) == 0)
                return 0;
        if (S_ISSOCK(mode) && (d->replay_feature_flags & CA_FORMAT_WITH_SOCKETS) == 0)
                return 0;
        if ((S_ISBLK(mode) || S_ISCHR(mode)) &&
                     (d->replay_feature_flags & CA_FORMAT_WITH_DEVICE_NODES) == 0)
                return 0;

        name = child->temporary_name ?: child->name;

        if (child->fd >= 0)
                r = fstat(child->fd, &st);
        else {
                assert(dir_fd >= 0);

                r = fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW);
        }
        if (r < 0)
                return -errno;

        if (st.st_dev == d->cached_st_dev)
                magic = d->cached_magic;
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

                z = readlinkat(dir_fd, name, buf, l+1);
                if (z < 0)
                        return -errno;
                if ((size_t) z != l)
                        return -EEXIST;

                if (memcmp(child->symlink_target, buf, l) != 0)
                        return -EEXIST;
        }

        if (S_ISDIR(st.st_mode)) {
                r = ca_decoder_node_delete(d, child);
                if (r < 0)
                        return r;
        }

        if (d->replay_feature_flags & (CA_FORMAT_WITH_32BIT_UIDS|CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_USER_NAMES)) {
                uid_t uid;
                gid_t gid;

                if ((d->replay_feature_flags & CA_FORMAT_WITH_USER_NAMES) && child->user_name) {
                        r = name_to_uid(d, child->user_name, &uid);
                        if (r < 0)
                                return r;
                } else {
                        uid = (uid_t) read_le64(&child->entry->uid);

                        uid = ca_decoder_shift_uid(d, uid);
                        if (!uid_is_valid(uid))
                                return -EINVAL;
                }

                if ((d->replay_feature_flags & CA_FORMAT_WITH_USER_NAMES) && child->group_name) {
                        r = name_to_gid(d, child->group_name, &gid);
                        if (r < 0)
                                return r;
                } else {
                        gid = (gid_t) read_le64(&child->entry->gid);

                        gid = ca_decoder_shift_gid(d, gid);
                        if (!gid_is_valid(gid))
                                return -EINVAL;
                }

                if (st.st_uid != uid || st.st_gid != gid) {

                        if (child->fd >= 0)
                                r = fchown(child->fd, uid, gid);
                        else {
                                assert(dir_fd >= 0);

                                r = fchownat(dir_fd, name, uid, gid, AT_SYMLINK_NOFOLLOW);
                        }
                        if (r < 0)
                                return -errno;

                       /* on Linux, changing ownership can reset setuid/setgid bits. stat() the
                               file again so permission checking code below knows the new
                               state of affairs */
                       if (child->fd >= 0)
                               r = fstat(child->fd, &st);
                       else {
                               assert(dir_fd >= 0);

                               r = fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW);
                       }
                       if (r < 0)
                               return -errno;
               }
       }

        if (d->replay_feature_flags & CA_FORMAT_WITH_READ_ONLY) {

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
                                assert(dir_fd >= 0);

                                r = fchmodat(dir_fd, name, new_mode, 0);
                        }
                        if (r < 0)
                                return -errno;
                }

        } else if (d->replay_feature_flags & (CA_FORMAT_WITH_PERMISSIONS|CA_FORMAT_WITH_ACL)) {

                if ((st.st_mode & 07777) != (read_le64(&child->entry->mode) & 07777)) {

                        if (child->fd >= 0)
                                r = fchmod(child->fd, read_le64(&child->entry->mode) & 07777);
                        else {
                                assert(dir_fd >= 0);

                                r = fchmodat(dir_fd, name, read_le64(&child->entry->mode) & 07777, 0);
                        }
                        if (r < 0)
                                return -errno;
                }
        }

        if (d->replay_feature_flags & CA_FORMAT_WITH_ACL) {
                char proc_path[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
                int path_fd = -1;
                acl_t new_acl;

                if (child->fd < 0) {
                        assert(dir_fd >= 0);

                        path_fd = openat(dir_fd, name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_PATH);
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

        if ((d->replay_feature_flags & CA_FORMAT_WITH_XATTRS) && !S_ISLNK(st.st_mode) && child->fd >= 0) {
                CaDecoderExtendedAttribute *x;
                size_t space = 256;
                ssize_t l;
                _cleanup_free_ char *p = NULL;
                char *q;

                p = new(char, space);
                if (!p)
                        return -ENOMEM;

                for (;;) {
                        l = flistxattr(child->fd, p, space);
                        if (l < 0) {
                                if (IN_SET(errno, EOPNOTSUPP, EBADF)) {
                                        l = 0;
                                        break;
                                }

                                if (errno != ERANGE)
                                        return -errno;
                        } else
                                break;

                        if (space*2 <= space)
                                return -ENOMEM;

                        space *= 2;
                        q = realloc(p, space);
                        if (!q)
                                return -ENOMEM;
                        p = q;
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

                        for (x = child->xattrs_first; x; x = x->next)
                                if (streq((char*) x->format.name_and_value, q)) {
                                        found = true;
                                        break;
                                }

                        if (found)
                                goto next;

                        if (fremovexattr(child->fd, q) < 0)
                                return -errno;

                next:
                        q += z + 1;
                        l -= z + 1;
                }

                for (x = child->xattrs_first; x; x = x->next) {
                        size_t k;

                        k = strlen((char*) x->format.name_and_value);

                        if (fsetxattr(child->fd, (char*) x->format.name_and_value,
                                      x->format.name_and_value + k + 1,
                                      read_le64(&x->format.header.size) - offsetof(CaFormatXAttr, name_and_value) - k - 1,
                                      0) < 0)
                                return -errno;
                }
        }

        if ((d->replay_feature_flags & CA_FORMAT_WITH_FCAPS) && S_ISREG(st.st_mode) && child->fd >= 0) {

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

        if (d->replay_feature_flags & CA_FORMAT_WITH_SELINUX) {
#if HAVE_SELINUX
                _cleanup_free_ char *subpath = NULL;
                char *label = NULL;
                bool update = false;

                if (child->fd >= 0)
                        r = fgetfilecon(child->fd, &label) < 0 ? -errno : 0;
                else {
                        if (asprintf(&subpath, "/proc/self/fd/%i/%s", dir_fd, name) < 0)
                                return -ENOMEM;

                        r = lgetfilecon(subpath, &label) < 0 ? -errno : 0;
                }
                if (r == -EOPNOTSUPP) {
                        if (child->selinux_label)
                                return -EOPNOTSUPP;

                        /* If the backing file system doesn't support labels, and we are not supposed to set any, then that's fine */
                } else if (r == -ENODATA)
                        /* If there has been no label assigned so far, then update if we need to set one now */
                        update = !!child->selinux_label;
                else if (r < 0)
                        /* In all other error cases propagate the error */
                        return r;
                else {
                        update = !streq_ptr(child->selinux_label, label);
                        freecon(label);
                }

                if (update) {
                        if (child->selinux_label) {
                                if (child->fd >= 0)
                                        r = fsetfilecon(child->fd, child->selinux_label) < 0 ? -errno : 0;
                                else {
                                        assert(subpath);
                                        r = lsetfilecon(subpath, child->selinux_label) < 0 ? -errno : 0;
                                }
                        } else {
                                if (child->fd >= 0)
                                        r = fremovexattr(child->fd, "security.selinux") < 0 && errno != ENODATA ? -errno : 0;
                                else {
                                        assert(subpath);
                                        r = lremovexattr(subpath, "security.selinux") < 0 && errno != -ENODATA ? -errno : 0;
                                }
                        }
                } else
                        r = 0;
                if (r < 0)
                        return r;

#else
                if (child->selinux_label)
                        return -EOPNOTSUPP;
#endif
        }

        if (d->replay_feature_flags & (CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_NSEC_TIME|CA_FORMAT_WITH_2SEC_TIME)) {

                struct timespec ts[2] = {
                        { .tv_nsec = UTIME_OMIT },
                        nsec_to_timespec(read_le64(&child->entry->mtime)),
                };

                if (child->fd >= 0)
                        r = futimens(child->fd, ts);
                else {
                        assert(dir_fd >= 0);

                        r = utimensat(dir_fd, name, ts, AT_SYMLINK_NOFOLLOW);
                }
                if (r < 0)
                        return -errno;
        }

        if (child->temporary_name && child->name) {
                /* Move the final result into place. Note that the chattr() file attributes we only apply after this,
                 * as they might make prohibit us from renaming the file (consider the "immutable" flag) */

                r = ca_decoder_install_file(d, dir_fd, child->temporary_name, child->name);
                if (r < 0)
                        return r;

                child->temporary_name = mfree(child->temporary_name);
                name = child->name;
        }

        if ((d->replay_feature_flags & CA_FORMAT_WITH_CHATTR) != 0 && child->fd >= 0) {
                unsigned value, mask;

                value = ca_feature_flags_to_chattr(read_le64(&child->entry->flags));
                mask = ca_feature_flags_to_chattr(d->replay_feature_flags);

                r = mask_attr_fd(child->fd, value, mask);
                if (r < 0)
                        return r;
        }

        if ((d->replay_feature_flags & CA_FORMAT_WITH_FAT_ATTRS) != 0 && child->fd >= 0) {
                unsigned value, mask;

                value = ca_feature_flags_to_fat_attrs(read_le64(&child->entry->flags));
                mask = ca_feature_flags_to_fat_attrs(d->replay_feature_flags);

                if (IN_SET(magic, MSDOS_SUPER_MAGIC, FUSE_SUPER_MAGIC)) {

                        r = mask_fat_attr_fd(child->fd, value, mask);
                        if (r < 0)
                                return r;

                } else if ((value & mask) != 0)
                        return -EOPNOTSUPP;
        }

        if (d->replay_feature_flags & CA_FORMAT_WITH_SUBVOLUME) {
                bool is_subvol;

                is_subvol = F_TYPE_EQUAL(magic, BTRFS_SUPER_MAGIC) && st.st_ino == 256;

                if (!!(read_le64(&child->entry->flags) & CA_FORMAT_WITH_SUBVOLUME) != is_subvol)
                        return -EEXIST;

                if ((d->replay_feature_flags & CA_FORMAT_WITH_SUBVOLUME_RO) && is_subvol && child->fd >= 0) {
                        uint64_t bflags, nflags;

                        if (ioctl(child->fd, BTRFS_IOC_SUBVOL_GETFLAGS, &bflags) < 0)
                                return -errno;

                        if (read_le64(&child->entry->flags) & CA_FORMAT_WITH_SUBVOLUME_RO)
                                nflags = bflags | BTRFS_SUBVOL_RDONLY;
                        else
                                nflags = bflags & ~BTRFS_SUBVOL_RDONLY;

                        if (nflags != bflags) {
                                if (ioctl(child->fd, BTRFS_IOC_SUBVOL_SETFLAGS, &nflags) < 0)
                                        return -errno;
                        }
                }
        }

        if (d->replay_feature_flags & (CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_NSEC_TIME|CA_FORMAT_WITH_2SEC_TIME)) {
                uint64_t granularity;

                /* If we have restored the time validate it after all uses, since the backing file system might not
                 * provide the granularity we need, but we shouldn't permit that since we care about
                 * reproducibility. */

                if (child->fd >= 0)
                        r = fstat(child->fd, &st);
                else {
                        assert(dir_fd >= 0);
                        r = fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW);
                }
                if (r < 0)
                        return -errno;

                r = ca_feature_flags_time_granularity_nsec(d->replay_feature_flags, &granularity);
                if (r < 0)
                        return r;

                if (timespec_to_nsec(st.st_mtim) / granularity != read_le64(&child->entry->mtime) / granularity)
                        return -EOPNOTSUPP;
        }

        return 0;
}

static void ca_decoder_apply_seek_offset(CaDecoder *d) {
        assert(d);

        d->archive_offset = d->seek_offset;
        d->step_size = 0;
        d->eof = false;

        realloc_buffer_empty(&d->buffer);
        ca_origin_flush(d->buffer_origin);
}

static int ca_decoder_step_node(CaDecoder *d, CaDecoderNode *n) {
        mode_t mode;
        int r;

        assert(d);
        assert(n);

        mode = ca_decoder_node_mode(n);

        switch (d->state) {

        case CA_DECODER_INIT:
                if (CA_DECODER_IS_NAKED(d)) {
                        assert(CA_DECODER_AT_ROOT(d));

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

                ca_digest_reset(d->archive_digest);

                return CA_DECODER_FOUND;

        case CA_DECODER_ENTRY: {
                CaDecoderNode *parent;

                parent = ca_decoder_current_parent_node(d);
                if (parent) {
                        r = ca_decoder_realize_child(d, parent, n);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to realize child: %m");
                }

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                if (S_ISREG(mode)) {
                        ca_decoder_enter_state(d, CA_DECODER_IN_PAYLOAD);
                        return ca_decoder_step_node(d, n);
                }

                if (S_ISDIR(mode)) {
                        ca_decoder_enter_state(d, CA_DECODER_IN_DIRECTORY);
                        return ca_decoder_step_node(d, n);
                }

                ca_decoder_enter_state(d, CA_DECODER_FINALIZE);
                return CA_DECODER_DONE_FILE;
        }

        case CA_DECODER_IN_PAYLOAD:
                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISREG(mode) || S_ISBLK(mode));

                /* If the size of this payload is known, and we reached it, we are done */
                if (n->size != UINT64_MAX) {
                        assert(d->payload_offset <= n->size);

                        if (d->payload_offset == n->size) {
                                ca_decoder_enter_state(d, CA_DECODER_FINALIZE);
                                return CA_DECODER_DONE_FILE;
                        }
                }

                if (realloc_buffer_size(&d->buffer) > 0) {
                        if (n->size == UINT64_MAX)
                                d->step_size = realloc_buffer_size(&d->buffer);
                        else
                                d->step_size = MIN(realloc_buffer_size(&d->buffer), n->size - d->payload_offset);

                        if (d->want_archive_digest)
                                ca_decoder_write_digest(d, &d->archive_digest, realloc_buffer_data(&d->buffer), d->step_size);
                        if (d->want_payload_digest && !d->payload_digest_invalid)
                                ca_decoder_write_digest(d, &d->payload_digest, realloc_buffer_data(&d->buffer), d->step_size);
                        if (d->want_hardlink_digest && !d->hardlink_digest_invalid)
                                ca_decoder_write_digest(d, &d->hardlink_digest, realloc_buffer_data(&d->buffer), d->step_size);

                        return CA_DECODER_PAYLOAD;
                }

                if (d->eof) {
                        /* EOF before the object was supposed to end? */
                        if (n->size != UINT64_MAX)
                                return -EPIPE;

                        /* There are still parent nodes around that wait for the GOODBYE object, and we got EOF inside this
                         * file? */
                        if (!CA_DECODER_AT_ROOT(d))
                                return -EPIPE;

                        /* If we don't know the length and get an EOF, we are happy and just consider this the end of the payload */
                        ca_decoder_enter_state(d, CA_DECODER_FINALIZE);

                        /* If this is a top-level regular file, then do not generate CA_DECODER_DONE_FILE, as there is no file to speak of realy */
                        if (CA_DECODER_IS_NAKED(d)) {
                                assert(n == d->nodes);
                                return ca_decoder_step_node(d, n);
                        }

                        return CA_DECODER_DONE_FILE;
                }

                /* If the caller doesn't want the payload, and we don't need it either, but know how large it is, then let's skip over it */
                if (!d->payload && !d->want_payload_digest && n->fd < 0 && n->size != UINT64_MAX) {

                        d->skip_bytes = n->size - d->payload_offset;
                        ca_decoder_enter_state(d, CA_DECODER_SKIPPING);

                        return CA_DECODER_SKIP;
                }

                return CA_DECODER_REQUEST;

        case CA_DECODER_SKIPPING:

                d->archive_offset += d->skip_bytes;
                d->skip_bytes = 0;

                ca_decoder_enter_state(d, CA_DECODER_FINALIZE);
                return CA_DECODER_DONE_FILE;

        case CA_DECODER_IN_DIRECTORY:
        case CA_DECODER_SEEKING_TO_FILENAME:
        case CA_DECODER_SEEKING_TO_NEXT_SIBLING:
        case CA_DECODER_SEEKING_TO_GOODBYE:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISDIR(mode));

                return ca_decoder_parse_filename(d, n);

        case CA_DECODER_GOODBYE:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISDIR(mode));

                ca_decoder_enter_state(d, CA_DECODER_FINALIZE);
                return CA_DECODER_DONE_FILE;

        case CA_DECODER_FINALIZE: {
                CaDecoderNode *saved_child = n;

                r = ca_decoder_leave_child(d);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* We managed to one level up */
                        n = ca_decoder_current_node(d);
                        if (!n)
                                return -EUNATCH;

                        r = ca_decoder_finalize_child(d, n, saved_child);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to finalize child: %m");

                        ca_decoder_enter_state(d, CA_DECODER_IN_DIRECTORY);
                        return CA_DECODER_STEP;
                }

                /* We already are at the top level. Now also fix up the top-level entry */
                r = ca_decoder_finalize_child(d, ca_decoder_current_parent_node(d), n);
                if (r < 0)
                        return r;

                ca_decoder_enter_state(d, CA_DECODER_EOF);
                return CA_DECODER_FINISHED;
        }

        case CA_DECODER_PREPARING_SEEK_TO_OFFSET:

                assert(CA_DECODER_IS_NAKED(d));

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISREG(mode) || S_ISBLK(mode));

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_OFFSET);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_SEEKING_TO_OFFSET:

                assert(CA_DECODER_IS_NAKED(d));

                ca_decoder_enter_state(d, CA_DECODER_IN_PAYLOAD);
                d->payload_offset = d->seek_offset;
                ca_decoder_reset_seek(d);

                ca_digest_reset(d->archive_digest);
                d->payload_digest_invalid = d->hardlink_digest_invalid = true;

                return ca_decoder_step_node(d, n);

        case CA_DECODER_PREPARING_SEEK_TO_FILENAME:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISDIR(mode));

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_FILENAME);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_PREPARING_SEEK_TO_NEXT_SIBLING:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISDIR(mode));

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_NEXT_SIBLING);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_SEEKING_TO_PAYLOAD:

                ca_decoder_enter_state(d, CA_DECODER_IN_PAYLOAD);
                d->payload_offset = d->seek_payload;
                ca_decoder_reset_seek(d);

                ca_digest_reset(d->archive_digest);
                if (d->want_payload_digest) {

                        d->payload_digest_invalid = d->payload_offset > 0;
                        if (!d->payload_digest_invalid)
                                ca_digest_reset(d->payload_digest);
                }
                d->hardlink_digest_invalid = true;

                return ca_decoder_step_node(d, n);

        case CA_DECODER_PREPARING_SEEK_TO_PAYLOAD:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISREG(mode));

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_PAYLOAD);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_PREPARING_SEEK_TO_ENTRY:

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_ENTRY);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_PREPARING_SEEK_TO_GOODBYE:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISDIR(mode));

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_GOODBYE);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_PREPARING_SEEK_TO_GOODBYE_TAIL:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISDIR(mode));

                ca_decoder_enter_state(d, CA_DECODER_SEEKING_TO_GOODBYE_TAIL);
                ca_decoder_apply_seek_offset(d);

                return CA_DECODER_SEEK;

        case CA_DECODER_SEEKING_TO_GOODBYE_TAIL:

                if (mode == (mode_t) -1)
                        return -EUNATCH;

                assert(S_ISDIR(mode));

                return ca_decoder_parse_goodbye_tail(d, n);

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

        assert(d->step_size <= realloc_buffer_size(&d->buffer));

        if (d->state == CA_DECODER_IN_PAYLOAD) {

                if (n->fd >= 0) {
                        mode_t mode;

                        mode = ca_decoder_node_mode(n);
                        if (mode == (mode_t) -1)
                                return -EUNATCH;

                        /* If hole punching is supported and we are writing to a regular file, use it */
                        if (d->punch_holes && S_ISREG(mode)) {
                                uint64_t n_punched;

                                r = loop_write_with_holes(n->fd, realloc_buffer_data(&d->buffer), d->step_size, &n_punched);
                                if (r < 0)
                                        return r;

                                d->n_punch_holes_bytes += n_punched;
                        } else {
                                r = loop_write(n->fd, realloc_buffer_data(&d->buffer), d->step_size);
                                if (r < 0)
                                        return r;
                        }
                }

                if (d->reflink) {
                        if (!n->payload_origin) {
                                r = ca_origin_new(&n->payload_origin);
                                if (r < 0)
                                        return r;
                        }

                        r = ca_origin_concat(n->payload_origin, d->buffer_origin, d->step_size);
                        if (r < 0)
                                return r;
                }

                d->payload_offset += d->step_size;
        }

        r = realloc_buffer_advance(&d->buffer, d->step_size);
        if (r < 0)
                return r;

        if (d->reflink) {
                r = ca_origin_advance_bytes(d->buffer_origin, d->step_size);
                if (r < 0)
                        return r;
        }

        d->archive_offset += d->step_size;
        d->step_size = 0;

        return 0;
}

int ca_decoder_step(CaDecoder *d) {
        CaDecoderNode *n;
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

        return ca_decoder_step_node(d, n);
}

int ca_decoder_get_request_offset(CaDecoder *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = d->archive_offset + realloc_buffer_size(&d->buffer);
        return 0;
}

int ca_decoder_put_data(CaDecoder *d, const void *p, size_t size, CaOrigin *origin) {
        int r;

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

        if (d->reflink) {

                if (!d->buffer_origin) {
                        r = ca_origin_new(&d->buffer_origin);
                        if (r < 0)
                                return r;
                }

                if (!origin)
                        r = ca_origin_put_void(d->buffer_origin, size);
                else
                        r = ca_origin_concat(d->buffer_origin, origin, UINT64_MAX);
                if (r < 0)
                        return r;
        }

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
        if (mode == (mode_t) -1)
                return -EUNATCH;
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
        _cleanup_free_ char *p = NULL;
        size_t n = 0, i;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (d->n_nodes <= 0)
                return -EUNATCH;

        for (i = 1; i <= d->node_idx; i++) {
                CaDecoderNode *node;
                size_t k, nn;
                char *np, *q;

                node = d->nodes + i;
                assert(node->entry);

                k = strlen(node->name);
                nn = n + (n > 0) + k;

                np = realloc(p, nn+1);
                if (!np)
                        return -ENOMEM;

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
        p = NULL;
        return 0;
}

int ca_decoder_current_mode(CaDecoder *d, mode_t *ret) {
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
        if (mode == (mode_t) -1)
                return -ENODATA;

        *ret = mode;
        return 0;
}

int ca_decoder_current_target(CaDecoder *d, const char **ret) {
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
        if (mode == (mode_t) -1)
                return -ENODATA;
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

        if ((d->replay_feature_flags &
             (CA_FORMAT_WITH_NSEC_TIME|
              CA_FORMAT_WITH_USEC_TIME|
              CA_FORMAT_WITH_SEC_TIME|
              CA_FORMAT_WITH_2SEC_TIME)) == 0)
                return -ENODATA;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

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

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        mode = ca_decoder_node_mode(n);
        if (mode == (mode_t) -1)
                return -ENODATA;
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

        if ((d->replay_feature_flags &
             (CA_FORMAT_WITH_16BIT_UIDS|
              CA_FORMAT_WITH_32BIT_UIDS)) == 0)
                return -ENODATA;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

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

        if ((d->replay_feature_flags &
             (CA_FORMAT_WITH_16BIT_UIDS|
              CA_FORMAT_WITH_32BIT_UIDS)) == 0)
                return -ENODATA;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        if (!n->entry)
                return -ENODATA;

        *ret = (gid_t) read_le64(&n->entry->gid);
        return 0;
}

int ca_decoder_current_user(CaDecoder *d, const char **ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if ((d->replay_feature_flags & CA_FORMAT_WITH_USER_NAMES) == 0)
                return -ENODATA;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        if (n->user_name)
                *ret = n->user_name;
        else if (d->feature_flags & (CA_FORMAT_WITH_32BIT_UIDS|CA_FORMAT_WITH_16BIT_UIDS)) {
                uid_t uid, shifted_uid;

                /* As special case, the "root" user is not encoded as user name string if the UID is also
                 * encoded. Thus, let's synthesize the name here again. Note that the user name is based on the UID as
                 * encoded on the underlying file system — i.e. not the shifted UID. This means we first have to shift
                 * back here. */

                if (!n->entry)
                        return -ENODATA;

                uid = (uid_t) read_le64(&n->entry->uid);
                shifted_uid = ca_decoder_shift_uid(d, uid);
                if (!uid_is_valid(shifted_uid))
                        return -EINVAL;

                if (shifted_uid != 0)
                        return -ENODATA;

                *ret = "root";
        } else
                return -ENODATA;

        return 0;
}

int ca_decoder_current_group(CaDecoder *d, const char **ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if ((d->replay_feature_flags & CA_FORMAT_WITH_USER_NAMES) == 0)
                return -ENODATA;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        if (n->group_name)
                *ret = n->group_name;
        else if (d->feature_flags & (CA_FORMAT_WITH_32BIT_UIDS|CA_FORMAT_WITH_16BIT_UIDS)) {
                gid_t gid, shifted_gid;

                if (!n->entry)
                        return -ENODATA;

                gid = (gid_t) read_le64(&n->entry->gid);
                shifted_gid = ca_decoder_shift_gid(d, gid);
                if (!gid_is_valid(shifted_gid))
                        return -EINVAL;

                if (shifted_gid != 0)
                        return -ENODATA;

                *ret = "root";
        } else
                return -ENODATA;

        return 0;
}

int ca_decoder_current_rdev(CaDecoder *d, dev_t *ret) {
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
        if (mode == (mode_t) -1)
                return -ENODATA;
        if (!S_ISCHR(mode) && !S_ISBLK(mode))
                return -ENODATA;

        *ret = n->rdev;
        return 0;
}

int ca_decoder_current_chattr(CaDecoder *d, unsigned *ret) {
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
        if (mode == (mode_t) -1)
                return -ENODATA;
        if (!S_ISREG(mode) && !S_ISDIR(mode))
                return -ENODATA;
        if (!n->entry)
                return -ENODATA;

        *ret = ca_feature_flags_to_chattr(read_le64(&n->entry->flags) & d->replay_feature_flags);
        return 0;
}

int ca_decoder_current_fat_attrs(CaDecoder *d, uint32_t *ret) {
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
        if (mode == (mode_t) -1)
                return -ENODATA;
        if (!S_ISREG(mode) && !S_ISDIR(mode))
                return -ENODATA;
        if (!n->entry)
                return -ENODATA;

        *ret = ca_feature_flags_to_fat_attrs(read_le64(&n->entry->flags) & d->replay_feature_flags);
        return 0;
}

int ca_decoder_current_xattr(CaDecoder *d, CaIterate where, const char **ret_name, const void **ret_value, size_t *ret_size) {
        CaDecoderNode *n;
        CaDecoderExtendedAttribute *p = NULL;

        if (!d)
                return -EINVAL;
        if (!ret_name)
                return -EINVAL;
        if (where < 0)
                return -EINVAL;
        if (where >= _CA_ITERATE_MAX)
                return -EINVAL;
        if (!ret_name)
                return -EINVAL;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        switch (where) {

        case CA_ITERATE_NEXT:
                if (n->xattrs_current)
                        p = n->xattrs_current->next;
                else
                        p = NULL;
                break;

        case CA_ITERATE_PREVIOUS:
                if (n->xattrs_current)
                        p = n->xattrs_current->previous;
                else
                        p = NULL;
                break;

        case CA_ITERATE_FIRST:
                p = n->xattrs_first;
                break;

        case CA_ITERATE_LAST:
                p = n->xattrs_last;
                break;

        case CA_ITERATE_CURRENT:
                p = n->xattrs_current;
                break;

        case _CA_ITERATE_MAX:
        case _CA_ITERATE_INVALID:
                assert(false);
        }

        if (!p)
                goto eof;

        n->xattrs_current = p;

        *ret_name = (const char*) p->format.name_and_value;

        if (ret_value || ret_size) {
                const void *v;

                v = memchr(p->format.name_and_value, 0, read_le64(&p->format.header.size) - offsetof(CaFormatXAttr, name_and_value));
                assert(v);

                v = (const uint8_t*) v + 1;

                if (ret_value)
                        *ret_value = v;

                if (ret_size)
                        *ret_size = read_le64(&p->format.header.size) - offsetof(CaFormatXAttr, name_and_value) - ((const uint8_t*) v - (const uint8_t*) p->format.name_and_value);
        }

        return 1;

eof:
        *ret_name = NULL;
        if (ret_value)
                *ret_value = NULL;
        if (ret_size)
                *ret_size = 0;

        return 0;
}

int ca_decoder_current_quota_projid(CaDecoder *d, uint32_t *ret) {
        CaDecoderNode *n;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        if (!n->have_quota_projid)
                return -ENODATA;

        *ret = n->quota_projid;
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
        if (mode == (mode_t) -1)
                return -ENODATA;
        if (!S_ISREG(mode) && !S_ISBLK(mode))
                return -EISDIR;

        *ret = d->payload_offset;
        return 0;
}

int ca_decoder_seek_offset(CaDecoder *d, uint64_t offset) {
        /* Seek to the specified offset in the archive. Only supported when we decode a naked file, i.e. not a
         * directory tree serialization */

        if (!d)
                return -EINVAL;
        if (offset == UINT64_MAX)
                return -EINVAL;

        if (d->n_nodes <= 0)
                return -EUNATCH;
        if (!CA_DECODER_IS_NAKED(d))
                return -EISDIR;

        if (d->nodes[0].end_offset == UINT64_MAX) /* The top node must have a size set to be considered seekable */
                return -ESPIPE;

        if (offset > d->nodes[0].end_offset) {
                ca_decoder_enter_state(d, CA_DECODER_NOWHERE);
                return 0;
        }
        if (offset == d->nodes[0].end_offset) {
                ca_decoder_enter_state(d, CA_DECODER_EOF);
                return 0;
        }

        ca_decoder_reset_seek(d);

        d->seek_offset = offset;

        ca_decoder_enter_state(d, CA_DECODER_PREPARING_SEEK_TO_OFFSET);

        d->payload_digest_invalid = d->hardlink_digest_invalid = true;

        return 0;
}

static int ca_decoder_seek_path_internal(
                CaDecoder *d,
                const char *path,
                bool next_sibling,
                uint64_t offset) {

        char *path_copy = NULL;
        const char *p;
        size_t new_idx;
        mode_t mode;
        int r;

        if (!d)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (d->n_nodes <= 0)
                return -EUNATCH;
        if (d->nodes[0].end_offset == UINT64_MAX) /* The root directory must have a size set to be considered seekable */
                return -ESPIPE;

        mode = ca_decoder_node_mode(d->nodes);
        if (mode == (mode_t) -1)
                return -ENODATA;
        if (!S_ISDIR(mode))
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
                if (r == 0) /* Yay, we already found where we were supposed to go */
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
        d->seek_next_sibling = next_sibling;
        d->seek_payload = offset;

        d->node_idx = new_idx;
        ca_decoder_forget_children(d);

        return ca_decoder_do_seek(d, d->nodes + new_idx);
}

int ca_decoder_seek_path(CaDecoder *d, const char *path) {
        return ca_decoder_seek_path_internal(d, path, false, UINT64_MAX);
}

int ca_decoder_seek_path_offset(CaDecoder *d, const char *path, uint64_t offset) {

        if (offset == UINT64_MAX)
                return -EINVAL;

        return ca_decoder_seek_path_internal(d, path, false, offset);
}

int ca_decoder_seek_next_sibling(CaDecoder *d) {
        _cleanup_free_ char *p = NULL;
        int r;

        if (!d)
                return -EINVAL;

        r = ca_decoder_current_path(d, &p);
        if (r < 0)
                return r;

        return ca_decoder_seek_path_internal(d, p, true, UINT64_MAX);
}

int ca_decoder_get_seek_offset(CaDecoder *d, uint64_t *ret) {

        /* Called by the consumer whenever we issued a CA_DECODER_SEEK event, and informs the caller to which absolute
         * byte index to seek to. */

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!IN_SET(d->state,
                    CA_DECODER_SEEKING_TO_OFFSET,
                    CA_DECODER_SEEKING_TO_FILENAME,
                    CA_DECODER_SEEKING_TO_NEXT_SIBLING,
                    CA_DECODER_SEEKING_TO_ENTRY,
                    CA_DECODER_SEEKING_TO_PAYLOAD,
                    CA_DECODER_SEEKING_TO_GOODBYE,
                    CA_DECODER_SEEKING_TO_GOODBYE_TAIL))
                return -ENODATA;

        if (d->seek_offset == UINT64_MAX)
                return -ENODATA;

        *ret = d->seek_offset;
        return 0;
}

int ca_decoder_get_skip_size(CaDecoder *d, uint64_t *ret) {
        /* Called by the consumer whenever we issued a CA_DECODER_SKIP event, and informs the caller how many bytes to
         * skip in the input stream. */

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (d->state != CA_DECODER_SKIPPING)
                return -ENODATA;

        if (d->skip_bytes == 0)
                return -ENODATA;

        *ret = d->skip_bytes;
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

int ca_decoder_set_punch_holes(CaDecoder *d, bool enabled) {

        if (!d)
                return -EINVAL;

        d->punch_holes = enabled;
        return 0;
}

int ca_decoder_set_reflink(CaDecoder *d, bool enabled) {

        if (!d)
                return -EINVAL;

        d->reflink = enabled;
        return 0;
}

int ca_decoder_set_hardlink(CaDecoder *d, bool enabled) {

        if (!d)
                return -EINVAL;

        d->hardlink = enabled;
        return 0;
}

int ca_decoder_set_delete(CaDecoder *d, bool enabled) {

        if (!d)
                return -EINVAL;

        d->delete = enabled;
        return 0;
}

int ca_decoder_set_payload(CaDecoder *d, bool enabled) {

        if (!d)
                return -EINVAL;

        d->payload = enabled;
        return 0;
}

int ca_decoder_set_undo_immutable(CaDecoder *d, bool enabled) {

        if (!d)
                return -EINVAL;

        d->undo_immutable = enabled;
        return 0;
}

int ca_decoder_get_punch_holes_bytes(CaDecoder *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!d->punch_holes)
                return -ENODATA;

        *ret = d->n_punch_holes_bytes;
        return 0;
}

int ca_decoder_get_reflink_bytes(CaDecoder *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!d->reflink)
                return -ENODATA;

        *ret = d->n_reflink_bytes;
        return 0;
}

int ca_decoder_get_hardlink_bytes(CaDecoder *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!d->hardlink)
                return -ENODATA;

        *ret = d->n_hardlink_bytes;
        return 0;
}

int ca_decoder_set_uid_shift(CaDecoder *d, uid_t u) {
        if (!d)
                return -EINVAL;

        d->uid_shift = u;
        return 0;
}

int ca_decoder_set_uid_range(CaDecoder *d, uid_t u) {
        if (!d)
                return -EINVAL;

        d->uid_range = u;
        return 0;
}

int ca_decoder_current_archive_offset(CaDecoder *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = d->archive_offset;
        return 0;
}

int ca_decoder_enable_archive_digest(CaDecoder *d, bool b) {
        if (!d)
                return -EINVAL;

        d->want_archive_digest = b;
        return 0;
}

int ca_decoder_enable_payload_digest(CaDecoder *d, bool b) {
        if (!d)
                return -EINVAL;

        d->want_payload_digest = b;
        return 0;
}

int ca_decoder_enable_hardlink_digest(CaDecoder *d, bool b) {
        if (!d)
                return -EINVAL;

        d->want_hardlink_digest = b;
        return 0;
}

int ca_decoder_get_archive_digest(CaDecoder *d, CaChunkID *ret) {
        const void *q;
        int r;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!d->want_archive_digest)
                return -ENOMEDIUM;
        if (d->state != CA_DECODER_EOF)
                return -EBUSY;

        r = ca_digest_ensure_allocated(&d->archive_digest, ca_feature_flags_to_digest_type(d->feature_flags));
        if (r < 0)
                return r;

        q = ca_digest_read(d->archive_digest);
        if (!q)
                return -EIO;

        assert(ca_digest_get_size(d->archive_digest) == sizeof(CaChunkID));
        memcpy(ret, q, sizeof(CaChunkID));
        return 0;
}

int ca_decoder_get_payload_digest(CaDecoder *d, CaChunkID *ret) {
        CaDecoderNode *n;
        const void *q;
        mode_t mode;
        int r;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!d->want_payload_digest)
                return -ENOMEDIUM;
        if (d->state != CA_DECODER_FINALIZE)
                return -EBUSY;
        if (d->payload_digest_invalid)
                return -ESTALE;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;
        mode = ca_decoder_node_mode(n);
        if (mode == (mode_t) -1)
                return -ENODATA;
        if (!S_ISREG(mode) && !S_ISBLK(mode))
                return -ENOTTY;

        r = ca_digest_ensure_allocated(&d->payload_digest, ca_feature_flags_to_digest_type(d->feature_flags));
        if (r < 0)
                return r;

        q = ca_digest_read(d->payload_digest);
        if (!q)
                return -EIO;

        assert(ca_digest_get_size(d->payload_digest) == sizeof(CaChunkID));
        memcpy(ret, q, sizeof(CaChunkID));
        return 0;
}

int ca_decoder_get_hardlink_digest(CaDecoder *d, CaChunkID *ret) {
        CaDecoderNode *n;
        const void *q;
        mode_t mode;
        int r;

        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!d->want_hardlink_digest)
                return -ENOMEDIUM;
        if (d->state != CA_DECODER_FINALIZE)
                return -EBUSY;
        if (d->hardlink_digest_invalid)
                return -ESTALE;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;
        mode = ca_decoder_node_mode(n);
        if (mode == (mode_t) -1)
                return -ENODATA;
        if (S_ISDIR(mode))
                return -EISDIR;

        r = ca_digest_ensure_allocated(&d->hardlink_digest, ca_feature_flags_to_digest_type(d->feature_flags));
        if (r < 0)
                return r;

        q = ca_digest_read(d->hardlink_digest);
        if (!q)
                return -EIO;

        assert(ca_digest_get_size(d->hardlink_digest) == sizeof(CaChunkID));
        memcpy(ret, q, sizeof(CaChunkID));
        return 0;
}

static mode_t ca_decoder_mode_mask(CaDecoder *d) {
        assert(d);

        if (d->feature_flags & CA_FORMAT_WITH_PERMISSIONS)
                return 07777;

        if (d->feature_flags & CA_FORMAT_WITH_READ_ONLY)
                return 00200;

        return 0;
}

int ca_decoder_try_hardlink(CaDecoder *d, CaFileRoot *root, const char *path) {
        CaDecoderNode *n, *parent;
        struct stat st;
        mode_t mode;
        int r, dir_fd;

        if (!d)
                return -EINVAL;
        if (!root)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (d->state != CA_DECODER_FINALIZE)
                return -EBUSY;
        if (!d->hardlink)
                return 0;

        parent = ca_decoder_current_parent_node(d);
        if (!parent)
                return -EUNATCH;
        if (parent->fd < 0)
                return 0;

        n = ca_decoder_current_node(d);
        if (!n)
                return -EUNATCH;

        mode = ca_decoder_node_mode(n);
        if (mode == (mode_t) -1)
                return -EUNATCH;
        if (!S_ISREG(mode))
                return -ENOTTY;

        if (fstatat(root->fd, path, &st, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno == ENOENT) /* vanished by now? */
                        return 0;

                return -errno;
        }

        /* Before we put the symlink in place, make some superficial checks if the node is still the same as when we
         * generated the seed for it. */

        if (!S_ISREG(st.st_mode)) /* Not a regular file anymore? */
                return 0;
        if ((uint64_t) st.st_size != n->size)
                return 0;

        if (((st.st_mode ^ mode) & ca_decoder_mode_mask(d)) != 0)
                return 0;

        assert(n->entry);

        if ((d->feature_flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS)) &&
            (st.st_uid != read_le64(&n->entry->uid) || st.st_gid != read_le64(&n->entry->gid)))
                return 0;

        if (d->feature_flags & (CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_NSEC_TIME|CA_FORMAT_WITH_2SEC_TIME)) {
                uint64_t granularity;

                r = ca_feature_flags_time_granularity_nsec(d->feature_flags, &granularity);
                if (r < 0)
                        return r;

                if (timespec_to_nsec(st.st_mtim) / granularity != read_le64(&n->entry->mtime) / granularity)
                        return 0;
        }

        dir_fd = ca_decoder_node_get_fd(d, parent);
        if (dir_fd < 0)
                return dir_fd;

        if (linkat(root->fd, path, dir_fd, n->name, 0) < 0) {
                _cleanup_free_ char *t = NULL;

                /* NB: If a file system doesn't support hardlinks, it will return EPERM, yuck! */
                if (IN_SET(errno, EXDEV, EMLINK, EPERM))
                        return 0;

                if (errno != EEXIST)
                        return -errno;

                /* The file exists already. In that case, let's link it as temporary file first, and then rename it
                 * (which makes the replacement nicely atomic) */

                r = tempfn_random(n->name, &t);
                if (r < 0)
                        return r;

                if (linkat(root->fd, path, dir_fd, t, 0) < 0) {
                        if (IN_SET(errno, EXDEV, EMLINK, EPERM))
                                return 0;

                        return -errno;
                }

                r = ca_decoder_install_file(d, dir_fd, t, n->name);
                if (r < 0) {
                        (void) unlinkat(dir_fd, t, 0);
                        return r;
                }
        }

        /* All good. Let's remove the file we just wrote, we don't need it if we managed to create the hard link */
        assert(n->temporary_name);
        if (unlinkat(dir_fd, n->temporary_name, 0) < 0)
                return -errno;

        n->temporary_name = mfree(n->temporary_name);
        n->fd = safe_close(n->fd);

        n->hardlinked = true;

        d->n_hardlink_bytes += st.st_size;

        return 1;
}
