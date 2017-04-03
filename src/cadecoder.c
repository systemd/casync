#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
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
#include "def.h"
#include "realloc-buffer.h"
#include "util.h"

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

/* #undef EBADMSG */
/* #define EBADMSG __LINE__ */

/* #undef EBUSY */
/* #define EBUSY __LINE__ */

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
        CaFormatXAttr format;
} CaDecoderExtendedAttribute;

typedef struct CaDecoderNode {
        int fd;

        char *name;
        CaFormatEntry *entry;

        mode_t mode;          /* Only set if entry == NULL */
        uint64_t size;        /* Only for S_ISREG() */

        char *user_name;
        char *group_name;
        char *symlink_target; /* Only for S_ISLNK() */
        dev_t rdev;           /* Only for S_ISCHR() and S_ISBLK() */

        CaDecoderExtendedAttribute *xattrs;

        bool have_fcaps;
        void *fcaps;
        size_t fcaps_size;
} CaDecoderNode;

typedef enum CaDecoderState {
        CA_DECODER_INIT,
        CA_DECODER_ENTERED,
        CA_DECODER_ENTRY,
        CA_DECODER_IN_PAYLOAD,
        CA_DECODER_IN_DIRECTORY,
        CA_DECODER_GOODBYE,
        CA_DECODER_EOF,
} CaDecoderState;

struct CaDecoder {
        CaDecoderState state;

        uint64_t feature_flags;

        CaDecoderNode nodes[NODES_MAX];
        size_t n_nodes;
        size_t node_idx;

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

        /* Cached name → UID/GID translation */
        uid_t cached_uid;
        gid_t cached_gid;

        char *cached_user_name;
        char *cached_group_name;

        /* A cached pair of st_dev and magic, so that we don't have to call statfs() for each file */
        dev_t cached_st_dev;
        statfs_f_type_t cached_magic;
};

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
        n->mode = 0;
        n->rdev = 0;
        n->fcaps = mfree(n->fcaps);
        n->fcaps_size = 0;
        n->have_fcaps = false;

        ca_decoder_node_free_xattrs(n);
}

CaDecoder *ca_decoder_unref(CaDecoder *d) {
        size_t i;

        if (!d)
                return NULL;

        for (i = 0; i < d->n_nodes; i++)
                ca_decoder_node_free(d->nodes + i);

        realloc_buffer_free(&d->buffer);

        free(d->cached_user_name);
        free(d->cached_group_name);

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

        if (fstat(fd, &st) < 0)
                return -errno;
        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISBLK(st.st_mode))
                return -ENOTTY;

        d->nodes[0] = (CaDecoderNode) {
                .fd = fd,
                .mode = st.st_mode,
                .size = UINT64_MAX,
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

        d->nodes[0] = (CaDecoderNode) {
                .fd = -1,
                .mode = m,
                .size = UINT64_MAX,
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
                .size = UINT64_MAX,
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

        if (d->node_idx <= 0)
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

        if (d->feature_flags & CA_FORMAT_WITH_PERMISSIONS)
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

        if ((flags & CA_FORMAT_WITH_READ_ONLY) &&
            (flags & CA_FORMAT_WITH_PERMISSIONS))
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

        if (!(d->feature_flags & CA_FORMAT_WITH_XATTR))
                return NULL;

        /* Make sure there's a NUL byte in the first 256 bytes, so that we have a properly bounded name */
        n = memchr(x->name_and_value, 0, MIN(256U, read_le64(&x->header.size) - offsetof(CaFormatXAttr, name_and_value)));
        if (!n)
                return NULL;

        if (!ca_xattr_name_is_valid((char*) x->name_and_value))
                return NULL;

        return x;
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
        uint64_t b;

        if (read_le64(&g->header.size) < offsetof(CaFormatGoodbye, table) + sizeof(le64_t))
                return NULL;
        if (read_le64(&g->header.type) != CA_FORMAT_GOODBYE)
                return NULL;

        b = read_le64((uint8_t*) p + read_le64(&g->header.size) - sizeof(le64_t));
        if (b != read_le64(&g->header.size))
                return NULL;

        return g;
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
        const CaFormatFCaps *fcaps = NULL;
        uint64_t offset = 0;
        bool done = false;
        mode_t mode;
        size_t sz;
        void *p;
        int r;

        assert(d);
        assert(n);

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

                        offset += l;
                        break;

                case CA_FORMAT_GROUP:
                        if (!entry)
                                return -EBADMSG;
                        if (group)
                                return -EBADMSG;
                        if (n->xattrs)
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

                        offset += l;
                        break;

                case CA_FORMAT_XATTR: {
                        const struct CaFormatXAttr *x;
                        CaDecoderExtendedAttribute *u;

                        if (!entry)
                                return -EBADMSG;
                        if (fcaps)
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
                        u = malloc(offsetof(CaDecoderExtendedAttribute, format) + read_le64(&x->header.size));
                        if (!u)
                                return -ENOMEM;

                        memcpy(&u->format, x, l);
                        u->next = n->xattrs;
                        n->xattrs = u;

                        offset += l;

                        break;
                }

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
                        if (l < offsetof(CaFormatGoodbye, table) + sizeof(le64_t))
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

        ca_decoder_enter_state(d, CA_DECODER_ENTRY);
        d->step_size = offset;

        return CA_DECODER_NEXT_FILE;
}

static int ca_decoder_parse_filename(CaDecoder *d) {
        const CaFormatFilename *filename = NULL;
        const CaFormatGoodbye *goodbye = NULL;
        const CaFormatHeader *h;
        uint64_t l, t;
        size_t sz;
        int r;

        assert(d);

        sz = realloc_buffer_size(&d->buffer);
        if (sz < sizeof(CaFormatHeader))
                return CA_DECODER_REQUEST;

        h = realloc_buffer_data(&d->buffer);
        l = read_le64(&h->size);
        if (l < sizeof(CaFormatHeader))
                return -EBADMSG;
        if (l == 0)
                return -EBADMSG;

        t = read_le64(&h->type);

        switch (t) {

        case CA_FORMAT_FILENAME: {
                CaDecoderNode *child;

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

                child = ca_decoder_init_child(d);
                if (!child)
                        return -EFBIG;

                child->name = strdup(filename->name);
                if (!child->name)
                        return -ENOMEM;

                r = ca_decoder_enter_child(d);
                if (r < 0)
                        return r;

                ca_decoder_enter_state(d, CA_DECODER_ENTERED);
                d->step_size = l;

                return CA_DECODER_STEP;
        }

        case CA_FORMAT_GOODBYE:
                if (l < offsetof(CaFormatGoodbye, table) + sizeof(le64_t))
                        return -EBADMSG;

                r = ca_decoder_object_is_complete(h, sz);
                if (r < 0)
                        return r;
                if (r == 0)
                        return CA_DECODER_REQUEST;

                goodbye = validate_format_goodbye(d, h);
                if (!goodbye)
                        return -EBADMSG;

                ca_decoder_enter_state(d, CA_DECODER_GOODBYE);
                d->step_size = l;

                return CA_DECODER_STEP;

        default:
                fprintf(stderr, "Got unexpected object: %016" PRIx64 "\n", t);
                return -EBADMSG;
        }
}

static int ca_decoder_realize_child(CaDecoder *d, CaDecoderNode *n, CaDecoderNode *child) {
        mode_t mode;
        int r;

        assert(d);
        assert(n);
        assert(child);

        if (n->fd < 0)
                return 0;
        if (child->fd >= 0)
                return 0;

        assert(child->entry);
        assert(child->name);

        mode = le64toh(child->entry->mode);

        switch (mode & S_IFMT) {

        case S_IFDIR:
                if (mkdirat(n->fd, child->name, 0700) < 0) {

                        if (errno != EEXIST)
                                return -errno;
                }

                child->fd = openat(n->fd, child->name, O_CLOEXEC|O_NOCTTY|O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
                if (child->fd < 0)
                        return -errno;

                break;

        case S_IFREG:
                child->fd = openat(n->fd, child->name, O_CLOEXEC|O_NOCTTY|O_WRONLY|O_NOFOLLOW|O_CREAT|O_TRUNC, 0600 | mode);
                if (child->fd < 0) {
                        r = -errno;
                        if (r == -EACCES) {
                                /* If the file exists and is read-only, the open() will fail, in that case, remove it try again */
                                if (unlinkat(n->fd, child->name, 0) >= 0)
                                        child->fd = openat(n->fd, child->name, O_CLOEXEC|O_NOCTTY|O_WRONLY|O_NOFOLLOW|O_CREAT|O_TRUNC, 0600 | mode);
                        }

                        if (child->fd < 0)
                                return r;
                }

                break;

        case S_IFLNK:

                if (symlinkat(child->symlink_target, n->fd, child->name) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        case S_IFIFO:

                if (mkfifoat(n->fd, child->name, mode) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        case S_IFBLK:
        case S_IFCHR:

                if (mknodat(n->fd, child->name, mode, child->rdev) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        case S_IFSOCK:

                if (mknodat(n->fd, child->name, mode, 0) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                }
                break;

        default:
                assert(false);
        }

        if (child->fd >= 0 && (le64toh(child->entry->flags) & d->feature_flags & CA_FORMAT_WITH_CHATTR) != 0) {
                unsigned new_attr;

                /* A select few chattr() attributes need to be applied (or are better applied) on empty
                 * files/directories instead of the final result, do so here. */

                new_attr = ca_feature_flags_to_chattr(le64toh(child->entry->flags) & d->feature_flags) & APPLY_EARLY_FS_FL;

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

static int ca_decoder_finalize_child(CaDecoder *d, CaDecoderNode *n, CaDecoderNode *child) {
        statfs_f_type_t magic = 0;
        struct stat st;
        mode_t mode;
        int r;

        assert(d);
        assert(child);

        /* Finalizes the file attributes on the specified child node. 'n' specifies it's parent, except for the special
         * case where we are processing the root direction of the serialization, where it is NULL. */

        if ((!n || n->fd < 0) && child->fd < 0)
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

                r = fstatat(n->fd, child->name, &st, AT_SYMLINK_NOFOLLOW);
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

        if (((le64toh(child->entry->mode) ^ st.st_mode) & S_IFMT) != 0)
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

                z = readlinkat(n->fd, child->name, buf, l+1);
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
                        uid = le64toh(child->entry->uid);

                if (child->group_name) {
                        r = name_to_gid(d, child->group_name, &gid);
                        if (r < 0)
                                return r;
                } else
                        gid = le64toh(child->entry->gid);

                if (st.st_uid != uid || st.st_gid != gid) {

                        if (child->fd >= 0)
                                r = fchown(child->fd, uid, gid);
                        else {
                                if (!n)
                                        return -EINVAL;

                                r = fchownat(n->fd, child->name, uid, gid, AT_SYMLINK_NOFOLLOW);
                        }
                        if (r < 0)
                                return -errno;
                }
        }

        if (d->feature_flags & CA_FORMAT_WITH_READ_ONLY) {

                if ((st.st_mode & 0400) == 0 || /* not readable? */
                    (S_ISDIR(st.st_mode) && (st.st_mode & 0100) == 0) || /* a dir, but not executable? */
                    !(le64toh(child->entry->mode) & 0222) != !(st.st_mode & 0200)) { /* writable bit doesn't match what it should be? */

                        mode_t new_mode;

                        new_mode = (st.st_mode & 0444) | 0400;

                        if (S_ISDIR(st.st_mode))
                                new_mode |= 0100;

                        if (le64toh(child->entry->mode) & 0222)
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

                                r = fchmodat(n->fd, child->name, new_mode, AT_SYMLINK_NOFOLLOW);
                        }
                        if (r < 0)
                                return -errno;
                }

        } else if (d->feature_flags & CA_FORMAT_WITH_PERMISSIONS) {

                if ((st.st_mode & 07777) != (le64toh(child->entry->mode) & 07777)) {

                        if (child->fd >= 0)
                                r = fchmod(child->fd, le64toh(child->entry->mode) & 07777);
                        else {
                                if (!n)
                                        return -EINVAL;

                                r = fchmodat(n->fd, child->name, le64toh(child->entry->mode) & 07777, AT_SYMLINK_NOFOLLOW);
                        }
                        if (r < 0)
                                return -errno;
                }
        }

        if ((d->feature_flags & CA_FORMAT_WITH_XATTR) && !S_ISLNK(st.st_mode)) {
                CaDecoderExtendedAttribute *x;

                x = child->xattrs;
                while (x) {
                        size_t k;

                        k = strlen((char*) x->format.name_and_value);

                        if (fsetxattr(child->fd, (char*) x->format.name_and_value,
                                      x->format.name_and_value + k + 1,
                                      read_le64(&x->format.header.size) - offsetof(CaFormatXAttr, name_and_value) - k - 1, 0) < 0)
                                return -errno;

                        x = x->next;
                }

                /* FIXME: remove existing, unlisted xattrs */
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
                        nsec_to_timespec(le64toh(child->entry->mtime)),
                };

                if (child->fd >= 0)
                        r = futimens(child->fd, ts);
                else {
                        if (!n)
                                return -EINVAL;

                        r = utimensat(n->fd, child->name, ts, AT_SYMLINK_NOFOLLOW);
                }
                if (r < 0)
                        return -errno;
        }

        if ((d->feature_flags & CA_FORMAT_WITH_CHATTR) != 0) {
                unsigned new_attr, old_attr;
                int cfd;

                new_attr = ca_feature_flags_to_chattr(le64toh(child->entry->flags) & d->feature_flags);

                if (child->fd >= 0)
                        cfd = child->fd;
                else {
                        if (!n)
                                return -EINVAL;

                        cfd = openat(n->fd, child->name, O_CLOEXEC|O_NOFOLLOW|O_PATH);
                        if (cfd < 0)
                                return -errno;
                }

                if (ioctl(cfd, FS_IOC_GETFLAGS, &old_attr) < 0) {

                        if (new_attr != 0 || !IN_SET(errno, ENOTTY, EBADF, EOPNOTSUPP)) {

                                if (cfd != child->fd)
                                        safe_close(cfd);

                                return -errno;
                        }

                } else if (old_attr != new_attr) {

                        if (ioctl(cfd, FS_IOC_SETFLAGS, &new_attr) < 0) {

                                if (cfd != child->fd)
                                        safe_close(cfd);

                                return -errno;
                        }
                }

                if (cfd != child->fd)
                        safe_close(cfd);
        }

        if ((d->feature_flags & CA_FORMAT_WITH_FAT_ATTRS) != 0 && child->fd >= 0) {
                uint32_t new_attr;

                new_attr = ca_feature_flags_to_fat_attrs(le64toh(child->entry->flags) & d->feature_flags);

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
                return ca_decoder_parse_entry(d, n);

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

                return ca_decoder_parse_filename(d);

        case CA_DECODER_GOODBYE:
                ca_decoder_enter_state(d, CA_DECODER_EOF);
                return CA_DECODER_FINISHED;

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
        r = ca_decoder_finalize_child(d, NULL, n);
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

        if (d->state != CA_DECODER_INIT)
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
