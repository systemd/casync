#include <linux/fs.h>
#include <linux/msdos_fs.h>

#include "caformat.h"
#include "caformat-util.h"

const char *ca_format_type_name(uint64_t u) {

        switch (u) {

        case CA_FORMAT_ENTRY:
                return "entry";

        case CA_FORMAT_USER:
                return "user";

        case CA_FORMAT_GROUP:
                return "group";

        case CA_FORMAT_XATTR:
                return "xattr";

        case CA_FORMAT_FCAPS:
                return "fcaps";

        case CA_FORMAT_ACL_USER:
                return "acl-user";

        case CA_FORMAT_ACL_GROUP:
                return "acl-group";

        case CA_FORMAT_ACL_GROUP_OBJ:
                return "acl-group-obj";

        case CA_FORMAT_ACL_DEFAULT:
                return "acl-default";

        case CA_FORMAT_ACL_DEFAULT_USER:
                return "acl-default-user";

        case CA_FORMAT_ACL_DEFAULT_GROUP:
                return "acl-default-group";

        case CA_FORMAT_SYMLINK:
                return "symlink";

        case CA_FORMAT_DEVICE:
                return "device";

        case CA_FORMAT_PAYLOAD:
                return "payload";

        case CA_FORMAT_FILENAME:
                return "filename";

        case CA_FORMAT_GOODBYE:
                return "goodbye";

        case CA_FORMAT_INDEX:
                return "index";

        case CA_FORMAT_TABLE:
                return "table";
        }

        return NULL;
}

static const struct {
        const char *name;
        uint64_t feature;
} with_feature_map[] = {
        { "16bit-uids",       CA_FORMAT_WITH_16BIT_UIDS       },
        { "32bit-uids",       CA_FORMAT_WITH_32BIT_UIDS       },
        { "user-names",       CA_FORMAT_WITH_USER_NAMES       },
        { "sec-time",         CA_FORMAT_WITH_SEC_TIME         },
        { "usec-time",        CA_FORMAT_WITH_USEC_TIME        },
        { "nsec-time",        CA_FORMAT_WITH_NSEC_TIME        },
        { "2sec-time",        CA_FORMAT_WITH_2SEC_TIME        },
        { "read-only",        CA_FORMAT_WITH_READ_ONLY        },
        { "permissions",      CA_FORMAT_WITH_PERMISSIONS      },
        { "symlinks",         CA_FORMAT_WITH_SYMLINKS         },
        { "device-nodes",     CA_FORMAT_WITH_DEVICE_NODES     },
        { "fifos",            CA_FORMAT_WITH_FIFOS            },
        { "sockets",          CA_FORMAT_WITH_SOCKETS          },
        { "flag-hidden",      CA_FORMAT_WITH_FLAG_HIDDEN      },
        { "flag-system",      CA_FORMAT_WITH_FLAG_SYSTEM      },
        { "flag-archive",     CA_FORMAT_WITH_FLAG_ARCHIVE     },
        { "flag-append",      CA_FORMAT_WITH_FLAG_APPEND      },
        { "flag-noatime",     CA_FORMAT_WITH_FLAG_NOATIME     },
        { "flag-compr",       CA_FORMAT_WITH_FLAG_COMPR       },
        { "flag-nocow",       CA_FORMAT_WITH_FLAG_NOCOW       },
        { "flag-nodump",      CA_FORMAT_WITH_FLAG_NODUMP      },
        { "flag-dirsync",     CA_FORMAT_WITH_FLAG_DIRSYNC     },
        { "flag-immutable",   CA_FORMAT_WITH_FLAG_IMMUTABLE   },
        { "flag-sync",        CA_FORMAT_WITH_FLAG_SYNC        },
        { "flag-nocomp",      CA_FORMAT_WITH_FLAG_NOCOMP      },
        { "flag-projinherit", CA_FORMAT_WITH_FLAG_PROJINHERIT },
        { "flag-subvolume",   CA_FORMAT_WITH_SUBVOLUME        },
        { "flag-subvolume-ro",CA_FORMAT_WITH_SUBVOLUME_RO     },
        { "xattrs",           CA_FORMAT_WITH_XATTRS           },
        { "acl",              CA_FORMAT_WITH_ACL              },
        { "fcaps",            CA_FORMAT_WITH_FCAPS            },
        { "best",             CA_FORMAT_WITH_BEST             },
        { "unix",             CA_FORMAT_WITH_UNIX             },
        { "fat",              CA_FORMAT_WITH_FAT              },
        { "chattr",           CA_FORMAT_WITH_CHATTR           },
        { "fat-attrs",        CA_FORMAT_WITH_FAT_ATTRS        },
        { "privileged",       CA_FORMAT_WITH_PRIVILEGED       },
        { "fuse",             CA_FORMAT_WITH_FUSE             },
};

int ca_with_feature_flags_parse_one(const char *name, uint64_t *ret) {
        size_t i;

        for (i = 0; i < ELEMENTSOF(with_feature_map); i++)
                if (streq(with_feature_map[i].name, name)) {
                        *ret = with_feature_map[i].feature;
                        return 0;
                }

        return -ENXIO;
}

int ca_with_feature_flags_format(uint64_t features, char **ret) {
        char *s = NULL;
        size_t i;

        for (i = 0; i < ELEMENTSOF(with_feature_map); i++) {
                uint64_t f;

                if (features == 0)
                        break;

                f = with_feature_map[i].feature;

                if ((features & f) != f)
                        continue;

                if (!strextend(&s, s ? " " : "", with_feature_map[i].name, NULL)) {
                        free(s);
                        return -ENOMEM;
                }

                features &= ~f;
        }

        if ((features & ~(CA_FORMAT_EXCLUDE_NODUMP|CA_FORMAT_EXCLUDE_SUBMOUNTS|CA_FORMAT_SHA512_256)) != 0) {
                free(s);
                return -EINVAL;
        }

        *ret = s;
        return 0;
}

int ca_feature_flags_normalize(uint64_t flags, uint64_t *ret) {
        if (!ret)
                return -EINVAL;

        /* This normalizes the specified flags value, i.e. drops redundant bits, so that the resulting flags field has
         * the minimum number of bits that express the feature set set. */

        if (flags == UINT64_MAX)
                return -EINVAL;
        if ((flags & ~CA_FORMAT_FEATURE_FLAGS_MAX) != 0)
                return -EOPNOTSUPP;

        if ((flags & CA_FORMAT_WITH_ACL) &&
            (flags & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS|CA_FORMAT_WITH_USER_NAMES)) == 0)
                flags |= CA_FORMAT_WITH_32BIT_UIDS|CA_FORMAT_WITH_USER_NAMES;

        if (flags & CA_FORMAT_WITH_32BIT_UIDS)
                flags &= ~CA_FORMAT_WITH_16BIT_UIDS;

        if (flags & CA_FORMAT_WITH_NSEC_TIME)
                flags &= ~(CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_2SEC_TIME);
        if (flags & CA_FORMAT_WITH_USEC_TIME)
                flags &= ~(CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_2SEC_TIME);
        if (flags & CA_FORMAT_WITH_SEC_TIME)
                flags &= ~CA_FORMAT_WITH_2SEC_TIME;

        if (flags & CA_FORMAT_WITH_ACL)
                flags &= ~(CA_FORMAT_WITH_PERMISSIONS|CA_FORMAT_WITH_READ_ONLY);
        if (flags & CA_FORMAT_WITH_PERMISSIONS)
                flags &= ~CA_FORMAT_WITH_READ_ONLY;

        if (flags & CA_FORMAT_EXCLUDE_NODUMP)
                flags &= ~CA_FORMAT_WITH_FLAG_NODUMP;

        if (flags & CA_FORMAT_WITH_SUBVOLUME_RO)
                flags |= CA_FORMAT_WITH_SUBVOLUME;

        *ret = flags;
        return 0;
}

int ca_feature_flags_are_normalized(uint64_t flags) {

        if (flags == UINT64_MAX)
                return -EINVAL;

        if ((flags & ~CA_FORMAT_FEATURE_FLAGS_MAX) != 0)
                return -EOPNOTSUPP;

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

        if ((flags & CA_FORMAT_EXCLUDE_NODUMP) &&
            (flags & CA_FORMAT_WITH_FLAG_NODUMP))
                return false;

        if ((flags & CA_FORMAT_WITH_SUBVOLUME_RO) &&
            !(flags & CA_FORMAT_WITH_SUBVOLUME))
                return false;

        return true;
}

int ca_feature_flags_normalize_mask(uint64_t mask, uint64_t *ret) {
        if (!ret)
                return -EINVAL;

        /* This normalizes the specified flags parameter, so that all redundant bits that could be set are set. */

        if (mask == UINT64_MAX) {
                *ret = UINT64_MAX;
                return 0;
        }

        mask &= CA_FORMAT_FEATURE_FLAGS_MAX;

        if (mask & (CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS))
                mask |= CA_FORMAT_WITH_16BIT_UIDS|CA_FORMAT_WITH_32BIT_UIDS;
        if (mask & (CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_NSEC_TIME|CA_FORMAT_WITH_2SEC_TIME))
                mask |= CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_NSEC_TIME|CA_FORMAT_WITH_2SEC_TIME;
        if (mask & CA_FORMAT_WITH_PERMISSIONS)
                mask |= CA_FORMAT_WITH_READ_ONLY;
        if (mask & CA_FORMAT_WITH_ACL)
                mask |= CA_FORMAT_WITH_PERMISSIONS|CA_FORMAT_WITH_READ_ONLY;
        if (mask & CA_FORMAT_WITH_SUBVOLUME_RO)
                mask |= CA_FORMAT_WITH_SUBVOLUME;

        *ret = mask;
        return 0;
}

int ca_feature_flags_time_granularity_nsec(uint64_t flags, uint64_t *ret) {
        uint64_t granularity;

        if ((flags & ~CA_FORMAT_FEATURE_FLAGS_MAX) != 0)
                return -EOPNOTSUPP;
        if (!ret)
                return -EINVAL;

        if (flags & CA_FORMAT_WITH_NSEC_TIME)
                granularity = 1;
        else if (flags & CA_FORMAT_WITH_USEC_TIME)
                granularity = 1000;
        else if (flags & CA_FORMAT_WITH_SEC_TIME)
                granularity = 1000000000;
        else if (flags & CA_FORMAT_WITH_2SEC_TIME)
                granularity = 2000000000;
        else
                return -ENODATA;

        *ret = granularity;
        return 0;
}

static const struct {
        uint64_t feature_flag;
        unsigned chattr_flag;
} chattr_map[] = {
        { CA_FORMAT_WITH_FLAG_APPEND,      FS_APPEND_FL      },
        { CA_FORMAT_WITH_FLAG_NOATIME,     FS_NOATIME_FL     },
        { CA_FORMAT_WITH_FLAG_COMPR,       FS_COMPR_FL       },
        { CA_FORMAT_WITH_FLAG_NOCOW,       FS_NOCOW_FL       },
        { CA_FORMAT_WITH_FLAG_NODUMP,      FS_NODUMP_FL      },
        { CA_FORMAT_WITH_FLAG_DIRSYNC,     FS_DIRSYNC_FL     },
        { CA_FORMAT_WITH_FLAG_IMMUTABLE,   FS_IMMUTABLE_FL   },
        { CA_FORMAT_WITH_FLAG_SYNC,        FS_SYNC_FL        },
        { CA_FORMAT_WITH_FLAG_NOCOMP,      FS_NOCOMP_FL      },
        { CA_FORMAT_WITH_FLAG_PROJINHERIT, FS_PROJINHERIT_FL },
};

uint64_t ca_feature_flags_from_chattr(unsigned flags) {
        uint64_t f = 0;
        size_t i;

        for (i = 0; i < ELEMENTSOF(chattr_map); i++)
                if (flags & chattr_map[i].chattr_flag)
                        f |= chattr_map[i].feature_flag;

        return f;
}

unsigned ca_feature_flags_to_chattr(uint64_t flags) {
        unsigned f = 0;
        size_t i;

        for (i = 0; i < ELEMENTSOF(chattr_map); i++) {
                if (flags & chattr_map[i].feature_flag)
                        f |= chattr_map[i].chattr_flag;
        }

        return f;
}

static const struct {
        uint64_t feature_flag;
        uint32_t fat_flag;
} fat_attrs_map[] = {
        { CA_FORMAT_WITH_FLAG_HIDDEN,  ATTR_HIDDEN },
        { CA_FORMAT_WITH_FLAG_SYSTEM,  ATTR_SYS    },
        { CA_FORMAT_WITH_FLAG_ARCHIVE, ATTR_ARCH   },
};

uint64_t ca_feature_flags_from_fat_attrs(uint32_t flags) {
        uint64_t f = 0;
        size_t i;

        for (i = 0; i < ELEMENTSOF(fat_attrs_map); i++)
                if (flags & fat_attrs_map[i].fat_flag)
                        f |= fat_attrs_map[i].feature_flag;

        return f;
}

uint32_t ca_feature_flags_to_fat_attrs(uint64_t flags) {
        uint32_t f = 0;
        size_t i;

        for (i = 0; i < ELEMENTSOF(fat_attrs_map); i++) {
                if (flags & fat_attrs_map[i].feature_flag)
                        f |= fat_attrs_map[i].fat_flag;
        }

        return f;
}

uint64_t ca_feature_flags_from_magic(statfs_f_type_t magic) {

        /* Returns the set of features we know a specific file system type provides. Ideally the kernel would let us
         * know this, but this is Linux and hence we have crappy interfaces. */

        switch (magic) {

        case MSDOS_SUPER_MAGIC:
                return
                        CA_FORMAT_WITH_2SEC_TIME|
                        CA_FORMAT_WITH_READ_ONLY|
                        CA_FORMAT_WITH_FLAG_HIDDEN|
                        CA_FORMAT_WITH_FLAG_SYSTEM|
                        CA_FORMAT_WITH_FLAG_ARCHIVE;

        case EXT2_SUPER_MAGIC:
                return
                        CA_FORMAT_WITH_16BIT_UIDS|
                        CA_FORMAT_WITH_32BIT_UIDS|
                        CA_FORMAT_WITH_USER_NAMES|
                        CA_FORMAT_WITH_SEC_TIME|
                        CA_FORMAT_WITH_USEC_TIME|
                        CA_FORMAT_WITH_NSEC_TIME|
                        CA_FORMAT_WITH_2SEC_TIME|
                        CA_FORMAT_WITH_READ_ONLY|
                        CA_FORMAT_WITH_PERMISSIONS|
                        CA_FORMAT_WITH_SYMLINKS|
                        CA_FORMAT_WITH_DEVICE_NODES|
                        CA_FORMAT_WITH_FIFOS|
                        CA_FORMAT_WITH_SOCKETS|
                        CA_FORMAT_WITH_FLAG_APPEND|
                        CA_FORMAT_WITH_FLAG_NOATIME|
                        CA_FORMAT_WITH_FLAG_NODUMP|
                        CA_FORMAT_WITH_FLAG_DIRSYNC|
                        CA_FORMAT_WITH_FLAG_IMMUTABLE|
                        CA_FORMAT_WITH_FLAG_SYNC|
                        CA_FORMAT_WITH_XATTRS|
                        CA_FORMAT_WITH_ACL|
                        CA_FORMAT_WITH_FCAPS;

        case XFS_SUPER_MAGIC:
                return
                        CA_FORMAT_WITH_16BIT_UIDS|
                        CA_FORMAT_WITH_32BIT_UIDS|
                        CA_FORMAT_WITH_USER_NAMES|
                        CA_FORMAT_WITH_SEC_TIME|
                        CA_FORMAT_WITH_USEC_TIME|
                        CA_FORMAT_WITH_NSEC_TIME|
                        CA_FORMAT_WITH_2SEC_TIME|
                        CA_FORMAT_WITH_READ_ONLY|
                        CA_FORMAT_WITH_PERMISSIONS|
                        CA_FORMAT_WITH_SYMLINKS|
                        CA_FORMAT_WITH_DEVICE_NODES|
                        CA_FORMAT_WITH_FIFOS|
                        CA_FORMAT_WITH_SOCKETS|
                        CA_FORMAT_WITH_FLAG_APPEND|
                        CA_FORMAT_WITH_FLAG_NOATIME|
                        CA_FORMAT_WITH_FLAG_NODUMP|
                        CA_FORMAT_WITH_FLAG_IMMUTABLE|
                        CA_FORMAT_WITH_FLAG_SYNC|
                        CA_FORMAT_WITH_XATTRS|
                        CA_FORMAT_WITH_ACL|
                        CA_FORMAT_WITH_FCAPS;

        case BTRFS_SUPER_MAGIC:
                return
                        CA_FORMAT_WITH_16BIT_UIDS|
                        CA_FORMAT_WITH_32BIT_UIDS|
                        CA_FORMAT_WITH_USER_NAMES|
                        CA_FORMAT_WITH_SEC_TIME|
                        CA_FORMAT_WITH_USEC_TIME|
                        CA_FORMAT_WITH_NSEC_TIME|
                        CA_FORMAT_WITH_2SEC_TIME|
                        CA_FORMAT_WITH_READ_ONLY|
                        CA_FORMAT_WITH_PERMISSIONS|
                        CA_FORMAT_WITH_SYMLINKS|
                        CA_FORMAT_WITH_DEVICE_NODES|
                        CA_FORMAT_WITH_FIFOS|
                        CA_FORMAT_WITH_SOCKETS|
                        CA_FORMAT_WITH_FLAG_APPEND|
                        CA_FORMAT_WITH_FLAG_NOATIME|
                        CA_FORMAT_WITH_FLAG_COMPR|
                        CA_FORMAT_WITH_FLAG_NOCOW|
                        CA_FORMAT_WITH_FLAG_NODUMP|
                        CA_FORMAT_WITH_FLAG_DIRSYNC|
                        CA_FORMAT_WITH_FLAG_IMMUTABLE|
                        CA_FORMAT_WITH_FLAG_SYNC|
                        CA_FORMAT_WITH_FLAG_NOCOMP|
                        CA_FORMAT_WITH_XATTRS|
                        CA_FORMAT_WITH_ACL|
                        CA_FORMAT_WITH_SUBVOLUME|
                        CA_FORMAT_WITH_SUBVOLUME_RO|
                        CA_FORMAT_WITH_FCAPS;

        case TMPFS_MAGIC:
                return
                        CA_FORMAT_WITH_16BIT_UIDS|
                        CA_FORMAT_WITH_32BIT_UIDS|
                        CA_FORMAT_WITH_USER_NAMES|
                        CA_FORMAT_WITH_SEC_TIME|
                        CA_FORMAT_WITH_USEC_TIME|
                        CA_FORMAT_WITH_NSEC_TIME|
                        CA_FORMAT_WITH_2SEC_TIME|
                        CA_FORMAT_WITH_READ_ONLY|
                        CA_FORMAT_WITH_PERMISSIONS|
                        CA_FORMAT_WITH_SYMLINKS|
                        CA_FORMAT_WITH_DEVICE_NODES|
                        CA_FORMAT_WITH_FIFOS|
                        CA_FORMAT_WITH_SOCKETS|
                        CA_FORMAT_WITH_ACL;

        case FUSE_SUPER_MAGIC:
                /* We don't actually know what the backing FUSE file system supports, but it's likely more limited than
                 * what we support ourselves, hence use that.*/
                return CA_FORMAT_WITH_FUSE;

        default:
                return
                        CA_FORMAT_WITH_16BIT_UIDS|
                        CA_FORMAT_WITH_32BIT_UIDS|
                        CA_FORMAT_WITH_USER_NAMES|
                        CA_FORMAT_WITH_SEC_TIME|
                        CA_FORMAT_WITH_USEC_TIME|
                        CA_FORMAT_WITH_NSEC_TIME|
                        CA_FORMAT_WITH_2SEC_TIME|
                        CA_FORMAT_WITH_READ_ONLY|
                        CA_FORMAT_WITH_PERMISSIONS|
                        CA_FORMAT_WITH_SYMLINKS|
                        CA_FORMAT_WITH_DEVICE_NODES|
                        CA_FORMAT_WITH_FIFOS|
                        CA_FORMAT_WITH_SOCKETS;
        }
}

uint64_t ca_feature_flags_from_digest_type(CaDigestType type) {

        switch (type) {

        case CA_DIGEST_SHA256:
                return 0;

        case CA_DIGEST_SHA512_256:
                return CA_FORMAT_SHA512_256;

        default:
                return UINT64_MAX;
        }
}

CaDigestType ca_feature_flags_to_digest_type(uint64_t flags) {

        if (flags & CA_FORMAT_SHA512_256)
                return CA_DIGEST_SHA512_256;
        else
                return CA_DIGEST_SHA256;
}
