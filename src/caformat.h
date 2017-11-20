/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocaformathfoo
#define foocaformathfoo

#include <inttypes.h>
#include <stddef.h>

#include "cachunkid.h"
#include "util.h"

/* The format is like this: every archive begins items in the following order:
 *
 * ENTRY             -- containing general stat() data and related bits
 * USER              -- user name as text, if enabled
 * GROUP             -- group name as text, if enabled
 * XATTR             -- one extended attribute
 * ..                -- more of these when there are multiple defined
 * ACL_USER          -- one USER ACL entry
 * ...               -- more of these when there are multiple defined
 * ACL_GROUP         -- one GROUP ACL entry
 * ...               -- more of these when there are multiple defined
 * ACL_GROUP_OBJ     -- The ACL_GROUP_OBJ
 * ACL_DEFAULT       -- The various default ACL fields if there's one defined
 * ACL_DEFAULT_USER  -- one USER ACL entry
 * ...               -- more of these when multiple are defined
 * ACL_DEFAULT_GROUP -- one GROUP ACL entry
 * ...               -- more of these when multiple are defined
 * FCAPS             -- file capability in Linux disk format
 * PAYLOAD           -- file contents, if it is one
 * SYMLINK           -- symlink target, if it is one
 * DEVICE            -- device major/minor, if it is a block/char device
 *
 * If we are serializing a directory, then this is followed by:
 *
 * FILENAME          -- name of the first directory entry (strictly ordered!)
 * <archive>         -- serialization of the first directory entry's metadata and contents,
 *                      following the exact same archive format
 * FILENAME          -- name of the second directory entry (strictly ordered!)
 * <archive>         -- serialization of the second directory entry
 * …
 * GOODBYE           -- lookup table at the end of a list of directory entries
 *
 * And that's already it.
 *
 */

enum {
        /* The archive file format */
        CA_FORMAT_ENTRY                 = UINT64_C(0x1396fabcea5bbb51),
        CA_FORMAT_USER                  = UINT64_C(0xf453131aaeeaccb3),
        CA_FORMAT_GROUP                 = UINT64_C(0x25eb6ac969396a52),
        CA_FORMAT_XATTR                 = UINT64_C(0xb8157091f80bc486),
        CA_FORMAT_ACL_USER              = UINT64_C(0x297dc88b2ef12faf),
        CA_FORMAT_ACL_GROUP             = UINT64_C(0x36f2acb56cb3dd0b),
        CA_FORMAT_ACL_GROUP_OBJ         = UINT64_C(0x23047110441f38f3),
        CA_FORMAT_ACL_DEFAULT           = UINT64_C(0xfe3eeda6823c8cd0),
        CA_FORMAT_ACL_DEFAULT_USER      = UINT64_C(0xbdf03df9bd010a91),
        CA_FORMAT_ACL_DEFAULT_GROUP     = UINT64_C(0xa0cb1168782d1f51),
        CA_FORMAT_FCAPS                 = UINT64_C(0xf7267db0afed0629),
        CA_FORMAT_SELINUX               = UINT64_C(0x46faf0602fd26c59),
        CA_FORMAT_SYMLINK               = UINT64_C(0x664a6fb6830e0d6c),
        CA_FORMAT_DEVICE                = UINT64_C(0xac3dace369dfe643),
        CA_FORMAT_PAYLOAD               = UINT64_C(0x8b9e1d93d6dcffc9),
        CA_FORMAT_FILENAME              = UINT64_C(0x6dbb6ebcb3161f0b),
        CA_FORMAT_GOODBYE               = UINT64_C(0xdfd35c5e8327c403),

        /* The end marker used in the GOODBYE object */
        CA_FORMAT_GOODBYE_TAIL_MARKER   = UINT64_C(0x57446fa533702943),

        /* The index file format */
        CA_FORMAT_INDEX                 = UINT64_C(0x96824d9c7b129ff9),
        CA_FORMAT_TABLE                 = UINT64_C(0xe75b9e112f17417d),

        /* The end marker used in the TABLE object */
        CA_FORMAT_TABLE_TAIL_MARKER     = UINT64_C(0x4b4f050e5549ecd1),
};

/* Feature flags */
enum {
        CA_FORMAT_WITH_16BIT_UIDS        = 0x1,
        CA_FORMAT_WITH_32BIT_UIDS        = 0x2,
        CA_FORMAT_WITH_USER_NAMES        = 0x4,
        CA_FORMAT_WITH_SEC_TIME          = 0x8,
        CA_FORMAT_WITH_USEC_TIME         = 0x10,
        CA_FORMAT_WITH_NSEC_TIME         = 0x20,
        CA_FORMAT_WITH_2SEC_TIME         = 0x40, /* FAT-style 2s time granularity */
        CA_FORMAT_WITH_READ_ONLY         = 0x80,
        CA_FORMAT_WITH_PERMISSIONS       = 0x100,
        CA_FORMAT_WITH_SYMLINKS          = 0x200,
        CA_FORMAT_WITH_DEVICE_NODES      = 0x400,
        CA_FORMAT_WITH_FIFOS             = 0x800,
        CA_FORMAT_WITH_SOCKETS           = 0x1000,

        /* DOS file flags */
        CA_FORMAT_WITH_FLAG_HIDDEN       = 0x2000,
        CA_FORMAT_WITH_FLAG_SYSTEM       = 0x4000,
        CA_FORMAT_WITH_FLAG_ARCHIVE      = 0x8000,

        /* chattr() flags */
        CA_FORMAT_WITH_FLAG_APPEND       = 0x10000,
        CA_FORMAT_WITH_FLAG_NOATIME      = 0x20000,
        CA_FORMAT_WITH_FLAG_COMPR        = 0x40000,
        CA_FORMAT_WITH_FLAG_NOCOW        = 0x80000,
        CA_FORMAT_WITH_FLAG_NODUMP       = 0x100000,
        CA_FORMAT_WITH_FLAG_DIRSYNC      = 0x200000,
        CA_FORMAT_WITH_FLAG_IMMUTABLE    = 0x400000,
        CA_FORMAT_WITH_FLAG_SYNC         = 0x800000,
        CA_FORMAT_WITH_FLAG_NOCOMP       = 0x1000000,
        CA_FORMAT_WITH_FLAG_PROJINHERIT  = 0x2000000,

        /* btrfs magic */
        CA_FORMAT_WITH_SUBVOLUME         = 0x4000000,
        CA_FORMAT_WITH_SUBVOLUME_RO      = 0x8000000,

        /* Extended Attribute metadata */
        CA_FORMAT_WITH_XATTRS            = 0x10000000,
        CA_FORMAT_WITH_ACL               = 0x20000000,
        CA_FORMAT_WITH_SELINUX           = 0x40000000,
        CA_FORMAT_WITH_FCAPS             = 0x80000000,

        CA_FORMAT_SHA512_256             = UINT64_C(0x2000000000000000),
        CA_FORMAT_EXCLUDE_SUBMOUNTS      = UINT64_C(0x4000000000000000),
        CA_FORMAT_EXCLUDE_NODUMP         = UINT64_C(0x8000000000000000),

        CA_FORMAT_WITH_BEST =
                CA_FORMAT_WITH_32BIT_UIDS|
                CA_FORMAT_WITH_USER_NAMES|
                CA_FORMAT_WITH_NSEC_TIME|
                CA_FORMAT_WITH_SYMLINKS|
                CA_FORMAT_WITH_DEVICE_NODES|
                CA_FORMAT_WITH_FIFOS|
                CA_FORMAT_WITH_SOCKETS|
                CA_FORMAT_WITH_FLAG_HIDDEN|
                CA_FORMAT_WITH_FLAG_SYSTEM|
                CA_FORMAT_WITH_FLAG_ARCHIVE|
                CA_FORMAT_WITH_FLAG_APPEND|
                CA_FORMAT_WITH_FLAG_NOATIME|
                CA_FORMAT_WITH_FLAG_COMPR|
                CA_FORMAT_WITH_FLAG_NOCOW|
                CA_FORMAT_WITH_FLAG_NODUMP|
                CA_FORMAT_WITH_FLAG_DIRSYNC|
                CA_FORMAT_WITH_FLAG_IMMUTABLE|
                CA_FORMAT_WITH_FLAG_SYNC|
                CA_FORMAT_WITH_FLAG_NOCOMP|
                CA_FORMAT_WITH_FLAG_PROJINHERIT|
                CA_FORMAT_WITH_SUBVOLUME|
                CA_FORMAT_WITH_SUBVOLUME_RO|
                CA_FORMAT_WITH_XATTRS|
                CA_FORMAT_WITH_ACL|
                CA_FORMAT_WITH_SELINUX|
                CA_FORMAT_WITH_FCAPS,

        CA_FORMAT_WITH_UNIX = /* Conservative UNIX file properties */
                CA_FORMAT_WITH_16BIT_UIDS|
                CA_FORMAT_WITH_PERMISSIONS|
                CA_FORMAT_WITH_SEC_TIME|
                CA_FORMAT_WITH_SYMLINKS|
                CA_FORMAT_WITH_DEVICE_NODES|
                CA_FORMAT_WITH_FIFOS|
                CA_FORMAT_WITH_SOCKETS,

        CA_FORMAT_WITH_FAT = /* FAT file properties */
                CA_FORMAT_WITH_2SEC_TIME|
                CA_FORMAT_WITH_READ_ONLY|
                CA_FORMAT_WITH_FLAG_HIDDEN|
                CA_FORMAT_WITH_FLAG_SYSTEM|
                CA_FORMAT_WITH_FLAG_ARCHIVE,

        CA_FORMAT_WITH_CHATTR = /* All chattr file attributes */
                CA_FORMAT_WITH_FLAG_APPEND|
                CA_FORMAT_WITH_FLAG_NOATIME|
                CA_FORMAT_WITH_FLAG_COMPR|
                CA_FORMAT_WITH_FLAG_NOCOW|
                CA_FORMAT_WITH_FLAG_NODUMP|
                CA_FORMAT_WITH_FLAG_DIRSYNC|
                CA_FORMAT_WITH_FLAG_IMMUTABLE|
                CA_FORMAT_WITH_FLAG_SYNC|
                CA_FORMAT_WITH_FLAG_NOCOMP|
                CA_FORMAT_WITH_FLAG_PROJINHERIT,

        CA_FORMAT_WITH_FAT_ATTRS = /* All FAT file attributes */
                CA_FORMAT_WITH_FLAG_HIDDEN|
                CA_FORMAT_WITH_FLAG_SYSTEM|
                CA_FORMAT_WITH_FLAG_ARCHIVE,

        CA_FORMAT_WITH_PRIVILEGED = /* All bits that may only be restored with privileges */
                CA_FORMAT_WITH_16BIT_UIDS|
                CA_FORMAT_WITH_32BIT_UIDS|
                CA_FORMAT_WITH_USER_NAMES|
                CA_FORMAT_WITH_DEVICE_NODES|
                CA_FORMAT_WITH_FLAG_SYSTEM|
                CA_FORMAT_WITH_FLAG_APPEND|
                CA_FORMAT_WITH_FLAG_IMMUTABLE|
                CA_FORMAT_WITH_SUBVOLUME|
                CA_FORMAT_WITH_SUBVOLUME_RO|
                CA_FORMAT_WITH_ACL|
                CA_FORMAT_WITH_SELINUX|
                CA_FORMAT_WITH_FCAPS,

        CA_FORMAT_WITH_FUSE = /* All bits that may also be exposed via fuse */
                CA_FORMAT_WITH_16BIT_UIDS|
                CA_FORMAT_WITH_32BIT_UIDS|
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
                CA_FORMAT_WITH_FAT_ATTRS|
                CA_FORMAT_WITH_CHATTR|
                CA_FORMAT_WITH_XATTRS,

        CA_FORMAT_WITH_MASK = /* All with bits */
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
                CA_FORMAT_WITH_FLAG_HIDDEN|
                CA_FORMAT_WITH_FLAG_SYSTEM|
                CA_FORMAT_WITH_FLAG_ARCHIVE|
                CA_FORMAT_WITH_FLAG_APPEND|
                CA_FORMAT_WITH_FLAG_NOATIME|
                CA_FORMAT_WITH_FLAG_COMPR|
                CA_FORMAT_WITH_FLAG_NOCOW|
                CA_FORMAT_WITH_FLAG_NODUMP|
                CA_FORMAT_WITH_FLAG_DIRSYNC|
                CA_FORMAT_WITH_FLAG_IMMUTABLE|
                CA_FORMAT_WITH_FLAG_SYNC|
                CA_FORMAT_WITH_FLAG_NOCOMP|
                CA_FORMAT_WITH_FLAG_PROJINHERIT|
                CA_FORMAT_WITH_SUBVOLUME|
                CA_FORMAT_WITH_SUBVOLUME_RO|
                CA_FORMAT_WITH_XATTRS|
                CA_FORMAT_WITH_ACL|
                CA_FORMAT_WITH_SELINUX|
                CA_FORMAT_WITH_FCAPS,

        CA_FORMAT_DEFAULT = /* The default set of flags */
                CA_FORMAT_WITH_BEST|
                CA_FORMAT_EXCLUDE_NODUMP|
                CA_FORMAT_SHA512_256,

        CA_FORMAT_FEATURE_FLAGS_MAX = /* All known bits turned on */
                CA_FORMAT_WITH_MASK|
                CA_FORMAT_EXCLUDE_NODUMP|
                CA_FORMAT_EXCLUDE_SUBMOUNTS|
                CA_FORMAT_SHA512_256,
};

typedef struct CaFormatHeader {
        le64_t size;
        le64_t type;
} CaFormatHeader;

typedef struct CaFormatEntry {
        CaFormatHeader header;
        le64_t feature_flags;
        le64_t mode;
        le64_t flags;
        le64_t uid;
        le64_t gid;
        le64_t mtime; /* nsec */
} CaFormatEntry;

typedef struct CaFormatUser {
        CaFormatHeader header;
        char name[];
} CaFormatUser;

/* LOGIN_NAME_MAX on Linux is 256 (NUL byte already included) */
#define CA_FORMAT_USER_SIZE_MAX (offsetof(CaFormatUser, name) + 256)

typedef struct CaFormatGroup {
        CaFormatHeader header;
        char name[];
} CaFormatGroup;

#define CA_FORMAT_GROUP_SIZE_MAX (offsetof(CaFormatGroup, name) + 256)

typedef struct CaFormatXAttr {
        CaFormatHeader header;
        uint8_t name_and_value[]; /* a 0 char terminates the name, the value begins after that */
} CaFormatXAttr;

#define CA_FORMAT_XATTR_SIZE_MAX (offsetof(CaFormatXAttr, name_and_value) + 255 + 1 + (64 * 1024))

typedef struct CaFormatFCaps {
        CaFormatHeader header;
        uint8_t data[]; /* struct vfs_cap_data, in any of the supported sizes */
} CaFormatFCaps;

#define CA_FORMAT_FCAPS_SIZE_MAX (offsetof(CaFormatFCaps, data) + (64*1024))

#define CA_FORMAT_ACL_PERMISSION_READ 4
#define CA_FORMAT_ACL_PERMISSION_WRITE 2
#define CA_FORMAT_ACL_PERMISSION_EXECUTE 1

typedef struct CaFormatACLUser {
        CaFormatHeader header;
        le64_t uid;
        le64_t permissions;
        char name[];
} CaFormatACLUser;

#define CA_FORMAT_ACL_USER_SIZE_MAX (offsetof(CaFormatACLUser, name) + 256)

typedef struct CaFormatACLGroup {
        CaFormatHeader header;
        le64_t gid;
        le64_t permissions;
        char name[];
} CaFormatACLGroup;

#define CA_FORMAT_ACL_GROUP_SIZE_MAX (offsetof(CaFormatACLGroup, name) + 256)

typedef struct CaFormatACLGroupObj {
        CaFormatHeader header;
        le64_t permissions;
} CaFormatACLGroupObj;

typedef struct CaFormatACLDefault {
        CaFormatHeader header;
        le64_t user_obj_permissions;
        le64_t group_obj_permissions;
        le64_t other_permissions;
        le64_t mask_permissions;
} CaFormatACLDefault;

typedef struct CaFormatSELinux {
        CaFormatHeader header;
        char label[];
} CaFormatSELinux;

/* The kernel appears to permit one page max */
#define CA_FORMAT_SELINUX_SIZE_MAX (offsetof(CaFormatSELinux, label) + 4096)

typedef struct CaFormatSymlink {
        CaFormatHeader header;
        char target[];
} CaFormatSymlink;

/* PATH_MAX on Linux is 4096 (NUL byte already included) */
#define CA_FORMAT_SYMLINK_SIZE_MAX (offsetof(CaFormatSymlink, target) + 4096)

typedef struct CaFormatPayload {
        CaFormatHeader header;
        uint8_t data[];
} CaFormatPayload;

typedef struct CaFormatDevice {
        CaFormatHeader header;
        uint64_t major;
        uint64_t minor;
} CaFormatDevice;

typedef struct CaFormatFilename {
        CaFormatHeader header;
        char name[];
} CaFormatFilename;

/* NAME_MAX on Linux is 255 + NUL byte */
#define CA_FORMAT_FILENAME_SIZE_MAX (offsetof(CaFormatFilename, name) + 256)

typedef struct CaFormatGoodbyeItem {
        le64_t offset;
        le64_t size;
        le64_t hash;
} CaFormatGoodbyeItem;

typedef struct CaFormatGoodbyeTail {
        le64_t entry_offset; /* The offset from the start of the GOODBYE object to the start of the matching ENTRY object */
        le64_t size;         /* Size of GOODBYE object, a second time */
        le64_t marker;       /* CA_FORMAT_GOODBYE_TAIL_MARKER */
} CaFormatGoodbyeTail;

typedef struct CaFormatGoodbye {
        CaFormatHeader header;
        CaFormatGoodbyeItem items[];
        /* Followed by one CaFormatGoodbyeTail */
} CaFormatGoodbye;

#define CA_FORMAT_GOODBYE_HASH_KEY          \
        {                                   \
                0xb3U, 0x84U, 0x1dU, 0x0fU, \
                0x2bU, 0x44U, 0x74U, 0x85U, \
                0xc1U, 0x2eU, 0xc2U, 0xd1U, \
                0x30U, 0xedU, 0x36U, 0x27U, \
        }

/*** The following structures are used by the index files. ***/

typedef struct CaFormatIndex {
        CaFormatHeader header;
        le64_t feature_flags;
        le64_t chunk_size_min;
        le64_t chunk_size_avg;
        le64_t chunk_size_max;
} CaFormatIndex;

typedef struct CaFormatTableItem {
        le64_t offset;
        uint8_t chunk[CA_CHUNK_ID_SIZE];
} CaFormatTableItem;

typedef struct CaFormatTableTail {
        le64_t _zero_fill1;  /* Some extra space, to make sure CaFormatTableItem and CaFormatTableTail have the same size */
        le64_t _zero_fill2;
        le64_t index_offset; /* the offset from the start of the TABLE object to the start of the matching INDEX object */
        le64_t size;         /* the TABLE object size, a second time */
        le64_t marker;       /* CA_FORMAT_TABLE_TAIL_MARKER */
} CaFormatTableTail;

typedef struct CaFormatTable {
        CaFormatHeader header;  /* size is set to UINT64_MAX, so that we can put this together incrementally */
        CaFormatTableItem items[];
        /* Followed by one CaFormatTableTail */
} CaFormatTable;

#endif
