#ifndef foocaformathfoo
#define foocaformathfoo

#include <inttypes.h>

#include "util.h"
#include "cachunkid.h"

enum {
        /* The archive file format */
        CA_FORMAT_HELLO   = UINT64_C(0x3bdd0b541f4b4d71),
        CA_FORMAT_ENTRY   = UINT64_C(0x1396fabcea5bbb51),
        CA_FORMAT_USER    = UINT64_C(0xf453131aaeeaccb3),
        CA_FORMAT_GROUP   = UINT64_C(0x25eb6ac969396a52),
        CA_FORMAT_SYMLINK = UINT64_C(0x664a6fb6830e0d6c),
        CA_FORMAT_DEVICE  = UINT64_C(0xac3dace369dfe643),
        CA_FORMAT_PAYLOAD = UINT64_C(0x8b9e1d93d6dcffc9),
        CA_FORMAT_GOODBYE = UINT64_C(0xdfd35c5e8327c403),

        /* The index file format */
        CA_FORMAT_INDEX   = UINT64_C(0x96824d9c7b129ff9),
        CA_FORMAT_TABLE   = UINT64_C(0xe75b9e112f17417d),
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
        /* CA_FORMAT_WITH_FLAG_HIDDEN       = 0x2000, */
        /* CA_FORMAT_WITH_FLAG_SYSTEM       = 0x4000, */
        /* CA_FORMAT_WITH_FLAG_ARCHIVE      = 0x8000, */

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
        /* CA_FORMAT_WITH_FLAG_SUBVOLUME    = 0x4000000, */
        /* CA_FORMAT_WITH_FLAG_SUBVOLUME_RO = 0x8000000, */

        /* Extended Attribute metadata */
        /* CA_FORMAT_WITH_XATTR             = 0x10000000, */
        /* CA_FORMAT_WITH_ACL               = 0x20000000, */
        /* CA_FORMAT_WITH_SELINUX           = 0x40000000, */
        /* CA_FORMAT_WITH_FCAPS             = 0x80000000, */

        CA_FORMAT_RESPECT_FLAG_NODUMP    =  UINT64_C(0x8000000000000000),

        CA_FORMAT_WITH_BEST =
                CA_FORMAT_WITH_32BIT_UIDS|
                CA_FORMAT_WITH_USER_NAMES|
                CA_FORMAT_WITH_NSEC_TIME|
                CA_FORMAT_WITH_PERMISSIONS|
                CA_FORMAT_WITH_SYMLINKS|
                CA_FORMAT_WITH_DEVICE_NODES|
                CA_FORMAT_WITH_FIFOS|
                CA_FORMAT_WITH_SOCKETS|
                /* CA_FORMAT_WITH_FLAG_HIDDEN| */
                /* CA_FORMAT_WITH_FLAG_SYSTEM| */
                /* CA_FORMAT_WITH_FLAG_ARCHIVE| */
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
                /* CA_FORMAT_WITH_FLAG_SUBVOLUME| */
                /* CA_FORMAT_WITH_FLAG_SUBVOLUME_RO| */
                /* CA_FORMAT_WITH_XATTR| */
                /* CA_FORMAT_WITH_ACL| */
                /* CA_FORMAT_WITH_SELINUX| */
                /* CA_FORMAT_WITH_FCAPS */

        CA_FORMAT_WITH_UNIX = /* Conservative UNIX file properties */
                CA_FORMAT_WITH_16BIT_UIDS|
                CA_FORMAT_WITH_SEC_TIME|
                CA_FORMAT_WITH_SYMLINKS|
                CA_FORMAT_WITH_DEVICE_NODES|
                CA_FORMAT_WITH_FIFOS|
                CA_FORMAT_WITH_SOCKETS,

        CA_FORMAT_WITH_FAT = /* FAT file properties */
                CA_FORMAT_WITH_2SEC_TIME|
                CA_FORMAT_WITH_READ_ONLY,
                /* CA_FORMAT_WITH_FLAG_HIDDEN| */
                /* CA_FORMAT_WITH_FLAG_SYSTEM| */
                /* CA_FORMAT_WITH_FLAG_ARCHIVE, */

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

        CA_FORMAT_FEATURE_FLAGS_MAX        = 0xFFFFFFFF | CA_FORMAT_RESPECT_FLAG_NODUMP,
};

typedef struct CaFormatHeader {
        le64_t size;
        le64_t type;
} CaFormatHeader;

typedef struct CaFormatHello {
        CaFormatHeader header;
        le64_t uuid_part2; /* always CA_FORMAT_HELLO_UUID_PART2, see below */
        le64_t feature_flags;
} CaFormatHello;

/* The header's type field together with the uuid_part2 field shall be considered a 128bit UUID */
#define CA_FORMAT_HELLO_UUID_PART2 UINT64_C(0x9a213af1f35eb539)

typedef struct CaFormatEntry {
        CaFormatHeader header;
        le64_t mode;
        le64_t flags;
        le64_t uid;
        le64_t gid;
        le64_t mtime; /* nsec */
        char name[];
} CaFormatEntry;

/* NAME_MAX on Linux is 255 + NUL byte */
#define CA_FORMAT_ENTRY_SIZE_MAX (offsetof(CaFormatEntry, name) + 256)

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

typedef struct CaFormatGoodbye {
        CaFormatHeader header;
        /* entry bisection table here */
        le64_t table[];
        /* Followed by a final le64_t size; */
} CaFormatGoodbye;

/*** The following structures are used by the index files. ***/

typedef struct CaFormatIndex {
        CaFormatHeader header;
        le64_t uuid_part2; /* always CA_FORMAT_INDEX_UUID_PART2, see below */
        le64_t feature_flags;
        le64_t chunk_size_min;
        le64_t chunk_size_avg;
        le64_t chunk_size_max;
} CaFormatIndex;

/* The header's type field together with the uuid_part2 field shall be considered a 128bit UUID */
#define CA_FORMAT_INDEX_UUID_PART2 UINT64_C(0xce85c5466c13d709)

typedef struct CaFormatTableItem {
        le64_t offset;
        uint8_t chunk[CA_CHUNK_ID_SIZE];
} CaFormatTableItem;

typedef struct CaFormatTable {
        CaFormatHeader header;  /* size is set to UINT64_MAX, so that we can put this together incrementally */
        CaFormatTableItem items[];
        /* Followed by UINT64_MAX, as end marker */
        /* Followed by a digest of the whole blob */
        /* Followed by a final le64_t size; */
} CaFormatTable;

#endif
