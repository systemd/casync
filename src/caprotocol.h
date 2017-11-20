/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocaprotocolhfoo
#define foocaprotocolhfoo

#include <inttypes.h>

#include "util.h"
#include "cachunkid.h"

enum {
        CA_PROTOCOL_HELLO       = UINT64_C(0x3c71d0948ca5fbee),
        CA_PROTOCOL_INDEX       = UINT64_C(0xb32a91dd2b3e27f8),
        CA_PROTOCOL_INDEX_EOF   = UINT64_C(0x4f0932f1043718f5),
        CA_PROTOCOL_ARCHIVE     = UINT64_C(0x95d6428a69eddcc5),
        CA_PROTOCOL_ARCHIVE_EOF = UINT64_C(0x450bef663f24cbad),
        CA_PROTOCOL_REQUEST     = UINT64_C(0x8ab427e0f89d9210),
        CA_PROTOCOL_CHUNK       = UINT64_C(0x5213dd180a84bc8c),
        CA_PROTOCOL_MISSING     = UINT64_C(0xd010f9fac82b7b6c),
        CA_PROTOCOL_GOODBYE     = UINT64_C(0xad205dbf1a3686c3),
        CA_PROTOCOL_ABORT       = UINT64_C(0xe7d9136b7efea352),
};

/* Protocol description:
 *
 * Client C connects to server:
 *
 * Both C and S immediately send CA_PROTOCOL_HELLO:
 *      C → S: CA_PROTOCOL_HELLO
 *      S → C: CA_PROTOCOL_HELLO
 *
 * On pull:
 *      S → C: CA_PROTOCOL_INDEX
 *      S → C: CA_PROTOCOL_INDEX
 *      …
 *      S → C: CA_PROTOCOL_INDEX
 *      S → C: CA_PROTOCOL_INDEX_EOF
 *
 *      Followed by multiple:
 *      C → S: CA_PROTOCOL_REQUEST
 *      S → C: CA_PROTOCOL_CHUNK
 *
 *      Finshed by:
 *      C → S: CA_PROTOCOL_GOODBYE (optional)
 *
 * On push:
 *      C → S: CA_PROTOCOL_INDEX
 *      C → S: CA_PROTOCOL_INDEX
 *      …
 *      C → S: CA_PROTOCOL_INDEX
 *      C → S: CA_PROTOCOL_INDEX_EOF
 *
 *      Followed by multiple:
 *      S → C: CA_PROTOCOL_REQUEST
 *      C → S: CA_PROTOCOL_CHUNK (or CA_PROTOCOL_MISSING)
 *
 *      Finished by:
 *      S → C: CA_PROTOCOL_GOODBYE
 *
 * When a non-recoverable error occurs, either side can send CA_PROTOCOL_ABORTED with an explanation, and terminate the
 * connection.
 *
 * */

typedef struct CaProtocolHeader {
        le64_t size;
        le64_t type;
} CaProtocolHeader;

#define CA_PROTOCOL_SIZE_MIN (sizeof(CaProtocolHeader))
#define CA_PROTOCOL_SIZE_MAX (16*1024*1024)

typedef struct CaProtocolHello {
        CaProtocolHeader header;
        le64_t feature_flags;
} CaProtocolHello;

enum {
        /* Services I provide */
        CA_PROTOCOL_READABLE_STORE    = 0x1,    /* I provide chunks on request to you */
        CA_PROTOCOL_WRITABLE_STORE    = 0x2,    /* I can store chunks for you */
        CA_PROTOCOL_READABLE_INDEX    = 0x4,    /* I provide an index on request to you */
        CA_PROTOCOL_WRITABLE_INDEX    = 0x8,    /* I can store an index for you */
        CA_PROTOCOL_READABLE_ARCHIVE  = 0x10,   /* I provide an archive blob to you */
        CA_PROTOCOL_WRITABLE_ARCHIVE  = 0x20,   /* I can store an archive blob for you */

        /* Operations I'd like to execute */
        CA_PROTOCOL_PULL_CHUNKS       = 0x40,   /* I'd like to pull chunks from you  */
        CA_PROTOCOL_PULL_INDEX        = 0x80,   /* I'd like to pull an index from you */
        CA_PROTOCOL_PULL_ARCHIVE      = 0x100,  /* I'd like to pull an archive from you */
        CA_PROTOCOL_PUSH_CHUNKS       = 0x200,  /* I'd like to push chunks to you */
        CA_PROTOCOL_PUSH_INDEX        = 0x400,  /* I'd like to push an index to you */
        CA_PROTOCOL_PUSH_INDEX_CHUNKS = 0x800,  /* I'd like you to pull chunks from me, that are declared in the index I just pulled */
        CA_PROTOCOL_PUSH_ARCHIVE      = 0x1000, /* I'd like to push an archive to you */

        CA_PROTOCOL_FEATURE_FLAGS_MAX = 0x1fff,
};

typedef struct CaProtocolFile {  /* Used for index as well as archive */
        CaProtocolHeader header;
        uint8_t data[];
} CaProtocolFile;

typedef struct CaProtocolFileEOF { /* Used for index as well as archive */
        CaProtocolHeader header;
} CaProtocolFileEOF;

typedef struct CaProtocolRequest {
        CaProtocolHeader header;
        le64_t flags;
        uint8_t chunks[]; /* multiple of CA_CHUNK_ID_SIZE */
} CaProtocolRequest;

enum {
        CA_PROTOCOL_REQUEST_HIGH_PRIORITY = 1,
        CA_PROTOCOL_REQUEST_FLAG_MAX = 1,
};

typedef struct CaProtocolChunk {
        CaProtocolHeader header;
        le64_t flags;
        uint8_t chunk[CA_CHUNK_ID_SIZE];
        uint8_t data[];
} CaProtocolChunk;

enum {
        CA_PROTOCOL_CHUNK_COMPRESSED = 1,
        CA_PROTOCOL_CHUNK_FLAG_MAX = 1,
};

typedef struct CaProtocolMissing {
        CaProtocolHeader header;
        uint8_t chunk[CA_CHUNK_ID_SIZE];
} CaProtocolMissing;

typedef struct CaProtocolGoodbye {
        CaProtocolHeader header;
} CaProtocolGoodbye;

typedef struct CaProtocolAbort {
        CaProtocolHeader header;
        le64_t error; /* closest errno-style error, or 0 */
        char reason[];
} CaProtocolAbort;

#endif
