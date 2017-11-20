/* SPDX-License-Identifier: LGPL-2.1+ */

#include "caprotocol-util.h"
#include "caprotocol.h"

const char *ca_protocol_type_name(uint64_t u) {
        switch (u) {

        case CA_PROTOCOL_HELLO:
                return "hello";

        case CA_PROTOCOL_INDEX:
                return "index";

        case CA_PROTOCOL_INDEX_EOF:
                return "index-eof";

        case CA_PROTOCOL_ARCHIVE:
                return "archive";

        case CA_PROTOCOL_ARCHIVE_EOF:
                return "archive-eof";

        case CA_PROTOCOL_REQUEST:
                return "request";

        case CA_PROTOCOL_CHUNK:
                return "chunk";

        case CA_PROTOCOL_MISSING:
                return "missing";

        case CA_PROTOCOL_GOODBYE:
                return "goodbye";

        case CA_PROTOCOL_ABORT:
                return "abort";
        }

        return NULL;
}
