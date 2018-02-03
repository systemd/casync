/* SPDX-License-Identifier: LGPL-2.1+ */

#include "cacompression.h"
#include "util.h"

static const char* const table[_CA_COMPRESSION_TYPE_MAX] = {
        [CA_COMPRESSION_XZ] = "xz",
        [CA_COMPRESSION_GZIP] = "gzip",
        [CA_COMPRESSION_ZSTD] = "zstd",
};

const char* ca_compression_type_to_string(CaCompressionType c) {
        if (c < 0)
                return NULL;
        if (c >= _CA_COMPRESSION_TYPE_MAX)
                return NULL;

        return table[c];
}

CaCompressionType ca_compression_type_from_string(const char *s) {
        CaCompressionType i;

        if (isempty(s))
                return _CA_COMPRESSION_TYPE_INVALID;

        if (streq(s, "default"))
                return CA_COMPRESSION_DEFAULT;

        for (i = 0; i < _CA_COMPRESSION_TYPE_MAX; i++) {
                if (streq(table[i], s))
                        return i;
        }

        return _CA_COMPRESSION_TYPE_INVALID;

}
