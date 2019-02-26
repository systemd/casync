/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocacompressorhfoo
#define foocacompressorhfoo

typedef enum CaCompressionType {
        CA_COMPRESSION_XZ,
        CA_COMPRESSION_GZIP,
        CA_COMPRESSION_ZSTD,
        _CA_COMPRESSION_TYPE_MAX,
        _CA_COMPRESSION_TYPE_INVALID = -1,

        CA_COMPRESSION_DEFAULT =
#if HAVE_LIBZSTD
        CA_COMPRESSION_ZSTD,
#elif HAVE_LIBZ
        CA_COMPRESSION_GZIP,
#elif HAVE_LIBLZMA
        CA_COMPRESSION_XZ,
#else
        _CA_COMPRESSION_TYPE_INVALID
#endif
} CaCompressionType;

const char* ca_compression_type_to_string(CaCompressionType c);
CaCompressionType ca_compression_type_from_string(const char *s);

#endif
