#ifndef foocacompressorhfoo
#define foocacompressorhfoo

typedef enum CaCompressionType {
        CA_COMPRESSION_XZ,
        CA_COMPRESSION_GZIP,
        CA_COMPRESSION_ZSTD,
        _CA_COMPRESSION_TYPE_MAX,
        CA_COMPRESSION_DEFAULT = CA_COMPRESSION_ZSTD,
        _CA_COMPRESSION_TYPE_INVALID = -1,
} CaCompressionType;

const char* ca_compression_type_to_string(CaCompressionType c);
CaCompressionType ca_compression_type_from_string(const char *s);

#endif
