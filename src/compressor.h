#ifndef foocompresshorhfoo
#define foocompresshorhfoo

#include <lzma.h>
#include <stdbool.h>
#include <zlib.h>
#include <zstd.h>

#include "cacompression.h"

typedef enum CompressorOperation {
        COMPRESSOR_UNINITIALIZED,
        COMPRESSOR_ENCODE,
        COMPRESSOR_DECODE,
} CompressorOperation;

typedef struct CompressorContext {
        CompressorOperation operation;
        CaCompressionType compressor;

        union {
                lzma_stream xz;
                struct z_stream_s gzip;
                struct {
                        ZSTD_CStream *cstream;
                        ZSTD_DStream *dstream;
                        ZSTD_inBuffer input;
                        ZSTD_outBuffer output;
                } zstd;
        };
} CompressorContext;

#define COMPRESSOR_CONTEXT_INIT                             \
        {                                                   \
                .operation = COMPRESSOR_UNINITIALIZED,      \
                .compressor = _CA_COMPRESSION_TYPE_INVALID, \
        }

int compressor_start_decode(CompressorContext *c, CaCompressionType compressor);
int compressor_start_encode(CompressorContext *c, CaCompressionType compressor);
void compressor_finish(CompressorContext *c);

int compressor_input(CompressorContext *c, const void *p, size_t sz);

enum {
        COMPRESSOR_EOF,
        COMPRESSOR_MORE,
        COMPRESSOR_GOOD,
};

int compressor_decode(CompressorContext *c, void *p, size_t size, size_t *ret_done);
int compressor_encode(CompressorContext *c, bool finalize, void *p, size_t size, size_t *ret_done);

int detect_compression(const void *buffer, size_t size);

#endif
