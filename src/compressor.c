#include "compressor.h"
#include "util.h"

/* #undef EIO */
/* #define EIO __LINE__ */

/* #undef EBADMSG */
/* #define EBADMSG __LINE__ */

int detect_compression(const void *buffer, size_t size) {

        static const uint8_t xz_signature[] = {
                0xfd, '7', 'z', 'X', 'Z', 0x00
        };

        static const uint8_t gzip_signature[] = {
                0x1f, 0x8b
        };

        if (size >= sizeof(xz_signature) &&
            memcmp(buffer, xz_signature, sizeof(xz_signature)) == 0)
                return CA_COMPRESSION_XZ;

        if (size >= sizeof(gzip_signature) &&
            memcmp(buffer, gzip_signature, sizeof(gzip_signature)) == 0)
                return CA_COMPRESSION_GZIP;

        if (size < MAX(sizeof(xz_signature), sizeof(gzip_signature)))
                return -EAGAIN; /* Not ready to decide yet */

        return -EBADMSG;
}

int compressor_start_decode(CompressorContext *c, CaCompressionType compressor) {
        int r;

        if (!c)
                return -EINVAL;
        if (compressor < 0)
                return -EINVAL;
        if (compressor >= _CA_COMPRESSION_TYPE_MAX)
                return -EOPNOTSUPP;

        switch (compressor) {

        case CA_COMPRESSION_XZ: {
                lzma_ret xzr;

                xzr = lzma_stream_decoder(&c->xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK);
                if (xzr != LZMA_OK)
                        return -EIO;

                break;
        }

        case CA_COMPRESSION_GZIP:
                r = inflateInit2(&c->gzip, 15 | 16);
                if (r != Z_OK)
                        return -EIO;

                break;

        default:
                assert_not_reached("Unknown decompressor.");
        }

        c->operation = COMPRESSOR_DECODE;
        c->compressor = compressor;

        return 0;
}

int compressor_start_encode(CompressorContext *c, CaCompressionType compressor) {
        int r;

        if (!c)
                return -EINVAL;
        if (compressor < 0)
                return -EINVAL;
        if (compressor >= _CA_COMPRESSION_TYPE_MAX)
                return -EOPNOTSUPP;

        switch (compressor) {

        case CA_COMPRESSION_XZ: {
                lzma_ret xzr;

                xzr = lzma_easy_encoder(&c->xz, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
                if (xzr != LZMA_OK)
                        return -EIO;

                break;
        }

        case CA_COMPRESSION_GZIP:
                r = deflateInit2(&c->gzip, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
                if (r != Z_OK)
                        return -EIO;
                break;

        default:
                assert_not_reached("Unknown compressor.");
        }

        c->operation = COMPRESSOR_ENCODE;
        c->compressor = compressor;

        return 0;
}

void compressor_finish(CompressorContext *c) {
        if (!c)
                return;
        if (c->operation == COMPRESSOR_UNINITIALIZED)
                return;

        switch (c->compressor) {

        case CA_COMPRESSION_XZ:
                lzma_end(&c->xz);
                break;

        case CA_COMPRESSION_GZIP:
                if (c->operation == COMPRESSOR_DECODE)
                        inflateEnd(&c->gzip);
                else if (c->operation == COMPRESSOR_ENCODE)
                        deflateEnd(&c->gzip);
                else
                        assert_not_reached("Unknown operation.");
                break;

        default:
                assert_not_reached("Unknown compressor.");
        }
}

int compressor_input(CompressorContext *c, const void *p, size_t sz) {

        if (!c)
                return -EINVAL;
        if (sz > 0 && !p)
                return -EINVAL;

        switch (c->compressor) {

        case CA_COMPRESSION_XZ:
                c->xz.next_in = p;
                c->xz.avail_in = sz;
                break;

        case CA_COMPRESSION_GZIP:
                c->gzip.next_in = (void*) p;
                c->gzip.avail_in = sz;
                break;

        default:
                assert_not_reached("Unknown compressor.");
        }

        return 0;
}

int compressor_decode(CompressorContext *c, void *p, size_t sz, size_t *ret_done) {
        int r;

        if (!c)
                return -EINVAL;
        if (sz > 0 && !p)
                return -EINVAL;
        if (!ret_done)
                return -EINVAL;

        if (c->operation != COMPRESSOR_DECODE)
                return -ENOTTY;

        switch (c->compressor) {

        case CA_COMPRESSION_XZ: {
                lzma_ret xzr;

                c->xz.next_out = p;
                c->xz.avail_out = sz;

                assert(c->xz.avail_out > 0);
                assert(c->xz.avail_in > 0);

                xzr = lzma_code(&c->xz, LZMA_RUN);
                if (xzr == LZMA_STREAM_END) {

                        if (c->xz.avail_in > 0)
                                return -EBADMSG;

                        *ret_done = sz - c->xz.avail_out;
                        return COMPRESSOR_EOF;

                } else if (xzr != LZMA_OK)
                        return -EIO;

                *ret_done = sz - c->xz.avail_out;

                if (c->xz.avail_in > 0)
                        return COMPRESSOR_MORE;

                return COMPRESSOR_GOOD;
        }

        case CA_COMPRESSION_GZIP:
                c->gzip.next_out = p;
                c->gzip.avail_out = sz;

                assert(c->gzip.avail_out > 0);
                assert(c->gzip.avail_in > 0);

                r = inflate(&c->gzip, Z_NO_FLUSH);
                if (r == Z_STREAM_END) {

                        if (c->gzip.avail_in > 0)
                                return -EBADMSG;

                        *ret_done = sz - c->gzip.avail_out;
                        return COMPRESSOR_EOF;

                } else if (r != Z_OK)
                        return -EIO;

                *ret_done = sz - c->gzip.avail_out;

                if (c->gzip.avail_in > 0)
                        return COMPRESSOR_MORE;

                return COMPRESSOR_GOOD;

        default:
                assert_not_reached("Unknown compressor.");
        }
}

int compressor_encode(CompressorContext *c, bool finalize, void *p, size_t sz, size_t *ret_done) {
        int r;

        if (!c)
                return -EINVAL;
        if (sz > 0 && !p)
                return -EINVAL;
        if (!ret_done)
                return -EINVAL;

        if (c->operation != COMPRESSOR_ENCODE)
                return -ENOTTY;

        switch (c->compressor) {

        case CA_COMPRESSION_XZ: {
                lzma_ret xzr;

                c->xz.next_out = p;
                c->xz.avail_out = sz;

                xzr = lzma_code(&c->xz, finalize ? LZMA_FINISH : LZMA_RUN);
                if (xzr == LZMA_STREAM_END) {
                        assert(c->xz.avail_in == 0);
                        *ret_done = sz - c->xz.avail_out;
                        return COMPRESSOR_EOF;
                } else if (xzr != LZMA_OK)
                        return -EIO;

                *ret_done = sz - c->xz.avail_out;

                if (c->xz.avail_in > 0)
                        return COMPRESSOR_MORE;

                return COMPRESSOR_GOOD;
        }

        case CA_COMPRESSION_GZIP:

                c->gzip.next_out = p;
                c->gzip.avail_out = sz;

                r = deflate(&c->gzip, finalize ? Z_FINISH : Z_NO_FLUSH);
                if (r == Z_STREAM_END) {
                        assert(c->gzip.avail_in == 0);
                        *ret_done = sz - c->gzip.avail_out;
                        return COMPRESSOR_EOF;
                } else if (r != Z_OK)
                        return -EIO;

                *ret_done = sz - c->gzip.avail_out;

                if (c->gzip.avail_in > 0)
                        return COMPRESSOR_MORE;

                return COMPRESSOR_GOOD;

        default:
                assert_not_reached("Unknown compressor.");
        }
}
