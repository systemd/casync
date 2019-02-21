/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "cachunk.h"
#include "cautil.h"
#include "compressor.h"
#include "def.h"
#include "util.h"

int ca_load_fd(int fd, ReallocBuffer *buffer) {
        uint64_t count = 0;

        if (fd < 0)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        for (;;) {
                ssize_t l;
                void *p;

                /* Don't permit loading chunks larger than the chunk limit */
                if (count >= CA_CHUNK_SIZE_LIMIT_MAX)
                        return -EBADMSG;

                p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                if (!p)
                        return -ENOMEM;

                l = read(fd, p, BUFFER_SIZE);
                if (l < 0)
                        return -errno;

                realloc_buffer_shorten(buffer, BUFFER_SIZE - l);
                count += l;

                if (l == 0)
                        break;
        }

        /* Don't permit empty chunks */
        if (count < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EBADMSG;

        return 0;
}

int ca_load_and_decompress_fd(int fd, ReallocBuffer *buffer) {
        CompressorContext context = COMPRESSOR_CONTEXT_INIT;
        int compression_type = _CA_COMPRESSION_TYPE_INVALID;
        uint8_t fd_buffer[BUFFER_SIZE];
        bool got_decoder_eof = false;
        uint64_t ccount = 0, dcount = 0;
        ssize_t l;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        /* First, read enough of the file, so that we can figure out which algorithm is used */
        for (;;) {
                assert(ccount < BUFFER_SIZE);

                l = read(fd, fd_buffer + ccount, sizeof(fd_buffer) - ccount);
                if (l < 0)
                        return -errno;
                if (l == 0)
                        return -EPIPE;

                ccount += l;

                compression_type = detect_compression(fd_buffer, ccount);
                if (compression_type >= 0)
                        break;
                if (compression_type != -EAGAIN) /* EAGAIN means: need more data before I can decide */
                        return compression_type;
        }

        r = compressor_start_decode(&context, compression_type);
        if (r < 0)
                return r;

        l = ccount;
        for (;;) {
                r = compressor_input(&context, fd_buffer, l);
                if (r < 0)
                        goto finish;

                for (;;) {
                        size_t done;
                        void *p;

                        p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        r = compressor_decode(&context, p, BUFFER_SIZE, &done);
                        if (r < 0)
                                goto finish;

                        realloc_buffer_shorten(buffer, BUFFER_SIZE - done);
                        dcount += done;

                        if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                                r = -EBADMSG;
                                goto finish;
                        }

                        got_decoder_eof = r == COMPRESSOR_EOF;

                        if (r != COMPRESSOR_MORE)
                                break;
                };

                l = read(fd, fd_buffer, sizeof(fd_buffer));
                if (l < 0) {
                        r = -errno;
                        goto finish;
                }
                if (l == 0) {
                        if (!got_decoder_eof) { /* Premature end of file */
                                r = -EPIPE;
                                goto finish;
                        }

                        break;
                }

                if (got_decoder_eof) { /* Trailing noise */
                        r = -EBADMSG;
                        goto finish;
                }

                ccount += l;

                if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EBADMSG;
                        goto finish;
                }
        }

        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN || dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EBADMSG;
                goto finish;
        }

        r = 0;

finish:
        compressor_finish(&context);
        return r;
}

int ca_load_and_compress_fd(int fd, CaCompressionType compression_type, ReallocBuffer *buffer) {
        CompressorContext context = COMPRESSOR_CONTEXT_INIT;
        uint64_t ccount = 0, dcount = 0;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;
        if (compression_type < 0)
                return -EINVAL;
        if (compression_type >= _CA_COMPRESSION_TYPE_MAX)
                return -EOPNOTSUPP;

        r = compressor_start_encode(&context, compression_type);
        if (r < 0)
                return r;

        for (;;) {
                uint8_t fd_buffer[BUFFER_SIZE];
                ssize_t l;
                bool eof, got_encoder_eof = false;

                l = read(fd, fd_buffer, sizeof(fd_buffer));
                if (l < 0) {
                        r = -errno;
                        goto finish;
                }

                eof = (size_t) l < sizeof(fd_buffer);
                dcount += l;

                if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EBADMSG;
                        goto finish;
                }

                r = compressor_input(&context, fd_buffer, l);
                if (r < 0)
                        goto finish;

                for (;;) {
                        uint8_t *p;
                        size_t done;

                        p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        r = compressor_encode(&context, eof, p, BUFFER_SIZE, &done);
                        if (r < 0)
                                goto finish;

                        realloc_buffer_shorten(buffer, BUFFER_SIZE - done);
                        ccount += done;

                        if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                                r = -EBADMSG;
                                goto finish;
                        }

                        got_encoder_eof = r == COMPRESSOR_EOF;

                        if (r != COMPRESSOR_MORE)
                                break;
                }

                if (got_encoder_eof)
                        break;
        }

        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN || dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EBADMSG;
                goto finish;
        }

        r = 0;

finish:
        compressor_finish(&context);
        return r;
}

int ca_save_fd(int fd, const void *data, size_t size) {
        if (fd < 0)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        return loop_write(fd, data, size);
}

int ca_save_and_compress_fd(int fd, CaCompressionType compression_type, const void *data, size_t size) {
        CompressorContext context = COMPRESSOR_CONTEXT_INIT;
        uint64_t ccount = 0;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (compression_type < 0)
                return -EINVAL;
        if (compression_type >= _CA_COMPRESSION_TYPE_MAX)
                return -EOPNOTSUPP;

        r = compressor_start_encode(&context, compression_type);
        if (r < 0)
                return r;

        r = compressor_input(&context, data, size);
        if (r < 0)
                return r;

        for (;;) {
                uint8_t buffer[BUFFER_SIZE];
                size_t done;
                int k;

                r = compressor_encode(&context, true, buffer, sizeof(buffer), &done);
                if (r < 0)
                        goto finish;

                k = loop_write(fd, buffer, done);
                if (k < 0) {
                        r = k;
                        goto finish;
                }

                ccount += done;

                if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                if (r == COMPRESSOR_EOF)
                        break;
        }

        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        compressor_finish(&context);
        return r;
}

int ca_save_and_decompress_fd(int fd, const void *data, size_t size) {
        CompressorContext context = COMPRESSOR_CONTEXT_INIT;
        int compression_type;
        uint64_t dcount = 0;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        compression_type = detect_compression(data, size);
        if (compression_type == -EAGAIN) /* If we the data isn't long enough to contain a signature, refuse */
                return -EBADMSG;
        if (compression_type < 0)
                return compression_type;

        r = compressor_start_decode(&context, compression_type);
        if (r < 0)
                return r;

        r = compressor_input(&context, data, size);
        if (r < 0)
                goto finish;

        for (;;) {
                uint8_t buffer[BUFFER_SIZE];
                size_t done;
                int k;

                r = compressor_decode(&context, buffer, sizeof(buffer), &done);
                if (r < 0)
                        goto finish;

                k = loop_write(fd, buffer, done);
                if (k < 0) {
                        r = k;
                        goto finish;
                }

                dcount += done;

                if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                if (r == COMPRESSOR_EOF)
                        break;
        }

        if (dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        compressor_finish(&context);
        return r;
}

int ca_compress(CaCompressionType compression_type, const void *data, size_t size, ReallocBuffer *buffer) {
        CompressorContext context = COMPRESSOR_CONTEXT_INIT;
        uint64_t ccount = 0;
        int r;

        if (!buffer)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        r = compressor_start_encode(&context, compression_type);
        if (r < 0)
                return r;

        r = compressor_input(&context, data, size);
        if (r < 0)
                return r;

        for (;;) {
                size_t done;
                uint8_t *p;

                p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = compressor_encode(&context, true, p, BUFFER_SIZE, &done);
                if (r < 0)
                        goto finish;

                realloc_buffer_shorten(buffer, BUFFER_SIZE - done);
                ccount += done;

                if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                if (r == COMPRESSOR_EOF)
                        break;
        }

        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        compressor_finish(&context);
        return r;
}

int ca_decompress(const void *data, size_t size, ReallocBuffer *buffer) {
        CompressorContext context = COMPRESSOR_CONTEXT_INIT;
        uint64_t dcount = 0;
        int compression_type;
        int r;

        if (!buffer)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        compression_type = detect_compression(data, size);
        if (compression_type == -EAGAIN)
                return -EBADMSG;
        if (compression_type < 0)
                return compression_type;

        r = compressor_start_decode(&context, compression_type);
        if (r < 0)
                return r;

        r = compressor_input(&context, data, size);
        if (r < 0)
                return r;

        for (;;) {
                uint8_t *p;
                size_t done;

                p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = compressor_decode(&context, p, BUFFER_SIZE, &done);
                if (r < 0)
                        goto finish;

                realloc_buffer_shorten(buffer, BUFFER_SIZE - done);
                dcount += done;

                if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                if (r == COMPRESSOR_EOF)
                        break;
        }

        if (dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        compressor_finish(&context);
        return r;
}

int ca_chunk_file_open(int chunk_fd, const char *prefix, const CaChunkID *chunkid, const char *suffix, int flags) {

        char path[CA_CHUNK_ID_PATH_SIZE(prefix, suffix)];
        bool made = false;
        char *slash = NULL;
        int r, fd;

        /* Opens a file below the directory identified by 'chunk_fd', built as <prefix><4ch id prefix>/<id><suffix>. */

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_chunk_id_format_path(prefix, chunkid, suffix, path);

        if ((flags & O_CREAT) == O_CREAT) {
                assert_se(slash = strrchr(path, '/'));
                *slash = 0;

                if (mkdirat(chunk_fd, path, 0777) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                } else
                        made = true;

                *slash = '/';
        }

        fd = openat(chunk_fd, path, flags, 0444); /* we mark the chunk files read-only, as they should be considered immutable after creation */
        if (fd < 0) {
                r = -errno;

                if (made) {
                        assert(slash);
                        *slash = 0;

                        (void) unlinkat(chunk_fd, path, AT_REMOVEDIR);
                }

                return r;
        }

        return fd;
}

static int ca_chunk_file_access(int chunk_fd, const char *prefix, const CaChunkID *chunkid, const char *suffix) {
        char path[CA_CHUNK_ID_PATH_SIZE(prefix, suffix)];

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_chunk_id_format_path(prefix, chunkid, suffix, path);

        if (faccessat(chunk_fd, path, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                return errno == ENOENT ? 0 : -errno;

        return 1;
}

static int ca_chunk_file_unlink(int chunk_fd, const char *prefix, const CaChunkID *chunkid, const char *suffix) {
        char path[CA_CHUNK_ID_PATH_SIZE(prefix, suffix)], *slash;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_chunk_id_format_path(prefix, chunkid, suffix, path);

        if (unlinkat(chunk_fd, path, 0) < 0)
                return -errno;

        slash = strrchr(path, '/');
        assert(slash);
        *slash = 0;

        (void) unlinkat(chunk_fd, path, AT_REMOVEDIR);

        return 0;
}

static int ca_chunk_file_rename(int chunk_fd, const char *prefix, const CaChunkID *chunkid, const char *old_suffix, const char *new_suffix) {
        char old_path[CA_CHUNK_ID_PATH_SIZE(prefix, old_suffix)], new_path[CA_CHUNK_ID_PATH_SIZE(prefix, new_suffix)];
        int r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_chunk_id_format_path(prefix, chunkid, old_suffix, old_path);
        ca_chunk_id_format_path(prefix, chunkid, new_suffix, new_path);

        r = rename_noreplace(chunk_fd, old_path, chunk_fd, new_path);
        if (r < 0)
                return r;

        return 0;
}

int ca_chunk_file_load(
                int chunk_fd,
                const char *prefix,
                const CaChunkID *chunkid,
                CaChunkCompression desired_compression,
                CaCompressionType compression_type,
                ReallocBuffer *buffer,
                CaChunkCompression *ret_effective_compression) {

        int fd, r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;
        if (desired_compression < 0)
                return -EINVAL;
        if (desired_compression >= _CA_CHUNK_COMPRESSION_MAX)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        fd = ca_chunk_file_open(chunk_fd, prefix, chunkid, NULL, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0) {
                if (fd == -ELOOP) /* If it's a symlink, then it's marked as "missing" */
                        return -EADDRNOTAVAIL;
                if (fd != -ENOENT)
                        return fd;

                fd = ca_chunk_file_open(chunk_fd, prefix, chunkid, ca_compressed_chunk_suffix(), O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd == -ELOOP)
                        return -EADDRNOTAVAIL;
                if (fd < 0)
                        return fd;

                if (desired_compression == CA_CHUNK_UNCOMPRESSED)
                        r = ca_load_and_decompress_fd(fd, buffer);
                else
                        r = ca_load_fd(fd, buffer);

                if (r >= 0 && ret_effective_compression)
                        *ret_effective_compression = desired_compression == CA_CHUNK_AS_IS ? CA_CHUNK_COMPRESSED : desired_compression;

        } else {
                if (desired_compression == CA_CHUNK_COMPRESSED)
                        r = ca_load_and_compress_fd(fd, compression_type, buffer);
                else
                        r = ca_load_fd(fd, buffer);

                if (r >= 0 && ret_effective_compression)
                        *ret_effective_compression = desired_compression == CA_CHUNK_AS_IS ? CA_CHUNK_UNCOMPRESSED : desired_compression;
        }

        safe_close(fd);
        return r;
}

int ca_chunk_file_save(
                int chunk_fd,
                const char *prefix,
                const CaChunkID *chunkid,
                CaChunkCompression effective_compression,
                CaChunkCompression desired_compression,
                CaCompressionType compression_type,
                const void *p,
                uint64_t l) {

        _cleanup_free_ char *suffix = NULL;
        int fd, r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;
        if (desired_compression < 0)
                return -EINVAL;
        if (desired_compression >= _CA_CHUNK_COMPRESSION_MAX)
                return -EINVAL;
        if (effective_compression < 0)
                return -EINVAL;
        if (effective_compression >= _CA_CHUNK_COMPRESSION_MAX)
                return -EINVAL;
        if (effective_compression == CA_CHUNK_AS_IS)
                return -EINVAL;
        if (!p)
                return -EINVAL;
        if (l <= 0)
                return -EINVAL;

        r = ca_chunk_file_test(chunk_fd, prefix, chunkid);
        if (r < 0)
                return r;
        if (r > 0)
                return -EEXIST;

        if (asprintf(&suffix, ".%" PRIx64 ".tmp", random_u64()) < 0)
                return -ENOMEM;

        fd = ca_chunk_file_open(chunk_fd, prefix, chunkid, suffix, O_WRONLY|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        if (desired_compression == CA_CHUNK_AS_IS)
                desired_compression = effective_compression;

        if (desired_compression == effective_compression)
                r = loop_write(fd, p, l);
        else if (desired_compression == CA_CHUNK_COMPRESSED)
                r = ca_save_and_compress_fd(fd, compression_type, p, l);
        else {
                assert(desired_compression == CA_CHUNK_UNCOMPRESSED);
                r = ca_save_and_decompress_fd(fd, p, l);
        }
        safe_close(fd);
        if (r < 0)
                goto fail;

        r = ca_chunk_file_rename(chunk_fd, prefix, chunkid, suffix, desired_compression == CA_CHUNK_COMPRESSED ? ca_compressed_chunk_suffix() : NULL);
        if (r < 0)
                goto fail;

        return 0;

fail:
        (void) ca_chunk_file_unlink(chunk_fd, prefix, chunkid, suffix);
        return r;
}

int ca_chunk_file_mark_missing(int chunk_fd, const char *prefix, const CaChunkID *chunkid) {
        char path[CA_CHUNK_ID_PATH_SIZE(prefix, NULL)];
        bool made = false;
        char *slash;
        int r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        r = ca_chunk_file_test(chunk_fd, prefix, chunkid);
        if (r < 0)
                return r;
        if (r > 0)
                return -EEXIST;

        ca_chunk_id_format_path(prefix, chunkid, NULL, path);

        assert_se(slash = strrchr(path, '/'));
        *slash = 0;

        if (mkdirat(chunk_fd, path, 0777) < 0) {
                if (errno != EEXIST)
                        return -errno;
        } else
                made = true;

        *slash = '/';

        if (symlinkat("/dev/null", chunk_fd, path) < 0) {
                r = -errno;

                if (made) {
                        *slash = 0;

                        (void) unlinkat(chunk_fd, path, AT_REMOVEDIR);
                }

                return r;
        }

        return 0;
}

int ca_chunk_file_test(int chunk_fd, const char *prefix, const CaChunkID *chunkid) {
        int r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        r = ca_chunk_file_access(chunk_fd, prefix, chunkid, NULL);
        if (r != 0)
                return r;

        return ca_chunk_file_access(chunk_fd, prefix, chunkid, ca_compressed_chunk_suffix());
}

int ca_chunk_file_remove(int chunk_fd, const char *prefix, const CaChunkID *chunkid) {
        int r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        r = ca_chunk_file_unlink(chunk_fd, prefix, chunkid, NULL);
        if (r < 0 && r != -ENOENT)
                return -EINVAL;

        return ca_chunk_file_unlink(chunk_fd, prefix, chunkid, ca_compressed_chunk_suffix());
}
