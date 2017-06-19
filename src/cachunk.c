#include <errno.h>
#include <fcntl.h>
#include <lzma.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "cachunk.h"
#include "def.h"
#include "util.h"

#define CHUNK_PATH_SIZE(prefix, suffix)                                 \
        (strlen_null(prefix) + 4 + 1 + CA_CHUNK_ID_FORMAT_MAX + strlen_null(suffix))

static char* ca_format_chunk_path(
                const char *prefix,
                const CaChunkID *chunkid,
                const char *suffix,
                char buffer[]) {

        size_t n;

        assert(chunkid);
        assert(buffer);

        if (prefix) {
                n = strlen(prefix);
                memcpy(buffer, prefix, n);
        } else
                n = 0;

        ca_chunk_id_format(chunkid, buffer + n + 4 + 1);
        memcpy(buffer + n, buffer + n + 4 + 1, 4);
        buffer[n + 4] = '/';

        if (suffix)
                strcpy(buffer + n + 4 + 1 + CA_CHUNK_ID_FORMAT_MAX - 1, suffix);

        return buffer;
}

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
        uint64_t ccount = 0, dcount = 0;
        bool got_xz_eof = false;
        lzma_stream xz = {};
        lzma_ret xzr;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        xzr = lzma_stream_decoder(&xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK);
        if (xzr != LZMA_OK)
                return -EIO;

        for (;;) {
                uint8_t fd_buffer[BUFFER_SIZE];
                ssize_t l;

                if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EBADMSG;
                        goto finish;
                }

                l = read(fd, fd_buffer, sizeof(fd_buffer));
                if (l < 0) {
                        r = -errno;
                        goto finish;
                }

                ccount += l;

                if (l == 0) {
                        if (!got_xz_eof) {
                                r = -EPIPE;
                                goto finish;
                        }

                        break;
                }

                xz.next_in = fd_buffer;
                xz.avail_in = l;

                do {
                        void *p;

                        if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                                r = -EBADMSG;
                                goto finish;
                        }

                        p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        xz.next_out = p;
                        xz.avail_out = BUFFER_SIZE;

                        xzr = lzma_code(&xz, LZMA_RUN);
                        if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                                r = -EIO;
                                goto finish;
                        }

                        realloc_buffer_shorten(buffer, xz.avail_out);
                        dcount += BUFFER_SIZE - xz.avail_out;

                        if (xzr == LZMA_STREAM_END) {

                                if (xz.avail_in > 0) {
                                        r = -EBADMSG;
                                        goto finish;
                                }

                                got_xz_eof = true;
                        }

                } while (xz.avail_in > 0);
        }

        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN || dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EBADMSG;
                goto finish;
        }

        r = 0;

finish:
        lzma_end(&xz);
        return r;
}

int ca_load_and_compress_fd(int fd, ReallocBuffer *buffer) {
        uint64_t ccount = 0, dcount = 0;
        lzma_stream xz = {};
        lzma_ret xzr;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        xzr = lzma_easy_encoder(&xz, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
        if (xzr != LZMA_OK)
                return -EIO;

        for (;;) {
                uint8_t fd_buffer[BUFFER_SIZE];
                ssize_t l;

                if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EBADMSG;
                        goto finish;
                }

                l = read(fd, fd_buffer, sizeof(fd_buffer));
                if (l < 0) {
                        r = -errno;
                        goto finish;
                }

                dcount += l;

                xz.next_in = fd_buffer;
                xz.avail_in = l;

                do {
                        uint8_t *p;

                        if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                                r = -EBADMSG;
                                goto finish;
                        }

                        p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        xz.next_out = p;
                        xz.avail_out = BUFFER_SIZE;

                        xzr = lzma_code(&xz, (size_t) l < sizeof(fd_buffer) ? LZMA_FINISH : LZMA_RUN);
                        if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                                r = -EIO;
                                goto finish;
                        }

                        realloc_buffer_shorten(buffer, xz.avail_out);
                        ccount += BUFFER_SIZE - xz.avail_out;

                        if (xzr == LZMA_STREAM_END) {
                                assert(xz.avail_in == 0);
                                goto done;
                        }

                } while (xz.avail_in > 0);
        }

done:
        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN || dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EBADMSG;
                goto finish;
        }

        r = 0;

finish:
        lzma_end(&xz);
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

int ca_save_and_compress_fd(int fd, const void *data, size_t size) {
        uint64_t ccount = 0;
        lzma_stream xz = {};
        lzma_ret xzr;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        xzr = lzma_easy_encoder(&xz, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
        if (xzr != LZMA_OK)
                return -EIO;

        xz.next_in = data;
        xz.avail_in = size;

        for (;;) {
                uint8_t buffer[BUFFER_SIZE];

                if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                xz.next_out = buffer;
                xz.avail_out = sizeof(buffer);

                xzr = lzma_code(&xz, LZMA_FINISH);
                if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                        r = -EIO;
                        goto finish;
                }

                r = loop_write(fd, buffer, sizeof(buffer) - xz.avail_out);
                if (r < 0)
                        goto finish;

                ccount += sizeof(buffer) - xz.avail_out;

                if (xzr == LZMA_STREAM_END)
                        break;
        }

        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        lzma_end(&xz);
        return r;
}

int ca_save_and_decompress_fd(int fd, const void *data, size_t size) {
        uint64_t dcount = 0;
        lzma_stream xz = {};
        lzma_ret xzr;
        int r;

        if (fd < 0)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        xzr = lzma_stream_decoder(&xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK);
        if (xzr != LZMA_OK)
                return -EIO;

        xz.next_in = data;
        xz.avail_in = size;

        for (;;) {
                uint8_t buffer[BUFFER_SIZE];

                if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                xz.next_out = buffer;
                xz.avail_out = sizeof(buffer);

                xzr = lzma_code(&xz, LZMA_FINISH);
                if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                        r = -EIO;
                        goto finish;
                }

                r = loop_write(fd, buffer, sizeof(buffer) - xz.avail_out);
                if (r < 0)
                        goto finish;

                dcount += sizeof(buffer) - xz.avail_out;

                if (xzr == LZMA_STREAM_END) {

                        if (xz.avail_in > 0) {
                                r = -EBADMSG;
                                goto finish;
                        }

                        break;
                }
        }

        if (dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        lzma_end(&xz);
        return r;
}

int ca_compress(const void *data, size_t size, ReallocBuffer *buffer) {
        uint64_t ccount = 0;
        lzma_stream xz = {};
        lzma_ret xzr;
        int r;

        if (!buffer)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        xzr = lzma_easy_encoder(&xz, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
        if (xzr != LZMA_OK)
                return -EIO;

        xz.next_in = data;
        xz.avail_in = size;

        for (;;) {
                uint8_t *p;

                if (ccount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                xz.next_out = p;
                xz.avail_out = BUFFER_SIZE;

                xzr = lzma_code(&xz, LZMA_FINISH);
                if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                        r = -EIO;
                        goto finish;
                }

                realloc_buffer_shorten(buffer, xz.avail_out);
                ccount += BUFFER_SIZE - xz.avail_out;

                if (xzr == LZMA_STREAM_END)
                        break;
        }

        if (ccount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        lzma_end(&xz);
        return r;
}

int ca_decompress(const void *data, size_t size, ReallocBuffer *buffer) {
        uint64_t dcount = 0;
        lzma_stream xz = {};
        lzma_ret xzr;
        int r;

        if (!buffer)
                return -EINVAL;
        if (size < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (size > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        xzr = lzma_stream_decoder(&xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK);
        if (xzr != LZMA_OK)
                return -EIO;

        xz.next_in = data;
        xz.avail_in = size;

        for (;;) {
                uint8_t *p;

                if (dcount >= CA_CHUNK_SIZE_LIMIT_MAX) {
                        r = -EINVAL;
                        goto finish;
                }

                p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                xz.next_out = p;
                xz.avail_out = BUFFER_SIZE;

                xzr = lzma_code(&xz, LZMA_FINISH);
                if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                        r = -EIO;
                        goto finish;
                }

                realloc_buffer_shorten(buffer, xz.avail_out);
                dcount += BUFFER_SIZE - xz.avail_out;

                if (xzr == LZMA_STREAM_END) {

                        if (xz.avail_in > 0) {
                                r = -EBADMSG;
                                goto finish;
                        }

                        break;
                }
        }

        if (dcount < CA_CHUNK_SIZE_LIMIT_MIN) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        lzma_end(&xz);
        return r;
}

int ca_chunk_file_open(int chunk_fd, const char *prefix, const CaChunkID *chunkid, const char *suffix, int flags) {

        char path[CHUNK_PATH_SIZE(prefix, suffix)];
        bool made = false;
        char *slash = NULL;
        int r, fd;

        /* Opens a file below the directory identified by 'chunk_fd', built as <prefix><4ch id prefix>/<id><suffix>. */

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_format_chunk_path(prefix, chunkid, suffix, path);

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

        fd = openat(chunk_fd, path, flags, 0666);
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
        char path[CHUNK_PATH_SIZE(prefix, suffix)];

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_format_chunk_path(prefix, chunkid, suffix, path);

        if (faccessat(chunk_fd, path, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                return errno == ENOENT ? 0 : -errno;

        return 1;
}

static int ca_chunk_file_unlink(int chunk_fd, const char *prefix, const CaChunkID *chunkid, const char *suffix) {
        char path[CHUNK_PATH_SIZE(prefix, suffix)], *slash;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_format_chunk_path(prefix, chunkid, suffix, path);

        if (unlinkat(chunk_fd, path, 0) < 0)
                return -errno;

        slash = strrchr(path, '/');
        assert(slash);
        *slash = 0;

        (void) unlinkat(chunk_fd, path, AT_REMOVEDIR);

        return 0;
}

static int ca_chunk_file_rename(int chunk_fd, const char *prefix, const CaChunkID *chunkid, const char *old_suffix, const char *new_suffix) {
        char old_path[CHUNK_PATH_SIZE(prefix, old_suffix)], new_path[CHUNK_PATH_SIZE(prefix, new_suffix)];

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!chunkid)
                return -EINVAL;

        ca_format_chunk_path(prefix, chunkid, old_suffix, old_path);
        ca_format_chunk_path(prefix, chunkid, new_suffix, new_path);

        if (renameat2(chunk_fd, old_path, chunk_fd, new_path, RENAME_NOREPLACE) < 0)
        /* if (renameat(chunk_fd, old_path, chunk_fd, new_path) < 0) */
                return -errno;

        return 0;
}

int ca_chunk_file_load(
                int chunk_fd,
                const char *prefix,
                const CaChunkID *chunkid,
                CaChunkCompression desired_compression,
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

                fd = ca_chunk_file_open(chunk_fd, prefix, chunkid, ".xz", O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
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
                        r = ca_load_and_compress_fd(fd, buffer);
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
                const void *p,
                size_t l) {

        char *suffix;
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
        if (fd < 0) {
                free(suffix);
                return fd;
        }

        if (desired_compression == CA_CHUNK_AS_IS)
                desired_compression = effective_compression;

        if (desired_compression == effective_compression)
                r = loop_write(fd, p, l);
        else if (desired_compression == CA_CHUNK_COMPRESSED)
                r = ca_save_and_compress_fd(fd, p, l);
        else {
                assert(desired_compression == CA_CHUNK_UNCOMPRESSED);
                r = ca_save_and_decompress_fd(fd, p, l);
        }
        safe_close(fd);
        if (r < 0)
                goto fail;

        r = ca_chunk_file_rename(chunk_fd, prefix, chunkid, suffix, desired_compression == CA_CHUNK_COMPRESSED ? ".xz" : NULL);
        if (r < 0)
                goto fail;

        free(suffix);
        return 0;

fail:
        (void) ca_chunk_file_unlink(chunk_fd, prefix, chunkid, suffix);
        free(suffix);
        return r;
}

int ca_chunk_file_mark_missing(int chunk_fd, const char *prefix, const CaChunkID *chunkid) {
        char path[CHUNK_PATH_SIZE(prefix, NULL)];
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

        ca_format_chunk_path(prefix, chunkid, NULL, path);

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

        return ca_chunk_file_access(chunk_fd, prefix, chunkid, ".xz");
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

        return ca_chunk_file_unlink(chunk_fd, prefix, chunkid, ".xz");
}
