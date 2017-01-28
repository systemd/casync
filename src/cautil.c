#include <errno.h>
#include <fcntl.h>
#include <lzma.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "cautil.h"
#include "def.h"
#include "util.h"

#define CHUNK_PATH_SIZE(prefix, suffix)                                 \
        (strlen_null(prefix) + 4 + 1 + CA_OBJECT_ID_FORMAT_MAX + strlen_null(suffix))

static char* ca_format_chunk_path(
                const char *prefix,
                const CaObjectID *objectid,
                const char *suffix,
                char buffer[]) {

        size_t n;

        assert(objectid);
        assert(buffer);

        if (prefix) {
                n = strlen(prefix);
                memcpy(buffer, prefix, n);
        } else
                n = 0;

        ca_object_id_format(objectid, buffer + n + 4 + 1);
        memcpy(buffer + n, buffer + n + 4 + 1, 4);
        buffer[n + 4] = '/';

        if (suffix)
                strcpy(buffer + n + 4 + 1 + CA_OBJECT_ID_FORMAT_MAX - 1, suffix);

        return buffer;
}

int ca_open_chunk_file(int chunk_fd, const char *prefix, const CaObjectID *objectid, const char *suffix, int flags) {

        char path[CHUNK_PATH_SIZE(prefix, suffix)];
        bool made = false;
        int r, fd;

        /* Opens a file below the directory identified by 'chunk_fd', built as <prefix><4ch id prefix>/<id><suffix>. */

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;

        ca_format_chunk_path(prefix, objectid, suffix, path);

        if ((flags & O_CREAT) == O_CREAT) {
                path[4] = 0;

                if (mkdirat(chunk_fd, path, 0777) < 0) {
                        if (errno != EEXIST)
                                return -errno;
                } else
                        made = true;

                path[4] = '/';
        }

        fd = openat(chunk_fd, path, flags, 0777);
        if (fd < 0) {
                r = -errno;

                if (made) {
                        path[4] = 0;
                        (void) unlinkat(chunk_fd, path, AT_REMOVEDIR);
                }

                return r;
        }

        return fd;
}

static int ca_access_chunk_file(int chunk_fd, const char *prefix, const CaObjectID *objectid, const char *suffix) {
        char path[CHUNK_PATH_SIZE(prefix, suffix)];

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;

        ca_format_chunk_path(prefix, objectid, suffix, path);

        if (faccessat(chunk_fd, path, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                return errno == ENOENT ? 0 : -errno;

        return 1;
}

static int ca_remove_chunk_file(int chunk_fd, const char *prefix, const CaObjectID *objectid, const char *suffix) {
        char path[CHUNK_PATH_SIZE(prefix, suffix)];

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;

        ca_format_chunk_path(prefix, objectid, suffix, path);

        if (unlinkat(chunk_fd, path, 0) < 0)
                return -errno;

        path[4] = 0;
        (void) unlinkat(chunk_fd, path, AT_REMOVEDIR);

        return 0;
}

static int ca_rename_chunk_file(int chunk_fd, const char *prefix, const CaObjectID *objectid, const char *old_suffix, const char *new_suffix) {
        char old_path[CHUNK_PATH_SIZE(prefix, old_suffix)], new_path[CHUNK_PATH_SIZE(prefix, new_suffix)];

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;

        ca_format_chunk_path(prefix, objectid, old_suffix, old_path);
        ca_format_chunk_path(prefix, objectid, new_suffix, new_path);

        if (renameat2(chunk_fd, old_path, chunk_fd, new_path, RENAME_NOREPLACE) < 0)
        /* if (renameat(chunk_fd, old_path, chunk_fd, new_path) < 0) */
                return -errno;

        return 0;
}

int ca_load_fd(int fd, ReallocBuffer *buffer) {
        if (fd < 0)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        for (;;) {
                ssize_t l;
                void *p;

                p = realloc_buffer_extend(buffer, BUFFER_SIZE);
                if (!p)
                        return -ENOMEM;

                l = read(fd, p, BUFFER_SIZE);
                if (l < 0)
                        return -errno;

                realloc_buffer_shorten(buffer, BUFFER_SIZE - l);
                if (l == 0)
                        break;
        }

        return 0;
}

int ca_load_compressed_fd(int fd, ReallocBuffer *buffer) {
        lzma_stream xz = {};
        lzma_ret xzr;
        bool got_xz_eof = false;
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

                l = read(fd, fd_buffer, sizeof(fd_buffer));
                if (l < 0) {
                        r = -errno;
                        goto finish;
                }
                if (l == 0) {
                        if (!got_xz_eof) {
                                r = -EPIPE;
                                goto finish;
                        }

                        break;
                }

                xz.next_in = fd_buffer;
                xz.avail_in = l;

                while (xz.avail_in > 0) {
                        void *p;

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

                        if (xzr == LZMA_STREAM_END) {

                                if (xz.avail_in > 0) {
                                        r = -EBADMSG;
                                        goto finish;
                                }

                                got_xz_eof = true;
                        }
                }
        }

        r = 0;

finish:
        lzma_end(&xz);
        return r;
}

int ca_load_chunk_file(int chunk_fd, const char *prefix, const CaObjectID *objectid, ReallocBuffer *buffer) {
        int fd, r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        fd = ca_open_chunk_file(chunk_fd, prefix, objectid, NULL, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0) {
                if (fd == -ELOOP) /* If it's a symlink, then it's marked as "missing" */
                        return -EADDRNOTAVAIL;
                if (fd != -ENOENT)
                        return fd;

                fd = ca_open_chunk_file(chunk_fd, prefix, objectid, ".xz", O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd == -ELOOP)
                        return -EADDRNOTAVAIL;
                if (fd < 0)
                        return fd;

                r = ca_load_compressed_fd(fd, buffer);
        } else
                r = ca_load_fd(fd, buffer);

        safe_close(fd);
        return r;
}

int ca_save_chunk_file(int chunk_fd, const char *prefix, const CaObjectID *objectid, bool compressed, const void *p, size_t l) {
        int fd, r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;
        if (!p)
                return -EINVAL;
        if (l <= 0)
                return -EINVAL;

        r = ca_test_chunk_file(chunk_fd, prefix, objectid);
        if (r < 0)
                return r;
        if (r > 0)
                return -EEXIST;

        fd = ca_open_chunk_file(chunk_fd, prefix, objectid, ".tmp", O_WRONLY|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC);
        r = loop_write(fd, p, l);
        safe_close(fd);
        if (r < 0)
                goto fail;

        r = ca_rename_chunk_file(chunk_fd, prefix, objectid, ".tmp", compressed ? ".xz" : NULL);
        if (r < 0)
                goto fail;

        return 0;

fail:
        (void) ca_remove_chunk_file(chunk_fd, prefix, objectid, ".tmp");
        return r;
}

int ca_save_chunk_missing(int chunk_fd, const char *prefix, const CaObjectID *objectid) {
        char path[CHUNK_PATH_SIZE(prefix, NULL)];
        int r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;

        r = ca_test_chunk_file(chunk_fd, prefix, objectid);
        if (r < 0)
                return r;
        if (r > 0)
                return -EEXIST;

        ca_format_chunk_path(prefix, objectid, NULL, path);

        if (symlinkat("/dev/null", chunk_fd, path) < 0)
                return -errno;

        return 0;
}

int ca_test_chunk_file(int chunk_fd, const char *prefix, const CaObjectID *objectid) {
        int r;

        if (chunk_fd < 0 && chunk_fd != AT_FDCWD)
                return -EINVAL;
        if (!objectid)
                return -EINVAL;

        r = ca_access_chunk_file(chunk_fd, prefix, objectid, NULL);
        if (r != 0)
                return r;

        return ca_access_chunk_file(chunk_fd, prefix, objectid, ".xz");
}

static bool ca_is_definitely_path(const char *s) {

        assert(s);

        /* We consider ".", ".." and everything starting with either "/" or "./" a file system path. */

        if (s[0] == '/')
                return true;

        if (s[0] == '.') {
                if (s[1] == 0)
                        return true;

                if (s[1] == '/')
                        return true;

                if (s[1] == '.' && s[2] == 0)
                        return true;
        }

        return false;
}

bool ca_is_url(const char *s) {
        const char *e;
        size_t n, k;

        assert(s);

        /* Checks whether something appears to be a URL. This is inspired by RFC3986, but a bit more restricted, so
         * that we can clearly distuingish URLs from file system paths, and ssh specifications. For example, the kind
         * of URLs we are interested in must contain '://' as host/path separator.
         *
         * We explicit exclude all strings starting with either "/" or "./" as URL from being detected as URLs, so that
         * this can always be used for explicitly referencing local directories. */

        if (ca_is_definitely_path(s))
                return false;

        if (!strchr(URL_PROTOCOL_FIRST, s[0]))
                return false;

        n = 1 + strspn(s + 1, URL_PROTOCOL_CHARSET);

        e = startswith(s + n, "://");
        if (!e)
                return false;

        k = strspn(e, HOSTNAME_CHARSET "@");
        if (k <= 0)
                return false;

        if (e[k] != '/' && e[k] != 0)
                return false;

        return true;
}

bool ca_is_ssh_path(const char *s) {
        size_t n;

        assert(s);

        if (ca_is_definitely_path(s))
                return false;

        n = strspn(s, HOSTNAME_CHARSET);
        if (n <= 0)
                return false;

        if (s[n] == '@') {
                size_t k;

                k = strspn(s + n + 1, HOSTNAME_CHARSET);
                if (k <= 0)
                        return false;

                if (s[n + 1 + k] != ':')
                        return false;

                n += 1 + k;

        } else if (s[n] != ':')
                return false;

        return true;
}

CaLocatorClass ca_classify_locator(const char *s) {
        if (isempty(s))
                return _CA_LOCATOR_CLASS_INVALID;

        if (ca_is_url(s))
                return CA_LOCATOR_URL;

        if (ca_is_ssh_path(s))
                return CA_LOCATOR_SSH;

        return CA_LOCATOR_PATH;
}

char *ca_strip_file_url(const char *p) {
        const char *e, *f;
        char *t, *result;

        assert(p);

        /* If the input is a file:// URL, turn it into a normal path, in a very defensive way. */

        e = startswith(p, "file://");
        if (!e)
                return strdup(p);

        if (*e == '/')
                goto unescape;

        e = startswith(e, "localhost/");
        if (e) {
                e --;
                goto unescape;
        }

        return strdup(p);

unescape:
        result = new(char, strlen(e) + 1);
        if (!result)
                return NULL;

        for (f = e, t = result; *f; f++) {
                int a, b;

                if (f[0] == '%' &&
                    (a = unhexchar(f[1])) >= 0 &&
                    (b = unhexchar(f[2])) >= 0) {

                        *(t++) = (char) (((uint8_t) a << 4) | (uint8_t) b);
                        f += 2;
                        continue;
                }

                *(t++) = *f;
        }

        *t = 0;

        return result;
}

bool ca_locator_has_suffix(const char *p, const char *suffix) {
        const char *e, *q;

        if (isempty(suffix))
                return true;

        if (isempty(p))
                return false;

        if (ca_is_url(p)) {
                size_t n;

                n = strlen(suffix);

                e = strrchr(p, '?');
                if (!e)
                        e = strrchr(p, ';');
                if (!e)
                        e = strchr(p, 0);

                if ((size_t) (e - p) < n)
                        return false;

                return memcmp(e - n, suffix, n) == 0;
        }

        e = strrchr(p, '/');
        if (e)
                e++;
        else
                e = p;

        q = endswith(e, suffix);

        return q && q != e;
}
