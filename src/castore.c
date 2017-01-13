#include <fcntl.h>
#include <lzma.h>
#include <sys/stat.h>
#include <unistd.h>

#include "castore.h"
#include "def.h"
#include "realloc-buffer.h"
#include "util.h"

struct CaStore {
        CaStoreType type;
        char *root;
        bool compress;
};

CaStore* ca_store_new(void) {
        CaStore *store;

        store = new0(CaStore, 1);
        if (!store)
                return NULL;

        store->type = _CA_STORE_TYPE_INVALID;
        store->compress = true;
        return store;
}

CaStore* ca_store_unref(CaStore *store) {
        if (!store)
                return NULL;

        free(store->root);

        return mfree(store);
}

int ca_store_set_local(CaStore *store, const char *path) {
        if (!store)
                return -EINVAL;

        if (store->type != _CA_STORE_TYPE_INVALID)
                return -EBUSY;
        if (store->root)
                return -EBUSY;

        store->root = strdup(path);
        if (!store->root)
                return -ENOMEM;

        store->type = CA_STORE_LOCAL;

        return 0;
}

int ca_store_set_compress(CaStore *store, bool b) {
        if (!store)
                return -EINVAL;

        store->compress = b;
        return 0;
}

static int load_uncompressed(int fd, void **ret, size_t *ret_size) {
        ReallocBuffer buffer = {};
        int r;

        assert(fd >= 0);
        assert(ret);
        assert(ret_size);

        for (;;) {
                ssize_t l;
                void *p;

                p = realloc_buffer_extend(&buffer, BUFFER_SIZE);
                if (!p) {
                        r = -ENOMEM;
                        goto fail;
                }

                l = read(fd, p, BUFFER_SIZE);
                if (l < 0) {
                        r = -errno;
                        goto fail;
                }

                realloc_buffer_shorten(&buffer, BUFFER_SIZE - l);
                if (l == 0)
                        break;
        }

        *ret = buffer.data;
        *ret_size = buffer.size;

        return 0;

fail:
        realloc_buffer_free(&buffer);
        return r;
}

static int load_compressed(int fd, void **ret, size_t *ret_size) {
        ReallocBuffer buffer = {};
        lzma_stream xz = {};
        lzma_ret xzr;
        bool got_xz_eof = false;
        int r;

        assert(fd >= 0);
        assert(ret);
        assert(ret_size);

        xzr = lzma_stream_decoder(&xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK);
        if (xzr != LZMA_OK)
                return -EIO;

        for (;;) {
                uint8_t fd_buffer[BUFFER_SIZE];
                ssize_t l;

                l = read(fd, fd_buffer, sizeof(fd_buffer));
                if (l < 0) {
                        r = -errno;
                        goto fail;
                }
                if (l == 0) {
                        if (!got_xz_eof) {
                                r = -EPIPE;
                                goto fail;
                        }

                        break;
                }

                xz.next_in = fd_buffer;
                xz.avail_in = l;

                while (xz.avail_in > 0) {
                        void *p;

                        p = realloc_buffer_extend(&buffer, BUFFER_SIZE);
                        if (!p) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        xz.next_out = p;
                        xz.avail_out = BUFFER_SIZE;

                        xzr = lzma_code(&xz, LZMA_RUN);
                        if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                                r = -EIO;
                                goto fail;
                        }

                        realloc_buffer_shorten(&buffer, xz.avail_out);

                        if (xzr == LZMA_STREAM_END) {

                                if (xz.avail_in > 0) {
                                        r = -EBADMSG;
                                        goto fail;
                                }

                                got_xz_eof = true;
                        }
                }
        }

        lzma_end(&xz);

        *ret = buffer.data;
        *ret_size = buffer.size;

        return 0;

fail:
        realloc_buffer_free(&buffer);
        lzma_end(&xz);

        return r;
}

int ca_store_get(CaStore *store, const ObjectID *object_id, void **ret, size_t *ret_size) {
        char *fn, *sid;
        int fd, r;
        size_t n;

        if (!store)
                return -EINVAL;
        if (!object_id)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        if (!store->root)
                return -ENOTTY;

        n = strlen(store->root);
        fn = newa(char, n + 1 + 4 + 1 + OBJECT_ID_FORMAT_MAX + 3);
        sid = fn + n + 1 + 4 + 1;
        object_id_format(object_id, sid);
        memcpy(mempcpy(mempcpy(mempcpy(fn, store->root, n), "/", 1), sid, 4), "/", 1);

        fd = open(fn, O_CLOEXEC|O_NOCTTY|O_RDONLY);
        if (fd < 0) {
                if (errno != ENOENT)
                        return -errno;

                strcpy(sid + OBJECT_ID_FORMAT_MAX-1, ".xz");

                fd = open(fn, O_CLOEXEC|O_NOCTTY|O_RDONLY);
                if (fd < 0)
                        return -errno;

                r = load_compressed(fd, ret, ret_size);
        } else
                r = load_uncompressed(fd, ret, ret_size);

        /* fprintf(stderr, "Retrieved object %s.\n", sid); */

        safe_close(fd);
        return r;
}

static int save_compressed(int fd, const void *data, size_t size) {
        lzma_stream xz = {};
        lzma_ret xzr;
        int r;

        assert(fd >= 0);
        assert(data);
        assert(size > 0);

        xzr = lzma_easy_encoder(&xz, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
        if (xzr != LZMA_OK)
                return -EIO;

        xz.next_in = data;
        xz.avail_in = size;

        for (;;) {
                uint8_t buffer[BUFFER_SIZE];

                xz.next_out = buffer;
                xz.avail_out = sizeof(buffer);

                xzr = lzma_code(&xz, LZMA_FINISH);
                if (xzr != LZMA_OK && xzr != LZMA_STREAM_END) {
                        r = -EIO;
                        goto fail;
                }

                r = loop_write(fd, buffer, sizeof(buffer) - xz.avail_out);
                if (r < 0)
                        goto fail;

                if (xzr == LZMA_STREAM_END)
                        break;
        }

        r = 0;

fail:
        lzma_end(&xz);
        return r;
}

int ca_store_put(CaStore *store, const ObjectID *object_id, const void *data, size_t size) {
        char *fn, *sid, *d, *t;
        uint64_t u;
        int r, fd;
        size_t n;

        if (!store)
                return -EINVAL;
        if (!object_id)
                return -EINVAL;
        if (!data && size != 0)
                return -EINVAL;

        if (!store->root)
                return -ENOTTY;

        n = strlen(store->root);
        fn = newa(char, n + 1 + 4 + 1 + OBJECT_ID_FORMAT_MAX + 3);
        sid = fn + n + 1 + 4 + 1;
        object_id_format(object_id, sid);
        memcpy(mempcpy(mempcpy(mempcpy(fn, store->root, n), "/", 1), sid, 4), "/", 1);

        if (access(fn, F_OK) >= 0) {
                /* fprintf(stderr, "Object %s exists already.\n", sid); */
                return 0;
        }

        strcpy(sid + OBJECT_ID_FORMAT_MAX - 1, ".xz");
        if (access(fn, F_OK) >= 0) {
                /* fprintf(stderr, "Object %s exists already.\n", sid); */
                return 0;
        }

        if (!store->compress)
                sid[OBJECT_ID_FORMAT_MAX-1] = 0;

        r = dev_urandom(&u, sizeof(u));
        if (r < 0)
                return r;

        (void) mkdir(store->root, 0777);

        d = strndupa(fn, n + 1 + 4);
        (void) mkdir(d, 0777);

        t = newa(char, n + 1 + 4 + 1 + 2 + OBJECT_ID_FORMAT_MAX-1 + 1 + 16 + 4 + 3 + 1);
        sprintf(mempcpy(t, fn, n + 1 + 4 + 1), ".#%s.%016" PRIx64 ".tmp", sid, u);

        fd = open(t, O_CLOEXEC|O_NOCTTY|O_WRONLY|O_CREAT|O_EXCL, 0666);
        if (fd < 0)
                return -errno;

        if (store->compress)
                r = save_compressed(fd, data, size);
        else
                r = loop_write(fd, data, size);

        safe_close(fd);

        if (r < 0) {
                (void) unlink(t);
                return r;
        }

        if (rename(t, fn) < 0) {
                r = -errno;
                (void) unlink(t);
                return r;
        }

        /* fprintf(stderr, "Installed object %s.\n", sid); */

        return 1;
}
