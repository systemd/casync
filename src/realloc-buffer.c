/* SPDX-License-Identifier: LGPL-2.1+ */

#include <assert.h>
#include <stdarg.h>
#include <unistd.h>

#include "def.h"
#include "realloc-buffer.h"
#include "util.h"

/* Safety net: don't permit buffers beyond 1G in size */
#define REALLOC_BUFFER_MAX (1024UL*1024LU*1024LU)

void* realloc_buffer_acquire(ReallocBuffer *b, size_t size) {
        size_t ns, na, ne;
        void *p;

        if (!b)
                return NULL;

        if (size == 0) {
                b->start = b->end = 0;

                /* If a buffer of size 0 is requested, that's OK and not an error. On non-error we want to return
                 * non-NULL, but also not actually allocate any memory. Hence return a pointer to the ReallocBuffer
                 * object itself, as that's a known valid pointer. */

                return b->data ?: b;
        }
        if (_unlikely_(size > REALLOC_BUFFER_MAX))
                return NULL;

        ne = b->start + size;
        if (_unlikely_(ne < b->start)) /* overflow? */
                return NULL;

        if (ne <= b->allocated) {
                b->end = ne;
                return realloc_buffer_data(b);
        }

        na = b->allocated * 2;
        if (_unlikely_(na < b->allocated)) /* overflow? */
                return NULL;
        if (_unlikely_(na > REALLOC_BUFFER_MAX))
                na = REALLOC_BUFFER_MAX;

        ns = MAX(na, size);
        ns = ALIGN_TO(ns, page_size());

        if (b->start == 0) {
                p = realloc(b->data, ns);
                if (!p)
                        return NULL;
        } else {
                p = malloc(ns);
                if (!p)
                        return NULL;

                memcpy(p, realloc_buffer_data(b), realloc_buffer_size(b));
                free(b->data);

                b->start = 0;
        }

        b->data = p;
        b->end = size;
        b->allocated = ns;

        return b->data;
}

void *realloc_buffer_acquire0(ReallocBuffer *b, size_t size) {
        size_t na, ns;
        void *p;

        if (!b)
                return NULL;

        if (size == 0) {
                b->start = b->end = 0;
                return b->data ?: b;
        }
        if (_unlikely_(size > REALLOC_BUFFER_MAX))
                return NULL;

        if (size < b->allocated) {
                memset(b->data, 0, size);

                b->start = 0;
                b->end = size;

                return realloc_buffer_data(b);
        }

        na = b->allocated * 2;
        if (_unlikely_(na < b->allocated)) /* overflow? */
                return NULL;
        if (_unlikely_(na > REALLOC_BUFFER_MAX))
                na = REALLOC_BUFFER_MAX;

        ns = MAX(na, size);
        ns = ALIGN_TO(ns, page_size());

        p = calloc(ns, 1);
        if (!p)
                return NULL;

        free(b->data);
        b->data = p;
        b->allocated = ns;
        b->start = 0;
        b->end = size;

        return b->data;
}

void *realloc_buffer_extend(ReallocBuffer *b, size_t add) {
        size_t old_size, new_size;
        void *p;

        if (!b)
                return NULL;

        old_size = realloc_buffer_size(b);

        new_size = old_size + add;
        if (_unlikely_(new_size < old_size)) /* overflow? */
                return NULL;

        p = realloc_buffer_acquire(b, new_size);
        if (!p)
                return NULL;

        return (uint8_t*) p + old_size;
}

void *realloc_buffer_extend0(ReallocBuffer *b, size_t add) {
        void *p;

        p = realloc_buffer_extend(b, add);
        if (!p)
                return NULL;

        memset(p, 0, add);
        return p;
}

void *realloc_buffer_append(ReallocBuffer *b, const void *p, size_t size) {
        void *m;

        if (!b)
                return NULL;

        m = realloc_buffer_extend(b, size);
        if (!m)
                return NULL;

        memcpy(m, p, size);
        return m;
}

void realloc_buffer_free(ReallocBuffer *b) {
        if (!b)
                return;

        b->data = mfree(b->data);
        b->allocated = b->end = b->start = 0;
}

int realloc_buffer_advance(ReallocBuffer *b, size_t sz) {
        size_t ns;

        /* Remove something from the beginning of the buffer */

        if (!b)
                return -EINVAL;

        if (sz == 0)
                return 0;

        ns = b->start + sz;
        if (_unlikely_(ns < b->start)) /* Overflow? */
                return -EINVAL;
        if (_unlikely_(ns > b->end))
                return -EINVAL;

        if (ns == b->end)
                b->start = b->end = 0;
        else
                b->start = ns;

        return 0;
}

int realloc_buffer_shorten(ReallocBuffer *b, size_t sz) {

        /* Remove something from the end of the buffer */

        if (!b)
                return -EINVAL;
        if (_unlikely_(sz > realloc_buffer_size(b)))
                return -EINVAL;
        if (sz == 0)
                return 0;

        b->end -= sz;

        if (b->end == b->start)
                b->start = b->end = 0;

        return 0;
}

int realloc_buffer_truncate(ReallocBuffer *b, size_t sz) {
        if (!b)
                return -EINVAL;

        if (sz == 0) {
                b->start = b->end = 0;
                return 0;
        }

        if (_unlikely_(sz > realloc_buffer_size(b)))
                return -EINVAL;

        b->end = b->start + sz;
        return 0;
}

int realloc_buffer_read_size(ReallocBuffer *b, int fd, size_t add) {
        ssize_t l;
        void *p;

        if (!b)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (add == (size_t) -1 || add < BUFFER_SIZE)
                add = BUFFER_SIZE;

        p = realloc_buffer_extend(b, add);
        if (!p)
                return -ENOMEM;

        l = read(fd, p, add);
        if (l < 0) {
                realloc_buffer_shorten(b, add);
                return -errno;
        }

        realloc_buffer_shorten(b, add - l);
        return l > 0;
}

int realloc_buffer_read_full(ReallocBuffer *b, int fd, size_t limit) {
        int r;

        /* Reads from "fd" until EOF is hit, but never more than "limit" */

        for (;;) {
                if (limit != (size_t) -1 && realloc_buffer_size(b) > limit)
                        return -E2BIG;

                r = realloc_buffer_read(b, fd);
                if (r <= 0)
                        return r;
        }
}

int realloc_buffer_read_target(ReallocBuffer *b, int fd, size_t target_size) {
        int r;

        if (!b)
                return -EINVAL;

        /* Reads data from the specified fd until the buffer contains at least target_size bytes. Returns > 0 if the
         * size is reached, 0 if not (due to EOF) */

        for (;;) {
                size_t c;

                c = realloc_buffer_size(b);
                if (c >= target_size)
                        return 1;

                r = realloc_buffer_read_size(b, fd, target_size - c);
                if (r <= 0)
                        return r;
        }
}

void* realloc_buffer_steal(ReallocBuffer *b) {
        void *p;

        if (!b)
                return NULL;

        if (b->start == 0) {
                p = b->data;
                b->data = NULL;
        } else {
                p = memdup(realloc_buffer_data(b), realloc_buffer_size(b));
                if (!p)
                        return NULL;

                b->data = mfree(b->data);
        }

        b->start = b->end = b->allocated = 0;

        return p;
}

void* realloc_buffer_donate(ReallocBuffer *b, void *p, size_t size) {
        if (!b)
                return NULL;

        if (realloc_buffer_size(b) > 0) {
                void *ret;

                ret = realloc_buffer_append(b, p, size);
                if (!ret)
                        return NULL;

                free(p);
                return ret;
        }

        free(b->data);
        b->data = p;
        b->start = 0;
        b->allocated = b->end = size;

        return p;
}

int realloc_buffer_write(ReallocBuffer *b, int fd) {
        size_t done = 0;
        int r;

        if (!b)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        for (;;) {
                size_t l;
                ssize_t n;

                l = realloc_buffer_size(b);
                if (l <= 0)
                        return done > 0;

                n = write(fd, realloc_buffer_data(b), l);
                if (n < 0)
                        return -errno;

                r = realloc_buffer_advance(b, (size_t) n);
                if (r < 0)
                        return r;

                done += (size_t) n;
        }
}

int realloc_buffer_write_maybe(ReallocBuffer *b, int fd) {

        if (!b)
                return -EINVAL;

        /* Much like realloc_buffer_write(), but only write things if we collected a certain amount of data */

        if (realloc_buffer_size(b) < BUFFER_SIZE)
                return 0;

        return realloc_buffer_write(b, fd);
}

int realloc_buffer_printf(ReallocBuffer *b, const char *fmt, ...) {
        size_t m = 256;

        if (!b)
                return -EINVAL;
        if (!fmt)
                return -EINVAL;

        for (;;) {
                va_list ap;
                size_t mm;
                void *p;
                int n;

                p = realloc_buffer_extend(b, m);
                if (!p)
                        return -ENOMEM;

                va_start(ap, fmt);
                n = vsnprintf(p, m, fmt, ap);
                va_end(ap);

                if (n < (int) m) {
                        realloc_buffer_shorten(b, m - n);
                        return 0;
                }

                realloc_buffer_shorten(b, m);

                mm = 2 * m;
                if (mm < m)
                        return -EOVERFLOW;

                m = mm;
        }

}

int realloc_buffer_memchr(ReallocBuffer *buffer, uint8_t c) {
        const uint8_t *p, *q;
        size_t l, d;
        int ret;

        /* Looks for byte 'c' in the buffer. Returns -ENXIO when we can't find the byte. Returns an index >= 0 if
         * found. Returns -EOVERFLOW if found but the index doesn't fit in "int" */

        l = realloc_buffer_size(buffer);
        if (l <= 0)
                return -ENXIO;

        p = realloc_buffer_data(buffer);
        q = memchr(p, c, l);
        if (!q)
                return -ENXIO;

        d = (size_t) (q - p);
        ret = (int) d;

        if (_unlikely_(ret < 0))
                return -EOVERFLOW;
        if (_unlikely_((size_t) ret != d))
                return -EOVERFLOW;

        return ret;
}
