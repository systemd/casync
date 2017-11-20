/* SPDX-License-Identifier: LGPL-2.1+ */

#include <assert.h>
#include <unistd.h>

#include "def.h"
#include "realloc-buffer.h"
#include "util.h"

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

        ne = b->start + size;
        if (ne < b->start) /* overflow? */
                return NULL;

        if (ne <= b->allocated) {
                b->end = ne;
                return realloc_buffer_data(b);
        }

        na = b->allocated * 2;
        if (na < b->allocated) /* overflow? */
                return NULL;

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

        if (size < b->allocated) {
                memset(b->data, 0, size);

                b->start = 0;
                b->end = size;

                return realloc_buffer_data(b);
        }

        na = b->allocated * 2;
        if (na <= b->allocated) /* overflow? */
                return NULL;

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
        if (new_size < old_size) /* overflow? */
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
        if (ns < b->start) /* Overflow? */
                return -EINVAL;
        if (ns > b->end)
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
        if (sz > realloc_buffer_size(b))
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

        if (sz > realloc_buffer_size(b))
                return -EINVAL;

        b->end = b->start + sz;
        return 0;
}

int realloc_buffer_read(ReallocBuffer *b, int fd) {
        ssize_t l;
        void *p;

        if (!b)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        p = realloc_buffer_extend(b, BUFFER_SIZE);
        if (!p)
                return -ENOMEM;

        l = read(fd, p, BUFFER_SIZE);
        if (l < 0) {
                realloc_buffer_shorten(b, BUFFER_SIZE);
                return -errno;
        }

        realloc_buffer_shorten(b, BUFFER_SIZE - l);
        return l > 0;
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
