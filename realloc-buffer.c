#include <unistd.h>
#include <assert.h>

#include "util.h"
#include "realloc-buffer.h"

void* realloc_buffer_acquire(ReallocBuffer *b, size_t size) {
        if (!b)
                return NULL;

        if (b->allocated < size) {
                size_t ns, na;
                void *p;

                na = b->allocated*2;
                if (na < b->allocated)
                        return NULL;

                ns = MAX(na, size);

                p = realloc(b->data, ns);
                if (!p)
                        return NULL;

                b->data = p;
                b->allocated = ns;
        }

        b->size = size;
        return b->data;
}

void *realloc_buffer_acquire0(ReallocBuffer *b, size_t size) {
        if (!b)
                return NULL;

        if (b->allocated < size) {
                size_t na, ns;
                void *p;

                na = b->allocated*2;
                if (na < b->allocated)
                        return NULL;

                ns = MAX(na, size);

                p = calloc(ns, 1);
                if (!p)
                        return NULL;

                free(b->data);
                b->data = p;
                b->allocated = ns;
        } else
                memset(b->data, 0, size);

        b->size = size;

        return b->data;
}

void *realloc_buffer_extend(ReallocBuffer *b, size_t add) {
        void *p;
        size_t old_size, new_size;

        if (!b)
                return NULL;

        old_size = b->size;
        new_size = old_size + add;

        if (new_size < old_size)
                return NULL;

        p = realloc_buffer_acquire(b, new_size);
        if (!p)
                return NULL;

        return (uint8_t*) p + old_size;
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
        b->allocated = b->size = 0;
}

int realloc_buffer_advance(ReallocBuffer *b, size_t sz) {

        /* Remove something from the beginning of the buffer */

        if (!b)
                return -EINVAL;

        if (sz > b->size)
                return -EINVAL;

        if (sz == b->size)
                b->size = 0;
        else {
                b->size -= sz;
                memmove(b->data, (uint8_t*) b->data + sz, b->size);
        }

        return 0;
}

int realloc_buffer_shorten(ReallocBuffer *b, size_t sz) {

        /* Remove something from the end of the buffer */

        if (!b)
                return -EINVAL;

        if (sz > b->size)
                return -EINVAL;

        b->size -= sz;
        return 0;
}

int realloc_buffer_truncate(ReallocBuffer *b, size_t sz) {

        if (!b)
                return -EINVAL;
        if (sz > b->size)
                return -EINVAL;

        b->size = sz;
        return 0;
}
