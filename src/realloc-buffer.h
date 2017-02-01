#ifndef fooreallocbufferhfoo
#define fooreallocbufferhfoo

#include <sys/types.h>

#include "util.h"

typedef struct ReallocBuffer {
        void *data;
        size_t allocated;
        size_t start;
        size_t end;
} ReallocBuffer;

static inline void *realloc_buffer_data(ReallocBuffer *buffer) {
        assert(buffer);
        assert(buffer->start <= buffer->end);
        assert(buffer->end <= buffer->allocated);
        assert(buffer->data || buffer->allocated == 0);

        if (!buffer->data)
                return buffer;

        return (uint8_t*) buffer->data + buffer->start;
}

static inline void *realloc_buffer_data_offset(ReallocBuffer *buffer, size_t offset) {
        size_t p;

        assert(buffer);
        assert(buffer->start <= buffer->end);
        assert(buffer->end <= buffer->allocated);

        p = buffer->start + offset;
        if (p < buffer->start) /* overflow? */
                return NULL;
        if (p > buffer->end) /* out of bounds? */
                return NULL;

        return (uint8_t*) buffer->data + p;
}

static inline size_t realloc_buffer_size(ReallocBuffer *buffer) {
        assert(buffer);
        assert(buffer->start <= buffer->end);
        assert(buffer->end <= buffer->allocated);

        return buffer->end - buffer->start;
}

void* realloc_buffer_acquire(ReallocBuffer *b, size_t size);
void* realloc_buffer_acquire0(ReallocBuffer *b, size_t size);
void* realloc_buffer_extend(ReallocBuffer *b, size_t size);
void* realloc_buffer_extend0(ReallocBuffer *b, size_t size);
void* realloc_buffer_append(ReallocBuffer *b, const void *p, size_t size);

void realloc_buffer_free(ReallocBuffer *b);

static inline void realloc_buffer_empty(ReallocBuffer *b) {
        b->start = b->end = 0;
}

int realloc_buffer_advance(ReallocBuffer *b, size_t sz);
int realloc_buffer_shorten(ReallocBuffer *b, size_t sz);
int realloc_buffer_truncate(ReallocBuffer *b, size_t sz);

#endif
