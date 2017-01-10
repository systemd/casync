#ifndef fooreallocbufferhfoo
#define fooreallocbufferhfoo

#include <sys/types.h>

typedef struct ReallocBuffer {
        void *data;
        size_t allocated;
        size_t size;
} ReallocBuffer;

void* realloc_buffer_acquire(ReallocBuffer *b, size_t size);
void *realloc_buffer_acquire0(ReallocBuffer *b, size_t size);
void* realloc_buffer_extend(ReallocBuffer *b, size_t size);
void *realloc_buffer_append(ReallocBuffer *b, const void *p, size_t size);

void realloc_buffer_free(ReallocBuffer *b);

static inline void realloc_buffer_empty(ReallocBuffer *b) {
        b->size = 0;
}

int realloc_buffer_advance(ReallocBuffer *b, size_t sz);
int realloc_buffer_shorten(ReallocBuffer *b, size_t sz);
int realloc_buffer_truncate(ReallocBuffer *b, size_t sz);

#endif
