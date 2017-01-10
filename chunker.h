#ifndef foochunkerhfoo
#define foochunkerhfoo

#include <inttypes.h>
#include <sys/types.h>

/* Our checksum window size */
#define WINDOW_SIZE 48

/* The minimum and maximum chunk size to spit out */
#define CHUNK_MIN (4*1024)
#define CHUNK_MAX (64*1024)

/* The average chunk size to spit out (the largest prime smaller than 16*1024) */
#define CHUNK_AVG 16381

typedef struct CaChunker {
        uint16_t a, b;
        size_t window_size;
        size_t chunk_size;
        uint8_t window[WINDOW_SIZE];
} CaChunker;

#define CA_CHUNKER_INIT { .a = 1 }

/* Scans the specified data for a chunk border. Returns (size_t) -1 if none was found (and the function should be
 * called with more data later on), or another value indicating the position of a border. */
size_t ca_chunker_scan(CaChunker *c, const void* p, size_t n);

/* Low-level Adler-32 functions. Only exported for testing purposes. */
uint32_t ca_chunker_start(CaChunker *c, const void *p, size_t n);
uint32_t ca_chunker_roll(CaChunker *c, uint8_t pop_byte, uint8_t push_byte);

#endif
