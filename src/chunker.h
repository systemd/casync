#ifndef foochunkerhfoo
#define foochunkerhfoo

#include <inttypes.h>
#include <sys/types.h>
#include <stdbool.h>

/* Our checksum window size */
#define WINDOW_SIZE 48

/* The hardcoded, maximum chunk size, after which we refuse operation */
#define CHUNK_SIZE_LIMIT (128U*1024U*1024U)

typedef struct CaChunker {
        uint16_t a, b;
        size_t window_size;
        size_t chunk_size;

        size_t chunk_size_min;
        size_t chunk_size_max;
        size_t chunk_size_avg;

        uint8_t window[WINDOW_SIZE];
} CaChunker;

/* The default initializer for the chunker. We pick an average chunk size equivalent to 16K */
#define CA_CHUNKER_INIT { .a = 1, .chunk_size_min = 3840, .chunk_size_avg = 16381, .chunk_size_max = 28928 }

/* Set the maximum size as passed as parameter and derive the minimum and average size from that.
 * This can only be invoked until the chunker is started. */
int ca_chunker_set_avg_size(CaChunker *c, size_t max_size);

/* Scans the specified data for a chunk border. Returns (size_t) -1 if none was found (and the function should be
 * called with more data later on), or another value indicating the position of a border. */
size_t ca_chunker_scan(CaChunker *c, const void* p, size_t n);

/* Low-level Adler-32 functions. Only exported for testing purposes. */
uint32_t ca_chunker_start(CaChunker *c, const void *p, size_t n);
uint32_t ca_chunker_roll(CaChunker *c, uint8_t pop_byte, uint8_t push_byte);

bool ca_size_is_prime(size_t n);

#endif
