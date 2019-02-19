/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foochunkerhfoo
#define foochunkerhfoo

#include <inttypes.h>
#include <sys/types.h>
#include <stdbool.h>

#include "cacutmark.h"

/* The default average chunk size */
#define CA_CHUNK_SIZE_AVG_DEFAULT ((size_t) (64U*1024U))

/* Our checksum window size */
#define CA_CHUNKER_WINDOW_SIZE 48

/* The chunk cut discriminator. In order to get an average chunk size of avg, we cut whenever for a hash value "h" at
 * byte "i" given the descriminator "d(avg)": h(i) mod d(avg) == d(avg) - 1. Note that the discriminator
 * calculated like this only yields correct results as long as the minimal chunk size is picked as avg/4, and the
 * maximum chunk size as avg*4. If they are picked differently the result might be skewed into either direction. */
#define CA_CHUNKER_DISCRIMINATOR_FROM_AVG(avg) ((size_t) (avg / (-1.42888852e-7 * avg + 1.33237515)))

typedef struct CaChunker {
        uint32_t h;

        size_t window_size;
        size_t chunk_size;

        size_t chunk_size_min;
        size_t chunk_size_max;
        size_t chunk_size_avg;

        size_t discriminator;

        uint8_t window[CA_CHUNKER_WINDOW_SIZE];

        const CaCutmark *cutmarks;  /* List of defined cutmarks to look for */
        size_t n_cutmarks;

        ssize_t last_cutmark; /* The byte offset we have seen the last cutmark at, relative to the current byte index */
        uint64_t qword_be;    /* The last 8 byte we read, always shifted through and hence in BE format. */
} CaChunker;

/* The default initializer for the chunker. We pick an average chunk size equivalent to 64K */
#define CA_CHUNKER_INIT                                                                        \
        {                                                                                      \
                .chunk_size_min = CA_CHUNK_SIZE_AVG_DEFAULT/4,                                 \
                .chunk_size_avg = CA_CHUNK_SIZE_AVG_DEFAULT,                                   \
                .chunk_size_max = CA_CHUNK_SIZE_AVG_DEFAULT*4,                                 \
                .discriminator = CA_CHUNKER_DISCRIMINATOR_FROM_AVG(CA_CHUNK_SIZE_AVG_DEFAULT), \
        }

/* Set the min/avg/max chunk size. Each parameter may be 0, in which case a default is used. */
int ca_chunker_set_size(CaChunker *c, size_t min_size, size_t avg_size, size_t max_size);

/* Scans the specified data for a chunk border. Returns (size_t) -1 if none was found (and the function should be
 * called with more data later on), or another value indicating the position of a border. */
size_t ca_chunker_scan(CaChunker *c, const void* p, size_t n);

/* Low-level buzhash functions. Only exported for testing purposes. */
uint32_t ca_chunker_start(CaChunker *c, const void *p, size_t n);
uint32_t ca_chunker_roll(CaChunker *c, uint8_t pop_byte, uint8_t push_byte);

#endif
