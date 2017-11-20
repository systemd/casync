/* SPDX-License-Identifier: CC0-1.0 */

#ifndef foosiphash24hfoo

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct siphash {
        uint64_t v0;
        uint64_t v1;
        uint64_t v2;
        uint64_t v3;
        uint64_t padding;
        size_t inlen;
};

void siphash24_init(struct siphash *state, const uint8_t k[16]);
void siphash24_compress(const void *in, size_t inlen, struct siphash *state);
#define siphash24_compress_byte(byte, state) siphash24_compress((const uint8_t[]) { (byte) }, 1, (state))

uint64_t siphash24_finalize(struct siphash *state);

uint64_t siphash24(const void *in, size_t inlen, const uint8_t k[16]);

#endif
