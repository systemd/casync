#include "chunker.h"
#include "util.h"

/* The modulo used by Adler32: the largest prime smaller than 2^16, see RFC1950 */
#define MODULO 65521U

/* How many bytes we can push into the checksum before we have to calculate the modulo. This is merely an
 * optimization. See RFC1950 for details. */
#define BYTES_PUSH_MAX 5552U

bool ca_size_is_prime(size_t n) {
        size_t i;

        if (n <= 1)
                return false;
        if (n <= 3)
                return true;
        if (n % 2 == 0 || n % 3 == 0)
                return false;

        i = 5;
        while (i*i <= n) {
                if ((n % i == 0) || (n % (i + 2) == 0))
                        return false;

                i += 6;
        }

        return true;
}

int ca_chunker_set_avg_size(CaChunker *c, size_t avg) {
        size_t delta, closest;

        assert(c);

        /* Find an average block size that is close to the requested number but is prime,
         * because this number is used in the modulo operation that determines the chunk
         * break points and we don't want to waste any bits there. */

        if (avg < 1)
                return -EINVAL;
        if (avg > CA_CHUNK_SIZE_LIMIT)
                return -EINVAL;

        if (c->window_size != 0)
                return -EBUSY;

        for (delta = 0;; delta++) {
                if (delta >= avg)
                        return -EINVAL;

                closest = avg - delta;
                if (ca_size_is_prime(closest))
                        break;

                if (delta == 0)
                        continue;

                if (delta > CA_CHUNK_SIZE_LIMIT - avg)
                        return -EINVAL;

                closest = avg + delta;
                if (ca_size_is_prime(closest))
                        break;
        }

        c->chunk_size_avg = closest;

        c->chunk_size_min = (c->chunk_size_avg / 4) & ~0xff;
        if (c->chunk_size_min < 1)
                c->chunk_size_min = 1;

        c->chunk_size_max = (2*c->chunk_size_avg - c->chunk_size_min + 0xffU) & ~0xffU;
        if (c->chunk_size_max > CA_CHUNK_SIZE_LIMIT)
                c->chunk_size_max = CA_CHUNK_SIZE_LIMIT;

        /* fprintf(stderr, "Setting min/avg/max chunk size: %zu/%zu/%zu (requested: %zu)\n", */
        /*         c->chunk_size_min, c->chunk_size_avg, c->chunk_size_max, avg); */

        return 0;
}

uint32_t ca_chunker_start(CaChunker *c, const void *p, size_t n) {
        const uint8_t *q = p;
        uint32_t a, b;

        assert(c);
        assert(c->window_size + n <= UINT32_MAX);

        assert(0 < c->chunk_size_min);
        assert(c->chunk_size_min <= c->chunk_size_avg);
        assert(c->chunk_size_avg <= c->chunk_size_max);
        assert(c->chunk_size_max <= CA_CHUNK_SIZE_LIMIT);

        a = (uint32_t) c->a, b = (uint32_t) c->b;

        c->window_size += n;

        while (n > 0) {
                size_t m;

                m = MIN(n, BYTES_PUSH_MAX);
                n -= m;

                for (; m > 0; m--) {
                        a += *(q++);
                        b += a;
                }

                a %= MODULO;
                b %= MODULO;
        }

        c->a = (uint16_t) a, c->b = (uint16_t) b;

        return b << 16 | a;
}

uint32_t ca_chunker_roll(CaChunker *c, uint8_t leave, uint8_t enter) {
        uint32_t a, b, t;

        assert(c);

        a = (uint32_t) c->a, b = (uint32_t) c->b;

        a = (a + MODULO + enter - leave) % MODULO;
        t = c->window_size * leave;
        b = (b + (t / MODULO + 1) * MODULO + a - t - 1) % MODULO;

        c->a = (uint16_t) a, c->b = (uint16_t) b;

        return b << 16 | a;
}

static bool shall_break(CaChunker *c, uint32_t v) {
        assert(c);

        if (c->chunk_size >= c->chunk_size_max)
                return true;

        if (c->chunk_size < c->chunk_size_min)
                return false;

        return (v % c->chunk_size_avg) == (c->chunk_size_avg - 1);
}

size_t ca_chunker_scan(CaChunker *c, const void* p, size_t n) {
        const uint8_t *q = p;
        uint32_t v;
        size_t k = 0, idx;

        assert(c);
        assert(p);

        /* Scans the specified bytes for chunk borders. Returns (size_t) -1 if no border was discovered, otherwise the
         * chunk size. */

        if (c->window_size < CA_CHUNKER_WINDOW_SIZE) {
                size_t m;

                m = MIN(CA_CHUNKER_WINDOW_SIZE - c->window_size, n);
                memcpy(c->window + c->window_size, q, m);

                v = ca_chunker_start(c, q, m);
                c->chunk_size += m;
                k = m;

                if (shall_break(c, v))
                        goto now;

                q += m, n -= m;
        }

        idx = c->chunk_size % CA_CHUNKER_WINDOW_SIZE;

        while (n > 0) {
                v = ca_chunker_roll(c, c->window[idx], *q);
                c->chunk_size++;
                k++;

                if (shall_break(c, v))
                        goto now;

                c->window[idx++] = *q;
                if (idx == CA_CHUNKER_WINDOW_SIZE)
                        idx = 0;

                q++, n--;
        }

        return (size_t) -1;

now:
        c->a = 1;
        c->b = 0;
        c->chunk_size = 0;
        c->window_size = 0;

        return k;
}
