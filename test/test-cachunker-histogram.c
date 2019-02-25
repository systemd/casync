/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>

#include "time-util.h"
#include "util.h"
#include "cachunker.h"

#define BUFFER_SIZE (64*1024)
#define CHUNKS_MAX 1000000
#define THREADS_MAX 16
#define RUNTIME_NSEC UINT64_C(2000000000)

struct thread_info {
        pthread_t id;
        CaChunker chunker;
        unsigned *histogram;
        unsigned n_chunks;
        int random_fd;
        uint64_t until;
};

static void* process(void *q) {
        struct thread_info *t = q;
        size_t previous = 0;

        for (;;) {
                uint8_t buffer[BUFFER_SIZE], *p;
                ssize_t l;

                if (t->until < now(CLOCK_MONOTONIC))
                        return NULL;

                l = read(t->random_fd, buffer, sizeof(buffer));
                assert_se(l == sizeof(buffer));

                p = buffer;
                for (;;) {
                        size_t n;

                        n = ca_chunker_scan(&t->chunker, true, p, l);
                        if (n == (size_t) -1) {
                                previous += l;
                                break;
                        }

                        assert_se(n <= (size_t) l);

                        assert_se(previous + n >= t->chunker.chunk_size_min);
                        assert_se(previous + n <= t->chunker.chunk_size_max);

                        t->histogram[previous + n] ++;
                        t->n_chunks ++;

                        p += n;
                        l -= n;

                        previous = 0;
                }
        }
}

static void draw(unsigned *histogram, size_t n) {
        #define N_BUCKETS 30
        #define N_HEIGHT 69

        unsigned buckets[N_BUCKETS] = {};
        unsigned highest = 0;
        size_t i;

        for (i = 0; i < n; i++)
                buckets[i * N_BUCKETS / n] += histogram[i];

        for (i = 0; i < N_BUCKETS; i++)
                if (buckets[i] > highest)
                        highest = buckets[i];

        for (i = 0; i < N_BUCKETS; i++) {
                unsigned k, j;

                k = buckets[i] * N_HEIGHT / highest;

                printf("%10zu ", (i+1) * n / N_BUCKETS -1);

                for (j = 0; j < k; j++)
                        putchar('#');

                putchar('\n');
        }
}

static void run(size_t pick, size_t *ret_avg) {
        CaChunker chunker = CA_CHUNKER_INIT;
        unsigned *histogram, n_chunks = 0;
        struct thread_info threads[THREADS_MAX] = {};
        uint64_t until, sum = 0;
        size_t i;
        int fd, r;

        ca_chunker_set_size(&chunker, 0, pick, 0);

        histogram = new0(unsigned, chunker.chunk_size_max+1);
        assert_se(histogram);

        log_info("Min/Avg/Max = %zu/%zu/%zu (discriminator=%zu)",
                 chunker.chunk_size_min,
                 chunker.chunk_size_avg,
                 chunker.chunk_size_max,
                 chunker.discriminator);

        fd = open("/dev/urandom", O_CLOEXEC|O_RDONLY);
        assert_se(fd >= 0);

        until = now(CLOCK_MONOTONIC) + RUNTIME_NSEC;

        for (i = 0; i < THREADS_MAX; i++) {
                threads[i].chunker = chunker;

                threads[i].histogram = new0(unsigned, chunker.chunk_size_max+1);
                assert_se(threads[i].histogram);

                threads[i].random_fd = fd;
                threads[i].until = until;

                r = pthread_create(&threads[i].id, NULL, process, threads + i);
                assert_se(r == 0);
        }

        for (i = 0; i < THREADS_MAX; i++) {
                size_t j;

                r = pthread_join(threads[i].id, NULL);
                assert_se(r == 0);

                for (j = 0; j <= chunker.chunk_size_max; j++) {
                        histogram[j] += threads[i].histogram[j];
                        sum += threads[i].histogram[j] * j;
                }

                n_chunks += threads[i].n_chunks;

                free(threads[i].histogram);
        }

        log_info("Generated %u chunks.", n_chunks);
        log_info("Effective average is %" PRIu64 ".", sum / n_chunks);

        *ret_avg = sum / n_chunks;

        draw(histogram, chunker.chunk_size_max+1);

        free(histogram);
        safe_close(fd);

        return;
}

int main(int argc, char* argv[]) {
        size_t avg, start, end, step;

        if (argc > 1) {
                start = 4096;
                end = 1024*1024;
                step = 4*1024;
        } else {
                start = CA_CHUNK_SIZE_AVG_DEFAULT;
                end = CA_CHUNK_SIZE_AVG_DEFAULT+1;
                step = 1;
        }

        for (avg = start; avg < end; avg += step) {

                size_t effective_avg;
                double factor;

                run(avg, &effective_avg);

                factor = (double) effective_avg  / (double) avg;

                printf("%zu\t%zu\t%g\n", avg, effective_avg, factor);
                log_error("Asked for average: %zu — Got average: %zu — Factor: %g", avg, effective_avg, factor);
        }

        return 0;
}
