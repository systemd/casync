/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef footimeutilfoo
#define footimeutilfoo

#include <stdint.h>
#include <time.h>

#define NSEC_INFINITY ((uint64_t) -1)

#define NSEC_PER_SEC  ((uint64_t) UINT64_C(1000000000))
#define NSEC_PER_MSEC ((uint64_t) UINT64_C(1000000))
#define NSEC_PER_USEC ((uint64_t) UINT64_C(1000))

#define NSEC_PER_MINUTE ((uint64_t) (UINT64_C(60)*NSEC_PER_SEC))
#define NSEC_PER_HOUR ((uint64_t) (UINT64_C(60)*NSEC_PER_MINUTE))
#define NSEC_PER_DAY ((uint64_t) (UINT64_C(24)*NSEC_PER_HOUR))
#define NSEC_PER_WEEK ((uint64_t) (UINT64_C(7)*NSEC_PER_DAY))
#define NSEC_PER_MONTH ((uint64_t) (UINT64_C(2629800)*NSEC_PER_SEC))
#define NSEC_PER_YEAR ((uint64_t) (UINT64_C(31557600)*NSEC_PER_SEC))

static inline uint64_t timespec_to_nsec(struct timespec t) {

        if (t.tv_sec == (time_t) -1 &&
            t.tv_nsec == (long) -1)
                return UINT64_MAX;

        return (uint64_t) t.tv_sec * UINT64_C(1000000000) + (uint64_t) t.tv_nsec;
}

static inline struct timespec nsec_to_timespec(uint64_t u) {

        if (u == UINT64_MAX)
                return (struct timespec) {
                        .tv_sec = (time_t) -1,
                        .tv_nsec = (long) -1,
                };

        return (struct timespec) {
                .tv_sec = u / UINT64_C(1000000000),
                .tv_nsec = u % UINT64_C(1000000000)
        };
}

#define NSEC_TO_TIMESPEC_INIT(u) \
        { .tv_sec = u == UINT64_MAX ? (time_t) -1 : (time_t) (u / UINT64_C(1000000000)), \
          .tv_nsec = u == UINT64_MAX ? (long) -1 : (long) (u % UINT64_C(1000000000)) }

static inline uint64_t now(clockid_t id) {
        struct timespec ts;

        if (clock_gettime(id, &ts) < 0)
                return UINT64_MAX;

        return timespec_to_nsec(ts);
}

char *format_timespan(char *buf, size_t l, uint64_t t, uint64_t accuracy);

#endif
