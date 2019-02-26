/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef footimeutilfoo
#define footimeutilfoo

#define USEC_INFINITY ((uint64_t) -1)
#define NSEC_INFINITY ((uint64_t) -1)

#define MSEC_PER_SEC  1000ULL
#define USEC_PER_SEC  ((uint64_t) 1000000ULL)
#define USEC_PER_MSEC ((uint64_t) 1000ULL)
//#define NSEC_PER_SEC  ((uint64_t) 1000000000ULL) already defined in util.h
#define NSEC_PER_MSEC ((uint64_t) 1000000ULL)
#define NSEC_PER_USEC ((uint64_t) 1000ULL)

#define USEC_PER_MINUTE ((uint64_t) (60ULL*USEC_PER_SEC))
#define NSEC_PER_MINUTE ((uint64_t) (60ULL*NSEC_PER_SEC))
#define USEC_PER_HOUR ((uint64_t) (60ULL*USEC_PER_MINUTE))
#define NSEC_PER_HOUR ((uint64_t) (60ULL*NSEC_PER_MINUTE))
#define USEC_PER_DAY ((uint64_t) (24ULL*USEC_PER_HOUR))
#define NSEC_PER_DAY ((uint64_t) (24ULL*NSEC_PER_HOUR))
#define USEC_PER_WEEK ((uint64_t) (7ULL*USEC_PER_DAY))
#define NSEC_PER_WEEK ((uint64_t) (7ULL*NSEC_PER_DAY))
#define USEC_PER_MONTH ((uint64_t) (2629800ULL*USEC_PER_SEC))
#define NSEC_PER_MONTH ((uint64_t) (2629800ULL*NSEC_PER_SEC))
#define USEC_PER_YEAR ((uint64_t) (31557600ULL*USEC_PER_SEC))
#define NSEC_PER_YEAR ((uint64_t) (31557600ULL*NSEC_PER_SEC))

char *format_timespan(char *buf, size_t l, uint64_t t, uint64_t accuracy);

#endif
