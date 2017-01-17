#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <time.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the
 * POSIX version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "def.h"
#include "util.h"

int loop_write(int fd, const void *p, size_t l) {

        if (fd < 0)
                return -EBADF;
        if (!p && l > 0)
                return -EINVAL;

        while (l > 0) {
                ssize_t w;

                w = write(fd, p, l);
                if (w < 0)
                        return -errno;

                assert((size_t) w <= l);

                p = (const uint8_t*) p + w;
                l -= w;
        }

        return 0;
}

ssize_t loop_read(int fd, void *p, size_t l) {
        ssize_t sum = 0;

        if (fd < 0)
                return -EBADF;
        if (!p)
                return -EINVAL;
        if (l == 0)
                return -EINVAL;

        while (l > 0) {
                ssize_t r;

                r = read(fd, p, l);
                if (r < 0)
                        return -errno;
                if (r == 0)
                        break;

                p = (uint8_t*) p + r;
                l -= r;
                sum += r;
        }

        return sum;
}

int skip_bytes(int fd, uint64_t bytes) {
        size_t buffer_size;
        void *m;
        off_t p;

        if (bytes == 0)
                return 0;

        p = lseek(fd, (off_t) bytes, SEEK_CUR);
        if (p != (off_t) -1)
                return 0;

        buffer_size = MIN(bytes, BUFFER_SIZE);
        m = alloca(buffer_size);

        do {
                ssize_t l;

                l = read(fd, m, MIN(bytes, buffer_size));
                if (l < 0)
                        return -errno;
                if (l == 0)
                        return -EPIPE;

                assert((uint64_t) l <= bytes);
                bytes -= l;

        } while (bytes > 0);

        return 0;
}

char *endswith(const char *p, const char *suffix) {
        size_t a, b;
        const char *e;

        a = strlen(p);
        b = strlen(suffix);

        if (b > a)
                return NULL;

        e = p + a - b;

        return strcmp(e, suffix) == 0 ? (char*) e : NULL;
}

#if !HAVE_DECL_GETRANDOM
#  ifndef __NR_getrandom
#    if defined __x86_64__
#      define __NR_getrandom 318
#    elif defined(__i386__)
#      define __NR_getrandom 355
#    elif defined(__arm__)
#      define __NR_getrandom 384
#   elif defined(__aarch64__)
#      define __NR_getrandom 278
#    elif defined(__ia64__)
#      define __NR_getrandom 1339
#    elif defined(__m68k__)
#      define __NR_getrandom 352
#    elif defined(__s390x__)
#      define __NR_getrandom 349
#    elif defined(__powerpc__)
#      define __NR_getrandom 359
#    elif defined _MIPS_SIM
#      if _MIPS_SIM == _MIPS_SIM_ABI32
#        define __NR_getrandom 4353
#      endif
#      if _MIPS_SIM == _MIPS_SIM_NABI32
#        define __NR_getrandom 6317
#      endif
#      if _MIPS_SIM == _MIPS_SIM_ABI64
#        define __NR_getrandom 5313
#      endif
#    else
#      warning "__NR_getrandom unknown for your architecture"
#    endif
#  endif

static inline int getrandom(void *buffer, size_t count, unsigned flags) {
#  ifdef __NR_getrandom
        return syscall(__NR_getrandom, buffer, count, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif

#ifndef GRND_RANDOM
#define GRND_RANDOM 0x0002
#endif

int dev_urandom(void *p, size_t n) {
        static int have_syscall = -1;
        int fd, r;
        ssize_t l;

        if (have_syscall != 0 || (size_t) (int) n != n) {
                r = getrandom(p, n, GRND_NONBLOCK);
                if (r == (int) n) {
                        have_syscall = true;
                        return 0;
                }

                if (r < 0) {
                        if (errno == ENOSYS)
                                have_syscall = false;
                        else if (errno == EAGAIN)
                                have_syscall = true;
                        else
                                return -errno;
                } else
                        return -ENODATA;
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return errno == ENOENT ? -ENOSYS : -errno;

        l = loop_read(fd, p, n);
        (void) close(fd);

        if (l < 0)
                return (int) l;
        if ((size_t) l != n)
                return -EIO;

        return 0;
}

static char hexchar(int x) {
        static const char table[16] = "0123456789abcdef";

        return table[x & 15];
}

char *hexmem(const void *p, size_t l) {
        const uint8_t *x;
        char *r, *z;

        z = r = new(char, l * 2 + 1);
        if (!r)
                return NULL;

        for (x = p; x < (const uint8_t*) p + l; x++) {
                *(z++) = hexchar(*x >> 4);
                *(z++) = hexchar(*x & 15);
        }

        *z = 0;
        return r;
}

bool filename_is_valid(const char *p) {
        const char *e;

        if (isempty(p))
                return false;

        if (streq(p, "."))
                return false;

        if (streq(p, ".."))
                return false;

        e = strchrnul(p, '/');
        if (*e != 0)
                return false;

        if (e - p > FILENAME_MAX)
                return false;

        return true;
}

int tempfn_random(const char *p, char **ret) {
        const char *fn;
        char *t, *x;
        uint64_t u;
        unsigned i;

        assert(p);
        assert(ret);

        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this:
         *         /foo/bar/.#waldobaa2a261115984a9
         */

        fn = basename(p);
        if (!filename_is_valid(fn))
                return -EINVAL;

        t = new(char, strlen(p) + 2 + 16 + 1);
        if (!t)
                return -ENOMEM;

        x = stpcpy(stpcpy(mempcpy(t, p, fn - p), ".#"), fn);

        u = random_u64();
        for (i = 0; i < 16; i++) {
                *(x++) = hexchar(u & 0xF);
                u >>= 4;
        }

        *x = 0;

        *ret = t;
        return 0;
}

void hexdump(FILE *f, const void *p, size_t s) {
        const uint8_t *b = p;
        unsigned n = 0;

        assert(s == 0 || b);

        if (!f)
                f = stdout;

        while (s > 0) {
                size_t i;

                fprintf(f, "%04x  ", n);

                for (i = 0; i < 16; i++) {

                        if (i >= s)
                                fputs("   ", f);
                        else
                                fprintf(f, "%02x ", b[i]);

                        if (i == 7)
                                fputc(' ', f);
                }

                fputc(' ', f);

                for (i = 0; i < 16; i++) {

                        if (i >= s)
                                fputc(' ', f);
                        else
                                fputc(isprint(b[i]) ? (char) b[i] : '.', f);
                }

                fputc('\n', f);

                if (s < 16)
                        break;

                n += 16;
                b += 16;
                s -= 16;
        }
}

char* dirname_malloc(const char *path) {
        char *d, *dir, *dir2;

        assert(path);

        d = strdup(path);
        if (!d)
                return NULL;

        dir = dirname(d);
        assert(dir);

        if (dir == d)
                return d;

        dir2 = strdup(dir);
        free(d);

        return dir2;
}

char *strjoin_real(const char *x, ...) {
        va_list ap;
        size_t l;
        char *r, *p;

        va_start(ap, x);

        if (x) {
                l = strlen(x);

                for (;;) {
                        const char *t;
                        size_t n;

                        t = va_arg(ap, const char *);
                        if (!t)
                                break;

                        n = strlen(t);
                        if (n > ((size_t) -1) - l) {
                                va_end(ap);
                                return NULL;
                        }

                        l += n;
                }
        } else
                l = 0;

        va_end(ap);

        r = new(char, l+1);
        if (!r)
                return NULL;

        if (x) {
                p = stpcpy(r, x);

                va_start(ap, x);

                for (;;) {
                        const char *t;

                        t = va_arg(ap, const char *);
                        if (!t)
                                break;

                        p = stpcpy(p, t);
                }

                va_end(ap);
        } else
                r[0] = 0;

        return r;
}

char* ls_format_mode(mode_t m, char ret[LS_FORMAT_MODE_MAX]) {

        if (m == (mode_t) -1)
                return NULL;

        switch (m & S_IFMT) {

        case S_IFSOCK:
                ret[0] = 's';
                break;

        case S_IFDIR:
                ret[0] = 'd';
                break;

        case S_IFREG:
                ret[0] = '-';
                break;

        case S_IFBLK:
                ret[0] = 'b';
                break;

        case S_IFCHR:
                ret[0] = 'c';
                break;

        case S_IFLNK:
                ret[0] = 'l';
                break;

        case S_IFIFO:
                ret[0] = 'p';
                break;

        default:
                return NULL;
        }

        ret[1] = m & 0400 ? 'r' : '-';
        ret[2] = m & 0200 ? 'w' : '-';
        ret[3] = (m & S_ISUID) ? (m & 0100 ? 's' : 'S') : (m & 0100 ? 'x' : '-');

        ret[4] = m & 0040 ? 'r' : '-';
        ret[5] = m & 0020 ? 'w' : '-';
        ret[6] = (m & S_ISGID) ? (m & 0010 ? 's' : 'S') : (m & 0010 ? 'x' : '-');

        ret[7] = m & 0004 ? 'r' : '-';
        ret[8] = m & 0002 ? 'w' : '-';
        ret[9] = (S_ISDIR(m) && (m & S_ISVTX)) ? (m & 0001 ? 't' : 'T') : (m & 0001 ? 'x' : '-');

        ret[10] = 0;

        return ret;
}

int safe_atou(const char *s, unsigned *ret_u) {
        char *x = NULL;
        unsigned long l;

        assert(s);
        assert(ret_u);

        /* strtoul() is happy to parse negative values, and silently
         * converts them to unsigned values without generating an
         * error. We want a clean error, hence let's look for the "-"
         * prefix on our own, and generate an error. But let's do so
         * only after strtoul() validated that the string is clean
         * otherwise, so that we return EINVAL preferably over
         * ERANGE. */

        s += strspn(s, WHITESPACE);

        errno = 0;
        l = strtoul(s, &x, 0);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x)
                return -EINVAL;
        if (s[0] == '-')
                return -ERANGE;
        if ((unsigned long) (unsigned) l != l)
                return -ERANGE;

        *ret_u = (unsigned) l;
        return 0;
}

int safe_atollu(const char *s, long long unsigned *ret_llu) {
        char *x = NULL;
        unsigned long long l;

        assert(s);
        assert(ret_llu);

        s += strspn(s, WHITESPACE);

        errno = 0;
        l = strtoull(s, &x, 0);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x)
                return -EINVAL;
        if (*s == '-')
                return -ERANGE;

        *ret_llu = l;
        return 0;
}

int readlinkat_malloc(int fd, const char *p, char **ret) {
        size_t l = 100;
        int r;

        assert(p);
        assert(ret);

        for (;;) {
                char *c;
                ssize_t n;

                c = new(char, l);
                if (!c)
                        return -ENOMEM;

                n = readlinkat(fd, p, c, l-1);
                if (n < 0) {
                        r = -errno;
                        free(c);
                        return r;
                }

                if ((size_t) n < l-1) {
                        c[n] = 0;
                        *ret = c;
                        return 0;
                }

                free(c);
                l *= 2;
        }
}

int readlink_malloc(const char *p, char **ret) {
        return readlinkat_malloc(AT_FDCWD, p, ret);
}

char **strv_free(char **l) {
        char **k;

        if (!l)
                return NULL;

        for (k = l; *k; k++)
                free(*k);

        return mfree(l);
}

size_t strv_length(char **l) {
        size_t n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

int strv_push(char ***l, char *value) {
        char **c;
        unsigned n, m;

        assert(l);

        if (!value)
                return 0;

        n = strv_length(*l);

        /* Increase and check for overflow */
        m = n + 2;
        if (m < n)
                return -ENOMEM;

        c = realloc_multiply(*l, sizeof(char*), m);
        if (!c)
                return -ENOMEM;

        c[n] = value;
        c[n+1] = NULL;

        *l = c;
        return 0;
}

int strv_consume(char ***l, char *value) {
        int r;

        assert(l);

        r = strv_push(l, value);
        if (r < 0)
                free(value);

        return r;
}

int strv_extend(char ***l, const char *value) {
        char *v;

        assert(l);

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        return strv_consume(l, v);
}

int xopendirat(int fd, const char *name, int flags, DIR **ret) {
        int nfd;
        DIR *d;

        nfd = openat(fd, name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|flags, 0);
        if (nfd < 0)
                return -errno;

        d = fdopendir(nfd);
        if (!d) {
                safe_close(nfd);
                return -errno;
        }

        *ret = d;
        return 0;
}

void progress(void) {
        static const char slashes[] = {
                '-',
                '\\',
                '|',
                '/',
        };
        static unsigned i = 0;
        static uint64_t last_nsec = 0;

        struct timespec now;
        static uint64_t now_nsec;

        assert(clock_gettime(CLOCK_MONOTONIC, &now) >= 0);
        now_nsec = timespec_to_nsec(now);

        if (last_nsec + 250000000 > now_nsec)
                return;

        last_nsec = now_nsec;

        fputc(slashes[i % ELEMENTSOF(slashes)], stderr);
        fputc('\b', stderr);
        fflush(stderr);

        i++;
}
