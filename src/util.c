/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/msdos_fs.h>

#if USE_SYS_RANDOM_H
#  include <sys/random.h>
#endif

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the
 * POSIX version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "def.h"
#include "time-util.h"
#include "util.h"

#define HOLE_MIN 4096

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

int loop_write_block(int fd, const void *p, size_t l) {
        if (fd < 0)
                return -EBADF;
        if (!p && l > 0)
                return -EINVAL;

        while (l > 0) {
                ssize_t w;

                w = write(fd, p, l);
                if (w < 0) {
                        if (errno == EAGAIN) {

                                struct pollfd pollfd = {
                                        .fd = fd,
                                        .events = POLLOUT,
                                };

                                if (poll(&pollfd, 1, -1) < 0)
                                        return -errno;

                                continue;
                        }

                        return -errno;
                }

                assert((size_t) w <= l);

                p = (const uint8_t*) p + w;
                l -= w;
        }

        return 0;
}

int write_zeroes(int fd, size_t l) {
        const char *zeroes;
        off_t p, end;
        size_t bs;

        /* Writes the specified number of zero bytes to the current file position. If possible this is done via "hole
         * punching", i.e. by creating sparse files. Unfortunately there's no syscall currently available that
         * implements this efficiently, hence we have to fake it via the existing FALLOC_FL_PUNCH_HOLE operation, which
         * requires us to extend the file size manually if necessary. This means we need 6 syscalls in the worst case,
         * instead of one. Bummer... But this is Linux, so what did you expect? */

        if (fd < 0)
                return -EBADF;
        if (l == 0)
                return 0;

        p = lseek(fd, 0, SEEK_CUR); /* Determine where we are */
        if (p == (off_t) -1)
                goto fallback;

        if (p + (off_t) l < p)
                return -EOVERFLOW;

        end = lseek(fd, 0, SEEK_END); /* Determine file size (this also puts the file offset at the end, but we don't care) */
        if (end == (off_t) -1)
                return -errno;

        if (end > p) {
                if (fallocate(fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, p, l) < 0) {

                        if (lseek(fd, p, SEEK_SET) == (off_t) -1) /* Revert to the original position, before we fallback to write() */
                                return -errno;

                        goto fallback;
                }
        }

        if (p + (off_t) l > end) {
                if (ftruncate(fd, p + l) < 0)
                        return -errno;
        }

        if (lseek(fd, p + l, SEEK_SET) == (off_t) -1) /* Make sure we position the offset now after the hole we just added */
                return -errno;

        return 1; /* Return > 0 when we managed to punch holes */

fallback:
        bs = MIN(4096U, l);
        zeroes = alloca0(bs);

        while (l > 0) {
                ssize_t w;

                w = write(fd, zeroes, MIN(l, bs));
                if (w < 0)
                        return -errno;

                assert((size_t) w <= l);
                l -= w;
        }

        return 0; /* Return == 0 if we could only write out zeroes */
}

static bool memeqzero(const void *data, size_t length) {
        /* Does the buffer consist entirely of NULs?
         * Copied from https://github.com/rustyrussell/ccan/blob/master/ccan/mem/mem.c#L92,
         * which is licensed CC-0.
         */

        const uint8_t *p = data;
        size_t i;

        /* Check first 16 bytes manually */
        for (i = 0; i < 16; i++, length--) {
                if (length == 0)
                        return true;
                if (p[i])
                        return false;
        }

        /* Now we know first 16 bytes are NUL, memcmp with self.  */
        return memcmp(data, p + i, length) == 0;
}

int loop_write_with_holes(int fd, const void *p, size_t l, uint64_t *ret_punched) {
        const uint8_t *q, *start = p, *zero_start = NULL;
        uint64_t n_punched = 0;
        int r;

        /* Write out the specified data much like loop_write(), but try to punch holes for any longer series of zero
         * bytes, thus creating sparse files if possible. */

        for (q = p; q < (const uint8_t*) p + l; ) {
                size_t left = MIN(HOLE_MIN, (const uint8_t*) p + l - q);

                if (memeqzero(q, left)) {
                        if (!zero_start)
                                zero_start = q;

                } else if (zero_start) {
                        if (q - zero_start >= HOLE_MIN) {
                                r = loop_write(fd, start, zero_start - start);
                                if (r < 0)
                                        return r;

                                r = write_zeroes(fd, q - zero_start);
                                if (r < 0)
                                        return r;

                                /* Couldn't punch hole? then don't bother again */
                                if (r == 0) {
                                        r = loop_write(fd, q, (const uint8_t*) p + l - q);
                                        if (r < 0)
                                                return r;

                                        goto success;
                                }

                                n_punched += q - zero_start;
                                start = q;
                        }

                        zero_start = NULL;
                }

                q += left;
        }

        if (zero_start)
                if (q - zero_start >= HOLE_MIN) {
                        r = loop_write(fd, start, zero_start - start);
                        if (r < 0)
                                return r;

                        r = write_zeroes(fd, q - zero_start);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                n_punched += q - zero_start;

                        goto success;
                }

        r = loop_write(fd, start, q - start);
        if (r < 0)
                return r;

 success:
        if (ret_punched)
                *ret_punched = n_punched;

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

#if !HAVE_GETRANDOM
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

char octchar(int x) {
        return '0' + (x & 7);
}

char hexchar(int x) {
        static const char table[16] = "0123456789abcdef";

        return table[x & 15];
}

int unhexchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

        return -EINVAL;
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

        if (dot_or_dot_dot(p))
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

char *ls_format_chattr(unsigned flags, char ret[LS_FORMAT_CHATTR_MAX]) {

        static const struct {
                unsigned flag;
                char code;
        } table[] = {
                { FS_SYNC_FL,        'S' },
                { FS_DIRSYNC_FL,     'D' },
                { FS_IMMUTABLE_FL,   'i' },
                { FS_APPEND_FL,      'a' },
                { FS_NODUMP_FL,      'd' },
                { FS_NOATIME_FL,     'A' },
                { FS_COMPR_FL,       'c' },
                { FS_NOCOMP_FL,      'N' }, /* Not an official one, but one we made up, since lsattr(1) doesn't know it. Subject to change, as soon as it starts supporting that. */
                { FS_NOCOW_FL,       'C' },
                { FS_PROJINHERIT_FL, 'P' },
        };

        size_t i;

        if (flags == (unsigned) -1)
                return NULL;

        assert(ELEMENTSOF(table) == LS_FORMAT_CHATTR_MAX-1);

        for (i = 0; i < ELEMENTSOF(table); i++)
                ret[i] = flags & table[i].flag ? table[i].code : '-';

        ret[i] = 0;

        return ret;
}

char *ls_format_fat_attrs(uint32_t flags, char ret[LS_FORMAT_FAT_ATTRS_MAX]) {

        static const struct {
                uint32_t flag;
                char code;
        } table[] = {
                { ATTR_HIDDEN, 'h' },
                { ATTR_SYS,    's' },
                { ATTR_ARCH,   'a' },
        };

        size_t i;

        if (flags == (uint32_t) -1)
                return NULL;

        assert(ELEMENTSOF(table) == LS_FORMAT_FAT_ATTRS_MAX-1);

        for (i = 0; i < ELEMENTSOF(table); i++)
                ret[i] = flags & table[i].flag ? table[i].code : '-';

        ret[i] = 0;

        return ret;
}

int safe_atoi(const char *s, int *ret_i) {
        char *x = NULL;
        long l;

        assert(s);
        assert(ret_i);

        errno = 0;
        l = strtol(s, &x, 0);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x)
                return -EINVAL;
        if ((long) (int) l != l)
                return -ERANGE;

        *ret_i = (int) l;
        return 0;
}

int safe_atou(const char *s, unsigned *ret_u) {
        char *x = NULL;
        unsigned long l;

        assert(s);

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
        if (*s == '-')
                return -ERANGE;
        if ((unsigned long) (unsigned) l != l)
                return -ERANGE;

        if (ret_u)
                *ret_u = (unsigned) l;

        return 0;
}

int safe_atollu(const char *s, long long unsigned *ret_llu) {
        char *x = NULL;
        unsigned long long l;

        assert(s);

        s += strspn(s, WHITESPACE);

        errno = 0;
        l = strtoull(s, &x, 0);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if (*s == '-')
                return -ERANGE;

        if (ret_llu)
                *ret_llu = l;

        return 0;
}

int safe_atollx(const char *s, long long unsigned *ret_llu) {
        char *x = NULL;
        unsigned long long l;

        assert(s);

        s += strspn(s, WHITESPACE);

        errno = 0;
        l = strtoull(s, &x, 16);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if (*s == '-')
                return -ERANGE;

        if (ret_llu)
                *ret_llu = l;

        return 0;
}

int readlinkat_malloc(int fd, const char *p, char **ret) {
        size_t l = 256;
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

char *strextend(char **x, ...) {
        va_list ap;
        size_t f, l;
        char *r, *p;

        assert(x);

        l = f = *x ? strlen(*x) : 0;

        va_start(ap, x);
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
        va_end(ap);

        r = realloc(*x, l+1);
        if (!r)
                return NULL;

        p = r + f;

        va_start(ap, x);
        for (;;) {
                const char *t;

                t = va_arg(ap, const char *);
                if (!t)
                        break;

                p = stpcpy(p, t);
        }
        va_end(ap);

        *p = 0;
        *x = r;

        return r + l;
}

bool uid_is_valid(uid_t uid) {

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) UINT32_C(0xFFFFFFFF))
                return false;

        /* A long time ago UIDs where 16bit, hence explicitly avoid the 16bit -1 too */
        if (uid == (uid_t) UINT32_C(0xFFFF))
                return false;

        return true;
}

int parse_uid(const char *s, uid_t *ret) {
        uint32_t uid = 0;
        int r;

        assert(s);

        assert(sizeof(uid_t) == sizeof(uint32_t));
        r = safe_atou32(s, &uid);
        if (r < 0)
                return r;

        if (!uid_is_valid(uid))
                return -ENXIO; /* we return ENXIO instead of EINVAL
                                * here, to make it easy to distuingish
                                * invalid numeric uids from invalid
                                * strings. */

        if (ret)
                *ret = uid;

        return 0;
}

int wait_for_terminate(pid_t pid, siginfo_t *status) {
        siginfo_t dummy;

        assert(pid >= 1);

        if (!status)
                status = &dummy;

        for (;;) {
                memset(status, 0, sizeof(siginfo_t));

                if (waitid(P_PID, pid, status, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                return 0;
        }
}

char *strv_find(char **l, const char *name) {
        char **i;

        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

size_t page_size(void) {
        static size_t pgsz = 0;
        long v;

        if (_likely_(pgsz > 0))
                return pgsz;

        v = sysconf(_SC_PAGESIZE);
        assert(v > 0);

        pgsz = (size_t) v;
        return pgsz;
}

int parse_boolean(const char *v) {
        if (!v)
                return -EINVAL;

        if (streq(v, "1") || strcaseeq(v, "yes") || strcaseeq(v, "y") || strcaseeq(v, "true") || strcaseeq(v, "t") || strcaseeq(v, "on"))
                return 1;
        if (streq(v, "0") || strcaseeq(v, "no") || strcaseeq(v, "n") || strcaseeq(v, "false") || strcaseeq(v, "f") || strcaseeq(v, "off"))
                return 0;

        return -EINVAL;
}

int getenv_bool(const char *p) {
        const char *e;

        e = getenv(p);
        if (!e)
                return -ENXIO;

        return parse_boolean(e);
}

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size) {
        size_t a, newalloc;
        void *q;

        assert(p);
        assert(allocated);

        if (*allocated >= need)
                return *p;

        newalloc = MAX(need * 2, 64u / size);
        a = newalloc * size;

        /* check for overflows */
        if (a < size * need)
                return NULL;

        q = realloc(*p, a);
        if (!q)
                return NULL;

        *p = q;
        *allocated = newalloc;
        return q;
}

void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size) {
        size_t prev;
        uint8_t *q;

        assert(p);
        assert(allocated);

        prev = *allocated;

        q = greedy_realloc(p, allocated, need, size);
        if (!q)
                return NULL;

        if (*allocated > prev)
                memzero(q + prev * size, (*allocated - prev) * size);

        return q;
}

int skip_bytes_fd(int fd, uint64_t n_bytes) {
        void *p;
        size_t m;

        if (fd < 0)
                return -EBADF;
        if (n_bytes == 0)
                return 0;

        if (lseek(fd, n_bytes, SEEK_CUR) == (off_t) -1) {
                if (errno != -ESPIPE)
                        return -errno;
        } else
                return 0;

        m = (size_t) MIN(n_bytes, (uint64_t) PIPE_BUF);
        p = alloca(m);

        for (;;) {
                ssize_t k;

                k = read(fd, p, m);
                if (k < 0)
                        return -errno;
                if (k == 0)
                        return -ENXIO;

                n_bytes -= k;

                if (n_bytes == 0)
                        return 0;

                m = (size_t) MIN(n_bytes, (uint64_t) PIPE_BUF);
        }
}

char *truncate_nl(char *p) {

        char *e;

        for (e = strchr(p, 0); e > p; e --)
                if (!strchr(NEWLINE, e[-1]))
                        break;

        *e = 0;

        return p;
}

int rename_noreplace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
        int r;

        if (renameat2(olddirfd, oldpath, newdirfd, newpath, RENAME_NOREPLACE) >= 0)
                return 0;

        /* renameat2() exists since Linux 3.15, btrfs added support for it later.  If it is not implemented, fallback
         * to another method. */
        if (!ERRNO_IS_UNSUPPORTED(errno))
                return -errno;

        /* Let's try linkat(). This will of course failure for non-files, but that's fine. */
        if (linkat(olddirfd, oldpath, newdirfd, newpath, 0) >= 0) {
                if (unlinkat(olddirfd, oldpath, 0) >= 0)
                        return 0;

                r = -errno;
                (void) unlinkat(newdirfd, newpath, 0);
                return r;
        } else if (!ERRNO_IS_UNSUPPORTED(errno))
                return -errno;

        /* if renameat2 and linkat aren't supported, fallback to faccessat+renameat,
         * it isn't atomic but that's the best we can do */
        if (faccessat(newdirfd, newpath, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return -EEXIST;

        if (errno != ENOENT)
                return -errno;

        if (renameat(olddirfd, oldpath, newdirfd, newpath) < 0)
                return -errno;

        return 0;
}

char* path_startswith(const char *path, const char *prefix) {
        assert(path);
        assert(prefix);

        /* Returns a pointer to the start of the first component after the parts matched by
         * the prefix, iff
         * - both paths are absolute or both paths are relative,
         * and
         * - each component in prefix in turn matches a component in path at the same position.
         * An empty string will be returned when the prefix and path are equivalent.
         *
         * Returns NULL otherwise.
         */

        if ((path[0] == '/') != (prefix[0] == '/'))
                return NULL;

        for (;;) {
                size_t a, b;

                path += strspn(path, "/");
                prefix += strspn(prefix, "/");

                if (*prefix == 0)
                        return (char*) path;

                if (*path == 0)
                        return NULL;

                a = strcspn(path, "/");
                b = strcspn(prefix, "/");

                if (a != b)
                        return NULL;

                if (memcmp(path, prefix, a) != 0)
                        return NULL;

                path += a;
                prefix += b;
        }
}

static int getenv_tmp_dir(const char **ret_path) {
        const char *n;
        int r, ret = 0;

        assert(ret_path);

        /* We use the same order of environment variables python uses in tempfile.gettempdir():
         * https://docs.python.org/3/library/tempfile.html#tempfile.gettempdir */
        FOREACH_STRING(n, "TMPDIR", "TEMP", "TMP") {
                const char *e;

                e = secure_getenv(n);
                if (!e)
                        continue;
                if (!path_is_absolute(e)) {
                        r = -ENOTDIR;
                        goto next;
                }
                if (!path_is_safe(e)) {
                        r = -EPERM;
                        goto next;
                }

                r = is_dir(e, true);
                if (r < 0)
                        goto next;
                if (r == 0) {
                        r = -ENOTDIR;
                        goto next;
                }

                *ret_path = e;
                return 1;

        next:
                /* Remember first error, to make this more debuggable */
                if (ret >= 0)
                        ret = r;
        }

        if (ret < 0)
                return ret;

        *ret_path = NULL;
        return ret;
}

static int tmp_dir_internal(const char *def, const char **ret) {
        const char *e;
        int r, k;

        assert(def);
        assert(ret);

        r = getenv_tmp_dir(&e);
        if (r > 0) {
                *ret = e;
                return 0;
        }

        k = is_dir(def, true);
        if (k == 0)
                k = -ENOTDIR;
        if (k < 0)
                return r < 0 ? r : k;

        *ret = def;
        return 0;
}

int var_tmp_dir(const char **ret) {

        /* Returns the location for "larger" temporary files, that is backed by physical storage if available, and thus
         * even might survive a boot: /var/tmp. If $TMPDIR (or related environment variables) are set, its value is
         * returned preferably however. Note that both this function and tmp_dir() below are affected by $TMPDIR,
         * making it a variable that overrides all temporary file storage locations. */

        return tmp_dir_internal("/var/tmp", ret);
}

int tmp_dir(const char **ret) {

        /* Similar to var_tmp_dir() above, but returns the location for "smaller" temporary files, which is usually
         * backed by an in-memory file system: /tmp. */

        return tmp_dir_internal("/tmp", ret);
}

bool path_is_safe(const char *p) {

        if (isempty(p))
                return false;

        if (dot_or_dot_dot(p))
                return false;

        if (startswith(p, "../") || endswith(p, "/..") || strstr(p, "/../"))
                return false;

        if (strlen(p)+1 > PATH_MAX)
                return false;

        return true;
}

int is_dir(const char* path, bool follow) {
        struct stat st;
        int r;

        assert(path);

        if (follow)
                r = stat(path, &st);
        else
                r = lstat(path, &st);
        if (r < 0)
                return -errno;

        return !!S_ISDIR(st.st_mode);
}

int free_and_strdup(char **p, const char *s) {
        char *t;

        assert(p);

        /* Replaces a string pointer with an strdup()ed new string, possibly freeing the old one. */

        if (streq_ptr(*p, s))
                return 0;

        if (s) {
                t = strdup(s);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free(*p);
        *p = t;

        return 1;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, funlockfile);

int read_line(FILE *f, size_t limit, char **ret) {
        _cleanup_free_ char *buffer = NULL;
        size_t n = 0, allocated = 0, count = 0;

        assert(f);

        /* Something like a bounded version of getline().
         *
         * Considers EOF, \n and \0 end of line delimiters, and does not include these delimiters in the string
         * returned.
         *
         * Returns the number of bytes read from the files (i.e. including delimiters — this hence usually differs from
         * the number of characters in the returned string). When EOF is hit, 0 is returned.
         *
         * The input parameter limit is the maximum numbers of characters in the returned string, i.e. excluding
         * delimiters. If the limit is hit we fail and return -ENOBUFS.
         *
         * If a line shall be skipped ret may be initialized as NULL. */

        if (ret) {
                if (!GREEDY_REALLOC(buffer, allocated, 1))
                        return -ENOMEM;
        }

        {
                _unused_ _cleanup_(funlockfilep) FILE *flocked = f;
                flockfile(f);

                for (;;) {
                        int c;

                        if (n >= limit)
                                return -ENOBUFS;

                        errno = 0;
                        c = fgetc_unlocked(f);
                        if (c == EOF) {
                                /* if we read an error, and have no data to return, then propagate the error */
                                if (ferror_unlocked(f) && n == 0)
                                        return errno > 0 ? -errno : -EIO;

                                break;
                        }

                        count++;

                        if (IN_SET(c, '\n', 0)) /* Reached a delimiter */
                                break;

                        if (ret) {
                                if (!GREEDY_REALLOC(buffer, allocated, n + 2))
                                        return -ENOMEM;

                                buffer[n] = (char) c;
                        }

                        n++;
                }
        }

        if (ret) {
                buffer[n] = 0;

                *ret = buffer;
                buffer = NULL;
        }

        return (int) count;
}

char *delete_trailing_chars(char *s, const char *bad) {
        char *p, *c = s;

        /* Drops all specified bad characters, at the end of the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (p = s; *p; p++)
                if (!strchr(bad, *p))
                        c = p + 1;

        *c = 0;

        return s;
}

char *strstrip(char *s) {
        if (!s)
                return NULL;

        delete_trailing_chars(s, WHITESPACE);
        return s + strspn(s, WHITESPACE);
}
