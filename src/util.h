/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef fooutilhfoo
#define fooutilhfoo

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include <linux/btrfs.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/types.h>

#include "gcc-macro.h"
#include "log.h"

#define new(t, n) ((t*) malloc((n) * sizeof(t)))
#define new0(t, n) ((t*) calloc((n), sizeof(t)))

#define newa(t, n) ((t*) alloca((n) * sizeof(t)))

#define XCONCATENATE(x, y) x ## y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

#undef MAX
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define __MAX(aq, a, bq, b)                             \
        __extension__ ({                                \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A,aq) > UNIQ_T(B,bq) ? UNIQ_T(A,aq) : UNIQ_T(B,bq); \
        })

#define MAX3(a, b, c) MAX(MAX(a, b), c)

#undef MIN
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define __MIN(aq, a, bq, b)                             \
        __extension__ ({                                \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A,aq) < UNIQ_T(B,bq) ? UNIQ_T(A,aq) : UNIQ_T(B,bq); \
        })

#define CONST_MAX(_A, _B) \
        __extension__ (__builtin_choose_expr(                           \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                __builtin_types_compatible_p(typeof(_A), typeof(_B)),   \
                ((_A) > (_B)) ? (_A) : (_B),                            \
                (void)0))



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

int loop_write(int fd, const void *p, size_t l);
int loop_write_block(int fd, const void *p, size_t l);
ssize_t loop_read(int fd, void *p, size_t l);

int write_zeroes(int fd, size_t l);
int loop_write_with_holes(int fd, const void *p, size_t l, uint64_t *ret_punched);

int skip_bytes(int fd, uint64_t bytes);

char *endswith(const char *p, const char *suffix);

static inline void* mfree(void* p) {
        free(p);
        return NULL;
}

static inline int safe_close_above(int above, int fd) {
        if (fd >= above) {
                int saved_errno = errno;
                assert_se(close(fd) >= 0 || errno != EBADF);
                errno = saved_errno;
        }

        return -1;
}

static inline int safe_close(int fd) {
        return safe_close_above(0, fd);
}

static inline int safe_closep(int *fd) {
        return safe_close(*fd);
}

static inline void safe_close_nonstdp(int *fd) {
        safe_close_above(STDERR_FILENO, *fd);
}

static inline FILE *safe_fclose(FILE *f) {
        if (f)
                fclose(f);

        return NULL;
}

static inline void safe_fclosep(FILE **f) {
        if (f && *f)
                fclose(*f);
}

typedef uint16_t le16_t;
typedef uint32_t le32_t;
typedef uint64_t le64_t;

static inline uint64_t read_le64(const void *p) {
        uint64_t u;
        assert(p);
        memcpy(&u, p, sizeof(uint64_t));
        return le64toh(u);
}

static inline uint32_t read_le32(const void *p) {
        uint32_t u;
        assert(p);
        memcpy(&u, p, sizeof(uint32_t));
        return le32toh(u);
}

static inline uint16_t read_le16(const void *p) {
        uint16_t u;
        assert(p);
        memcpy(&u, p, sizeof(uint16_t));
        return le16toh(u);
}

static inline void write_le64(void *p, uint64_t u) {
        assert(p);
        u = htole64(u);
        memcpy(p, &u, sizeof(uint64_t));
}

static inline void write_le32(void *p, uint32_t u) {
        assert(p);
        u = htole32(u);
        memcpy(p, &u, sizeof(uint32_t));
}

static inline void write_le16(void *p, uint16_t u) {
        assert(p);
        u = htole16(u);
        memcpy(p, &u, sizeof(uint16_t));
}

static inline void* memdup(const void *p, size_t size) {
        void *q;

        q = malloc(size);
        if (!q)
                return NULL;

        memcpy(q, p, size);
        return q;
}

int dev_urandom(void *p, size_t n);

static inline uint64_t random_u64(void) {
        uint64_t u;
        dev_urandom(&u, sizeof(u));
        return u;
}

#define random_bytes(p, n) dev_urandom(p, n)

#define assert_cc(expr) static_assert(expr, #expr)

#define CASE_F(X) case X:
#define CASE_F_1(CASE, X) CASE_F(X)
#define CASE_F_2(CASE, X, ...)  CASE(X) CASE_F_1(CASE, __VA_ARGS__)
#define CASE_F_3(CASE, X, ...)  CASE(X) CASE_F_2(CASE, __VA_ARGS__)
#define CASE_F_4(CASE, X, ...)  CASE(X) CASE_F_3(CASE, __VA_ARGS__)
#define CASE_F_5(CASE, X, ...)  CASE(X) CASE_F_4(CASE, __VA_ARGS__)
#define CASE_F_6(CASE, X, ...)  CASE(X) CASE_F_5(CASE, __VA_ARGS__)
#define CASE_F_7(CASE, X, ...)  CASE(X) CASE_F_6(CASE, __VA_ARGS__)
#define CASE_F_8(CASE, X, ...)  CASE(X) CASE_F_7(CASE, __VA_ARGS__)
#define CASE_F_9(CASE, X, ...)  CASE(X) CASE_F_8(CASE, __VA_ARGS__)
#define CASE_F_10(CASE, X, ...) CASE(X) CASE_F_9(CASE, __VA_ARGS__)
#define CASE_F_11(CASE, X, ...) CASE(X) CASE_F_10(CASE, __VA_ARGS__)
#define CASE_F_12(CASE, X, ...) CASE(X) CASE_F_11(CASE, __VA_ARGS__)
#define CASE_F_13(CASE, X, ...) CASE(X) CASE_F_12(CASE, __VA_ARGS__)
#define CASE_F_14(CASE, X, ...) CASE(X) CASE_F_13(CASE, __VA_ARGS__)
#define CASE_F_15(CASE, X, ...) CASE(X) CASE_F_14(CASE, __VA_ARGS__)
#define CASE_F_16(CASE, X, ...) CASE(X) CASE_F_15(CASE, __VA_ARGS__)
#define CASE_F_17(CASE, X, ...) CASE(X) CASE_F_16(CASE, __VA_ARGS__)
#define CASE_F_18(CASE, X, ...) CASE(X) CASE_F_17(CASE, __VA_ARGS__)
#define CASE_F_19(CASE, X, ...) CASE(X) CASE_F_18(CASE, __VA_ARGS__)
#define CASE_F_20(CASE, X, ...) CASE(X) CASE_F_19(CASE, __VA_ARGS__)

#define GET_CASE_F(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,NAME,...) NAME
#define FOR_EACH_MAKE_CASE(...) \
        GET_CASE_F(__VA_ARGS__,CASE_F_20,CASE_F_19,CASE_F_18,CASE_F_17,CASE_F_16,CASE_F_15,CASE_F_14,CASE_F_13,CASE_F_12,CASE_F_11, \
                               CASE_F_10,CASE_F_9,CASE_F_8,CASE_F_7,CASE_F_6,CASE_F_5,CASE_F_4,CASE_F_3,CASE_F_2,CASE_F_1) \
                   (CASE_F,__VA_ARGS__)

#define IN_SET(x, ...)                          \
        ({                                      \
                bool _found = false;            \
                /* If the build breaks in the line below, you need to extend the case macros */ \
                static _unused_ char _static_assert__macros_need_to_be_extended[20 - sizeof((int[]){__VA_ARGS__})/sizeof(int)]; \
                switch(x) {                     \
                FOR_EACH_MAKE_CASE(__VA_ARGS__) \
                        _found = true;          \
                        break;                  \
                default:                        \
                        break;                  \
                }                               \
                _found;                         \
        })

char hexchar(int x);
int unhexchar(char c);
char octchar(int x);

char *hexmem(const void *p, size_t l);

bool filename_is_valid(const char *p);
int tempfn_random(const char *p, char **ret);

static inline bool isempty(const char *p) {
        return !p || !p[0];
}

static inline const char *strempty(const char *p) {
        return p ?: "";
}

static inline const char *strnone(const char *p) {
        return p ?: "none";
}

#define streq(a,b) (strcmp((a),(b)) == 0)

static inline bool streq_ptr(const char *a, const char *b) {
        if (!a && !b)
                return true;
        if (!a || !b)
                return false;

        return streq(a, b);
}

static inline const char *strna(const char *p) {
        return p ?: "n/a";
}

void hexdump(FILE *f, const void *p, size_t s);
char* dirname_malloc(const char *path);

char *strjoin_real(const char *x, ...) _sentinel_;
#define strjoin(a, ...) strjoin_real((a), __VA_ARGS__, NULL)

#define LS_FORMAT_MODE_MAX (1+3+3+3+1)
char* ls_format_mode(mode_t m, char ret[LS_FORMAT_MODE_MAX]);

#define LS_FORMAT_CHATTR_MAX 11
char *ls_format_chattr(unsigned flags, char ret[LS_FORMAT_CHATTR_MAX]);

#define LS_FORMAT_FAT_ATTRS_MAX 4
char *ls_format_fat_attrs(unsigned flags, char ret[LS_FORMAT_FAT_ATTRS_MAX]);

int safe_atoi(const char *s, int *ret_i);

int safe_atou(const char *s, unsigned *ret_u);
int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atollx(const char *s, unsigned long long *ret_u);

static inline int safe_atou64(const char *s, uint64_t *ret_u) {
        return safe_atollu(s, (unsigned long long*) ret_u);
}

static inline int safe_atou32(const char *s, uint32_t *ret_u) {
        return safe_atou(s, (unsigned*) ret_u);
}

static inline int safe_atox64(const char *s, uint64_t *ret_u) {
        return safe_atollx(s, (unsigned long long*) ret_u);
}

int readlinkat_malloc(int fd, const char *p, char **ret);
int readlink_malloc(const char *p, char **ret);

#define strjoina(a, ...)                                                \
        ({                                                              \
                const char *_appendees_[] = { a, __VA_ARGS__ };         \
                char *_d_, *_p_;                                        \
                int _len_ = 0;                                          \
                unsigned _i_;                                           \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _len_ += strlen(_appendees_[_i_]);              \
                _p_ = _d_ = alloca(_len_ + 1);                          \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _p_ = stpcpy(_p_, _appendees_[_i_]);            \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })

#define WHITESPACE " \t"
#define NEWLINE "\n\r"

#define ELEMENTSOF(x)                                                    \
        __extension__ (__builtin_choose_expr(                            \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                                \
                (void)0))

char **strv_free(char **l);
size_t strv_length(char **l);
int strv_push(char ***l, char *value);
int strv_consume(char ***l, char *value);
int strv_extend(char ***l, const char *value);
char *strv_find(char **l, const char *name) _pure_;

#define strv_contains(l, s) (!!strv_find((l), (s)))

static inline bool size_multiply_overflow(size_t size, size_t need) {
        return need != 0 && size > (SIZE_MAX / need);
}

_malloc_  _alloc_(1, 2) static inline void *malloc_multiply(size_t size, size_t need) {
        if (_unlikely_(size_multiply_overflow(size, need)))
                return NULL;

        return malloc(size * need);
}

_alloc_(2, 3) static inline void *realloc_multiply(void *p, size_t size, size_t need) {
        if (_unlikely_(size_multiply_overflow(size, need)))
                return NULL;

        return realloc(p, size * need);
}

#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)

int xopendirat(int fd, const char *name, int flags, DIR **ret);

static inline bool dot_or_dot_dot(const char *p) {
        if (!p)
                return false;

        if (p[0] != '.')
                return false;

        if (p[1] == 0)
                return true;

        if (p[1] != '.')
                return false;

        return p[2] == 0;
}

void progress(void);

char *strextend(char **x, ...) _sentinel_;

#if SIZEOF_UID_T == 4
#  define UID_FMT "%" PRIu32
#elif SIZEOF_UID_T == 2
#  define UID_FMT "%" PRIu16
#else
#  error Unknown uid_t size
#endif

#if SIZEOF_GID_T == 4
#  define GID_FMT "%" PRIu32
#elif SIZEOF_GID_T == 2
#  define GID_FMT "%" PRIu16
#else
#  error Unknown gid_t size
#endif

#if SIZEOF_PID_T == 4
#  define PID_PRI PRIi32
#elif SIZEOF_PID_T == 2
#  define PID_PRI PRIi16
#else
#  error Unknown pid_t size
#endif
#define PID_FMT "%" PID_PRI

bool uid_is_valid(uid_t uid);

static inline bool gid_is_valid(gid_t gid) {
        return uid_is_valid((uid_t) gid);
}

int parse_uid(const char *s, uid_t* ret_uid);

static inline int parse_gid(const char *s, gid_t *ret_gid) {
        return parse_uid(s, (uid_t*) ret_gid);
}

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

#define ALPHABET_LOWER "abcdefghijklmnopqrstuvwxyz"
#define ALPHABET_UPPER "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ALPHABET ALPHABET_LOWER ALPHABET_UPPER
#define DIGITS "0123456789"
#define HEXDIGITS DIGITS "ABCDEF" "abcdef"

/* This is a bit more restricted than RFC3986 */
#define URL_PROTOCOL_FIRST ALPHABET_LOWER
#define URL_PROTOCOL_CHARSET ALPHABET_LOWER DIGITS "+.-"
#define HOSTNAME_CHARSET ALPHABET DIGITS "-_."

int wait_for_terminate(pid_t pid, siginfo_t *status);

static inline void safe_close_pair(int pair[2]) {
        if (!pair)
                return;

        pair[0] = safe_close(pair[0]);
        pair[1] = safe_close(pair[1]);
}

static inline char *startswith(const char *s, const char *prefix) {
        size_t l;

        l = strlen(prefix);
        if (strncmp(s, prefix, l) == 0)
                return (char*) s + l;

        return NULL;
}

static inline bool strv_isempty(char **l) {
        return !l || !l[0];
}

#if !HAVE_RENAMEAT2
#  ifndef __NR_renameat2
#    if defined __x86_64__
#      define __NR_renameat2 316
#    elif defined __alpha__
#      define __NR_renameat2 510
#    elif defined __arm__
#      define __NR_renameat2 382
#    elif defined __aarch64__
#      define __NR_renameat2 276
#    elif defined __hppa__
#      define __NR_renameat2 337
#    elif defined __ia64__
#      define __NR_renameat2 1338
#    elif defined __m68k__
#      define __NR_renameat2 351
#    elif defined _MIPS_SIM
#      if _MIPS_SIM == _MIPS_SIM_ABI32
#        define __NR_renameat2 4351
#      endif
#      if _MIPS_SIM == _MIPS_SIM_NABI32
#        define __NR_renameat2 6315
#      endif
#      if _MIPS_SIM == _MIPS_SIM_ABI64
#        define __NR_renameat2 5311
#      endif
#    elif defined __i386__
#      define __NR_renameat2 353
#    elif defined __powerpc64__ || defined __powerpc__
#      define __NR_renameat2 357
#    elif defined __s390__ || defined __s390x__
#      define __NR_renameat2 347
#    elif defined __sh__
#      define __NR_renameat2 371
#    elif defined __sh64__
#      define __NR_renameat2 382
#    elif defined __sparc__
#      define __NR_renameat2 345
#    elif defined __arc__
#      define __NR_renameat2 276
#    else
#      warning "__NR_renameat2 unknown for your architecture"
#    endif
#  endif

static inline int renameat2(int oldfd, const char *oldname, int newfd, const char *newname, unsigned flags) {
#  ifdef __NR_renameat2
        return syscall(__NR_renameat2, oldfd, oldname, newfd, newname, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

static inline size_t strlen_null(const char *s) {
        if (!s)
                return 0;

        return strlen(s);
}

#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))

#define FOREACH_STRING(x, y, ...)                                       \
        for (char **_l = STRV_MAKE(({ x = y; }), ##__VA_ARGS__);        \
             x;                                                         \
             x = *(++_l))

#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)

static inline const char *empty_or_dash_to_null(const char *s) {
        if (isempty(s))
                return NULL;
        if (streq(s, "-"))
                return NULL;

        return s;
}

size_t page_size(void);

static inline size_t ALIGN_TO(size_t l, size_t ali) {
        return ((l + ali - 1) & ~(ali - 1));
}
#define PAGE_ALIGN(l) ALIGN_TO((l), page_size())

/* We align a bit more than necessary on 32bit arches */
#define ALIGN8(l) (((l) + 7) & ~7)
#define ALIGN(l) ALIGN8(l)

int parse_boolean(const char *v);

int getenv_bool(const char *p);

#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)

typedef typeof(((struct statfs*)NULL)->f_type) statfs_f_type_t;

static inline bool F_TYPE_EQUAL(statfs_f_type_t a, statfs_f_type_t b) {
        return a == b;
}

static inline bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) {
        assert(s);
        return F_TYPE_EQUAL(s->f_type, magic_value);
}

static inline bool is_temporary_fs(const struct statfs *s) {
    return is_fs_type(s, TMPFS_MAGIC) ||
           is_fs_type(s, RAMFS_MAGIC);
}

#define IS_POWER_OF_TWO(x) (__builtin_popcount(x) == 1)

static inline const char *yes_no(bool b) {
        return b ? "yes" : "no";
}

#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

#ifndef CONFIGFS_MAGIC
#define CONFIGFS_MAGIC 0x62656570
#endif

#ifndef MQUEUE_MAGIC
#define MQUEUE_MAGIC 0x19800202
#endif

#ifndef RPCAUTH_GSSMAGIC
#define RPCAUTH_GSSMAGIC 0x67596969
#endif

#ifndef NFSD_MAGIC
#define NFSD_MAGIC 0x6e667364
#endif

#ifndef FUSE_CTL_SUPER_MAGIC
#define FUSE_CTL_SUPER_MAGIC 0x65735543
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

#ifndef FICLONERANGE
struct file_clone_range {
        int64_t src_fd;
        uint64_t src_offset;
        uint64_t src_length;
        uint64_t dest_offset;
};

#define FICLONERANGE _IOW(0x94, 13, struct file_clone_range)
#endif

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size);
void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size);

#define GREEDY_REALLOC(array, allocated, need)                          \
        greedy_realloc((void**) &(array), &(allocated), (need), sizeof((array)[0]))

#define GREEDY_REALLOC0(array, allocated, need)                         \
        greedy_realloc0((void**) &(array), &(allocated), (need), sizeof((array)[0]))

#define alloca0(n)                                      \
        ({                                              \
                char *_new_;                            \
                size_t _len_ = n;                       \
                _new_ = alloca(_len_);                  \
                (void *) memset(_new_, 0, _len_);       \
        })

#define memzero(x,l) (memset((x), 0, (l)))
#define zero(x) (memzero(&(x), sizeof(x)))
#define malloc0(n) (calloc(1, (n)))

static inline void *mempset(void *s, int c, size_t n) {
        memset(s, c, n);
        return (uint8_t*)s + n;
}

#define DECIMAL_STR_MAX(type)                                           \
        (1+(sizeof(type) <= 1 ? 3 :                                     \
            sizeof(type) <= 2 ? 5 :                                     \
            sizeof(type) <= 4 ? 10 :                                    \
            sizeof(type) <= 8 ? 20 : sizeof(int[-2*(sizeof(type) > 8)])))

int skip_bytes_fd(int fd, uint64_t n_bytes);

char *truncate_nl(char *p);

#define SOCKADDR_UN_LEN(sa)                                             \
        ({                                                              \
                const struct sockaddr_un *_sa = &(sa);                  \
                assert(_sa->sun_family == AF_UNIX);                     \
                offsetof(struct sockaddr_un, sun_path) +                \
                        (_sa->sun_path[0] == 0 ?                        \
                         1 + strnlen(_sa->sun_path+1, sizeof(_sa->sun_path)-1) : \
                         strnlen(_sa->sun_path, sizeof(_sa->sun_path))); \
        })

static inline uint32_t rol32(uint32_t x, size_t i) {
        i %= 32;

        if (i == 0) /* Make ubsan happy */
                return x;

        return ((x) << (i)) | ((x) >> (32 - i));
}

static inline unsigned log2u(unsigned x) {
        assert(x > 0);

        return sizeof(unsigned) * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u_round_up(unsigned x) {
        assert(x > 0);

        if (x == 1)
                return 0;

        return log2u(x - 1) + 1;
}

#ifndef FS_PROJINHERIT_FL
#define FS_PROJINHERIT_FL 0x20000000
#endif

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

int rename_noreplace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

char* path_startswith(const char *path, const char *prefix);

static inline bool path_is_absolute(const char *p) {
        return p && p[0] == '/';
}

int var_tmp_dir(const char **ret);
int tmp_dir(const char **ret);

bool path_is_safe(const char *p);

int is_dir(const char* path, bool follow);

#ifndef BTRFS_IOC_SUBVOL_GETFLAGS
#define BTRFS_IOC_SUBVOL_GETFLAGS _IOR(BTRFS_IOCTL_MAGIC, 25, __u64)
#endif

#ifndef BTRFS_IOC_SUBVOL_SETFLAGS
#define BTRFS_IOC_SUBVOL_SETFLAGS _IOW(BTRFS_IOCTL_MAGIC, 26, __u64)
#endif

#ifndef FS_IOC_FSGETXATTR
struct fsxattr {
        uint32_t fsx_xflags;
        uint32_t fsx_extsize;
        uint32_t fsx_nextents;
        uint32_t fsx_projid;
        uint32_t fsx_cowextsize;
        uint8_t  fsx_pad[8];
};
#define FS_IOC_FSGETXATTR _IOR ('X', 31, struct fsxattr)
#define FS_IOC_FSSETXATTR _IOW ('X', 32, struct fsxattr)
#endif

#define NSEC_PER_SEC (UINT64_C(1000000000))

/* Cleanup functions */

#define _cleanup_(x) __attribute__((cleanup(x)))

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }                                                       \
        struct __useless_struct_to_allow_trailing_semicolon__

static inline void freep(void *p) {
        free(*(void**) p);
}

#define _cleanup_free_ _cleanup_(freep)

static inline void unlink_and_free(char *p) {
        int saved_errno;

        if (!p)
                return;

        saved_errno = errno;
        (void) unlink(p);
        errno = saved_errno;

        free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, unlink_and_free);

int free_and_strdup(char **p, const char *s);

/* A check against a list of errors commonly used to indicate that a syscall/ioctl/other kernel operation we request is
 * not supported locally. We maintain a generic list for this here, instead of adjusting the possible error codes to
 * exactly what the calls might return for the simple reasons that due to FUSE and many differing in-kernel
 * implementations of the same calls in various file systems and such the error codes seen varies wildly, and we'd like
 * to cover them all to some degree and be somewhat safe for the future too. */
#define ERRNO_IS_UNSUPPORTED(error) \
        IN_SET(error, ENOTTY, ENOSYS, EBADF, EOPNOTSUPP, EINVAL)

#define LARGE_LINE_MAX (64U*1024U)

int read_line(FILE *f, size_t limit, char **ret);

char *delete_trailing_chars(char *s, const char *bad);
char *strstrip(char *s);

#endif
