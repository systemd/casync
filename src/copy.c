/* SPDX-License-Identifier: LGPL-2.1+ */

#include "copy.h"

#if !HAVE_COPY_FILE_RANGE
#  ifndef __NR_copy_file_range
#    if defined(__x86_64__)
#      define __NR_copy_file_range 326
#    elif defined(__i386__)
#      define __NR_copy_file_range 377
#    elif defined __s390__
#      define __NR_copy_file_range 375
#    elif defined __arm__
#      define __NR_copy_file_range 391
#    elif defined __aarch64__
#      define __NR_copy_file_range 285
#    elif defined __powerpc__
#      define __NR_copy_file_range 379
#    else
#      warning "__NR_copy_file_range not defined for your architecture"
#    endif
#  endif

static inline ssize_t copy_file_range(
                int fd_in, loff_t *off_in,
                int fd_out, loff_t *off_out,
                size_t len,
                unsigned flags) {

#  ifdef __NR_copy_file_range
        return syscall(__NR_copy_file_range, fd_in, off_in, fd_out, off_out, len, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

static ssize_t try_copy_file_range(
                int fd_in, loff_t *off_in,
                int fd_out, loff_t *off_out,
                size_t len,
                unsigned flags) {

        static int have = -1;
        ssize_t r;

        if (have == false)
                return -ENOSYS;

        r = copy_file_range(fd_in, off_in, fd_out, off_out, len, flags);
        if (have < 0)
                have = r >= 0 || errno != ENOSYS;
        if (r >= 0)
                return r;
        else
                return -errno;
}

int copy_bytes(int fdf, int fdt, uint64_t max_bytes) {
        bool try_cfr = true, try_sendfile = true, try_splice = true;
        size_t m = SSIZE_MAX; /* that is the maximum that sendfile and c_f_r accept */
        int r;

        assert(fdf >= 0);
        assert(fdt >= 0);

        for (;;) {
                ssize_t n;

                if (max_bytes != (uint64_t) -1) {
                        if (max_bytes <= 0)
                                return 1; /* return > 0 if we hit the max_bytes limit */

                        if (m > max_bytes)
                                m = max_bytes;
                }

                /* First try copy_file_range(), unless we already tried */
                if (try_cfr) {
                        n = try_copy_file_range(fdf, NULL, fdt, NULL, m, 0u);
                        if (n < 0) {
                                if (!IN_SET(n, -EINVAL, -ENOSYS, -EXDEV, -EBADF))
                                        return n;

                                try_cfr = false;
                                /* use fallback below */
                        } else if (n == 0) /* EOF */
                                break;
                        else
                                /* Success! */
                                goto next;
                }

                /* First try sendfile(), unless we already tried */
                if (try_sendfile) {
                        n = sendfile(fdt, fdf, NULL, m);
                        if (n < 0) {
                                if (!IN_SET(errno, EINVAL, ENOSYS))
                                        return -errno;

                                try_sendfile = false;
                                /* use fallback below */
                        } else if (n == 0) /* EOF */
                                break;
                        else
                                /* Success! */
                                goto next;
                }

                /* Then try splice, unless we already tried */
                if (try_splice) {
                        n = splice(fdf, NULL, fdt, NULL, m, 0);
                        if (n < 0) {
                                if (!IN_SET(errno, EINVAL, ENOSYS))
                                        return -errno;

                                try_splice = false;
                                /* use fallback below */
                        } else if (n == 0) /* EOF */
                                break;
                        else
                                /* Success! */
                                goto next;
                }

                /* As a fallback just copy bits by hand */
                {
                        uint8_t buf[MIN(m, BUFFER_SIZE)];

                        n = read(fdf, buf, sizeof(buf));
                        if (n < 0)
                                return -errno;
                        if (n == 0) /* EOF */
                                break;

                        r = loop_write(fdt, buf, (size_t) n);
                        if (r < 0)
                                return r;
                }

        next:
                if (max_bytes != (uint64_t) -1) {
                        assert(max_bytes >= (uint64_t) n);
                        max_bytes -= n;
                }
                /* sendfile accepts at most SSIZE_MAX-offset bytes to copy,
                 * so reduce our maximum by the amount we already copied,
                 * but don't go below our copy buffer size, unless we are
                 * close the limit of bytes we are allowed to copy. */
                m = MAX(MIN(BUFFER_SIZE, max_bytes), m - n);
        }

        return 0; /* return 0 if we hit EOF earlier than the size limit */
}
