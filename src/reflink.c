/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <linux/fs.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "reflink.h"
#include "util.h"

#define FS_BLOCK_SIZE 4096U

#define VALIDATE 1

#if VALIDATE
static ssize_t pread_try_harder(int fd, void *p, size_t s, off_t o) {
        char path[sizeof("/proc/self/fd/") + DECIMAL_STR_MAX(fd)];
        ssize_t n;
        int fd_read, r;

        n = pread(fd, p, s, o);
        if (n >= 0)
                return n;

        r = -errno;

        sprintf(path, "/proc/self/fd/%i", fd);

        fd_read = open(path, O_CLOEXEC|O_RDONLY|O_NOCTTY);
        if (fd_read < 0) {
                errno = -r;
                return r;
        }

        n = pread(fd_read, p, s, o);
        safe_close(fd_read);
        if (n < 0) {
                errno = -r;
                return r;
        }

        return n;
}
#endif

static void validate(int source_fd, uint64_t source_offset, int destination_fd, uint64_t destination_offset, uint64_t size) {
#if VALIDATE
        ssize_t x, y;
        uint8_t *buffer1, *buffer2;

        buffer1 = new(uint8_t, size);
        assert_se(buffer1);
        buffer2 = new(uint8_t, size);
        assert_se(buffer2);

        x = pread_try_harder(source_fd, buffer1, size, source_offset);
        y = pread_try_harder(destination_fd, buffer2, size, destination_offset);

        assert_se(x == (ssize_t) size);
        assert_se(y == (ssize_t) size);
        assert_se(memcmp(buffer1, buffer2, size) == 0);

        free(buffer1);
        free(buffer2);
#endif
}

int reflink_fd(
                int source_fd,
                uint64_t source_offset,
                int destination_fd,
                uint64_t destination_offset,
                uint64_t size,
                uint64_t *ret_reflinked) {

        struct stat a, b;
        uint64_t add, reflinked;

        /* Creates a reflink on btrfs and other file systems that know the concept. The input parameters are aligned to
         * match the fundamental block size (for now assumed to be 4K), and possibly to EOF. */

        if (source_fd < 0)
                return -EBADF;
        if (destination_fd < 0)
                return -EBADF;

        /* Can only merge blocks starting at a block size boundary */
        if (source_offset % FS_BLOCK_SIZE != destination_offset % FS_BLOCK_SIZE)
                return -EBADR;

        /* Overflow checks */
        if (source_offset + size < source_offset)
                return -ERANGE;
        if (destination_offset + size < destination_offset)
                return -ERANGE;

        /* First step, round up start offsets to multiple of 4096 */
        if (source_offset % FS_BLOCK_SIZE > 0) {
                add = FS_BLOCK_SIZE - (source_offset % FS_BLOCK_SIZE);
                if (add >= size)
                        return -EBADR;

                source_offset += add;
                destination_offset += add;
                size -= add;
        }

        if (fstat(source_fd, &a) < 0)
                return -errno;
        if (fstat(destination_fd, &b) < 0)
                return -errno;

        /* Never call the ioctls on something that isn't a regular file, as that's not safe (for example, if the fd
         * refers to a block or char device of some kind, which overloads the same ioctl numbers) */
        if (S_ISDIR(a.st_mode) || S_ISDIR(b.st_mode))
                return -EISDIR;
        if (!S_ISREG(a.st_mode) || !S_ISREG(b.st_mode))
                return -ENOTTY;

        /* Extend to EOF if we can */
        if (source_offset + size >= (uint64_t) a.st_size &&
            destination_offset + size >= (uint64_t) b.st_size) {
                reflinked = size;
                size = 0;
        } else {
                /* Round down size to multiple of 4096 */
                size = (size / FS_BLOCK_SIZE) * FS_BLOCK_SIZE;
                if (size <= 0)
                        return -EBADR;

                reflinked = size;
        }

        validate(source_fd, source_offset, destination_fd, destination_offset, reflinked);

        if (ioctl(destination_fd, FICLONERANGE,
                  &(struct file_clone_range) {
                          .src_fd = source_fd,
                          .src_offset = source_offset,
                          .src_length = size,
                          .dest_offset = destination_offset,
                  }) < 0)
                return -errno;

        validate(source_fd, source_offset, destination_fd, destination_offset, reflinked);

        if (ret_reflinked)
                *ret_reflinked = reflinked;

        return 0;
}
