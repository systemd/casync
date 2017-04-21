#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "reflink.h"
#include "util.h"

#define FS_BLOCK_SIZE 4096U

int reflink_fd(
                int source_fd,
                uint64_t source_offset,
                int destination_fd,
                uint64_t destination_offset,
                uint64_t size) {

        struct stat a, b;
        uint64_t add;

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
            destination_offset + size >= (uint64_t) b.st_size)
                size = 0;
        else {
                /* Round down size to multiple of 4096 */
                size = (size / FS_BLOCK_SIZE) * FS_BLOCK_SIZE;
                if (size <= 0)
                        return -EBADR;
        }

        if (ioctl(destination_fd, FICLONERANGE,
                  &(struct file_clone_range) {
                          .src_fd = source_fd,
                          .src_offset = source_offset,
                          .src_length = size,
                          .dest_offset = destination_offset,
                  }) < 0)
                return -errno;

        return 0;
}
