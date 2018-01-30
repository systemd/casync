/* SPDX-License-Identifier: LGPL-2.1+ */

#include <assert.h>
#include <linux/msdos_fs.h>
#include <sys/ioctl.h>

#include "util.h"
#include "chattr.h"

int read_attr_fd(int fd, unsigned *ret) {
        assert(fd >= 0);
        assert(ret);

        if (ioctl(fd, FS_IOC_GETFLAGS, ret) < 0) {

                if (!ERRNO_IS_UNSUPPORTED(errno))
                        return -errno;

                /* If a file system or node type doesn't support chattr flags, then all flags should be considered 0 */
                *ret = 0;
                return 0;
        }

        return 1;
}

int write_attr_fd(int fd, unsigned attr) {
        assert(fd >= 0);

        if (ioctl(fd, FS_IOC_SETFLAGS, &attr) < 0) {

                /* If we shall write the attributes as 0, and we can't write them because the file system or node type
                 * doesn't support them, that's fine */
                if (attr == 0 && ERRNO_IS_UNSUPPORTED(errno))
                        return 0;

                return -errno;
        }

        return 1;
}

int mask_attr_fd(int fd, unsigned value, unsigned mask) {
        unsigned old_attr, new_attr;
        int r;

        assert(fd >= 0);

        if (mask == 0)
                return 0;

        r = read_attr_fd(fd, &old_attr);
        if (r < 0)
                return r;

        new_attr = (old_attr & ~mask) | (value & mask);
        if (new_attr == old_attr)
                return 0;

        return write_attr_fd(fd, new_attr);
}

int read_fat_attr_fd(int fd, uint32_t *ret) {
        assert(fd >= 0);
        assert(ret);

        if (ioctl(fd, FAT_IOCTL_GET_ATTRIBUTES, ret) < 0) {

                if (!ERRNO_IS_UNSUPPORTED(errno))
                        return -errno;

                *ret = 0;
                return 0;
        }

        return 1;
}

int write_fat_attr_fd(int fd, uint32_t attr) {
        assert(fd >= 0);

        if (ioctl(fd, FAT_IOCTL_SET_ATTRIBUTES, &attr) < 0) {

                if (attr == 0 && ERRNO_IS_UNSUPPORTED(errno))
                        return 0;

                return -errno;
        }

        return 1;
}

int mask_fat_attr_fd(int fd, uint32_t value, uint32_t mask) {
        uint32_t old_attr, new_attr;
        int r;

        assert(fd >= 0);

        if (mask == 0)
                return 0;

        r = read_fat_attr_fd(fd, &old_attr);
        if (r < 0)
                return r;

        new_attr = (old_attr & ~mask) | (value & mask);
        if (new_attr == old_attr)
                return 0;

        return write_fat_attr_fd(fd, new_attr);
}
