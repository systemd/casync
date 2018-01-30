/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/ioctl.h>
#include <linux/fs.h>

#include "quota-projid.h"
#include "util.h"

int read_quota_projid(int fd, uint32_t *ret) {
        struct fsxattr fa;

        assert(fd >= 0);
        assert(ret);

        if (ioctl(fd, FS_IOC_FSGETXATTR, &fa) < 0) {

                if (!ERRNO_IS_UNSUPPORTED(errno))
                        return -errno;

                /* If the file system doesn't do project quota we assume it's all owned by project 0 */
                *ret = 0;
                return 0;
        }

        *ret = fa.fsx_projid;
        return 1;
}

int write_quota_projid(int fd, uint32_t id) {
        struct fsxattr fa;

        assert(fd >= 0);

        if (ioctl(fd, FS_IOC_FSGETXATTR, &fa) < 0) {

                /* When the file system doesn't support project IDs, then we consider this as equivalent to all files
                 * being owned by project 0 */
                if (id == 0 && ERRNO_IS_UNSUPPORTED(errno))
                        return 0;

                return -errno;
        }

        if (fa.fsx_projid == id)
                return 0;

        fa.fsx_projid = id;

        if (ioctl(fd, FS_IOC_FSSETXATTR, &fa) < 0)
                return -errno;

        return 0;
}
