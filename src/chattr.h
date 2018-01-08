/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foochattrhfoo
#define foochattrhfoo

#include <inttypes.h>

int read_attr_fd(int fd, unsigned *ret);
int write_attr_fd(int fd, unsigned attr);
int mask_attr_fd(int fd, unsigned value, unsigned mask);

int read_fat_attr_fd(int fd, uint32_t *ret);
int write_fat_attr_fd(int fd, uint32_t attr);
int mask_fat_attr_fd(int fd, uint32_t value, uint32_t mask);

#endif
