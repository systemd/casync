/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef fooquotaprojidhfoo
#define fooquotaprojidhfoo

#include <inttypes.h>

int read_quota_projid(int fd, uint32_t *ret);
int write_quota_projid(int fd, uint32_t id);

#endif
