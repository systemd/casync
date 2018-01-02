#ifndef fooudevutilhfoo
#define fooudevutilhfoo

/* SPDX-License-Identifier: LGPL-2.1+ */

#include "util.h"

#include <libudev.h>

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev*, udev_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device*, udev_device_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_monitor*, udev_monitor_unref);

#endif
