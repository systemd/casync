AC_PREREQ([2.64])

AC_INIT([casync], 0.1)

AC_CONFIG_SRCDIR([src/casync.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_FILES([
        Makefile
])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PREFIX_DEFAULT([/usr])
AM_MAINTAINER_MODE([enable])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AM_SILENT_RULES([yes])
LT_PREREQ(2.2)
LT_INIT([disable-static])

AC_PROG_CC_C99

AC_CHECK_DECLS([
        getrandom,
        ],
        [], [], [[
#include <linux/random.h>
]])

AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)

AM_PATH_LIBGCRYPT([1.4.5],, AC_MSG_ERROR([*** libgcrypt was not found.]))
AC_SUBST([LIBGCRYPT_CFLAGS])
AC_SUBST([LIBGCRYPT_LIBS])

PKG_CHECK_MODULES(LIBLZMA, [liblzma >= 5.2.2],
                  [], [AC_MSG_ERROR([*** lzma library not found])])

AC_OUTPUT
