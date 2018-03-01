/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foogccmacrohfoo
#define foogccmacrohfoo

#define _printf_(a,b) __attribute__ ((format (printf, a, b)))
#define _sentinel_ __attribute__ ((sentinel))
#define _unused_ __attribute__ ((unused))
#define _unused_ __attribute__ ((unused))
#define _likely_(x) (__builtin_expect(!!(x),1))
#define _unlikely_(x) (__builtin_expect(!!(x),0))
#define _malloc_ __attribute__ ((malloc))
#define _pure_ __attribute__ ((pure))
#define _packed_ __attribute__ ((packed))
#define _const_ __attribute__ ((const))
#ifdef __clang__
#  define _alloc_(...)
#else
#  define _alloc_(...) __attribute__ ((alloc_size(__VA_ARGS__)))
#endif
#if __GNUC__ >= 7
#define _fallthrough_ __attribute__((fallthrough))
#else
#define _fallthrough_
#endif

#endif
