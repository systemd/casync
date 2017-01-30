#ifndef fooparse_utilfoo
#define fooparse_utilfoo

#include <inttypes.h>

int parse_size(const char *t, uint64_t *ret);

char *format_bytes(char *buf, size_t l, uint64_t t);

#endif
