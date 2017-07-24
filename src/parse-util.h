#ifndef fooparseutilfoo
#define fooparseutilfoo

#include <inttypes.h>

#define FORMAT_BYTES_MAX 128

int parse_size(const char *t, uint64_t *ret);

char *format_bytes(char *buf, size_t l, uint64_t t);

#endif
