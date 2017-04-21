#ifndef fooreflinkhfoo
#define fooreflinkhfoo

#include <inttypes.h>

int reflink_fd(int source_fd, uint64_t source_offset, int destination_fd, uint64_t destination_offset, uint64_t size);

#endif
