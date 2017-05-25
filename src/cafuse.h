#ifndef cafusehfoo
#define cafusehfoo

#include "casync.h"

#if HAVE_FUSE
int ca_fuse_run(CaSync *s, const char *what, const char *where, bool do_mkdir);
#endif

#endif
