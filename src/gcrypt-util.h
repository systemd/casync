#ifndef foogcryptutilhfoo
#define foogcryptutilhfoo

#include <stdbool.h>
#include <gcrypt.h>

void initialize_libgcrypt(void);

int allocate_sha256_digest(gcry_md_hd_t *md, bool b);

#endif
