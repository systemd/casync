#include <assert.h>
#include <errno.h>
#include <gcrypt.h>

#include "cachunkid.h"
#include "gcrypt-util.h"

void initialize_libgcrypt(void) {
        const char *p;

        if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
                return;

        p = gcry_check_version("1.4.5");
        assert(p);

        gcry_control(GCRYCTL_DISABLE_SECMEM);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int allocate_sha256_digest(gcry_md_hd_t *md, bool b) {

        assert(md);

        if (b == !!*md)
                return 0;

        if (b) {
                initialize_libgcrypt();

                assert(gcry_md_get_algo_dlen(GCRY_MD_SHA256) == sizeof(CaChunkID));

                if (gcry_md_open(md, GCRY_MD_SHA256, 0) != 0)
                        return -EIO;
        } else {
                gcry_md_close(*md);
                *md = NULL;
        }

        return 1;
}
