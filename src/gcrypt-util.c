#include <assert.h>
#include <gcrypt.h>

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
