/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>

#include "fuzz.h"
#include "util.h"

#define EXIT_TEST_SKIP 77

/* This is a test driver for fuzzers that provides a main function
 * for regression testing outside of oss-fuzz (https://github.com/google/oss-fuzz)
 *
 * It reads files named on the command line and passes them one by one
 * into the fuzzer that it is compiled into. */

/* This one was borrowed from
 * https://github.com/google/oss-fuzz/blob/646fca1b506b056db3a60d32c4a1a7398f171c94/infra/base-images/base-runner/bad_build_check#L19
 */

int main(int argc, char **argv) {
        int i;

        for (i = 1; i < argc; i++) {
                const char *name = argv[i];
                char buf[4096];
                ssize_t size;

                _cleanup_(safe_fclosep) FILE *f = fopen(name, "r");
                if (!f) {
                        log_error_errno(errno, "Failed to open %s: %m", name);
                        return EXIT_FAILURE;
                }

                size = fread(buf, 1, sizeof(buf), f);
                if (size < 0) {
                        log_error_errno(errno, "Failed to read %s: %m", name);
                        return EXIT_FAILURE;
                }

                printf("%s... ", name);
                fflush(stdout);
                if (LLVMFuzzerTestOneInput((uint8_t*)buf, size) == EXIT_TEST_SKIP)
                        return EXIT_TEST_SKIP;
                printf("ok\n");
        }

        return EXIT_SUCCESS;
}
