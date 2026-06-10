/* SPDX-License-Identifier: LGPL-2.1+ */

/* Fuzzer for the casync .catar archive decoder (CaDecoder, src/cadecoder.c).
 * The existing fuzz-compress.c only covers the compression layer; this drives
 * the untrusted archive-format parser. No base_fd is set, so the decoder only
 * parses in memory and never touches the filesystem. */

#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <syslog.h>

#include "cadecoder.h"
#include "fuzz.h"
#include "log.h"
#include "util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        CaDecoder *d = NULL;
        unsigned long iterations;
        int r, step;

        if (!getenv("CASYNC_LOG_LEVEL"))
                set_log_level(LOG_CRIT);

        d = ca_decoder_new();
        if (!d)
                return 0;

        /* S_IFDIR: parse a directory-tree archive; no base_fd, so in-memory only. */
        r = ca_decoder_set_base_mode(d, S_IFDIR | 0700);
        if (r < 0)
                goto finish;

        if (size > 0) {
                r = ca_decoder_put_data(d, data, size, NULL);
                if (r < 0)
                        goto finish;
        }

        r = ca_decoder_put_eof(d);
        if (r < 0)
                goto finish;

        /* Bound the loop to guarantee termination on adversarial input. */
        for (iterations = 0; iterations < (1u << 20); iterations++) {
                step = ca_decoder_step(d);
                if (step < 0 || step == CA_DECODER_FINISHED)
                        break;

                switch (step) {

                case CA_DECODER_STEP:
                case CA_DECODER_NEXT_FILE:
                case CA_DECODER_DONE_FILE:
                        break;

                case CA_DECODER_PAYLOAD: {
                        const void *p;
                        size_t n;

                        r = ca_decoder_get_payload(d, &p, &n);
                        if (r < 0)
                                goto finish;
                        break;
                }

                default:
                        /* REQUEST (truncated stream), SEEK/SKIP/FOUND/NOT_FOUND: stop. */
                        goto finish;
                }
        }

finish:
        ca_decoder_unref(d);
        return 0;
}
