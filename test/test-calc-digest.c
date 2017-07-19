#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "cadigest.h"
#include "util.h"

int main(int argc, char *argv[]) {
        CaDigest *digest = NULL;
        CaDigestType type;
        int fd = -1, r;
        const char *q, *path, *dt;
        size_t l;
        char *p = NULL;

        if (argc > 3) {
                fprintf(stderr, "Expected a two arguments: digest and file name.\n");
                r = -EINVAL;
                goto finish;
        }

        path = argc == 3 ? argv[2] : NULL;
        dt = argc >= 2 ? argv[1] : NULL;

        if (dt) {
                type = ca_digest_type_from_string(dt);
                if (type < 0) {
                        fprintf(stderr, "Failed to parse digest name: %s\n", dt);
                        r = -EINVAL;
                        goto finish;
                }
        } else
                type = CA_DIGEST_SHA512_256;

        r = ca_digest_new(type, &digest);
        if (r < 0) {
                fprintf(stderr, "Failed to set up digest %s: %s\n", dt, strerror(-r));
                goto finish;
        }

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(-r));
                        goto finish;
                }
        } else
                fd = STDIN_FILENO;

        for (;;) {
                uint8_t buffer[64*1024];
                ssize_t n;

                n = read(fd, buffer, sizeof(buffer));
                if (n < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to read: %s\n", strerror(-r));
                        goto finish;
                }
                if (n == 0) /* EOF */
                        break;

                ca_digest_write(digest, buffer, (size_t) n);
        }

        q = ca_digest_read(digest);
        l = ca_digest_get_size(digest);

        p = hexmem(q, l);
        if (!p) {
                r = log_oom();
                goto finish;
        }

        fputs(p, stdout);
        fputc('\n', stdout);

        r = 0;

finish:
        ca_digest_free(digest);

        if (fd > 2)
                safe_close(fd);

        free(p);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
