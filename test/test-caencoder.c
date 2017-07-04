#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cadecoder.h"
#include "caencoder.h"
#include "caformat.h"

static int encode(int dfd, int fd) {
        CaEncoder *e = NULL;
        uint64_t flags;
        int r;

        assert(dfd >= 0);
        assert(fd >= 0);

        printf("ENCODING...\n");

        e = ca_encoder_new();
        if (!e) {
                r = -ENOMEM;
                goto finish;
        }

        r = ca_encoder_set_base_fd(e, dfd);
        if (r < 0)
                goto finish;

        flags = CA_FORMAT_WITH_BEST|CA_FORMAT_EXCLUDE_NODUMP;

        if (geteuid() != 0)
                flags &= ~CA_FORMAT_WITH_PRIVILEGED;

        r = ca_encoder_set_feature_flags(e, flags);
        if (r < 0)
                goto finish;

        dfd = -1;

        for (;;) {
                int step;
                step = ca_encoder_step(e);
                if (step < 0) {
                        r = step;
                        goto finish;
                }

                switch (step) {

                case CA_ENCODER_FINISHED:
                        r = 0;
                        goto finish;

                case CA_ENCODER_NEXT_FILE:
                case CA_ENCODER_DONE_FILE: {
                        char *path = NULL;
                        mode_t mode;

                        r = ca_encoder_current_path(e, &path);
                        if (r < 0)
                                goto finish;

                        r = ca_encoder_current_mode(e, &mode);
                        if (r < 0)
                                goto finish;

                        printf("%s %08o %s\n", step == CA_ENCODER_NEXT_FILE ? "→" : "←", mode, path);
                        free(path);
                }

                        /* Fall through */

                case CA_ENCODER_PAYLOAD:
                case CA_ENCODER_DATA: {
                        const void *p;
                        size_t sz;
                        ssize_t n;

                        r = ca_encoder_get_data(e, &p, &sz);
                        if (r == -ENODATA)
                                break;
                        if (r < 0)
                                goto finish;

                        n = write(fd, p, sz);
                        if (n < 0) {
                                r = -errno;
                                goto finish;
                        }

                        break;
                }

                default:
                        assert(false);
                }
        }

finish:

        if (r == 0) {
                uint64_t offset;
                off_t foffset;

                r = ca_encoder_current_archive_offset(e, &offset);
                if (r < 0)
                        goto finish;

                foffset = lseek(fd, 0, SEEK_CUR);
                if (foffset == (off_t) -1) {
                        r = -errno;
                        goto finish;
                }

                if ((off_t) offset != foffset) {
                        r = -EIO;
                        goto finish;
                }
        }

        ca_encoder_unref(e);

        if (fd >= 0)
                (void) close(fd);

        if (dfd >= 0)
                (void) close(dfd);

        return r;
}

static int decode(int fd) {
        CaDecoder *d = NULL;
        int r;

        assert(fd >= 0);

        printf("DECODING...\n");

        d = ca_decoder_new();
        if (!d) {
                r = -ENOMEM;
                goto finish;
        }

        r = ca_decoder_set_base_mode(d, S_IFDIR);
        if (r < 0)
                goto finish;

        for (;;) {
                int step;

                step = ca_decoder_step(d);
                if (step < 0)
                        goto finish;

                switch (step) {

                case CA_DECODER_FINISHED:
                        r = 0;
                        goto finish;

                case CA_DECODER_STEP:
                        break;

                case CA_DECODER_REQUEST: {
                        uint8_t buffer[4096];
                        ssize_t n;

                        n = read(fd, buffer, sizeof(buffer));
                        if (n < 0) {
                                r = -errno;
                                goto finish;
                        }
                        if (n == 0)
                                r = ca_decoder_put_eof(d);
                        else
                                r = ca_decoder_put_data(d, buffer, n, NULL);
                        if (r < 0)
                                goto finish;

                        break;
                }

                case CA_DECODER_DONE_FILE:
                case CA_DECODER_NEXT_FILE: {
                        char *path = NULL;
                        mode_t mode;

                        r = ca_decoder_current_mode(d, &mode);
                        if (r < 0)
                                goto finish;

                        r = ca_decoder_current_path(d, &path);
                        if (r < 0)
                                goto finish;

                        printf("%s %08o %s\n", step == CA_DECODER_NEXT_FILE ? "→" : "←", mode, path);
                        free(path);
                        break;
                }

                case CA_DECODER_PAYLOAD:
                        /* ignore for now */
                        break;

                }
        }

finish:
        ca_decoder_unref(d);

        if (fd >= 0)
                (void) close(fd);

        return r;
}

int main(int argc, char *argv[]) {
        int fd = -1, dfd = -1, r;
        bool do_unlink = false;
        const char *d;
        char *t;

        assert(var_tmp_dir(&d) >= 0);
        t = strjoina(d, "/castream-test.XXXXXX");

        dfd = open(argc > 1 ? argv[1] : ".", O_CLOEXEC|O_RDONLY|O_NOCTTY);
        if (dfd < 0) {
                r = -errno;
                goto finish;
        }

        fd = mkostemp(t, O_WRONLY|O_CLOEXEC);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }

        do_unlink = true;

        fprintf(stderr, "Writing to: %s\n", t);

        r = encode(dfd, fd);
        dfd = fd = -1;
        if (r < 0)
                goto finish;

        fd = open(t, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }

        r = decode(fd);
        fd = -1;

finish:
        fprintf(stderr, "Done: %s\n", strerror(-r));

        if (fd >= 0)
                (void) close(fd);

        if (dfd >= 0)
                (void) close(dfd);

        if (do_unlink)
                assert_se(unlink(t) >= 0);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
