/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>

#include "util.h"

#define PART1 127
#define PART2 99
#define PART3 3333
#define PART4 4444
#define PART5 13

int main(int argc, char *argv[]) {
        uint8_t buffer[PART1 + PART2 + PART3 + PART4 + PART5];
        uint8_t buffer2[sizeof(buffer)];
        char *fn;
        int fd, p[2];
        uint64_t n_punched;
        const char *d;

        assert_se(tmp_dir(&d) >= 0);
        fn = strjoina(d, "/zeroXXXXXX");

        memzero(buffer, PART1);
        dev_urandom(buffer + PART1, PART2);
        memzero(buffer + PART1 + PART2, PART3);
        dev_urandom(buffer + PART1 + PART2 + PART3, PART4);
        memzero(buffer + PART1 + PART2 + PART3 + PART4, PART5);

        fd = mkostemp(fn, O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(unlink(fn) == 0);

        assert_se(loop_write_with_holes(fd, buffer, sizeof(buffer), &n_punched) >= 0);
        assert_se(n_punched >= PART1 + PART3);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(loop_read(fd, buffer2, sizeof(buffer2)) == sizeof(buffer2));
        assert_se(memcmp(buffer, buffer2, sizeof(buffer)) == 0);

        memzero(buffer + PART1 + 1, PART2 - 2);
        assert_se(lseek(fd, PART1-1, SEEK_SET) == PART1-1);
        assert_se(loop_write_with_holes(fd, buffer + PART1 - 1, PART2 + 2, &n_punched) >= 0);
        assert_se(n_punched >= PART2 - 2);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(loop_read(fd, buffer2, sizeof(buffer2)) == sizeof(buffer2));
        assert_se(memcmp(buffer, buffer2, sizeof(buffer)) == 0);

        fd = safe_close(fd);

        assert_se(pipe2(p, O_CLOEXEC) >= 0);

        assert_se(loop_write_with_holes(p[1], buffer, MIN(sizeof(buffer), (size_t) PIPE_BUF), &n_punched) >= 0);
        assert_se(n_punched == 0);

        p[1] = safe_close(p[1]);

        assert_se(loop_read(p[0], buffer2, sizeof(buffer2)) == MIN((ssize_t) sizeof(buffer2), PIPE_BUF));

        p[0] = safe_close(p[0]);

        assert_se(memcmp(buffer, buffer2, MIN(sizeof(buffer), (size_t) PIPE_BUF)) == 0);

        return 0;
}
