#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "cachunker.h"
#include "util.h"

static void test_rolling(void) {

        static const char buffer[] =
                "The licenses for most software are designed to take away your freedom to share and change it. By contrast, the GNU General Public License is intended to guarantee your freedom to share and change free software--to make sure the software is free for all its users. This General Public License applies to most of the Free Software Foundation's software and to any other program whose authors commit to using it. (Some other Free Software Foundation software is covered by the GNU Lesser General Public License instead.) You can apply it to your programs, too.\n"
                "When we speak of free software, we are referring to freedom, not price. Our General Public Licenses are designed to make sure that you have the freedom to distribute copies of free software (and charge for this service if you wish), that you receive source code or can get it if you want it, that you can change the software or use pieces of it in new free programs; and that you know you can do these things.\n"
                "To protect your rights, we need to make restrictions that forbid anyone to deny you these rights or to ask you to surrender the rights. These restrictions translate to certain responsibilities for you if you distribute copies of the software, or if you modify it.\n"
                "For example, if you distribute copies of such a program, whether gratis or for a fee, you must give the recipients all the rights that you have. You must make sure that they, too, receive or can get the source code. And you must show them these terms so they know their rights.\n"
                "We protect your rights with two steps: (1) copyright the software, and (2) offer you this license which gives you legal permission to copy, distribute and/or modify the software.\n"
                "Also, for each author's protection and ours, we want to make certain that everyone understands that there is no warranty for this free software. If the software is modified by someone else and passed on, we want its recipients to know that what they have is not the original, so that any problems introduced by others will not reflect on the original authors' reputations.\n"
                "Finally, any free program is threatened constantly by software patents. We wish to avoid the danger that redistributors of a free program will individually obtain patent licenses, in effect making the program proprietary. To prevent this, we have made it clear that any patent must be licensed for everyone's free use or not licensed at all.\n"
                "The precise terms and conditions for copying, distribution and modification follow.\n";

        const char *p = buffer;
        CaChunker x = CA_CHUNKER_INIT;

        assert(sizeof(buffer) > CA_CHUNKER_WINDOW_SIZE);
        ca_chunker_start(&x, buffer, CA_CHUNKER_WINDOW_SIZE);

        while (p < buffer + sizeof(buffer) - CA_CHUNKER_WINDOW_SIZE) {
                CaChunker y = CA_CHUNKER_INIT;
                uint32_t k, v;

                k = ca_chunker_roll(&x, p[0], p[CA_CHUNKER_WINDOW_SIZE]);
                v = ca_chunker_start(&y, p+1, CA_CHUNKER_WINDOW_SIZE);

                /* printf("%08x vs. %08x\n", k, v); */

                assert_se(k == v);

                p++;
        }
}

static void test_chunk(void) {
        CaChunker x = CA_CHUNKER_INIT;
        uint8_t buffer[8*1024];
        size_t acc = 0;
        int fd;
        unsigned count = 0;

        fd = open("/dev/urandom", O_CLOEXEC|O_RDONLY|O_NOCTTY);
        assert_se(fd >= 0);

        for (;;) {
                const uint8_t *p;
                size_t n;

                assert_se(read(fd, buffer, sizeof(buffer)) == sizeof(buffer));

                p = buffer;
                n = sizeof(buffer);

                for (;;) {
                        size_t k;

                        k = ca_chunker_scan(&x, p, n);
                        if (k == (size_t) -1) {
                                acc += n;
                                break;
                        }

                        acc += k;
                        printf("%zu\n", acc);

                        assert_se(acc >= x.chunk_size_min);
                        assert_se(acc <= x.chunk_size_max);
                        acc = 0;

                        p += k, n -= k;

                        count ++;

                        if (count > 500)
                                goto finish;
                }
        }

finish:

        (void) close(fd);
}

static int test_set_size(void) {
        struct CaChunker x = CA_CHUNKER_INIT, y = CA_CHUNKER_INIT;

        ca_chunker_set_size(&y, 1024, 0, 0);
        assert_se(y.chunk_size_min == 1024);
        assert_se(y.chunk_size_avg == 4*1024);
        assert_se(y.chunk_size_max == 16*1024);

        y = x;
        ca_chunker_set_size(&y, 0, 0, 16*1024);
        assert_se(y.chunk_size_min == 1024);
        assert_se(y.chunk_size_avg == 4*1024);
        assert_se(y.chunk_size_max == 16*1024);

        y = x;
        ca_chunker_set_size(&y, 0, 4*1024, 0);
        assert_se(y.chunk_size_min == 1024);
        assert_se(y.chunk_size_avg == 4*1024);
        assert_se(y.chunk_size_max == 16*1024);

        y = x;
        ca_chunker_set_size(&y, 0, 4*1024, 16*1024);
        assert_se(y.chunk_size_min == 1024);
        assert_se(y.chunk_size_avg == 4*1024);
        assert_se(y.chunk_size_max == 16*1024);

        y = x;
        ca_chunker_set_size(&y, 1024, 4*1024, 16*1024);
        assert_se(y.chunk_size_min == 1024);
        assert_se(y.chunk_size_avg == 4*1024);
        assert_se(y.chunk_size_max == 16*1024);

        y = x;
        ca_chunker_set_size(&y, 1024, 4*1024, 0);
        assert_se(y.chunk_size_min == 1024);
        assert_se(y.chunk_size_avg == 4*1024);
        assert_se(y.chunk_size_max == 16*1024);

        y = x;
        ca_chunker_set_size(&y, 1024, 0, 16*1024);
        assert_se(y.chunk_size_min == 1024);
        assert_se(y.chunk_size_avg == 4*1024);
        assert_se(y.chunk_size_max == 16*1024);

        y = x;
        ca_chunker_set_size(&y, 128*1024, 0, 512*1024);
        assert_se(y.chunk_size_min == 128*1024);
        assert_se(y.chunk_size_avg == 256*1024);
        assert_se(y.chunk_size_max == 512*1024);

        return 0;
}

int main(int argc, char *argv[]) {

        test_rolling();
        test_chunk();
        test_set_size();

        return 0;
}
