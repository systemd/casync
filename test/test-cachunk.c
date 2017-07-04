#include <fcntl.h>

#include "cachunk.h"
#include "def.h"
/* #include "util.h" */

static void test_chunk_file(void) {
        uint8_t buffer[BUFFER_SIZE*4];
        ReallocBuffer rb = {}, rb2 = {};
        const char *d;
        char *path;
        int fd, r;

        assert(var_tmp_dir(&d) >= 0);
        path = strjoina(d, "/chunk-test.XXXXXX");

        assert_se(dev_urandom(buffer, sizeof(buffer)) >= 0);

        fd = mkostemp(path, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(unlink(path) >= 0);

        r = ca_save_and_compress_fd(fd, buffer, sizeof(buffer));
        assert_se(r >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);

        r = ca_load_and_decompress_fd(fd, &rb);
        safe_close(r >= 0);

        assert_se(realloc_buffer_size(&rb) == sizeof(buffer));
        assert_se(memcmp(realloc_buffer_data(&rb), buffer, sizeof(buffer)) == 0);

        realloc_buffer_empty(&rb);

        r = ca_compress(buffer, sizeof(buffer), &rb);
        assert_se(r >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) == 0);

        r = ca_save_and_decompress_fd(fd, realloc_buffer_data(&rb), realloc_buffer_size(&rb));
        assert_se(r >= 0);

        realloc_buffer_empty(&rb);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);

        r = ca_load_and_compress_fd(fd, &rb);
        assert_se(r >= 0);

        r = ca_decompress(realloc_buffer_data(&rb), realloc_buffer_size(&rb), &rb2);
        assert_se(r >= 0);

        assert_se(realloc_buffer_size(&rb2) == sizeof(buffer));
        assert_se(memcmp(realloc_buffer_data(&rb2), buffer, sizeof(buffer)) == 0);

        realloc_buffer_free(&rb);
        realloc_buffer_free(&rb2);

        safe_close(fd);
}

int main(int argc, char *argv[]) {

        test_chunk_file();

        return 0;
}
