#include <fcntl.h>

#include "util.h"
#include "cautil.h"
#include "def.h"

static void test_locator_has_suffix(void) {

        assert_se(ca_locator_has_suffix(NULL, NULL));
        assert_se(ca_locator_has_suffix("", ""));
        assert_se(ca_locator_has_suffix(NULL, ""));
        assert_se(ca_locator_has_suffix("", NULL));

        assert_se(ca_locator_has_suffix("foo", NULL));
        assert_se(ca_locator_has_suffix("foo", ""));
        assert_se(!ca_locator_has_suffix("", "foo"));
        assert_se(!ca_locator_has_suffix(NULL, "foo"));

        assert_se(ca_locator_has_suffix("foo.bar", ".bar"));
        assert_se(ca_locator_has_suffix("foo.bar", "bar"));
        assert_se(ca_locator_has_suffix("foo.bar", "ar"));
        assert_se(ca_locator_has_suffix("foo.bar", "r"));
        assert_se(ca_locator_has_suffix("foo.bar", ""));
        assert_se(!ca_locator_has_suffix("foo.bar", "foo"));

        assert_se(ca_locator_has_suffix("http://foobar.com/foo.bar", ".bar"));
        assert_se(!ca_locator_has_suffix("http://foobar.com/foo.bar", ".qux"));

        assert_se(ca_locator_has_suffix("http://foobar.com/foo.bar?miep=mup", ".bar"));
        assert_se(ca_locator_has_suffix("http://foobar.com/foo.bar?miep=.qux", ".bar"));
        assert_se(!ca_locator_has_suffix("http://foobar.com/foo.bar?miep=.qux", ".qux"));

        assert_se(ca_locator_has_suffix("http://foobar.com/foo.bar;miep=mup", ".bar"));
        assert_se(ca_locator_has_suffix("http://foobar.com/foo.bar;miep=.qux", ".bar"));
        assert_se(!ca_locator_has_suffix("http://foobar.com/foo.bar;miep=.qux", ".qux"));
}

static void test_strip_file_url_one(const char *a, const char *b) {
        char *s;

        s = ca_strip_file_url(a);
        assert_se(s);

        assert_se(streq(s, b));

        free(s);
}

static void test_strip_file_url(void) {

        test_strip_file_url_one("/foo/bar", "/foo/bar");
        test_strip_file_url_one("", "");
        test_strip_file_url_one("file:///foobar.txt", "/foobar.txt");
        test_strip_file_url_one("file:///foo%20bar.txt", "/foo bar.txt");
        test_strip_file_url_one("file:///foo bar.txt", "/foo bar.txt");
        test_strip_file_url_one("file:///foo%%xyz.txt", "/foo%%xyz.txt");

        test_strip_file_url_one("file://localhost/piff.txt", "/piff.txt");

        test_strip_file_url_one("file://elsewhere/piff.txt", "file://elsewhere/piff.txt");
        test_strip_file_url_one("http://online.com/piff.txt", "http://online.com/piff.txt");
}

static void test_classify_locator(void) {
        assert_se(ca_classify_locator(NULL) == _CA_LOCATOR_CLASS_INVALID);
        assert_se(ca_classify_locator("") == _CA_LOCATOR_CLASS_INVALID);
        assert_se(ca_classify_locator("x") == CA_LOCATOR_PATH);
        assert_se(ca_classify_locator(".") == CA_LOCATOR_PATH);
        assert_se(ca_classify_locator("..") == CA_LOCATOR_PATH);
        assert_se(ca_classify_locator("./") == CA_LOCATOR_PATH);
        assert_se(ca_classify_locator("/") == CA_LOCATOR_PATH);
        assert_se(ca_classify_locator("/foo") == CA_LOCATOR_PATH);
        assert_se(ca_classify_locator("./foo") == CA_LOCATOR_PATH);
        assert_se(ca_classify_locator("http://foobar.com/xyz.txt") == CA_LOCATOR_URL);
        assert_se(ca_classify_locator("http://foobar.com/xyz.txt?piff=paff") == CA_LOCATOR_URL);
        assert_se(ca_classify_locator("http://user@foobar.com/xyz.txt?piff=paff") == CA_LOCATOR_URL);
        assert_se(ca_classify_locator("http://user@foobar.com") == CA_LOCATOR_URL);
        assert_se(ca_classify_locator("foobar:quux.txt") == CA_LOCATOR_SSH);
        assert_se(ca_classify_locator("lennart@foobar:quux.txt") == CA_LOCATOR_SSH);
}

static void test_chunk_file(void) {
        uint8_t buffer[BUFFER_SIZE*4];
        ReallocBuffer rb = {}, rb2 = {};
        char path[] = "/var/tmp/chunk-test.XXXXXX";
        int fd, r;

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

        test_locator_has_suffix();
        test_strip_file_url();
        test_classify_locator();
        test_chunk_file();

        return 0;
}
