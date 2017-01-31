#include "cautil.h"
#include "util.h"

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
        assert_se(ca_classify_locator("http://user@localhost:1234/xyz.txt?piff=paff") == CA_LOCATOR_URL);
        assert_se(ca_classify_locator("http://user@foobar.com") == CA_LOCATOR_URL);
        assert_se(ca_classify_locator("foobar:quux.txt") == CA_LOCATOR_SSH);
        assert_se(ca_classify_locator("lennart@foobar:quux.txt") == CA_LOCATOR_SSH);
}

int main(int argc, char *argv[]) {

        test_locator_has_suffix();
        test_strip_file_url();
        test_classify_locator();

        return 0;
}
