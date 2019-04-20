/* SPDX-License-Identifier: LGPL-2.1+ */

#include "cacutmark.h"
#include "util.h"

static void test_cutmark_parse_one(const char *s, int ret, uint64_t value, uint64_t mask, int64_t delta) {
        CaCutmark c = {};

        assert_se(ca_cutmark_parse(&c, s) == ret);

        assert_se(c.value == value);
        assert_se(c.mask == mask);
        assert_se(c.delta == delta);
}

static void test_cutmark_parse(void) {
        test_cutmark_parse_one("aaaaa", 0, 0xaaaaaU, 0xfffffU, 0);
        test_cutmark_parse_one("0/1", 0, 0, 1, 0);
        test_cutmark_parse_one("ff/ff+99", 0, 0xffU, 0xffU, 99);
        test_cutmark_parse_one("ff/ff-99", 0, 0xffU, 0xffU, -99);
        test_cutmark_parse_one("abc+99", 0, 0xabcU, 0xfffU, 99);
        test_cutmark_parse_one("abc-99", 0, 0xabcU, 0xfffU, -99);
        test_cutmark_parse_one("abc/eee", 0, 0xabcU, 0xeeeU, 0);
        test_cutmark_parse_one("abcdef0123456789/123456789abcdef0+2147483647", 0, 0xabcdef0123456789U, 0x123456789abcdef0U, 2147483647);
        test_cutmark_parse_one("abcdef0123456789/123456789abcdef0-2147483648", 0, 0xabcdef0123456789U, 0x123456789abcdef0U, -2147483648);
        test_cutmark_parse_one("abcdef0123456789/123456789abcdef0+2147483647", 0, 0xabcdef0123456789U, 0x123456789abcdef0U, 2147483647);
        test_cutmark_parse_one("abcdef0123456789/123456789abcdef0+9223372036854775807", 0, 0xabcdef0123456789U, 0x123456789abcdef0U, INT64_MAX);
        test_cutmark_parse_one("abcdef0123456789/123456789abcdef0-9223372036854775808", 0, 0xabcdef0123456789U, 0x123456789abcdef0U, INT64_MIN);
        test_cutmark_parse_one("1000000000000000/1000000000000000+0", 0, 0x1000000000000000U, 0x1000000000000000U, 0);
        test_cutmark_parse_one("1000000000000000/1000000000000000-0", 0, 0x1000000000000000U, 0x1000000000000000U, 0);

        test_cutmark_parse_one("", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("fg", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("/", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("/f", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("+", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("+1", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("-", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("-1", -EINVAL, 0, 0, 0);
        test_cutmark_parse_one("0/0", -EINVAL, 0, 0, 0);

        test_cutmark_parse_one("10000000000000000", -EOVERFLOW, 0, 0, 0);
        test_cutmark_parse_one("0/10000000000000000", -EOVERFLOW, 0, 0, 0);
        test_cutmark_parse_one("abcdef0123456789/123456789abcdef0+9223372036854775808", -EOVERFLOW, 0, 0, 0);
        test_cutmark_parse_one("abcdef0123456789/123456789abcdef0-9223372036854775809", -EOVERFLOW, 0, 0, 0);
}

int main(int argc, char *argv[]) {

        test_cutmark_parse();

        return 0;
}
