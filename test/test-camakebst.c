#include "camakebst.h"
#include "util.h"

#define TEST_MAX 9999

static size_t find_bst(const int b[], size_t n, int x) {
        size_t i = 0;

        for (;;) {
                if (i >= n)
                        return (size_t) -1;

                if (b[i] == x)
                        return i;

                if (x < b[i])
                        i = 2*i + 1;
                else if (x > b[i])
                        i = 2*i + 2;
        }
}

static void test_makebst_size(size_t n) {
        size_t i;

        int a[n], b[n];

        for (i = 0; i < n; i++) {
                a[i] = (int) i;
                b[i] = -1;
        }

        ca_make_bst(a, n, sizeof(int), b);

        for (i = 0; i < n; i++) {
                assert_se(i*2+1 >= n || b[i] > b[i*2+1]);
                assert_se(i*2+2 >= n || b[i] < b[i*2+2]);
        }

        for (i = 0; i < n; i++) {
                size_t j;

                j = find_bst(b, n, (int) i);
                assert_se(j != (size_t) -1);

                assert_se(b[j] == (int) i);
        }

        assert_se(find_bst(b, n, -2)  == (size_t) -1);
        assert_se(find_bst(b, n, -1)  == (size_t) -1);
        assert_se(find_bst(b, n, n)   == (size_t) -1);
        assert_se(find_bst(b, n, n+1) == (size_t) -1);
}

int main(int argc, char *argv[]) {
        size_t i;

        for (i = 0; i < TEST_MAX; i++)
                test_makebst_size(i);

        return 0;
}
