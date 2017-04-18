#include "camakebst.h"
#include "util.h"

/* Permutation function originally by L. Bressel, 2017 */

static inline size_t pow_of_2(size_t e) {
        return (size_t) 1U << e;
}

static inline size_t log_of_2(size_t k) {
        assert(sizeof(size_t) == sizeof(unsigned long));

        return sizeof(unsigned long)*8 - __builtin_clzl(k) - 1;
}

static void make_bst_inner(
                const void *input,
                size_t n,
                size_t size,
                size_t e,
                void *output,
                size_t i) {

        size_t k, p, q;

        if (n == 0)
                return;

        assert(input);
        assert(size > 0);
        assert(e > 0);
        assert(output);

        p = pow_of_2(e-1);
        q = pow_of_2(e);

        if (n >= p - 1 + p / 2)
                k = (q - 2) / 2;
        else {
                size_t v;

                v = p - 1 + p / 2 - n;
                k = (q - 2) / 2 - v;
        }

        memcpy((uint8_t*) output + i * size, (const uint8_t*) input + k * size, size);

        /* Prepare left-side subtree */
        make_bst_inner(input,
                       k,
                       size,
                       e - 1,
                       output,
                       i*2+1);

        /* Prepare right-side subtree */
        make_bst_inner((const uint8_t*) input + (k + 1) * size,
                       n - k - 1,
                       size,
                       e - 1,
                       output,
                       i*2+2);
}

void ca_make_bst(const void *input, size_t n, size_t size, void *output) {
        assert(size > 0);

        /* Generate a binary search tree stored in an array from a sorted array. Specifically, for any given sorted
         * array 'input' of 'n' elements of size 'size' permute the array so that the following rule holds:
         *
         * For each array item with index i, the item at 2*i+1 is smaller and the item 2*i+2 is larger.
         *
         * This structure permits efficient (meaning: O(log(n)) binary searches: start with item i=0 (i.e. the root of
         * the BST), compare the value with the searched item, if smaller proceed at item i*2+1, if larger proceed at
         * item i*2+2, and repeat, until either the item is found, or the indexes grow beyond the array size, which
         * means the entry does not exist. Effectively this implements bisection, but instead of jumping around wildly
         * in the array during a single search we only search with strictly monotonically increasing indexes.
         */

        make_bst_inner(input, n, size, log_of_2(n) + 1, output, 0);
}
