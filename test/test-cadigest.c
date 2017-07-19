#include "util.h"
#include "cadigest.h"

#define TEST_SPEED_RUNTIME_NSEC (5U*NSEC_PER_SEC)

static void test_speed(CaDigestType t) {

        uint32_t megabyte[1024*1024/sizeof(uint32_t)];
        size_t k, c = 0;
        CaDigest *d;
        uint64_t n;

        /* Generate 1MB test data */
        srand(0);
        for (k = 0; k < ELEMENTSOF(megabyte); k++)
                megabyte[k] = rand();

        assert_se(ca_digest_new(t, &d) >= 0);

        n = now(CLOCK_MONOTONIC);

        while (n + TEST_SPEED_RUNTIME_NSEC > now(CLOCK_MONOTONIC)) {
                ca_digest_write(d, megabyte, sizeof(megabyte));
                c++;
        }

        printf("%s: %zu MB/s\n", ca_digest_type_to_string(t), (size_t) ((c * NSEC_PER_SEC) / TEST_SPEED_RUNTIME_NSEC));
}

int main(int argc, char *argv[]) {
        CaDigest *d;
        CaDigestType t;

        assert_se(ca_digest_new(CA_DIGEST_SHA256, &d) >= 0);

        assert_se(memcmp(ca_digest_read(d), (const uint8_t[]) {
                                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 }, 32) == 0);

        ca_digest_reset(d);
        ca_digest_write(d, "foobar", 6);

        assert_se(memcmp(ca_digest_read(d), (const uint8_t[]) {
                                0xc3, 0xab, 0x8f, 0xf1, 0x37, 0x20, 0xe8, 0xad,
                                0x90, 0x47, 0xdd, 0x39, 0x46, 0x6b, 0x3c, 0x89,
                                0x74, 0xe5, 0x92, 0xc2, 0xfa, 0x38, 0x3d, 0x4a,
                                0x39, 0x60, 0x71, 0x4c, 0xae, 0xf0, 0xc4, 0xf2 }, 32) == 0);


        ca_digest_reset(d);

        ca_digest_write(d, "foo", 3);
        ca_digest_write(d, "bar", 3);

        assert_se(memcmp(ca_digest_read(d), (const uint8_t[]) {
                                0xc3, 0xab, 0x8f, 0xf1, 0x37, 0x20, 0xe8, 0xad,
                                0x90, 0x47, 0xdd, 0x39, 0x46, 0x6b, 0x3c, 0x89,
                                0x74, 0xe5, 0x92, 0xc2, 0xfa, 0x38, 0x3d, 0x4a,
                                0x39, 0x60, 0x71, 0x4c, 0xae, 0xf0, 0xc4, 0xf2 }, 32) == 0);

        d = ca_digest_free(d);

        assert_se(ca_digest_new(CA_DIGEST_SHA512_256, &d) >= 0);

        assert_se(memcmp(ca_digest_read(d), (const uint8_t[]) {
                                0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28,
                                0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14, 0x06,
                                0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74,
                                0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a }, 32) == 0);

        ca_digest_reset(d);
        ca_digest_write(d, "foobar", 6);

        assert_se(memcmp(ca_digest_read(d), (const uint8_t[]) {
                                0xd0, 0x14, 0xc7, 0x52, 0xbc, 0x2b, 0xe8, 0x68,
                                0xe1, 0x63, 0x30, 0xf4, 0x7e, 0x0c, 0x31, 0x6a,
                                0x59, 0x67, 0xbc, 0xbc, 0x9c, 0x28, 0x6a, 0x45,
                                0x77, 0x61, 0xd7, 0x05, 0x5b, 0x92, 0x14, 0xce }, 32) == 0);

        ca_digest_reset(d);

        ca_digest_write(d, "foo", 3);
        ca_digest_write(d, "bar", 3);

        assert_se(memcmp(ca_digest_read(d), (const uint8_t[]) {
                                0xd0, 0x14, 0xc7, 0x52, 0xbc, 0x2b, 0xe8, 0x68,
                                0xe1, 0x63, 0x30, 0xf4, 0x7e, 0x0c, 0x31, 0x6a,
                                0x59, 0x67, 0xbc, 0xbc, 0x9c, 0x28, 0x6a, 0x45,
                                0x77, 0x61, 0xd7, 0x05, 0x5b, 0x92, 0x14, 0xce }, 32) == 0);

        d = ca_digest_free(d);

        for (t = 0; t < _CA_DIGEST_TYPE_MAX; t++)
                test_speed(t);

        return 0;
}
