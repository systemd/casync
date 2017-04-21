#include "caorigin.h"

int main(int argc, char *argv[]) {
        CaOrigin *o, *p;
        CaLocation *a, *b, *c, *d;

        assert_se(ca_location_new("/foo", CA_LOCATION_ENTRY, 0, 22, &a) >= 0);
        assert_se(ca_location_new("/foo", CA_LOCATION_PAYLOAD, 0, 55, &b) >= 0);
        assert_se(ca_location_new("/foo", CA_LOCATION_PAYLOAD, 55, 77, &c) >= 0);
        assert_se(ca_location_new("/quux", CA_LOCATION_ENTRY, 0, 33, &d) >= 0);

        assert_se(ca_origin_new(&o) >= 0);
        assert_se(ca_origin_put(o, a) >= 0);
        assert_se(ca_origin_put(o, b) >= 0);
        assert_se(ca_origin_put(o, c) >= 0);
        assert_se(ca_origin_put(o, d) >= 0);

        assert_se(ca_origin_dump(NULL, o) >= 0);
        assert_se(ca_origin_advance_bytes(o, 1) >= 0);
        assert_se(ca_origin_dump(NULL, o) >= 0);
        assert_se(ca_origin_advance_bytes(o, 20) >= 0);
        assert_se(ca_origin_dump(NULL, o) >= 0);
        assert_se(ca_origin_advance_bytes(o, 2) >= 0);
        assert_se(ca_origin_dump(NULL, o) >= 0);

        assert_se(ca_origin_concat(o, o, UINT64_MAX) >= 0);
        assert_se(ca_origin_dump(NULL, o) >= 0);

        assert_se(ca_origin_new(&p) >= 0);
        assert_se(ca_origin_put(p, b) >= 0);
        assert_se(ca_origin_put(p, b) >= 0);
        assert_se(ca_origin_put(p, c) >= 0);
        assert_se(ca_origin_dump(NULL, p) >= 0);

        assert_se(ca_origin_concat(o, p, UINT64_MAX) >= 0);
        assert_se(ca_origin_dump(NULL, o) >= 0);

        assert_se(ca_origin_concat(o, p, 56) >= 0);
        assert_se(ca_origin_dump(NULL, o) >= 0);

        ca_origin_unref(o);
        ca_origin_unref(p);
        ca_location_unref(a);
        ca_location_unref(b);
        ca_location_unref(c);
        ca_location_unref(d);

        return 0;
}
