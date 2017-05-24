#ifndef cacommonhfoo
#define cacommonhfoo

typedef enum CaIterate {
        CA_ITERATE_CURRENT,
        CA_ITERATE_FIRST,
        CA_ITERATE_LAST,
        CA_ITERATE_NEXT,
        CA_ITERATE_PREVIOUS,
        _CA_ITERATE_MAX,
        _CA_ITERATE_INVALID = -1,
} CaIterate;

#endif
