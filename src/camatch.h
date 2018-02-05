/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocamatchhfoo
#define foocamatchhfoo

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct CaMatch CaMatch;

typedef enum CaMatchType {
        CA_MATCH_POSITIVE,
        CA_MATCH_NEGATIVE,    /* Path is prefixed with an exclamation mark: reverses operation */
        CA_MATCH_INNER,       /* Item does not match anything, just exists to track children */
        _CA_MATCH_TYPE_MAX,
        _CA_MATCH_TYPE_INVALID = -1,
} CaMatchType;

struct CaMatch {
        unsigned n_ref;

        CaMatchType type;

        bool anchored:1;       /* Path starts with a slash (or contained them originall, though not at the end): only
                                * applies to the current directory, not any children */
        bool directory_only:1; /* Path is suffixed with a slash: only matches directories */

        CaMatch **children;
        size_t n_children;
        size_t n_allocated;

        char name[];
};

int ca_match_new_from_file(int dir_fd, const char *filename, CaMatch **ret);
int ca_match_new_from_strings(char **path, CaMatch **ret);

CaMatch* ca_match_ref(CaMatch *match);
CaMatch* ca_match_unref(CaMatch *match);

static inline void ca_match_unrefp(CaMatch **match) {
        if (match)
                ca_match_unref(*match);
}

int ca_match_add_child(CaMatch *match, CaMatch *child);

int ca_match_merge(CaMatch **a, CaMatch *b);

int ca_match_normalize(CaMatch **match);

int ca_match_test(CaMatch *match, const char *name, bool is_directory, CaMatch **ret);

static inline size_t ca_match_children(CaMatch *match) {
        return match ? match->n_children : 0;
}

void ca_match_dump(FILE *f, CaMatch *match, const char *prefix);

bool ca_match_equal(CaMatch *a, CaMatch *b);

#endif
