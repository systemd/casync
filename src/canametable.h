/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef foocanametablehfoo
#define foocanametablehfoo

#include <inttypes.h>
#include <sys/types.h>

#include "util.h"

/* A name table object. Contains a list of CaNameItem that carry the hash of a filename plus the start and end archive
 * offsets of the serializations of these files. The object is considered immutable, unless only a single reference is
 * taken. The object also contains a reference to the same table of the parent node. This way it encodes reliably the
 * current context of the directory serializations of all nodes and their parents at any moment in time. */

typedef struct CaNameItem {
        uint64_t hash; /* hash of the filename */
        uint64_t start_offset; /* start offset of the node's serialization in the archive stream */
        uint64_t end_offset; /* end offset */
} CaNameItem;

typedef struct CaNameTable {
        unsigned n_ref;
        struct CaNameTable *parent; /* Parent's name table chained up */

        uint64_t entry_offset;

        size_t n_items;
        size_t n_allocated;

        char *formatted;

        CaNameItem items[];
} CaNameTable;

CaNameTable *ca_name_table_new_size(size_t m);
#define ca_name_table_new() ca_name_table_new_size((size_t) -1)

CaNameTable *ca_name_table_ref(CaNameTable *t);
CaNameTable *ca_name_table_unref(CaNameTable *t);

DEFINE_TRIVIAL_CLEANUP_FUNC(CaNameTable*, ca_name_table_unref);

int ca_name_table_make_writable(CaNameTable **t, size_t add);
int ca_name_table_add(CaNameTable **t, CaNameItem **ret);

char* ca_name_table_format(CaNameTable *t);
int ca_name_table_parse(const char **text, CaNameTable **ret);

static inline size_t ca_name_table_items(CaNameTable *t) {
        return t ? t->n_items : 0;
}

static inline CaNameItem* ca_name_table_get(CaNameTable *t, size_t i) {
        if (i >= ca_name_table_items(t))
                return NULL;

        return t->items + i;
}

static inline CaNameItem *ca_name_table_last(CaNameTable *t) {
        size_t n;

        n = ca_name_table_items(t);
        if (n <= 0)
                return NULL;

        return t->items + n - 1;
}

int ca_name_table_make_bst(CaNameTable *t, CaNameTable **ret);

int ca_name_table_dump(FILE *f, CaNameTable *t);
int ca_name_table_dump_recursive(FILE *f, CaNameTable *t);

#endif
