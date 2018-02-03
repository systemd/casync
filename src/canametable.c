/* SPDX-License-Identifier: LGPL-2.1+ */

#include "camakebst.h"
#include "canametable.h"
#include "realloc-buffer.h"

#define START_ITEMS 16U

CaNameTable *ca_name_table_new_size(size_t m) {
        CaNameTable *t;

        if (m == (size_t) -1 || m < START_ITEMS)
                m = START_ITEMS;

        t = malloc0(offsetof(CaNameTable, items) + m * sizeof(CaNameItem));
        if (!t)
                return NULL;

        t->n_ref = 1;
        t->entry_offset = UINT64_MAX;

        t->n_allocated = m;

        return t;
}

CaNameTable *ca_name_table_ref(CaNameTable *t) {
        if (!t)
                return NULL;

        assert(t->n_ref > 0);

        t->n_ref++;
        return t;
}

CaNameTable *ca_name_table_unref(CaNameTable *t) {
        if (!t)
                return NULL;

        assert(t->n_ref > 0);

        t->n_ref--;

        if (t->n_ref > 0)
                return NULL;

        ca_name_table_unref(t->parent);
        free(t->formatted);
        free(t);

        return NULL;
}

int ca_name_table_make_writable(CaNameTable **t, size_t add) {
        CaNameTable *nt;
        size_t om, nm;

        if (!t)
                return -EINVAL;

        if ((*t) && (*t)->n_ref == 1) {
                size_t k;

                k = (*t)->n_items + add;
                if (k < (*t)->n_items)
                        return -EOVERFLOW;

                if ((*t)->n_allocated >= k)
                        return 0;
        }

        om = *t ? (*t)->n_items : 0;
        nm = MAX(om * 2, START_ITEMS);

        if (nm < om+1)
                return -EOVERFLOW;

        nt = malloc0(offsetof(CaNameTable, items) + nm * sizeof(CaNameItem));
        if (!nt)
                return -ENOMEM;

        nt->n_ref = 1;
        nt->entry_offset = (*t)->entry_offset;
        nt->n_items = (*t)->n_items;
        nt->n_allocated = nm;
        nt->parent = ca_name_table_ref((*t)->parent);

        if (*t)
                memcpy(nt->items, (*t)->items, om * sizeof(CaNameItem));

        ca_name_table_unref(*t);
        *t = nt;

        return 0;
}

int ca_name_table_add(CaNameTable **t, CaNameItem **ret) {
        int r;

        r = ca_name_table_make_writable(t, 1);
        if (r < 0)
                return r;

        assert(*t);
        assert((*t)->n_ref == 1);
        assert((*t)->n_allocated > (*t)->n_items);

        (*t)->formatted = mfree((*t)->formatted);

        *ret = (*t)->items + (*t)->n_items ++;
        return 0;
}

char* ca_name_table_format(CaNameTable *t) {
        _cleanup_(realloc_buffer_free) ReallocBuffer buffer = {};
        CaNameTable *p;
        char nul = 0;
        int r;

        if (!t)
                return NULL;

        if (t->formatted)
                return t->formatted;

        for (p = t; p; p = p->parent) {
                size_t i;

                r = realloc_buffer_printf(&buffer, "O%" PRIx64, p->entry_offset);
                if (r < 0)
                        return NULL;

                for (i = 0; i < p->n_items; i++) {
                        CaNameItem *item;

                        item = p->items + i;

                        r = realloc_buffer_printf(&buffer, "H%" PRIx64 "S%" PRIx64 "X%" PRIx64,
                                                  item->hash, item->start_offset, item->end_offset);
                        if (r < 0)
                                return NULL;
                }
        }

        if (!realloc_buffer_append(&buffer, &nul, sizeof(nul)))
                return NULL;

        t->formatted = realloc_buffer_steal(&buffer);
        return t->formatted;
}

static int parse_one(const char **text, uint64_t *ret_hash, uint64_t *ret_start_offset, uint64_t *ret_end_offset) {
        uint64_t hash, start_offset, end_offset;
        const char *x, *c;
        size_t z;
        int r;

        assert(text);
        assert(*text);
        assert(ret_hash);
        assert(ret_start_offset);
        assert(ret_end_offset);

        x = *text;

        if (*x != 'H')
                return -EINVAL;
        x++;

        z = strspn(x, HEXDIGITS);
        c = strndupa(x, z);
        r = safe_atox64(c, &hash);
        if (r < 0)
                return r;

        x += z;

        if (*x != 'S')
                return -EINVAL;
        x++;

        z = strspn(x, HEXDIGITS);
        c = strndupa(x, z);
        r = safe_atox64(c, &start_offset);
        if (r < 0)
                return r;

        x += z;

        if (*x != 'X')
                return -EINVAL;
        x++;

        z = strspn(x, HEXDIGITS);
        c = strndupa(x, z);
        r = safe_atox64(c, &end_offset);
        if (r < 0)
                return r;

        x += z;

        *text = x;

        *ret_hash = hash;
        *ret_start_offset = start_offset;
        *ret_end_offset = end_offset;

        return 0;
}

int ca_name_table_parse(const char **text, CaNameTable **ret) {
        _cleanup_(ca_name_table_unrefp) CaNameTable *nt = NULL;
        const char *x, *eo;
        size_t z;
        int r;

        if (!text)
                return -EINVAL;
        if (!*text)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        x = *text;
        if (x[0] != 'O')
                return -EINVAL;
        x++;

        nt = ca_name_table_new();
        if (!nt)
                return -ENOMEM;

        z = strspn(x, HEXDIGITS);
        eo = strndupa(x, z);
        r = safe_atox64(eo, &nt->entry_offset);
        if (r < 0)
                return r;

        x += z;

        for (;;) {
                uint64_t hash, start_offset, end_offset;
                CaNameItem *item;

                if (*x == 'O') {
                        r = ca_name_table_parse(&x, &nt->parent);
                        if (r < 0)
                                return r;

                        break;
                }
                if (*x == 0)
                        break;

                r = parse_one(&x, &hash, &start_offset, &end_offset);
                if (r < 0)
                        return r;

                r = ca_name_table_add(&nt, &item);
                if (r < 0)
                        return r;

                item->hash = hash;
                item->start_offset = start_offset;
                item->end_offset= end_offset;
        }

        *text = x;

        *ret = nt;
        nt = NULL;

        return 0;
}

static int name_table_compare(const void *a, const void *b) {
        const CaNameItem *x = a, *y = b;

        if (x->hash < y->hash)
                return -1;
        if (x->hash > y->hash)
                return 1;

        if (x->start_offset < y->start_offset)
                return -1;
        if (x->start_offset > y->start_offset)
                return 1;

        return 0;
}

int ca_name_table_make_bst(CaNameTable *t, CaNameTable **ret) {
        _cleanup_free_ CaNameItem *buffer = NULL;
        CaNameTable *nt = NULL;
        size_t m;

        /* Reorders the specified name table to become a binary search tree. */

        m = ca_name_table_items(t);
        if (m <= 1) {
                *ret = ca_name_table_ref(t);
                return 0;
        }

        buffer = new(CaNameItem, m);
        if (!buffer)
                return -ENOMEM;

        memcpy(buffer, t->items, m * sizeof(CaNameItem));
        qsort(buffer, m, sizeof(CaNameItem), name_table_compare);

        nt = ca_name_table_new_size(m);
        if (!nt)
                return -ENOMEM;

        nt->entry_offset = t->entry_offset;
        nt->n_items = t->n_items;

        ca_make_bst(buffer, t->n_items, sizeof(CaNameItem), nt->items);

        *ret = nt;
        return 0;
}

int ca_name_table_dump(FILE *f, CaNameTable *t) {
        size_t i;

        if (!f)
                f = stderr;

        for (i = 0; i < ca_name_table_items(t); i++)
                fprintf(f, "%5zu %016"PRIx64" %16"PRIx64" → %16"PRIx64" (%" PRIu64 ")\n",
                        i,
                        t->items[i].hash,
                        t->items[i].start_offset,
                        t->items[i].end_offset,
                        t->items[i].end_offset - t->items[i].start_offset);

        return 0;
}

int ca_name_table_dump_recursive(FILE *f, CaNameTable *t) {
        int r;

        if (!f)
                f = stderr;

        while (t) {
                r = ca_name_table_dump(f, t);
                if (r < 0)
                        return r;

                t = t->parent;
                fputs("LEVEL\n", f);
        }

        fputs("TOP\n", f);
        return 0;
}
