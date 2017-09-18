/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/fcntl.h>

#include "caindex.h"
#include "gc.h"
#include "set.h"

typedef struct CaChunkCollection {
        size_t n_used;

        Set *used_chunks;
} CaChunkCollection;

static void chunk_hash_func(const void *p, struct siphash *state) {
        const CaChunkID *id = p;

        siphash24_compress(id, sizeof(CaChunkID), state);
}

static int chunk_compare_func(const void *a, const void *b) {
        return memcmp(a, b, sizeof(CaChunkID));
}

const struct hash_ops chunk_hash_ops = {
        .hash = chunk_hash_func,
        .compare = chunk_compare_func,
};

CaChunkCollection* ca_chunk_collection_new(void) {
        CaChunkCollection *c;

        c = new0(CaChunkCollection, 1);
        if (!c)
                return NULL;

        c->used_chunks = set_new(&chunk_hash_ops);

        return c;
}

CaChunkCollection* ca_chunk_collection_unref(CaChunkCollection *c) {
        if (!c)
                return NULL;

        set_free_free(c->used_chunks);

        return mfree(c);
}

int ca_chunk_collection_usage(CaChunkCollection *c, size_t *ret) {
        if (!c)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = c->n_used;
        return 0;
}

int ca_chunk_collection_size(CaChunkCollection *c, size_t *ret) {
        if (!c)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        *ret = set_size(c->used_chunks);
        return 0;
}

static int gc_add_chunk_id(CaChunkCollection *coll, CaChunkID *id) {
        CaChunkID *copy;
        int r;

        coll->n_used++;

        copy = memdup(id, sizeof(CaChunkID));
        if (!copy)
                return log_oom();

        r = set_consume(coll->used_chunks, copy);
        if (r == -EEXIST)
                return 0;

        return r;
}

int ca_chunk_collection_add_index(CaChunkCollection *coll, const char *path) {
        _cleanup_(ca_index_unrefp) CaIndex* index = NULL;
        int r;

        index = ca_index_new_read();
        if (index == 0)
                return log_oom();

        r = ca_index_set_path(index, path);
        if (r < 0) {
                fprintf(stderr, "Failed to set index path to \"%s\": %s\n", path, strerror(-r));
                return r;
        }

        r = ca_index_open(index);
        if (r < 0) {
                fprintf(stderr, "Failed to open index \"%s\": %s\n", path, strerror(-r));
                return r;
        }

        for (;;) {
                CaChunkID id;
                char ids[CA_CHUNK_ID_FORMAT_MAX];

                r = ca_index_read_chunk(index, &id, NULL, NULL);
                if (r < 0)

                assert_se(r >= 0);
                if (r < 0) {
                        fprintf(stderr, "Failed to open index \"%s\": %s\n", path, strerror(-r));
                        return r;
                }

                if (r == 0)
                        break;

                r = gc_add_chunk_id(coll, &id);
                if (r < 0) {
                        fprintf(stderr, "Failed to add chunk ID %s: %s\n",
                                ca_chunk_id_format(&id, ids),
                                strerror(-r));
                        return r;
                }
        }

        return 0;
}

int ca_gc_cleanup_unused(CaStore *store, CaChunkCollection *coll, unsigned flags) {
        _cleanup_(ca_store_iterator_unrefp) CaStoreIterator* iter;
        int r;
        _cleanup_free_ char *ids = NULL;
        size_t ids_size = 0;
        size_t removed_chunks = 0, all_chunks = 0, removed_dirs = 0;

        if (!store || !coll)
                return -EINVAL;

        iter = ca_store_iterator_new(store);
        if (!iter)
                return log_oom();

        while (true) {
                int rootdir_fd, subdir_fd;
                const char *subdir, *chunk, *dot;
                CaChunkID id;

                r = ca_store_iterator_next(iter, &rootdir_fd, &subdir, &subdir_fd, &chunk);
                if (r < 0) {
                        fprintf(stderr, "Failed to iterate over store: %s", strerror(-r));
                        return r;
                }
                if (r == 0)
                        break;

                all_chunks++;

                assert_se(dot = strchr(chunk, '.')); /* we requested .chunk extension before */
                if (!GREEDY_REALLOC(ids, ids_size, dot - chunk + 1))
                        return log_oom();

                strncpy(ids, chunk, dot - chunk);
                ids[dot - chunk] = '\0';
                if (!ca_chunk_id_parse(ids, &id)) {
                        fprintf(stderr, "Failed to parse chunk ID \"%s\", ignoring.\n", ids);
                        continue;
                }

                if (set_contains(coll->used_chunks, &id))
                        continue;

                if (flags & CA_GC_VERBOSE)
                        printf("%s chunk %s.\n",
                               flags & CA_GC_DRY_RUN ? "Would remove" : "Removing",
                               chunk);

                if (!(flags & CA_GC_DRY_RUN)) {
                        if (unlinkat(subdir_fd, chunk, 0) < 0) {
                                fprintf(stderr, "Failed to unlink chunk file \"%s\", ignoring.\n", chunk);
                                continue;
                        }

                        r = unlinkat(rootdir_fd, subdir, AT_REMOVEDIR);
                        if (r >= 0)
                                removed_dirs++;
                }

                removed_chunks++;
        }

        if (flags & CA_GC_DRY_RUN)
                printf("Would remove %zu chunks, %zu chunks remaining.\n",
                       removed_chunks, all_chunks - removed_chunks);
        else if (flags & CA_GC_VERBOSE)
                printf("Removed %zu chunks, %zu directories, %zu chunks remaining.\n",
                       removed_chunks, removed_dirs, all_chunks - removed_chunks);
        return 0;
}
