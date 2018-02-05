/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <fnmatch.h>

#include "camatch.h"
#include "util.h"

static CaMatch* ca_match_alloc(CaMatchType type, const char *name) {
        CaMatch *ret;
        size_t l;

        assert(type >= 0);
        assert(type < _CA_MATCH_TYPE_MAX);

        l = strlen_null(name);

        ret = malloc0(offsetof(CaMatch, name) + l + 1);
        if (!ret)
                return NULL;

        ret->n_ref = 1;
        ret->type = type;

        if (name)
                memcpy(ret->name, name, l);

        return ret;
}

static CaMatch* ca_match_alloc_subtree(void) {
        CaMatch *ret;

        ret = ca_match_alloc(CA_MATCH_INNER, NULL);
        if (!ret)
                return NULL;

        ret->anchored = true;
        ret->directory_only = true;

        return ret;
}

static int parse_line(CaMatch *parent, const char *line) {
        _cleanup_(ca_match_unrefp) CaMatch *first = NULL;
        CaMatch *current = NULL;
        const char *p = line;
        CaMatchType type;
        bool anchored;
        int r;

        assert(parent);
        assert(parent->type == CA_MATCH_INNER);
        assert(line);

        if (*p == '!') {
                type = CA_MATCH_NEGATIVE;
                p++;
        } else
                type = CA_MATCH_POSITIVE;

        /* If this contains at least one / this expressions is anchored here */
        anchored = !!strchr(p, '/');

        /* Remove initial slashes now */
        p += strspn(p, "/");

        for (;;) {
                _cleanup_(ca_match_unrefp) CaMatch *item = NULL;
                _cleanup_free_ char *name = NULL;
                bool directory_only;
                size_t k;

                /* Determine length of this component */
                k = strcspn(p, "/");

                /* Don't allow empty path components, or ".", or "..". */
                if (k == 0)
                        return -EINVAL;
                if (k == 1 && p[0] == '.')
                        return -EINVAL;
                if (k == 2 && p[0] == '.' && p[1] == '.')
                        return -EINVAL;

                name = strndup(p, k);
                if (!name)
                        return -ENOMEM;
                p += k;

                /* If this ends in a slash, we should match against a slash only */
                directory_only = *p == '/';
                p += strspn(p, "/");

                item = ca_match_alloc(isempty(p) ? type : CA_MATCH_INNER, name);
                if (!item)
                        return -ENOMEM;

                item->anchored = anchored;
                item->directory_only = directory_only;

                if (!first) {
                        /* If this is the top-level item, then let's remember it, so that we can add it when we leave
                         * the loop, after all is complete */
                        first = item;
                        item = NULL;
                } else {
                        /* This is not the top-level item, let's add it right-away. */
                        assert(current);

                        r = ca_match_add_child(current, item);
                        if (r < 0)
                                return r;
                }

                /* Did we reach the end of the string? If so, exit the loop */
                if (isempty(p))
                        break;

                /* On the next iteration, this is where the child will be added. Note that we don't bother to take a
                 * ref here, as the items we are creating are implicitly ref'ed by 'first' and its chain anyway. */
                current = item ?: first;

                anchored = true;
        }

        return ca_match_add_child(parent, first);
}

int ca_match_new_from_file(int dir_fd, const char *filename, CaMatch **ret) {
        _cleanup_(ca_match_unrefp) CaMatch *match = NULL;
        _cleanup_(safe_fclosep) FILE *f = NULL;
        int fd, r;

        assert(ret);

        fd = openat(dir_fd, filename, O_CLOEXEC|O_RDONLY|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return -errno;

        f = fdopen(fd, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *l;

                r = read_line(f, LARGE_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                l = strstrip(line);

                if (isempty(l))
                        continue;

                if (l[0] == '#')
                        continue;

                if (!match) {
                        match = ca_match_alloc_subtree();
                        if (!match)
                                return -ENOMEM;
                }

                r = parse_line(match, l);
                if (r < 0)
                        return r;
        }

        *ret = match;
        match = NULL;

        return !!*ret;
}

int ca_match_new_from_strings(char **list, CaMatch **ret) {
        _cleanup_(ca_match_unrefp) CaMatch *match = NULL;
        char **i;
        int r;

        assert(ret);

        STRV_FOREACH(i, list) {
                if (!match) {
                        match = ca_match_alloc_subtree();
                        if (!match)
                                return -ENOMEM;
                }

                r = parse_line(match, *i);
                if (r < 0)
                        return r;
        }

        *ret = match;
        match = NULL;

        return !!*ret;
}

CaMatch* ca_match_ref(CaMatch *match) {
        if (!match)
                return NULL;

        assert(match->n_ref > 0);
        match->n_ref++;

        return match;
}

CaMatch* ca_match_unref(CaMatch *match) {
        size_t i;

        if (!match)
                return NULL;

        assert(match->n_ref > 0);
        match->n_ref--;

        if (match->n_ref > 0)
                return NULL;

        for (i = 0; i < match->n_children; i++)
                ca_match_unref(match->children[i]);

        free(match->children);

        return mfree(match);
}

int ca_match_add_child(CaMatch *match, CaMatch *child) {
        assert(match);
        assert(child);

        /* Don't allow modifications like this if anyone else owns a reference */
        if (match->n_ref > 1)
                return -EBUSY;

        if (!GREEDY_REALLOC(match->children, match->n_allocated, match->n_children + 1))
                return -ENOMEM;

        match->children[match->n_children++] = ca_match_ref(child);

        return 0;
}

static int ca_match_make_writable(CaMatch **match) {
        _cleanup_(ca_match_unrefp) CaMatch *copy = NULL;
        size_t i;
        int r;

        assert(match);

        if (!*match)
                return -EINVAL;

        assert((*match)->n_ref > 0);

        if ((*match)->n_ref == 1)
                return 0;

        copy = ca_match_alloc((*match)->type, (*match)->name);
        if (!copy)
                return -ENOMEM;

        copy->anchored = (*match)->anchored;
        copy->directory_only = (*match)->directory_only;

        for (i = 0; i < (*match)->n_children; i++) {
                r = ca_match_add_child(copy, (*match)->children[i]);
                if (r < 0)
                        return r;
        }

        ca_match_unref(*match);
        *match = copy;
        copy = NULL;

        return 0;
}

int ca_match_merge(CaMatch **a, CaMatch *b) {
        size_t i;
        int r;

        assert(a);

        if (!b)
                return 0;

        if (!*a) {
                *a = ca_match_ref(b);
                return 0;
        }

        if ((*a)->type != b->type)
                return -EDOM;

        if ((*a)->anchored != b->anchored)
                return -EDOM;

        if ((*a)->directory_only != b->directory_only)
                return -EDOM;

        if (!streq((*a)->name, b->name))
                return -EDOM;

        if (b->n_children > 0) {
                r = ca_match_make_writable(a);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC((*a)->children, (*a)->n_allocated, (*a)->n_children + b->n_children))
                        return -ENOMEM;

                for (i = 0; i < b->n_children; i++)
                        (*a)->children[(*a)->n_children++] = ca_match_ref(b->children[i]);
        }

        return 0;
}

static int compare_match(const void *a, const void *b) {
        const CaMatch *x = *(CaMatch**) a, *y = *(CaMatch**) b;
        size_t i;
        int k;

        if (x == y)
                return 0;

        if (x->type < y->type)
                return -1;
        if (x->type > y->type)
                return 1;

        k = strcmp(x->name, y->name);
        if (k != 0)
                return k;

        if (!x->anchored && y->anchored)
                return -1;
        if (x->anchored && !y->anchored)
                return 1;

        if (!x->directory_only && y->directory_only)
                return -1;
        if (x->directory_only && !y->directory_only)
                return 1;

        for (i = 0;; i++) {

                /* Reached the end of the list of children on both? then they are equal */
                if (i >= x->n_children && i >= y->n_children)
                        return 0;

                /* Reached the end on one? Then they have an order */
                if (i >= x->n_children)
                        return 1;
                if (i >= y->n_children)
                        return -1;

                /* Otherwise, compare this entry */
                k = compare_match(x->children + i, y->children +i);
                if (k != 0)
                        return k;
        }

        return 0;
}

int ca_match_normalize(CaMatch **match) {
        bool normalize_previous = false;
        size_t i, j;
        int r, q = 0;

        /* "Normalizes" the specified origin object, i.e. brings it into a defined order and tries to merge identical
         * subtrees. Note that this might fail for some reasons — if it does then we'll return a consistent object,
         * that might not be normalized but might still be different from the original, however it will express the
         * same ruleset as before. */

        assert(match);

        if (ca_match_children(*match) == 0)
                return 0;

        /* Only inner nodes may have children */
        assert((*match)->type == CA_MATCH_INNER);

        /* Only anchored nodes may have children */
        assert((*match)->anchored);

        /* Only directory-only nodes may have children */
        assert((*match)->directory_only);

        r = ca_match_make_writable(match);
        if (r < 0)
                return r;

        /* First, let's normalize all children */
        for (i = 0; i < ca_match_children(*match); i++) {
                r = ca_match_normalize(&(*match)->children[i]);
                if (r < 0)
                        return r;
        }

        /* If our object is empty or has one entry only it's normalized already */
        if (ca_match_children(*match) <= 1)
                return 0;

        /* Bring lines into a defined order. */
        qsort((*match)->children, (*match)->n_children, sizeof(CaMatch*), compare_match);

        /* And now, let's see if we can merge each item with the one immediately following. */
        for (i = 1, j = 1; i < ca_match_children(*match); i++) {

                /* Can we merge this item into the previous one? */
                r = ca_match_merge((*match)->children + j - 1, (*match)->children[i]);
                if (r >= 0) {
                        /* Yes! This worked. Let's remember that we now need to normalize the previous one again, but
                         * then let's proceed maybe we can merge more. */
                        normalize_previous = true;
                        ca_match_unref((*match)->children[i]);
                        continue;
                }
                if (r != -EDOM && q >= 0) /* Hmm, so this failed. Let's remember the first error, but proceed our loop,
                                           * since we should return a consistent object that can be freed safely, even
                                           * if not successfully normalized. */
                        q = r;

                /* If the previous item was merged, then we should normalize it again, before we got to the next
                 * item. */
                if (normalize_previous) {
                        r = ca_match_normalize((*match)->children + j - 1);
                        if (r < 0 && q >= 0)
                                q = r;

                        normalize_previous = false;
                }

                (*match)->children[j++] = (*match)->children[i];
        }

        if (normalize_previous) {
                r = ca_match_normalize((*match)->children + j - 1);
                if (r < 0 && q >= 0)
                        q = r;
        }

        (*match)->n_children = j;
        return q;
}

int ca_match_test(CaMatch *match, const char *name, bool is_directory, CaMatch **ret_subtree) {
        _cleanup_(ca_match_unrefp) CaMatch *subtree = NULL;
        bool has_positive = false, has_negative = false,
                has_unanchored = false, has_2nd_level = false;
        size_t i;
        int r;

        /* Checks wether the match object knows a match for the specified 'name'. If it has a positive match returns
         * 1, if it has a negative one, returns 0. If 'ret_subtree' is non-NULL creates a new object for all children
         * that match. */

        if (isempty(name) || dot_or_dot_dot(name))
                return -EINVAL;

        for (i = 0; i < ca_match_children(match); i++) {
                CaMatch *child = match->children[i];
                int k;

                /* If we are invoked for a directory, and the caller is interested in subtree CaMatch object, then
                 * let's add all our non-anchored items to that too. */
                if (ret_subtree && !child->anchored && is_directory) {
                        if (!subtree) {
                                subtree = ca_match_alloc_subtree();
                                if (!subtree)
                                        return -ENOMEM;
                        }

                        r = ca_match_add_child(subtree, child);
                        if (r < 0)
                                return r;

                        has_unanchored = true;
                }

                if (child->directory_only && !is_directory)
                        continue;

                k = fnmatch(child->name, name, FNM_PERIOD);
                if (k == FNM_NOMATCH)
                        continue;
                if (k != 0)
                        return -EINVAL;

                switch (child->type) {

                case CA_MATCH_NEGATIVE:
                        if (!ret_subtree) /* if the caller is not interested in the child list, then we don't have to collect anything, and shortcut things. */
                                return false;

                        has_negative = true;
                        break;

                case CA_MATCH_POSITIVE:
                        has_positive = true;
                        break;

                case CA_MATCH_INNER:
                        if (ret_subtree && child->n_children > 0) {
                                size_t j;

                                if (!subtree) {
                                        subtree = ca_match_alloc_subtree();
                                        if (!subtree)
                                                return -ENOMEM;
                                }

                                for (j = 0; j < child->n_children; j++) {
                                        r = ca_match_add_child(subtree, child->children[j]);
                                        if (r < 0)
                                                return r;

                                        has_2nd_level = true;
                                }
                        }

                        break;

                default:
                        assert_not_reached("Unexpected match node");
                }
        }

        if (ret_subtree) {

                /* If our subtree object has children both originating in our own CaMatch object (where they are
                 * unanchored and thus apply to all child directories too), and from a "long path" (i.e. a path
                 * containing at least two components), then we might want to normalize the subtree. If we only
                 * acquired nodes from one or neither source then there's no need to normalize things, as we just took
                 * a subset of a normalized tree without reordering it and that results in a normalized tree too. */

                if (has_2nd_level && has_unanchored) {
                        r = ca_match_normalize(&subtree);
                        if (r < 0)
                                return r;
                }

                *ret_subtree = subtree;
                subtree = NULL;
        }

        return has_negative ? false : has_positive;
}

void ca_match_dump(FILE *f, CaMatch *match, const char *prefix) {
        size_t i;

        if (!match)
                return;
        if (!f)
                f = stdout;
        prefix = strempty(prefix);

        fprintf(f, "%s%s <%s> %s %s\n",
                prefix,
                match->type == CA_MATCH_POSITIVE ? "POSITIVE" :
                match->type == CA_MATCH_NEGATIVE ? "NEGATIVE" : "INNER",
                match->name,
                match->anchored ? "ANCHORED=YES" : "ANCHORED=NO",
                match->directory_only ? "DIRECTORY-ONLY=YES" : "DIRECTORY-ONLY=NO");

        prefix = strjoina("\t", prefix);

        for (i = 0; i < match->n_children; i++)
                ca_match_dump(f, match->children[i], prefix);
}

bool ca_match_equal(CaMatch *a, CaMatch *b) {
        return compare_match(&a, &b) == 0;
}
