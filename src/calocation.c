#include <sys/fcntl.h>

#include "calocation.h"
#include "util.h"

int ca_location_new(
                const char *path,
                CaLocationDesignator designator,
                uint64_t offset,
                uint64_t size,
                CaLocation **ret) {

        CaLocation *l;

        if (!CA_LOCATION_DESIGNATOR_VALID(designator))
                return -EINVAL;
        if (size == 0)
                return -EINVAL;
        if (designator == CA_LOCATION_VOID && path)
                return -EINVAL;

        if (size != UINT64_MAX && offset + size < offset)
                return -EINVAL;

        l = new0(CaLocation, 1);
        if (!l)
                return -ENOMEM;

        if (path) {
                l->path = strdup(path);
                if (!l->path) {
                        free(l);
                        return -ENOMEM;
                }
        }

        l->designator = designator;
        l->offset = designator == CA_LOCATION_VOID ? 0 : offset;
        l->size = size;
        l->n_ref = 1;

        *ret = l;
        return 0;
}

CaLocation* ca_location_unref(CaLocation *l) {
        if (!l)
                return NULL;

        assert(l->n_ref > 0);
        l->n_ref--;

        if (l->n_ref > 0)
                return NULL;

        free(l->path);
        free(l->formatted);

        ca_file_root_unref(l->root);

        return mfree(l);
}

CaLocation* ca_location_ref(CaLocation *l) {
        if (!l)
                return NULL;

        assert(l->n_ref > 0);
        l->n_ref++;

        return l;
}

const char* ca_location_format(CaLocation *l) {
        if (!l)
                return NULL;

        if (!l->formatted) {

                if (l->size == UINT64_MAX) {
                        if (asprintf(&l->formatted, "%s+%c%" PRIu64, strempty(l->path), (char) l->designator, l->offset) < 0)
                                return NULL;
                } else {
                        if (asprintf(&l->formatted, "%s+%c%" PRIu64 ":%" PRIu64, strempty(l->path), (char) l->designator, l->offset, l->size) < 0)
                                return NULL;
                }
        }

        return l->formatted;
}

int ca_location_parse(const char *text, CaLocation **ret) {
        uint64_t offset, size;
        const char *e, *c;
        CaLocation *l;
        char *n;
        int r;

        if (!text)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        e = strrchr(text, '+');
        if (!e)
                return -EINVAL;

        if (e != text && text[0] == '/')
                return -EINVAL;

        if (!CA_LOCATION_DESIGNATOR_VALID(e[1]))
                return -EINVAL;

        c = strchr(e+2, ':');
        if (c) {
                const char *a;

                a = strndupa(e+2, c-e-2);

                r = safe_atou64(a, &offset);
                if (r < 0)
                        return r;

                r = safe_atou64(c+1, &size);
        } else {
                size = UINT64_MAX;

                r = safe_atou64(e+2, &offset);
        }
        if (r < 0)
                return r;

        if (size == 0)
                return -EINVAL;
        if (size != UINT64_MAX && offset + size < offset)
                return -EINVAL;

        if (e == text)
                n = NULL;
        else {
                n = strndup(text, e - text);
                if (!n)
                        return -ENOMEM;
        }

        if (e[1] == CA_LOCATION_VOID && !isempty(n)) {
                free(n);
                return -EINVAL;
        }

        l = new0(CaLocation, 1);
        if (!l) {
                free(n);
                return -ENOMEM;
        }

        l->path = n;
        l->offset = e[1] == CA_LOCATION_VOID ? 0 : offset;
        l->size = size;
        l->designator = e[1];
        l->n_ref = 1;

        *ret = l;
        return 0;
}

int ca_location_patch_size(CaLocation **l, uint64_t size) {
        CaLocation *n;
        int r;

        /* Since we consider CaLocation objects immutable, let's duplicate the object, unless we are the only owner of it */

        if (!l)
                return -EINVAL;
        if (!*l)
                return -EINVAL;

        if ((*l)->size == size)
                return 0;

        if ((*l)->n_ref == 1) {
                (*l)->size = size;
                (*l)->formatted = mfree((*l)->formatted);
                return 1;
        }

        r = ca_location_new((*l)->path, (*l)->designator, (*l)->offset, size, &n);
        if (r < 0)
                return r;

        n->root = ca_file_root_ref((*l)->root);

        ca_location_unref(*l);
        *l = n;

        return 1;
}

int ca_location_patch_root(CaLocation **l, CaFileRoot *root) {
        CaLocation *copy;
        int r;

        if (!l)
                return -EINVAL;
        if (!*l)
                return -EINVAL;

        if ((*l)->root == root)
                return 0;

        if ((*l)->n_ref == 1) {
                ca_file_root_unref((*l)->root);
                (*l)->root = ca_file_root_ref(root);
                return 0;
        }

        r = ca_location_new((*l)->path,
                            (*l)->designator,
                            (*l)->offset,
                            (*l)->size,
                            &copy);
        if (r < 0)
                return r;

        copy->root = ca_file_root_ref(root);

        ca_location_unref(*l);
        *l = copy;

        return 0;
}
int ca_location_advance(CaLocation **l, uint64_t n_bytes) {
        CaLocation *n;
        int r;

        if (!l)
                return -EINVAL;
        if (!*l)
                return -EINVAL;

        if (n_bytes == 0)
                return 0;

        if ((*l)->size == UINT64_MAX)
                return -ESPIPE;
        if (n_bytes > (*l)->size)
                return -ESPIPE;

        if ((*l)->n_ref == 1) {
                if ((*l)->designator != CA_LOCATION_VOID)
                        (*l)->offset += n_bytes;
                (*l)->size -= n_bytes;
                (*l)->formatted = mfree((*l)->formatted);
                return 1;
        }

        r = ca_location_new((*l)->path, (*l)->designator, (*l)->offset + n_bytes, (*l)->size - n_bytes, &n);
        if (r < 0)
                return r;

        n->root = ca_file_root_ref((*l)->root);

        ca_location_unref(*l);
        *l = n;

        return 1;
}

int ca_location_merge(CaLocation **a, CaLocation *b) {
        CaLocation *copy;
        int r;

        if (!a)
                return -EINVAL;
        if (!*a)
                return -EINVAL;
        if (!b)
                return -EINVAL;

        if ((*a)->size == UINT64_MAX)
                return -EINVAL;
        if (b->size == UINT64_MAX)
                return -EINVAL;

        if ((*a)->root != b->root)
                return 0;

        if (!streq_ptr((*a)->path, b->path))
                return 0;

        if ((*a)->designator != b->designator)
                return 0;
        if ((*a)->designator != CA_LOCATION_VOID && (*a)->offset + (*a)->size != b->offset)
                return 0;

        if ((*a)->n_ref == 1) {
                (*a)->size += b->size;
                (*a)->formatted = mfree((*a)->formatted);
                return 1;
        }

        r = ca_location_new((*a)->path,
                            (*a)->designator,
                            (*a)->offset,
                            (*a)->size + b->size,
                            &copy);
        if (r < 0)
                return r;

        copy->root = ca_file_root_ref((*a)->root);

        ca_location_unref(*a);
        *a = copy;

        return 1;
}

int ca_location_open(CaLocation *l) {
        int r;

        if (!l)
                return -EINVAL;
        if (l->designator == CA_LOCATION_VOID)
                return -ENOTTY;
        if (!l->root)
                return -EUNATCH;
        if (l->root->invalidated)
                return -EUNATCH;

        if (l->root->fd >= 0) {

                if (isempty(l->path))
                        r = fcntl(l->root->fd, F_DUPFD_CLOEXEC, 3);
                else
                        r = openat(l->root->fd, l->path, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_NOFOLLOW);

        } else {
                const char *p;

                if (isempty(l->path) && isempty(l->root->path))
                        p = "/";
                else if (isempty(l->path))
                        p = l->root->path;
                else if (isempty(l->root->path))
                        p = l->path;
                else
                        p = strjoina(l->root->path, "/", l->path);

                r = open(p, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_NOFOLLOW);
        }

        if (r < 0)
                return -errno;

        return r;
}
