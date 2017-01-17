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
        l->offset = offset;
        l->size = size;
        l->n_ref = 1;

        *ret = l;
        return 0;
}

CaLocation* ca_location_unref(CaLocation *l) {
        if (!l)
                return NULL;

        free(l->path);
        free(l->formatted);

        return mfree(l);
}

CaLocation* ca_location_ref(CaLocation *l) {
        if (!l)
                return NULL;

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

        l = new0(CaLocation, 1);
        if (!l) {
                free(n);
                return -ENOMEM;
        }

        l->path = n;
        l->offset = offset;
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
                return 1;
        }

        r = ca_location_new((*l)->path, (*l)->designator, (*l)->offset, size, &n);
        if (r < 0)
                return r;

        ca_location_unref(*l);
        *l = n;

        return 1;
}
