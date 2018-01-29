/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/fs.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "calocation.h"
#include "util.h"
#include "realloc-buffer.h"

int ca_location_new(
                const char *path,
                CaLocationDesignator designator,
                uint64_t offset,
                uint64_t size,
                CaLocation **ret) {

        CaLocation *l;

        if (!CA_LOCATION_DESIGNATOR_VALID(designator))
                return -EINVAL;
        if (!isempty(path) && path[0] == '/') /* insist on relative paths */
                return -EINVAL;
        if (offset == UINT64_MAX)
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

        if (!isempty(path)) {
                l->path = strdup(path);
                if (!l->path) {
                        free(l);
                        return -ENOMEM;
                }
        }

        l->n_ref = 1;
        l->designator = designator;
        l->offset = designator == CA_LOCATION_VOID ? 0 : offset;
        l->size = size;
        l->mtime = UINT64_MAX;
        l->archive_offset = UINT64_MAX;
        l->feature_flags = UINT64_MAX;

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
        ca_name_table_unref(l->name_table);

        return mfree(l);
}

CaLocation* ca_location_ref(CaLocation *l) {
        if (!l)
                return NULL;

        assert(l->n_ref > 0);
        l->n_ref++;

        return l;
}

int ca_location_copy(CaLocation *l, CaLocation **ret) {
        CaLocation *copy = NULL;
        int r;

        if (!ret)
                return -EINVAL;

        if (!l) {
                *ret = NULL;
                return 0;
        }

        r = ca_location_new(l->path, l->designator, l->offset, l->size, &copy);
        if (r < 0)
                return r;

        copy->root = ca_file_root_ref(l->root);

        copy->mtime = l->mtime;
        copy->inode = l->inode;
        copy->generation_valid = l->generation_valid;
        copy->generation = l->generation;
        copy->name_table = ca_name_table_ref(l->name_table);
        copy->archive_offset = l->archive_offset;
        copy->feature_flags = l->feature_flags;

        *ret = copy;

        return 1;
}

const char* ca_location_format(CaLocation *l) {
        _cleanup_(realloc_buffer_free) ReallocBuffer buffer = {};
        int r;

        if (!l)
                return NULL;

        /* Here's how we format location strings:
         *
         *     <path>+<designator><offset>[:<size>][@<inode>.<mtime>[.<generation>]][%<features>]
         *
         * == Mandatory
         *
         * path:       the file system path, relative to the top of the tree we operate on, empty when we operate on the root element
         * designator: single character encoding which kind of data object we are currently serializing
         * offset:     relative offset to the beginning of the object we are currently serializing
         *
         * == Optional
         *
         * size:       when known the size of the current data object we are serializing
         * inode:      the inode number of the path to the file/directory we are serializing
         * mtime:      the modification time in ns of the inode
         * generation: when known the file's generation code
         * features:   the feature mask used for encoding
         *
         */

        if (l->formatted)
                return l->formatted;

        r = realloc_buffer_printf(&buffer, "%s+%c%" PRIu64, strempty(l->path), (char) l->designator, l->offset);
        if (r < 0)
                return NULL;

        if (l->size != UINT64_MAX) {
                r = realloc_buffer_printf(&buffer, ":%" PRIu64, l->size);
                if (r < 0)
                        return NULL;
        }

        if (l->mtime != UINT64_MAX) {
                r = realloc_buffer_printf(&buffer, "@%" PRIu64 ".%" PRIu64, l->inode, l->mtime);
                if (r < 0)
                        return NULL;

                if (l->generation_valid) {
                        /* Note that the kernel API suggests the generation is an "int", i.e. a signed entity. We'll
                         * format it as unsigned here however, to avoid another "-" in the fomatted version. */
                        r = realloc_buffer_printf(&buffer, ".%u", (unsigned) l->generation);
                        if (r < 0)
                                return NULL;
                }
        }

        if (l->feature_flags != UINT64_MAX) {
                r = realloc_buffer_printf(&buffer, "%%%" PRIx64, l->feature_flags);
                if (r < 0)
                        return NULL;
        }

        l->formatted = realloc_buffer_steal(&buffer);

        return l->formatted;
}

int ca_location_parse(const char *text, CaLocation **ret) {
        uint64_t offset, size = UINT64_MAX, mtime = UINT64_MAX, inode = 0, features = UINT64_MAX;
        const char *q, *c, *u;
        CaLocation *l;
        char *n;
        int r, generation = 0;
        bool generation_valid = false;

        if (!text)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        u = c = strrchr(text, '+');
        if (!u)
                return -EINVAL;

        if (u != text && text[0] == '/') /* Don't allow absolute paths */
                return -EINVAL;

        if (!CA_LOCATION_DESIGNATOR_VALID(u[1]))
                return -EINVAL;

        /* The '%' suffix (feature flags) is optional */
        q = strchr(u+2, '%');
        if (q) {
                r = safe_atox64(q + 1, &features);
                if (r < 0)
                        return r;
                if (features == UINT64_MAX)
                        return -EINVAL;

                u = strndupa(u, q - u);
        }

        /* The '@' suffix (inode/mtime/generation info) is optional */
        q = strchr(u+2, '@');
        if (q) {
                const char *z, *k, *w;

                /* There are either two or three dot separated parts after the '@' */
                z = strchr(q+1, '.');
                if (!z)
                        return -EINVAL;

                /* The first part is the inode number */
                w = strndupa(q+1, z - q - 1);
                r = safe_atou64(w, &inode);
                if (r < 0)
                        return r;
                z++;

                k = strchr(z, '.');
                if (k) {
                        unsigned g;

                        /* The third part is the generation, if there is one */
                        r = safe_atou(k + 1, &g);
                        if (r < 0)
                                return r;

                        generation = (int) g;
                        generation_valid = true;

                        z = strndupa(z, k - z);
                }

                /* The second part is the mtime */
                r = safe_atou64(z, &mtime);
                if (r < 0)
                        return r;
                if (mtime == UINT64_MAX)
                        return -EINVAL;

                u = strndupa(u, q - u);
        }

        /* The size is component is optional, too */
        q = strchr(u+2, ':');
        if (q) {
                r = safe_atou64(q+1, &size);
                if (r < 0)
                        return r;
                if (size == 0 || size == UINT64_MAX)
                        return -EINVAL;

                u = strndupa(u, q - u);
        }

        r = safe_atou64(u+2, &offset);
        if (r < 0)
                return r;
        if (offset == UINT64_MAX)
                return -EINVAL;

        if (size != UINT64_MAX && offset + size < offset)
                return -EINVAL;

        if (c == text)
                n = NULL;
        else {
                n = strndup(text, c - text);
                if (!n)
                        return -ENOMEM;
        }

        if (u[1] == CA_LOCATION_VOID && !isempty(n)) {
                free(n);
                return -EINVAL;
        }

        l = new0(CaLocation, 1);
        if (!l) {
                free(n);
                return -ENOMEM;
        }

        l->path = n;
        l->offset = u[1] == CA_LOCATION_VOID ? 0 : offset;
        l->size = size;
        l->designator = u[1];
        l->n_ref = 1;
        l->inode = inode;
        l->mtime = mtime;
        l->generation = generation;
        l->generation_valid = generation_valid;
        l->archive_offset = UINT64_MAX;
        l->feature_flags = features;

        *ret = l;
        return 0;
}

int ca_location_patch_size(CaLocation **l, uint64_t size) {
        int r;

        /* Since we consider CaLocation objects immutable, let's duplicate the object, unless we are the only owner of it */

        if (!l)
                return -EINVAL;
        if (!*l)
                return -EINVAL;

        if ((*l)->size == size)
                return 0;

        if ((*l)->n_ref == 1)
                (*l)->formatted = mfree((*l)->formatted);
        else {
                CaLocation *n;

                r = ca_location_copy(*l, &n);
                if (r < 0)
                        return r;

                ca_location_unref(*l);
                *l = n;
        }

        (*l)->size = size;
        return 1;
}

int ca_location_patch_root(CaLocation **l, CaFileRoot *root) {
        int r;

        if (!l)
                return -EINVAL;
        if (!*l)
                return -EINVAL;

        if ((*l)->root == root)
                return 0;

        if ((*l)->n_ref != 1) {
                CaLocation *n;

                r = ca_location_copy(*l, &n);
                if (r < 0)
                        return r;

                ca_location_unref(*l);
                *l = n;
        }

        ca_file_root_unref((*l)->root);
        (*l)->root = ca_file_root_ref(root);

        return 0;
}

int ca_location_advance(CaLocation **l, uint64_t n_bytes) {
        int r;

        if (!l)
                return -EINVAL;
        if (!*l)
                return -EINVAL;

        if (n_bytes == 0)
                return 0;

        if ((*l)->size != UINT64_MAX && n_bytes > (*l)->size)
                return -ESPIPE;

        if ((*l)->n_ref == 1)
                (*l)->formatted = mfree((*l)->formatted);
        else {
                CaLocation *n;

                r = ca_location_copy(*l, &n);
                if (r < 0)
                        return r;

                ca_location_unref(*l);
                *l = n;
        }

        if ((*l)->designator != CA_LOCATION_VOID)
                (*l)->offset += n_bytes;

        if ((*l)->archive_offset != UINT64_MAX)
                (*l)->archive_offset += n_bytes;

        if ((*l)->size != UINT64_MAX)
                (*l)->size -= n_bytes;

        return 1;
}

int ca_location_merge(CaLocation **a, CaLocation *b) {
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

        if ((*a)->mtime != b->mtime)
                return 0;

        if ((*a)->mtime != UINT64_MAX) {

                if ((*a)->inode != b->inode)
                        return 0;

                if ((*a)->generation_valid != b->generation_valid)
                        return 0;

                if ((*a)->generation_valid && (*a)->generation != b->generation)
                        return 0;
        }

        if ((*a)->n_ref == 1)
                (*a)->formatted = mfree((*a)->formatted);
        else {
                CaLocation *n;

                r = ca_location_copy(*a, &n);
                if (r < 0)
                        return r;

                ca_location_unref(*a);
                *a = n;
        }

        (*a)->size += b->size;
        return 1;
}

int ca_location_open(CaLocation *l) {
        _cleanup_(safe_closep) int fd = -1;
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
                        fd = fcntl(l->root->fd, F_DUPFD_CLOEXEC, 3);
                else
                        fd = openat(l->root->fd, l->path, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK);

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

                fd = open(p, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_NOFOLLOW);
        }
        if (fd < 0)
                return -errno;

        if (l->mtime != UINT64_MAX) {
                struct stat st;
                uint64_t n;

                /* Ensure inode, mtime and generation still match */

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (st.st_ino != l->inode)
                        return -ESTALE;

                n = MAX(timespec_to_nsec(st.st_mtim), timespec_to_nsec(st.st_ctim));
                if (l->mtime != n)
                        return -ESTALE;

                if (l->generation_valid) {
                        int v;

                        if (ioctl(fd, FS_IOC_GETVERSION, &v) < 0)
                                return -ESTALE; /* If the fs doesn't support the FS_IOC_GETVERSION ioctl anymore, the file has changed */

                        if (v != l->generation)
                                return -ESTALE;
                }
        }

        r = fd;
        fd = -1;

        return r;
}

int ca_location_id_make(CaDigest *digest, CaLocation *l, bool include_size, CaChunkID *ret) {
        if (!digest)
                return -EINVAL;
        if (!l)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (ca_digest_get_size(digest) != sizeof(CaChunkID))
                return -EINVAL;

        ca_digest_reset(digest);

        if (l->path)
                ca_digest_write(digest, l->path, strlen(l->path));

        ca_digest_write_u8(digest, (uint8_t) l->designator);
        ca_digest_write_u64(digest, l->offset);

        if (include_size && l->size != UINT64_MAX)
                ca_digest_write_u64(digest, l->size);

        if (l->mtime != UINT64_MAX) {
                ca_digest_write_u64(digest, l->mtime);
                ca_digest_write_u64(digest, l->inode);

                if (l->generation_valid)
                        ca_digest_write_u32(digest, (uint32_t) l->generation);
        }

        if (l->feature_flags != UINT64_MAX)
                ca_digest_write_u64(digest, l->feature_flags);

        memcpy(ret, ca_digest_read(digest), sizeof(CaChunkID));
        return 0;
}

bool ca_location_equal(CaLocation *a, CaLocation *b, bool compare_size) {
        if (a == b)
                return true;

        if (!a || !b)
                return false;

        if (a->designator != b->designator)
                return false;

        if (a->offset != b->offset)
                return false;

        if (!streq(strempty(a->path), strempty(b->path)))
                return false;

        if (compare_size)
                if (a->size != b->size)
                        return false;

        if (a->feature_flags != b->feature_flags)
                return false;

        if (a->mtime != b->mtime)
                return false;

        if (a->mtime != UINT64_MAX) {
                if (a->inode != b->inode)
                        return false;

                if (a->generation_valid != b->generation_valid)
                        return false;

                if (a->generation_valid)
                        if (a->generation != b->generation)
                                return false;
        }

        return true;
}
