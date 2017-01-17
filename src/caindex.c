#include <fcntl.h>
#include <stddef.h>

#include "caformat.h"
#include "caindex.h"
#include "util.h"

#undef EBADMSG
#define EBADMSG __LINE__

struct CaIndex {
        int open_flags;
        int fd;

        char *path;
        char *temporary_path;

        bool opened;
        bool wrote_eof;

        uint64_t start_offset, offset;
        uint64_t n_items;
        uint64_t previous_object;

        CaObjectID digest;
        bool digest_valid;
};

static CaIndex* ca_index_new(void) {
        CaIndex *i;

        i = new0(CaIndex, 1);
        if (!i)
                return NULL;

        i->fd = -1;
        return i;
}

CaIndex *ca_index_new_write(void) {
        CaIndex *i;

        i = ca_index_new();
        if (!i)
                return NULL;

        i->open_flags = O_CLOEXEC|O_NOCTTY|O_WRONLY|O_CREAT|O_EXCL;
        return i;
}

CaIndex *ca_index_new_read(void) {
        CaIndex *i;

        i = ca_index_new();
        if (!i)
                return NULL;

        i->open_flags = O_CLOEXEC|O_NOCTTY|O_RDONLY;
        return i;
}

CaIndex *ca_index_unref(CaIndex *i) {
        if (!i)
                return NULL;

        free(i->path);

        if (i->temporary_path) {
                (void) unlink(i->temporary_path);
                free(i->temporary_path);
        }

        safe_close(i->fd);

        return mfree(i);
}

int ca_index_set_fd(CaIndex *i, int fd) {
        if (!i)
                return -EINVAL;
        if (i->fd >= 0)
                return -EBUSY;
        if (i->path)
                return -EBUSY;

        i->fd = fd;
        return 0;
}

int ca_index_set_path(CaIndex *i, const char *path) {
        if (!i)
                return -EINVAL;
        if (i->fd >= 0)
                return -EBUSY;
        if (i->path)
                return -EBUSY;

        i->path = strdup(path);
        if (!i->path)
                return -ENOMEM;

        return 0;
}

static int ca_index_open_fd(CaIndex *i) {
        const char *p;
        int r;

        assert(i);

        if (i->fd >= 0)
                return 0;

        switch (i->open_flags & O_ACCMODE) {

        case O_RDONLY:
                p = i->path;
                break;

        case O_WRONLY:
                if (!i->temporary_path) {
                        r = tempfn_random(i->path, &i->temporary_path);
                        if (r < 0)
                                return r;
                }

                p = i->temporary_path;
                break;

        default:
                assert(false);
        }

        i->fd = open(p, i->open_flags, 0666);
        if (i->fd < 0)
                return -errno;

        return 1;
}

static int ca_index_write_head(CaIndex *i) {

        struct {
                CaFormatIndex index;
                CaFormatHeader table;
        } head = {
                .index.header.size = sizeof(CaFormatIndex),
                .index.header.type = htole64(CA_FORMAT_INDEX),
                .index.uuid_part2 = htole64(CA_FORMAT_INDEX_UUID_PART2),
                .table.size = htole64(UINT64_MAX),
                .table.type = htole64(CA_FORMAT_TABLE),
        };
        int r;

        if ((i->open_flags & O_ACCMODE) != O_WRONLY)
                return 0;

        r = loop_write(i->fd, &head, sizeof(head));
        if (r < 0)
                return r;

        i->start_offset = i->offset = sizeof(head);

        return 0;
}

static int ca_index_read_head(CaIndex *i) {
        struct {
                CaFormatIndex index;
                CaFormatHeader table;
        } head;
        ssize_t n;

        if ((i->open_flags & O_ACCMODE) != O_RDONLY)
                return 0;

        n = loop_read(i->fd, &head, sizeof(head));
        if (n < 0)
                return (int) n;
        if (n != sizeof(head))
                return -EPIPE;

        if (head.index.header.size != sizeof(CaFormatIndex) ||
            head.index.header.type != htole64(CA_FORMAT_INDEX) ||
            head.index.uuid_part2 != htole64(CA_FORMAT_INDEX_UUID_PART2))
                return -EBADMSG;

        if (head.index.feature_flags != 0)
                return -EOPNOTSUPP;

        if (head.table.size != htole64(UINT64_MAX) ||
            head.table.type != htole64(CA_FORMAT_TABLE))
                return -EBADMSG;

        i->start_offset = i->offset = sizeof(head);

        return 0;
}

int ca_index_open(CaIndex *i) {
        int r;

        if (!i)
                return -EINVAL;
        if (i->fd < 0 && !i->path)
                return -EINVAL;
        if (i->opened)
                return 0;

        r = ca_index_open_fd(i);
        if (r < 0)
                return r;

        r = ca_index_read_head(i);
        if (r < 0)
                return r;

        r = ca_index_write_head(i);
        if (r < 0)
                return r;

        i->opened = true;

        return 0;
}

static int ca_index_install(CaIndex *i) {
        assert(i);

        if ((i->open_flags & O_ACCMODE) == O_RDONLY)
                return 0;

        if (!i->wrote_eof)
                return 0;

        if (!i->temporary_path)
                return 0;
        if (!i->path)
                return 0;

        if (rename(i->temporary_path, i->path) < 0)
                return -errno;

        i->temporary_path = mfree(i->temporary_path);
        return 0;
}

int ca_index_close(CaIndex *i) {
        if (!i)
                return -EINVAL;
        if (!i->opened)
                return 0;

        if (i->path || i->fd >= 2)
                i->fd = safe_close(i->fd);

        return ca_index_install(i);
}

int ca_index_write_object(CaIndex *i, const CaObjectID *id, uint64_t size) {
        CaFormatTableItem item = {};
        uint64_t end;
        int r;

        if (!i)
                return -EINVAL;
        if (!id)
                return -EINVAL;
        if (size == 0)
                return -EINVAL;
        if ((i->open_flags & O_ACCMODE) == O_RDONLY)
                return -EROFS;
        if (i->wrote_eof)
                return -EBUSY;

        end = i->previous_object + size;
        if (end < i->previous_object)
                return -E2BIG;

        item.offset = htole64(end);
        memcpy(&item.object, id, sizeof(CaObjectID));

        r = loop_write(i->fd, &item, sizeof(item));
        if (r < 0)
                return r;

        i->previous_object = end;
        i->offset += sizeof(item);
        i->n_items++;

        return 0;
}

int ca_index_write_eof(CaIndex *i) {
        struct {
                CaFormatTableItem marker_item;
                le64_t size;
        } tail = {
                .marker_item.offset = htole64(UINT64_MAX)
        };
        int r;

        if (!i)
                return -EINVAL;
        if ((i->open_flags & O_ACCMODE) == O_RDONLY)
                return -EROFS;
        if (i->wrote_eof)
                return -EBUSY;

        write_le64(&tail.marker_item.offset, UINT64_MAX);
        memcpy(&tail.marker_item.object, &i->digest, CA_OBJECT_ID_SIZE);
        write_le64(&tail.size,
                   offsetof(CaFormatTable, items) +
                   (i->n_items * sizeof(CaFormatTableItem)) +
                   sizeof(tail));

        r = loop_write(i->fd, &tail, sizeof(tail));
        if (r < 0)
                return r;

        i->wrote_eof = true;

        return 0;
}

int ca_index_read_object(CaIndex *i, CaObjectID *ret_id, uint64_t *ret_size) {
        CaFormatTableItem item;
        ssize_t n;

        if (!i)
                return -EINVAL;
        if (!ret_id)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        if ((i->open_flags & O_ACCMODE) == O_WRONLY)
                return -EACCES;

        n = loop_read(i->fd, &item, sizeof(item));
        if (n < 0)
                return (int) n;
        if (n != sizeof(item))
                return -EPIPE;

        if (le64toh(item.offset) == UINT64_MAX) {
                struct {
                        le64_t final_size;
                        uint8_t space;
                } tail;

                /* We try to read one more byte than we expect. if we can read it there's trailing garbage. */
                n = loop_read(i->fd, &tail, sizeof(tail));
                if (n < 0)
                        return (int) n;
                if (n != sizeof(le64_t))
                        return -EBADMSG;

                i->offset += sizeof(item) + n;

                if (le64toh(tail.final_size) != (i->offset - i->start_offset + offsetof(CaFormatTable, items)))
                        return -EBADMSG;

                memcpy(&i->digest, item.object, sizeof(CaObjectID));
                i->digest_valid = true;

                memset(&ret_id, 0, sizeof(CaObjectID));
                *ret_size = 0;

                return 0; /* EOF */
        }

        if (i->previous_object >= le64toh(item.offset))
                return -EBADMSG;

        memcpy(ret_id, item.object, sizeof(CaObjectID));
        *ret_size = le64toh(item.offset) - i->previous_object;

        i->previous_object = le64toh(item.offset);
        i->n_items++;
        i->offset += sizeof(item);

        return 1;
}

int ca_index_seek(CaIndex *i, uint64_t offset) {
        return -EOPNOTSUPP;
}

int ca_index_get_digest(CaIndex *i, CaObjectID *ret) {
        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!i->digest_valid)
                return -ENODATA;

        *ret = i->digest;
        return 0;
}

int ca_index_set_digest(CaIndex *i, const CaObjectID *id) {
        if (!i)
                return -EINVAL;
        if (!id)
                return -EINVAL;

        if (i->digest_valid)
                return -EBUSY;

        i->digest = *id;
        i->digest_valid = true;
        return 0;
}
