#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>

#include "cachunk.h"
#include "caformat-util.h"
#include "caformat.h"
#include "caindex.h"
#include "def.h"
#include "util.h"

/* #undef EBADMSG */
/* #define EBADMSG __LINE__ */

/* #undef EINVAL */
/* #define EINVAL __LINE__ */

typedef enum CaIndexMode {
        CA_INDEX_WRITE,                  /* only cooked writing */
        CA_INDEX_READ,                   /* only cooked reading */
        CA_INDEX_INCREMENTAL_WRITE,      /* cooked writing + incremental raw reading back */
        CA_INDEX_INCREMENTAL_READ,       /* incremental raw writing + cooked reading back */
} CaIndexMode;

struct CaIndex {
        CaIndexMode mode;

        int open_flags;
        int fd;
        mode_t make_mode;

        char *path;
        char *temporary_path;

        bool wrote_eof;

        uint64_t start_offset, cooked_offset, raw_offset;
        uint64_t item_position;
        uint64_t previous_chunk_offset;

        uint64_t chunk_size_min;
        uint64_t chunk_size_max;
        uint64_t chunk_size_avg;

        uint64_t feature_flags;

        uint64_t file_size; /* The size of the index file */
        uint64_t blob_size; /* The size of the blob this index file describes */
};

static inline uint64_t CA_INDEX_METADATA_SIZE(CaIndex *i) {
        assert(i);

        return i->start_offset + sizeof(CaFormatTableTail);
}

static CaIndex* ca_index_new(void) {
        CaIndex *i;

        i = new0(CaIndex, 1);
        if (!i)
                return NULL;

        i->fd = -1;
        i->make_mode = (mode_t) -1;
        i->file_size = UINT64_MAX;
        i->blob_size = UINT64_MAX;
        i->feature_flags = UINT64_MAX;

        return i;
}

CaIndex *ca_index_new_write(void) {
        CaIndex *i;

        i = ca_index_new();
        if (!i)
                return NULL;

        i->open_flags = O_CLOEXEC|O_NOCTTY|O_WRONLY|O_CREAT|O_EXCL;
        i->mode = CA_INDEX_WRITE;
        i->feature_flags = 0;

        return i;
}

CaIndex *ca_index_new_read(void) {
        CaIndex *i;

        i = ca_index_new();
        if (!i)
                return NULL;

        i->open_flags = O_CLOEXEC|O_NOCTTY|O_RDONLY;
        i->mode = CA_INDEX_READ;
        i->feature_flags = UINT64_MAX;

        return i;
}

CaIndex *ca_index_new_incremental_write(void) {
        CaIndex *i;

        i = ca_index_new();
        if (!i)
                return NULL;

        i->open_flags = O_CLOEXEC|O_NOCTTY|O_RDWR|O_CREAT|O_EXCL;
        i->mode = CA_INDEX_INCREMENTAL_WRITE;
        i->feature_flags = 0;

        return i;
}

CaIndex *ca_index_new_incremental_read(void) {
        CaIndex *i;

        i = ca_index_new();
        if (!i)
                return NULL;

        i->open_flags = O_CLOEXEC|O_NOCTTY|O_RDWR|O_CREAT|O_EXCL;
        i->mode = CA_INDEX_INCREMENTAL_READ;
        i->feature_flags = UINT64_MAX;

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

        if (i->fd >= 2)
                safe_close(i->fd);

        return mfree(i);
}

int ca_index_set_make_mode(CaIndex *i, mode_t m) {
        if (!i)
                return -EINVAL;
        if (m & ~0666)
                return -EINVAL;
        if (i->mode == CA_INDEX_READ)
                return -ENOTTY;

        if (i->make_mode != (mode_t) -1)
                return -EBUSY;

        i->make_mode = m;
        return 0;
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

                if (!i->path)
                        return -EUNATCH;

                p = i->path;
                break;

        case O_WRONLY:
        case O_RDWR:

                if (!i->temporary_path) {
                        if (i->path) {
                                r = tempfn_random(i->path, &i->temporary_path);
                                if (r < 0)
                                        return r;
                        } else {
                                if (asprintf(&i->temporary_path, "/var/tmp/%" PRIx64 ".caidx", random_u64()) < 0)
                                        return -ENOMEM;
                        }
                }

                p = i->temporary_path;
                break;

        default:
                assert(false);
        }

        i->fd = open(p, i->open_flags, 0666 & i->make_mode);
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
                .table.size = htole64(UINT64_MAX),
                .table.type = htole64(CA_FORMAT_TABLE),
        };
        int r;

        assert(i);

        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE))
                return 0;
        if (i->start_offset != 0)
                return 0;

        if (i->feature_flags == UINT64_MAX)
                return -EINVAL;

        if (i->chunk_size_min == 0 ||
            i->chunk_size_avg == 0 ||
            i->chunk_size_max == 0)
                return -EUNATCH;

        if (!(i->chunk_size_min <= i->chunk_size_avg &&
              i->chunk_size_avg <= i->chunk_size_max))
                return -EINVAL;

        head.index.feature_flags = htole64(i->feature_flags);

        head.index.chunk_size_min = htole64(i->chunk_size_min);
        head.index.chunk_size_avg = htole64(i->chunk_size_avg);
        head.index.chunk_size_max = htole64(i->chunk_size_max);

        assert(i->cooked_offset == 0);

        r = loop_write(i->fd, &head, sizeof(head));
        if (r < 0)
                return r;

        i->start_offset = i->cooked_offset = sizeof(head);

        return 0;
}

static int ca_index_enough_data(CaIndex *i, size_t n) {
        size_t end;

        assert(i);

        if (i->mode == CA_INDEX_READ)
                return 1;
        if (i->mode != CA_INDEX_INCREMENTAL_READ)
                return -ENOTTY;
        if (i->wrote_eof)
                return 1;

        end = i->cooked_offset + n;
        if (end < i->cooked_offset) /* Overflow? */
                return -E2BIG;

        if (end > i->raw_offset)
                return 0;

        return 1;
}

static int ca_index_read_head(CaIndex *i) {
        struct {
                CaFormatIndex index;
                CaFormatHeader table;
        } head;
        ssize_t n;
        int r;

        assert(i);

        if (!IN_SET(i->mode, CA_INDEX_READ, CA_INDEX_INCREMENTAL_READ))
                return 0;
        if (i->start_offset != 0) /* already past the head */
                return 0;

        assert(i->cooked_offset == 0);

        r = ca_index_enough_data(i, sizeof(head));
        if (r < 0)
                return r;
        if (r == 0)
                return -EAGAIN;

        n = loop_read(i->fd, &head, sizeof(head));
        if (n < 0)
                return (int) n;
        if (n != sizeof(head))
                return -EPIPE;

        if (le64toh(head.index.header.size) != sizeof(CaFormatIndex) ||
            le64toh(head.index.header.type) != CA_FORMAT_INDEX)
                return -EBADMSG;

        r = ca_feature_flags_are_normalized(le64toh(head.index.feature_flags));
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        if (le64toh(head.index.chunk_size_min) < CA_CHUNK_SIZE_LIMIT_MIN ||
            le64toh(head.index.chunk_size_min) > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EBADMSG;

        if (le64toh(head.index.chunk_size_avg) < CA_CHUNK_SIZE_LIMIT_MIN ||
            le64toh(head.index.chunk_size_avg) > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EBADMSG;

        if (le64toh(head.index.chunk_size_max) < CA_CHUNK_SIZE_LIMIT_MIN ||
            le64toh(head.index.chunk_size_max) > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EBADMSG;

        if (!(le64toh(head.index.chunk_size_min) <= le64toh(head.index.chunk_size_avg) &&
              le64toh(head.index.chunk_size_avg) <= le64toh(head.index.chunk_size_max)))
                return -EBADMSG;

        if (le64toh(head.table.size) != UINT64_MAX ||
            le64toh(head.table.type) != CA_FORMAT_TABLE)
                return -EBADMSG;

        i->start_offset = i->cooked_offset = sizeof(head);

        i->feature_flags = le64toh(head.index.feature_flags);

        i->chunk_size_min = le64toh(head.index.chunk_size_min);
        i->chunk_size_avg = le64toh(head.index.chunk_size_avg);
        i->chunk_size_max = le64toh(head.index.chunk_size_max);

        return 0;
}

int ca_index_open(CaIndex *i) {
        int r;

        if (!i)
                return -EINVAL;

        r = ca_index_open_fd(i);
        if (r < 0)
                return r;

        r = ca_index_read_head(i);
        if (r < 0 && r != -EAGAIN)
                return r;

        r = ca_index_write_head(i);
        if (r < 0)
                return r;

        return 0;
}

int ca_index_install(CaIndex *i) {
        assert(i);

        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE, CA_INDEX_INCREMENTAL_READ))
                return -ENOTTY;
        if (!i->wrote_eof)
                return -EBUSY;

        if (!i->temporary_path)
                return 0;
        if (!i->path)
                return 0;

        if (rename(i->temporary_path, i->path) < 0)
                return -errno;

        i->temporary_path = mfree(i->temporary_path);
        return 1;
}

int ca_index_write_chunk(CaIndex *i, const CaChunkID *id, uint64_t size) {
        CaFormatTableItem item = {};
        uint64_t end;
        int r;

        if (!i)
                return -EINVAL;
        if (!id)
                return -EINVAL;
        if (size == 0)
                return -EINVAL;
        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE))
                return -ENOTTY;
        if (i->wrote_eof)
                return -EBUSY;

        r = ca_index_open(i);
        if (r < 0)
                return r;

        if (size > i->chunk_size_max)
                return -EINVAL;

        end = i->previous_chunk_offset + size;
        if (end < i->previous_chunk_offset)
                return -E2BIG;

        /* { */
        /*         char ids[CA_CHUNK_ID_FORMAT_MAX]; */
        /*         fprintf(stderr, "WRITING INDEX CHUNK: %s %zu\n", ca_chunk_id_format(id, ids), size); */
        /* } */

        item.offset = htole64(end);
        memcpy(&item.chunk, id, sizeof(CaChunkID));

        r = loop_write(i->fd, &item, sizeof(item));
        if (r < 0)
                return r;

        i->previous_chunk_offset = end;
        i->cooked_offset += sizeof(item);
        i->item_position++;

        return 0;
}

int ca_index_write_eof(CaIndex *i) {
        CaFormatTableTail tail = {};
        int r;

        assert(sizeof(CaFormatTableTail) == sizeof(CaFormatTableItem));

        if (!i)
                return -EINVAL;
        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE))
                return -ENOTTY;
        if (i->wrote_eof)
                return -EBUSY;

        r = ca_index_open(i);
        if (r < 0)
                return r;

        tail.index_offset = htole64(sizeof(CaFormatIndex));
        tail.size = htole64(offsetof(CaFormatTable, items) +
                            (i->item_position * sizeof(CaFormatTableItem)) +
                            sizeof(tail));
        tail.marker = htole64(CA_FORMAT_TABLE_TAIL_MARKER);

        r = loop_write(i->fd, &tail, sizeof(tail));
        if (r < 0)
                return r;

        i->cooked_offset += sizeof(tail);

        i->wrote_eof = true;

        return 0;
}

int ca_index_read_chunk(CaIndex *i, CaChunkID *ret_id, uint64_t *ret_offset_end, uint64_t *ret_size) {
        union {
                CaFormatTableItem item;
                CaFormatTableTail tail;
        } buffer;
        ssize_t n;
        int r;

        assert(sizeof(CaFormatTableTail) == sizeof(CaFormatTableItem));

        if (!i)
                return -EINVAL;

        r = ca_index_open(i);
        if (r < 0)
                return r;

        if (!IN_SET(i->mode, CA_INDEX_READ, CA_INDEX_INCREMENTAL_READ))
                return -ENOTTY;

        r = ca_index_enough_data(i, sizeof(buffer)+1);
        if (r < 0)
                return r;
        if (r == 0)
                return -EAGAIN;

        n = loop_read(i->fd, &buffer, sizeof(buffer));
        if (n < 0)
                return (int) n;
        if (n != sizeof(buffer))
                return -EPIPE;

        /* { */
        /*         char ids[CA_CHUNK_ID_FORMAT_MAX]; */
        /*         fprintf(stderr, "READING INDEX CHUNK: %s\n", ca_chunk_id_format((const CaChunkID*) item.chunk, ids)); */
        /* } */

        /* Check if this is the end? */
        if (buffer.tail.marker == htole64(CA_FORMAT_TABLE_TAIL_MARKER) &&
            buffer.tail._zero_fill1 == 0 &&
            buffer.tail._zero_fill2 == 0 &&
            buffer.tail.index_offset == htole64(sizeof(CaFormatIndex)) &&
            le64toh(buffer.tail.size) == (i->cooked_offset - i->start_offset + offsetof(CaFormatTable, items) + sizeof(CaFormatTableTail))) {
                uint8_t final_byte;

                /* We try to read one more byte than we expect. if we can read it there's trailing garbage. */
                n = read(i->fd, &final_byte, sizeof(final_byte));
                if (n < 0)
                        return -errno;
                if (n != 0)
                        return -EBADMSG;

                if (ret_id)
                        memset(ret_id, 0, sizeof(CaChunkID));

                if (ret_offset_end)
                        *ret_offset_end = UINT64_MAX;

                if (ret_size)
                        *ret_size = 0;

                return 0; /* EOF */
        }

        if (i->previous_chunk_offset != UINT64_MAX &&
            i->previous_chunk_offset >= le64toh(buffer.item.offset))
                return -EBADMSG;

        if (i->previous_chunk_offset != UINT64_MAX &&
            (le64toh(buffer.item.offset) - i->previous_chunk_offset) > i->chunk_size_max)
                return -EBADMSG;

        if (ret_id)
                memcpy(ret_id, buffer.item.chunk, sizeof(CaChunkID));

        if (ret_offset_end)
                *ret_offset_end = le64toh(buffer.item.offset);

        if (ret_size)
                *ret_size = i->previous_chunk_offset == UINT64_MAX ? UINT64_MAX : (le64toh(buffer.item.offset) - i->previous_chunk_offset);

        i->previous_chunk_offset = le64toh(buffer.item.offset);

        i->item_position++;
        i->cooked_offset += sizeof(buffer);

        return 1;
}

int ca_index_set_position(CaIndex *i, uint64_t position) {
        uint64_t p, q;

        if (!i)
                return -EINVAL;
        if (!IN_SET(i->mode, CA_INDEX_READ, CA_INDEX_INCREMENTAL_READ))
                return -ENOTTY;
        if (i->start_offset == 0)
                return -ENODATA;

        p = position * sizeof(CaFormatTableItem);
        if (p < position) /* Overflow? */
                return -EINVAL;

        q = i->start_offset + p;
        if (q < p)
                return -EINVAL;

        if (lseek(i->fd, q, SEEK_SET) == (off_t) -1)
                return -errno;

        i->cooked_offset = q;
        i->item_position = position;
        i->previous_chunk_offset = position == 0 ? 0 : UINT64_MAX;

        return 0;
}

int ca_index_get_position(CaIndex *i, uint64_t *ret) {
        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (i->start_offset == 0)
                return -ENODATA;

        *ret = i->item_position;
        return 0;
}

static int read_file_size(CaIndex *i) {
        struct stat st;

        assert(i);

        if (i->file_size != UINT64_MAX)
                return 0;

        if (fstat(i->fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode))
                return -EBADFD;

        i->file_size = st.st_size;

        return 1;
}

int ca_index_get_available_chunks(CaIndex *i, uint64_t *ret) {
        uint64_t available, metadata_size, n;
        int r;

        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        r = ca_index_read_head(i);
        if (r < 0)
                return r;

        if (i->start_offset == 0)
                return -ENODATA;

        if (i->mode == CA_INDEX_READ) {

                r = read_file_size(i);
                if (r < 0)
                        return r;

                available = i->file_size;

        } else if (i->mode == CA_INDEX_INCREMENTAL_READ)
                available = i->raw_offset;
        else
                return -ENOTTY;

        metadata_size = CA_INDEX_METADATA_SIZE(i);;
        if (available < metadata_size) {

                if (i->mode == CA_INDEX_READ || i->wrote_eof)
                        return -EBADMSG;

                *ret = 0;
                return 0;
        }

        n = available - metadata_size;
        if ((i->mode == CA_INDEX_READ || i->wrote_eof) &&
            (n % sizeof(CaFormatTableItem) != 0))
                return -EBADMSG;

        *ret = n / sizeof(CaFormatTableItem);
        return 0;
}

int ca_index_incremental_write(CaIndex *i, const void *data, size_t size) {
        uint64_t new_offset;
        ssize_t n;
        int r;

        if (!i)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (size == 0)
                return -EINVAL;

        if (i->mode != CA_INDEX_INCREMENTAL_READ)
                return -ENOTTY;
        if (i->wrote_eof)
                return -EBUSY;

        r = ca_index_open(i);
        if (r < 0)
                return r;

        new_offset = i->raw_offset + size;
        if (new_offset < i->raw_offset) /* overflow? */
                return -EFBIG;

        n = pwrite(i->fd, data, size, i->raw_offset);
        if (n < 0)
                return -errno;
        if ((size_t) n != size)
                return -EIO;

        i->raw_offset = new_offset;
        return 0;
}

int ca_index_incremental_eof(CaIndex *i) {
        int r;

        if (!i)
                return -EINVAL;

        if (i->mode != CA_INDEX_INCREMENTAL_READ)
                return -ENOTTY;
        if (i->wrote_eof)
                return -EBUSY;

        r = ca_index_open(i);
        if (r < 0)
                return r;

        i->wrote_eof = true;
        return 0;
}

int ca_index_incremental_read(CaIndex *i, ReallocBuffer *buffer) {
        size_t m;
        ssize_t n;
        char *p;
        int r;

        if (!i)
                return -EINVAL;
        if (!buffer)
                return -EINVAL;

        if (i->mode != CA_INDEX_INCREMENTAL_WRITE)
                return -ENOTTY;

        r = ca_index_open(i);
        if (r < 0)
                return r;

        if (i->raw_offset >= i->cooked_offset)
                return i->wrote_eof ? 0 : -EAGAIN;

        m = MIN(BUFFER_SIZE, i->cooked_offset - i->raw_offset);

        p = realloc_buffer_acquire(buffer, m);
        if (!p)
                return -ENOMEM;

        n = pread(i->fd, p, m, i->raw_offset);
        if (n < 0) {
                realloc_buffer_empty(buffer);
                return -errno;
        }

        r = realloc_buffer_shorten(buffer, m - n);
        if (r < 0)
                return r;

        i->raw_offset += n;
        return 1;
}

int ca_index_set_chunk_size_min(CaIndex *i, size_t cmin) {
        if (!i)
                return -EINVAL;
        if (cmin < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (cmin > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE))
                return -EROFS;

        i->chunk_size_min = cmin;
        return 0;
}

int ca_index_set_chunk_size_avg(CaIndex *i, size_t cavg) {
        if (!i)
                return -EINVAL;
        if (cavg < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (cavg > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE))
                return -EROFS;

        i->chunk_size_avg = cavg;
        return 0;
}

int ca_index_set_chunk_size_max(CaIndex *i, size_t cmax) {
        if (!i)
                return -EINVAL;
        if (cmax < CA_CHUNK_SIZE_LIMIT_MIN)
                return -EINVAL;
        if (cmax > CA_CHUNK_SIZE_LIMIT_MAX)
                return -EINVAL;
        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE))
                return -EROFS;

        i->chunk_size_max = cmax;
        return 0;
}

int ca_index_get_chunk_size_min(CaIndex *i, size_t *ret) {
        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (i->chunk_size_min == 0)
                return -ENODATA;

        *ret = i->chunk_size_min;
        return 0;
}

int ca_index_get_chunk_size_avg(CaIndex *i, size_t *ret) {
        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (i->chunk_size_avg == 0)
                return -ENODATA;

        *ret = i->chunk_size_avg;
        return 0;
}

int ca_index_get_chunk_size_max(CaIndex *i, size_t *ret) {
        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (i->chunk_size_max == 0)
                return -ENODATA;

        *ret = i->chunk_size_max;
        return 0;
}

int ca_index_get_index_size(CaIndex *i, uint64_t *ret) {
        uint64_t size, metadata_size;
        int r;

        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        r = ca_index_open(i);
        if (r < 0)
                return r;

        r = ca_index_read_head(i);
        if (r < 0)
                return r;

        switch (i->mode) {

        case CA_INDEX_READ:
                r = read_file_size(i);
                if (r < 0)
                        return r;

                size = i->file_size;
                break;

        case CA_INDEX_INCREMENTAL_READ:

                if (!i->wrote_eof)
                        return -EAGAIN;

                size = i->raw_offset;
                break;

        default:
                return -ENOTTY;
        }

        /* Some size validation checks */
        metadata_size = CA_INDEX_METADATA_SIZE(i);
        if (size < metadata_size)
                return -EBADMSG;

        if ((size - metadata_size) % sizeof(CaFormatTableItem) != 0)
                return -EBADMSG;

        *ret = size;
        return 0;
}

int ca_index_get_total_chunks(CaIndex *i, uint64_t *ret) {
        uint64_t size;
        int r;

        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        r = ca_index_get_index_size(i, &size);
        if (r < 0)
                return r;

        *ret = (size - CA_INDEX_METADATA_SIZE(i)) / sizeof(CaFormatTableItem);
        return 0;
}

static int ca_index_read_tail(CaIndex *i) {
        struct {
                CaFormatTableItem last_item;
                CaFormatTableTail tail;
        } buffer = {};
        uint64_t size;
        ssize_t l;
        int r;

        if (!i)
                return -EINVAL;

        r = ca_index_get_index_size(i, &size);
        if (r < 0)
                return r;

        if (size == CA_INDEX_METADATA_SIZE(i)) {
                /* If there's not a single chunk, then the blob has size zero, in this case only read the tail */

                l = pread(i->fd, &buffer.tail, sizeof(buffer.tail), size - sizeof(buffer.tail));
                if (l < 0)
                        return -errno;
                if (l != sizeof(buffer.tail))
                        return -EBADMSG;
        } else {
                /* If there's at least one chunk, then read the last chunk's data, too */

                l = pread(i->fd, &buffer, sizeof(buffer), size - sizeof(buffer));
                if (l < 0)
                        return -errno;
                if (l != sizeof(buffer))
                        return -EBADMSG;
        }

        if (le64toh(buffer.tail.marker) != CA_FORMAT_TABLE_TAIL_MARKER)
                return -EBADMSG;
        if (le64toh(buffer.tail.index_offset) != sizeof(CaFormatIndex))
                return -EBADMSG;
        if (le64toh(buffer.tail.size) + sizeof(CaFormatIndex) != size)
                return -EBADMSG;

        i->blob_size = le64toh(buffer.last_item.offset);

        return 0;
}

int ca_index_get_blob_size(CaIndex *i, uint64_t *ret) {
        int r;

        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (i->blob_size == UINT64_MAX) {
                r = ca_index_read_tail(i);
                if (r < 0)
                        return r;
        }

        *ret = i->blob_size;
        return 0;
}

int ca_index_seek(CaIndex *i, uint64_t offset, uint64_t *ret_skip) {
        uint64_t size, n_chunks, left, right;
        int r;

        if (!i)
                return -EINVAL;

        r = ca_index_get_blob_size(i, &size);
        if (r < 0)
                return r;

        if (offset >= size)
                return -ENXIO;

        r = ca_index_get_total_chunks(i, &n_chunks);
        if (n_chunks == 0)
                return -ENXIO;

        /* Small opimization for seeking within the first chunk */
        if (n_chunks == 1 || offset < i->chunk_size_min) {
                r = ca_index_set_position(i, 0);
                if (r < 0)
                        return r;

                if (ret_skip)
                        *ret_skip = offset;

                return 0;
        }

        /* Implement bisection to find the right chunk */
        left = 0;
        right = n_chunks - 2;
        for (;;) {
                uint64_t first_chunk_end, second_chunk_end, p;

                p = left + (right - left) / 2;

                r = ca_index_set_position(i, p);
                if (r < 0)
                        return r;

                r = ca_index_read_chunk(i, NULL, &first_chunk_end, NULL);
                if (r < 0)
                        return r;

                if (offset < first_chunk_end) {

                        if (p == 0) {
                                /* This is left of the first chunk boundary? Then it's definitely in the first chunk */

                                r = ca_index_set_position(i, 0);
                                if (r < 0)
                                        return r;

                                if (ret_skip)
                                        *ret_skip = offset;

                                return 0;
                        }

                        if (p == right)
                                return -EBADMSG;

                        right = p;
                        continue;
                }

                r = ca_index_read_chunk(i, NULL, &second_chunk_end, NULL);
                if (r < 0)
                        return r;

                if (offset >= second_chunk_end) {
                        left = p+1;
                        continue;
                }

                /* We found it, now let's position the read ptr on the second chunk again */

                r = ca_index_set_position(i, p + 1);
                if (r < 0)
                        return r;

                if (ret_skip)
                        *ret_skip = offset - first_chunk_end;

                return 0;
        }
}

int ca_index_set_feature_flags(CaIndex *i, uint64_t flags) {
        if (!i)
                return -EINVAL;

        if (!IN_SET(i->mode, CA_INDEX_WRITE, CA_INDEX_INCREMENTAL_WRITE))
                return -ENOTTY;
        if (i->start_offset > 0)
                return -EBUSY;

        return ca_feature_flags_normalize(flags, &i->feature_flags);
}

int ca_index_get_feature_flags(CaIndex *i, uint64_t *ret) {
        if (!i)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (i->feature_flags == UINT64_MAX)
                return -ENODATA;

        *ret = i->feature_flags;
        return 0;
}
