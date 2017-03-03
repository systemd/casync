#include <stdio.h>
#include <fcntl.h>

#include "caformat-util.h"
#include "caformat.h"
#include "realloc-buffer.h"
#include "util.h"

int main(int argc, char *argv[]) {
        ReallocBuffer buffer = {};
        size_t frame_size = 0, skip_size = 0;
        int fd = -1, r;

        if (argc != 2) {
                fprintf(stderr, "Expected single filename parameter.\n");
                r = -EINVAL;
                goto finish;
        }

        fd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                r = -errno;
                fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
                goto finish;
        }

        for (;;) {
                CaFormatHeader *h;
                size_t sz;

                sz = realloc_buffer_size(&buffer);

                if (skip_size > 0 && sz > 0) {
                        uint64_t t;

                        t = MIN(skip_size, sz);

                        realloc_buffer_advance(&buffer, t);
                        skip_size -= t;

                        continue;
                }

                if (frame_size < sizeof(CaFormatHeader))
                        frame_size = sizeof(CaFormatHeader);

                if (skip_size > 0 || sz < frame_size) {
                        r = realloc_buffer_read(&buffer, fd);
                        if (r < 0) {
                                fprintf(stderr, "Failed to read: %s\n", strerror(-r));
                                goto finish;
                        }
                        if (r == 0) {

                                if (sz == 0) {
                                        r = 0;
                                        goto finish;
                                }

                                fprintf(stderr, "Premature end of file.\n");
                                r = -EBADMSG;
                                goto finish;
                        }

                        continue;
                }

                h = realloc_buffer_data(&buffer);

                printf(">>> Record <%s>\n", ca_format_type_name(read_le64(&h->type)));

                switch (read_le64(&h->type)) {

                case CA_FORMAT_ENTRY: {
                        CaFormatEntry *entry;

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        entry = (CaFormatEntry*) h;

                        printf("\tMode: %08" PRIo64 "\n"
                               "\tUID: " UID_FMT "\n"
                               "\tGID: " GID_FMT "\n",
                               read_le64(&entry->mode),
                               (uid_t) read_le64(&entry->uid),
                               (gid_t) read_le64(&entry->gid));

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;
                        break;
                }

                case CA_FORMAT_USER: {
                        CaFormatUser *user;

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        user = (CaFormatUser*) h;

                        printf("\tUser: %s\n", user->name);

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;
                        break;
                }

                case CA_FORMAT_GROUP: {
                        CaFormatGroup *group;

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        group = (CaFormatGroup*) h;

                        printf("\tGroup: %s\n", group->name);

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;
                        break;
                }

                case CA_FORMAT_PAYLOAD:

                        frame_size = offsetof(CaFormatPayload, data);
                        if (sz < frame_size)
                                continue;

                        skip_size = read_le64(&h->size) - frame_size;
                        printf("\tPayload: %" PRIu64 "\n", skip_size);

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;

                        break;

                case CA_FORMAT_FILENAME: {
                        CaFormatFilename *f;

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        f = (CaFormatFilename*) h;

                        printf("\tFilename: %s\n", f->name);

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;
                        break;
                }

                case CA_FORMAT_SYMLINK: {
                        CaFormatSymlink *symlink;

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        symlink = (CaFormatSymlink*) h;

                        printf("\tSymlink: %s\n", symlink->target);

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;
                        break;
                }

                case CA_FORMAT_XATTR: {
                        CaFormatXAttr *xattr;

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        xattr = (CaFormatXAttr*) h;

                        printf("\tXAttr: %s\n", (char*) xattr->name_and_value);

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;
                        break;
                }

                case CA_FORMAT_FCAPS:
                case CA_FORMAT_GOODBYE:
                case CA_FORMAT_DEVICE:

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        realloc_buffer_advance(&buffer, frame_size);
                        frame_size = 0;
                        break;

                default:
                        fprintf(stderr, "Unknown record.\n");
                        r = -EBADMSG;
                        goto finish;
                }
        }

finish:

        safe_close(fd);
        realloc_buffer_free(&buffer);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
