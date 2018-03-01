/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <fcntl.h>

#include "caformat-util.h"
#include "caformat.h"
#include "realloc-buffer.h"
#include "util.h"

int main(int argc, char *argv[]) {
        _cleanup_(realloc_buffer_free) ReallocBuffer buffer = {};
        uint64_t frame_size = 0, skip_size = 0;
        _cleanup_(safe_closep) int fd = -1;
        int r;

        if (argc != 2) {
                log_error("Expected single filename parameter.");
                r = -EINVAL;
                goto finish;
        }

        fd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                log_error_errno(errno, "Failed to open %s: %m", argv[1]);
                goto finish;
        }

        for (;;) {
                CaFormatHeader *h;
                uint64_t sz;

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
                                log_error_errno(r, "Failed to read: %m");
                                goto finish;
                        }
                        if (r == 0) {

                                if (sz == 0) {
                                        r = 0;
                                        goto finish;
                                }

                                log_error("Premature end of file.");
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

                case CA_FORMAT_SELINUX: {
                        CaFormatSELinux *selinux;

                        frame_size = read_le64(&h->size);
                        if (sz < frame_size)
                                continue;

                        selinux = (CaFormatSELinux*) h;

                        printf("\tSELinux Label: %s\n", selinux->label);

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
                        log_error("Unknown record type.");
                        r = -EBADMSG;
                        goto finish;
                }
        }

 finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
