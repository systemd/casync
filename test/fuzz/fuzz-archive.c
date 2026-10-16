/* SPDX-License-Identifier: LGPL-2.1+ */

/*
 * Mutation-first .catar decode harness.
 *
 * Unlike fuzz-sync (which round-trips a well-formed tree for coverage), this
 * feeds attacker-controlled archive bytes into ca_sync_new_decode():
 *
 *   0 — raw: remaining input is the archive
 *   1 — mutate: start from a once-built valid template, apply fuzzer edits
 *   2 — structured: synthesize TLV objects with real CA_FORMAT_* type tags
 *   3 — raw + seek: like raw, then seek to a fuzzer-chosen archive offset
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "caformat.h"
#include "casync.h"
#include "def.h"
#include "fuzz.h"
#include "log.h"
#include "rm-rf.h"
#include "util.h"

#define MAX_ARCHIVE (256u * 1024u)
#define MAX_STEPS 8000
#define MAX_MUTATIONS 64
#define MAX_TLV_OBJECTS 48

static uint8_t *g_template;
static size_t g_template_len;

static const uint64_t format_types[] = {
        CA_FORMAT_ENTRY,
        CA_FORMAT_USER,
        CA_FORMAT_GROUP,
        CA_FORMAT_XATTR,
        CA_FORMAT_ACL_USER,
        CA_FORMAT_ACL_GROUP,
        CA_FORMAT_ACL_GROUP_OBJ,
        CA_FORMAT_ACL_DEFAULT,
        CA_FORMAT_ACL_DEFAULT_USER,
        CA_FORMAT_ACL_DEFAULT_GROUP,
        CA_FORMAT_FCAPS,
        CA_FORMAT_QUOTA_PROJID,
        CA_FORMAT_SELINUX,
        CA_FORMAT_SYMLINK,
        CA_FORMAT_DEVICE,
        CA_FORMAT_PAYLOAD,
        CA_FORMAT_FILENAME,
        CA_FORMAT_GOODBYE,
};

static int write_all(int fd, const void *p, size_t n) {
        const uint8_t *b = p;

        while (n > 0) {
                ssize_t k = write(fd, b, n);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (k == 0)
                        return -EIO;
                b += (size_t) k;
                n -= (size_t) k;
        }
        return 0;
}

static int read_all(int fd, void *p, size_t n) {
        uint8_t *b = p;

        while (n > 0) {
                ssize_t k = read(fd, b, n);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (k == 0)
                        return -EPIPE;
                b += (size_t) k;
                n -= (size_t) k;
        }
        return 0;
}

static uint64_t unpriv_flags(uint64_t flags) {
        if (geteuid() != 0)
                flags &= ~(uint64_t) CA_FORMAT_WITH_PRIVILEGED;
        return flags & SUPPORTED_FEATURE_MASK;
}

static int encode_template_once(void) {
        char dirtmpl[] = "/tmp/caarch-tmpl.XXXXXX";
        char *dir;
        char src[256], archive[256];
        int fd = -1, r;
        CaSync *enc = NULL;
        struct stat st;
        uint8_t *buf = NULL;

        if (g_template)
                return 0;

        dir = mkdtemp(dirtmpl);
        if (!dir)
                return -errno;

        snprintf(src, sizeof(src), "%s/tree", dir);
        snprintf(archive, sizeof(archive), "%s/base.catar", dir);
        if (mkdir(src, 0755) < 0) {
                r = -errno;
                goto out;
        }

        fd = open(src, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
                r = -errno;
                goto out;
        }

        {
                int nfd = openat(fd, "a", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
                if (nfd >= 0) {
                        (void) write_all(nfd, "hello-casync", 12);
                        close(nfd);
                }
                nfd = openat(fd, "b", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
                if (nfd >= 0) {
                        (void) write_all(nfd, "xxxxxxxx", 8);
                        close(nfd);
                }
                (void) symlinkat("a", fd, "link");
                (void) mkdirat(fd, "sub", 0755);
        }

        enc = ca_sync_new_encode();
        if (!enc) {
                r = -ENOMEM;
                goto out;
        }

        r = ca_sync_set_base_fd(enc, fd);
        fd = -1;
        if (r < 0)
                goto out;

        (void) ca_sync_set_feature_flags(enc, unpriv_flags(CA_FORMAT_DEFAULT));
        (void) ca_sync_set_chunk_size_max(enc, 4096);
        (void) ca_sync_set_chunk_size_avg(enc, 1024);
        (void) ca_sync_set_chunk_size_min(enc, 256);
        r = ca_sync_set_archive_path(enc, archive);
        if (r < 0)
                goto out;

        for (int i = 0; i < MAX_STEPS; i++) {
                r = ca_sync_step(enc);
                if (r == CA_SYNC_FINISHED) {
                        r = 0;
                        break;
                }
                if (r < 0)
                        goto out;
        }

        ca_sync_unref(enc);
        enc = NULL;

        fd = open(archive, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                r = -errno;
                goto out;
        }
        if (fstat(fd, &st) < 0) {
                r = -errno;
                goto out;
        }
        if (st.st_size <= 0 || (size_t) st.st_size > MAX_ARCHIVE) {
                r = -EFBIG;
                goto out;
        }

        buf = malloc((size_t) st.st_size);
        if (!buf) {
                r = -ENOMEM;
                goto out;
        }
        r = read_all(fd, buf, (size_t) st.st_size);
        if (r < 0)
                goto out;

        g_template = buf;
        g_template_len = (size_t) st.st_size;
        buf = NULL;
        r = 0;

out:
        free(buf);
        if (enc)
                ca_sync_unref(enc);
        if (fd >= 0)
                close(fd);
        (void) rm_rf(dir, REMOVE_ROOT | REMOVE_PHYSICAL);
        return r;
}

static size_t append_bytes(uint8_t *dst, size_t *len, size_t cap,
                           const void *p, size_t n) {
        if (n == 0 || *len >= cap)
                return 0;
        if (*len + n > cap)
                n = cap - *len;
        memcpy(dst + *len, p, n);
        *len += n;
        return n;
}

static size_t append_header(uint8_t *dst, size_t *len, size_t cap,
                            uint64_t type, uint64_t size) {
        uint8_t hdr[16];

        if (size < sizeof(CaFormatHeader))
                size = sizeof(CaFormatHeader);
        write_le64(hdr, size);
        write_le64(hdr + 8, type);
        return append_bytes(dst, len, cap, hdr, sizeof(hdr));
}

static size_t build_structured(const uint8_t *data, size_t size,
                               uint8_t *out, size_t cap) {
        size_t len = 0;
        size_t i = 0;
        unsigned objects = 0;

        while (i < size && objects < MAX_TLV_OBJECTS && len + 16 < cap) {
                uint8_t sel = data[i++];
                uint64_t type = format_types[sel % ELEMENTSOF(format_types)];
                uint64_t body_len;
                uint64_t total;

                if (type == CA_FORMAT_ENTRY) {
                        CaFormatEntry e = {};
                        uint64_t feature = CA_FORMAT_DEFAULT;
                        uint64_t mode = S_IFREG | 0644;

                        if (i + 16 <= size) {
                                memcpy(&feature, data + i, 8);
                                memcpy(&mode, data + i + 8, 8);
                                i += 16;
                        } else if (i < size) {
                                mode = S_IFDIR | 0755;
                        }

                        feature = unpriv_flags(feature);
                        /* Keep mode in a plausible file-type set. */
                        if (!(mode & S_IFMT))
                                mode |= S_IFREG;

                        total = sizeof(e);
                        write_le64(&e.header.size, total);
                        write_le64(&e.header.type, CA_FORMAT_ENTRY);
                        write_le64(&e.feature_flags, feature);
                        write_le64(&e.mode, mode);
                        write_le64(&e.flags, 0);
                        write_le64(&e.uid, geteuid());
                        write_le64(&e.gid, getegid());
                        write_le64(&e.mtime, 0);
                        append_bytes(out, &len, cap, &e, sizeof(e));
                        objects++;
                        continue;
                }

                body_len = 0;
                if (i < size) {
                        body_len = data[i++];
                        if (i < size && (sel & 0x80))
                                body_len |= ((uint64_t) data[i++]) << 8;
                }
                if (body_len > 1024)
                        body_len = 1024;
                if (type == CA_FORMAT_FILENAME || type == CA_FORMAT_USER ||
                    type == CA_FORMAT_GROUP || type == CA_FORMAT_SYMLINK) {
                        /* Ensure room for a NUL in the body we emit. */
                        if (body_len == 0)
                                body_len = 1;
                }

                total = sizeof(CaFormatHeader) + body_len;
                /* Occasionally lie about size to stress the parser. */
                if ((sel & 0x40) && i < size) {
                        uint64_t lied = total;
                        if (data[i] & 1)
                                lied += (data[i] & 0x3f);
                        else if (lied > sizeof(CaFormatHeader))
                                lied -= (data[i] % 8);
                        i++;
                        append_header(out, &len, cap, type, lied);
                } else
                        append_header(out, &len, cap, type, total);

                if (body_len > 0) {
                        size_t take = body_len;
                        if (i + take > size)
                                take = size - i;
                        append_bytes(out, &len, cap, data + i, take);
                        i += take;
                        /* Pad / NUL-fill if input short. */
                        while (take < body_len && len < cap) {
                                uint8_t z = (type == CA_FORMAT_FILENAME) ? 0 : (uint8_t) (take & 0xff);
                                append_bytes(out, &len, cap, &z, 1);
                                take++;
                        }
                }
                objects++;
        }

        return len;
}

static size_t mutate_template(const uint8_t *data, size_t size,
                              uint8_t *out, size_t cap) {
        size_t len;
        size_t i = 0;
        unsigned ops = 0;

        if (encode_template_once() < 0 || !g_template || g_template_len == 0)
                return 0;

        len = g_template_len < cap ? g_template_len : cap;
        memcpy(out, g_template, len);

        while (i + 3 <= size && ops < MAX_MUTATIONS) {
                uint8_t op = data[i++];
                uint16_t off = (uint16_t) (data[i] | ((uint16_t) data[i + 1] << 8));
                i += 2;
                if (len == 0)
                        break;
                off = (uint16_t) (off % len);

                switch (op % 6) {
                case 0: /* XOR one byte */
                        if (i < size)
                                out[off] ^= data[i++];
                        else
                                out[off] ^= (uint8_t) op;
                        break;
                case 1: /* Overwrite a le64 size/type-ish field */
                        if (off + 8 <= len && i + 8 <= size) {
                                memcpy(out + off, data + i, 8);
                                i += 8;
                        } else if (off + 8 <= len) {
                                write_le64(out + off, CA_FORMAT_PAYLOAD);
                        }
                        break;
                case 2: /* Truncate */
                        len = off ? off : 1;
                        break;
                case 3: /* Insert up to 16 fuzzer bytes (drop tail if needed) */
                        if (i < size) {
                                size_t n = (data[i++] % 16) + 1;
                                if (i + n > size)
                                        n = size - i;
                                if (len + n > cap)
                                        n = cap - len;
                                if (n > 0 && off <= len) {
                                        memmove(out + off + n, out + off, len - off);
                                        memcpy(out + off, data + i, n);
                                        len += n;
                                        i += n;
                                }
                        }
                        break;
                case 4: /* Force a known type tag at aligned-ish offset */
                        if (off + 16 <= len) {
                                uint64_t t = format_types[op % ELEMENTSOF(format_types)];
                                write_le64(out + off + 8, t);
                        }
                        break;
                case 5: /* Append junk */
                        if (i < size) {
                                size_t n = (data[i++] % 32) + 1;
                                if (i + n > size)
                                        n = size - i;
                                append_bytes(out, &len, cap, data + i, n);
                                i += n;
                        }
                        break;
                }
                ops++;
        }

        return len;
}

static void drain_sync(CaSync *s, bool do_seek, uint64_t seek_off) {
        bool sought = false;

        for (int i = 0; i < MAX_STEPS; i++) {
                int r = ca_sync_step(s);
                if (r == CA_SYNC_FINISHED)
                        return;
                if (r < 0)
                        return;
                if (r == CA_SYNC_POLL)
                        return;

                if (r == CA_SYNC_NEXT_FILE || r == CA_SYNC_DONE_FILE) {
                        char *path = NULL;
                        mode_t mode = 0;
                        if (ca_sync_current_path(s, &path) >= 0)
                                free(path);
                        (void) ca_sync_current_mode(s, &mode);
                }
                if (r == CA_SYNC_PAYLOAD) {
                        const void *p = NULL;
                        size_t n = 0;
                        (void) ca_sync_get_payload(s, &p, &n);
                }

                if (do_seek && !sought && i == 2) {
                        (void) ca_sync_seek_offset(s, seek_off);
                        sought = true;
                }
        }
}

static int decode_archive_bytes(const uint8_t *archive, size_t archive_len,
                                uint64_t feature_flags,
                                uint8_t opts,
                                bool do_seek,
                                uint64_t seek_off) {
        char tmpl[] = "/tmp/caarch.XXXXXX";
        char *root;
        char archive_path[256], extract_path[256];
        int afd = -1, efd = -1, r;
        CaSync *dec = NULL;

        if (!archive || archive_len == 0)
                return 0;

        root = mkdtemp(tmpl);
        if (!root)
                return 0;

        snprintf(archive_path, sizeof(archive_path), "%s/in.catar", root);
        snprintf(extract_path, sizeof(extract_path), "%s/out", root);
        if (mkdir(extract_path, 0755) < 0)
                goto out;

        afd = open(archive_path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
        if (afd < 0)
                goto out;
        if (write_all(afd, archive, archive_len) < 0) {
                close(afd);
                afd = -1;
                goto out;
        }
        close(afd);
        afd = -1;

        dec = ca_sync_new_decode();
        if (!dec)
                goto out;

        (void) ca_sync_set_feature_flags(dec, unpriv_flags(feature_flags));
        (void) ca_sync_set_hardlink(dec, !!(opts & 0x04));
        (void) ca_sync_set_delete(dec, !!(opts & 0x08));
        (void) ca_sync_set_punch_holes(dec, !!(opts & 0x10));
        (void) ca_sync_enable_archive_digest(dec, !!(opts & 0x20));
        (void) ca_sync_set_payload(dec, !!(opts & 0x40));
        (void) ca_sync_set_reflink(dec, false);

        efd = open(extract_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (efd < 0)
                goto out;
        r = ca_sync_set_base_fd(dec, efd);
        efd = -1;
        if (r < 0)
                goto out;

        afd = open(archive_path, O_RDONLY | O_CLOEXEC);
        if (afd < 0)
                goto out;
        r = ca_sync_set_archive_fd(dec, afd);
        afd = -1;
        if (r < 0)
                goto out;

        drain_sync(dec, do_seek, seek_off);

out:
        if (dec)
                ca_sync_unref(dec);
        if (afd >= 0)
                close(afd);
        if (efd >= 0)
                close(efd);
        (void) rm_rf(root, REMOVE_ROOT | REMOVE_PHYSICAL);
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        uint8_t opts;
        unsigned strategy;
        uint64_t feature_flags = CA_FORMAT_DEFAULT;
        uint64_t seek_off = 0;
        size_t off = 0;
        uint8_t archive[MAX_ARCHIVE];
        size_t archive_len = 0;
        bool do_seek = false;

        if (size < 1 || size > 1024 * 1024)
                return 0;

        if (!getenv("CASYNC_LOG_LEVEL"))
                set_log_level(LOG_CRIT);

        opts = data[off++];
        strategy = opts & 0x3;

        if ((opts & 0x80) && off + 8 <= size) {
                memcpy(&feature_flags, data + off, 8);
                off += 8;
                feature_flags = unpriv_flags(feature_flags);
        }

        if (strategy == 3 && off + 8 <= size) {
                memcpy(&seek_off, data + off, 8);
                off += 8;
                do_seek = true;
                strategy = 0; /* seek variant of raw */
        }

        if (off >= size)
                return 0;

        switch (strategy) {
        case 1:
                archive_len = mutate_template(data + off, size - off, archive, sizeof(archive));
                break;
        case 2:
                archive_len = build_structured(data + off, size - off, archive, sizeof(archive));
                break;
        case 0:
        default: {
                size_t n = size - off;
                if (n > sizeof(archive))
                        n = sizeof(archive);
                memcpy(archive, data + off, n);
                archive_len = n;
                break;
        }
        }

        (void) decode_archive_bytes(archive, archive_len, feature_flags, opts, do_seek, seek_off);
        return 0;
}
