/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <syslog.h>
#include <unistd.h>

#include "caformat.h"
#include "casync.h"
#include "cautil.h"
#include "compressor.h"
#include "fuzz.h"
#include "log.h"
#include "rm-rf.h"
#include "time-util.h"
#include "util.h"

static volatile unsigned g_sink;

static void keep(unsigned v) {
        g_sink += v;
}

static int write_all(int fd, const void *p, size_t n) {
        const uint8_t *b = p;

        while (n > 0) {
                ssize_t k = write(fd, b, n);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                b += k;
                n -= (size_t) k;
        }
        return 0;
}

static void append_out(uint8_t **buf, size_t *len, size_t *cap, const void *p, size_t n) {
        if (n == 0 || *len > 4 * 1024 * 1024)
                return;
        if (*len + n > *cap) {
                size_t nc = *cap ? *cap : 4096;
                while (nc < *len + n)
                        nc *= 2;
                uint8_t *np = realloc(*buf, nc);
                if (!np)
                        return;
                *buf = np;
                *cap = nc;
        }
        memcpy(*buf + *len, p, n);
        *len += n;
}

/* Encode then decode so xz and gzip actually run, not just the type switch. */
static void compress_roundtrip(CaCompressionType alg, const uint8_t *data, size_t size) {
        uint8_t *comp = NULL;
        size_t comp_len = 0, comp_cap = 0;
        uint8_t out[4096];
        int r;

        if (!compressor_is_supported(alg))
                return;
        if (size == 0) {
                static const uint8_t one = 0;
                data = &one;
                size = 1;
        }
        if (size > 1024)
                size = 1024;

        _cleanup_(compressor_finish) CompressorContext enc = COMPRESSOR_CONTEXT_INIT;
        r = compressor_start_encode(&enc, alg);
        if (r < 0)
                return;
        r = compressor_input(&enc, data, size);
        if (r < 0)
                return;

        for (int i = 0; i < 32; i++) {
                size_t done = 0;
                r = compressor_encode(&enc, true, out, sizeof(out), &done);
                if (done > 0)
                        append_out(&comp, &comp_len, &comp_cap, out, done);
                if (r != COMPRESSOR_MORE && r != COMPRESSOR_GOOD)
                        break;
        }
        compressor_finish(&enc);
        enc.operation = COMPRESSOR_UNINITIALIZED;

        keep(detect_compression(comp, comp_len));
        if (comp_len == 0) {
                free(comp);
                return;
        }

        _cleanup_(compressor_finish) CompressorContext dec = COMPRESSOR_CONTEXT_INIT;
        r = compressor_start_decode(&dec, alg);
        if (r < 0) {
                free(comp);
                return;
        }
        r = compressor_input(&dec, comp, comp_len);
        if (r < 0) {
                free(comp);
                return;
        }
        for (int i = 0; i < 32; i++) {
                size_t done = 0;
                r = compressor_decode(&dec, out, sizeof(out), &done);
                keep((unsigned) done);
                if (r != COMPRESSOR_MORE && r != COMPRESSOR_GOOD)
                        break;
        }
        free(comp);
}

static void exercise_utils(const uint8_t *data, size_t size) {
        char text[256];
        size_t n = size < sizeof(text) - 1 ? size : sizeof(text) - 1;
        char modebuf[64];
        char *joined = NULL, *dir = NULL, *hex = NULL, *tmp = NULL;
        char **sv = NULL;
        unsigned u = 0;
        int i = 0;
        long long unsigned llu = 0;
        uid_t uid = 0;
        const char *p;

        memcpy(text, data, n);
        text[n] = 0;
        for (size_t k = 0; k < n; k++) {
                if (text[k] == 0)
                        text[k] = 'a';
        }

        keep(filename_is_valid(text));
        keep(path_is_safe(text));
        keep(uid_is_valid(uid));
        keep((unsigned) safe_atoi(text, &i));
        keep((unsigned) safe_atou(text, &u));
        keep((unsigned) safe_atollu(text, &llu));
        keep((unsigned) safe_atollx(text, &llu));
        keep((unsigned) parse_uid(text, &uid));
        keep((unsigned) parse_boolean(text));
        keep((unsigned) unhexchar(text[0]));
        keep((unsigned) (uintptr_t) endswith(text, ".caidx"));
        keep((unsigned) (uintptr_t) path_startswith(text, "/tmp"));
        keep(ca_is_url(text));
        keep(ca_is_ssh_path(text));
        keep(ca_xattr_name_is_valid(text));
        keep(ca_xattr_name_store("user.fuzz"));
        keep((unsigned) (uintptr_t) ca_compression_type_to_string(CA_COMPRESSION_XZ));
        keep((unsigned) (uintptr_t) ca_compression_type_to_string(CA_COMPRESSION_GZIP));
        keep((unsigned) ca_compression_type_from_string("xz"));
        keep((unsigned) ca_compression_type_from_string("gzip"));
        keep((unsigned) ca_compression_type_from_string("zstd"));
        keep(ca_locator_has_suffix("out.caidx", ".caidx"));
        keep(ca_locator_has_suffix("blob.caibx", ".caibx"));
        keep(ca_locator_has_suffix("out.catar", ".catar"));

        p = ca_strip_file_url("file:///tmp/x");
        free((void *) p);
        if (ca_locator_patch_last_component("file:///tmp/old", "new", &tmp) >= 0)
                free(tmp);

        hex = hexmem(text, n > 16 ? 16 : n);
        free(hex);
        dir = dirname_malloc("/tmp/cafuzz/file");
        free(dir);
        joined = strjoin("casync-", text);
        free(joined);
        if (tempfn_random("/tmp/seed", &tmp) >= 0)
                free(tmp);

        ls_format_mode(0644 | S_IFREG, modebuf);
        keep(modebuf[0]);
        strstrip(text);
        truncate_nl(text);

        if (strv_extend(&sv, "xz") >= 0 && strv_extend(&sv, "gzip") >= 0)
                keep((unsigned) strv_length(sv));
        strv_free(sv);

        FILE *nf = fopen("/dev/null", "w");
        if (nf) {
                hexdump(nf, data, size > 32 ? 32 : size);
                fclose(nf);
        }

        char span[128];
        format_timespan(span, sizeof(span), 1000000, 1000);
        keep(span[0]);
}

static int add_tree(const char *dir, const uint8_t *data, size_t size) {
        char path[512];
        int dfd, fd, r;

        dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0)
                return -errno;

        fd = openat(dfd, "payload", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0) {
                size_t n = size > 2048 ? 2048 : size;
                if (n == 0)
                        r = write_all(fd, "casync", 6);
                else
                        r = write_all(fd, data, n);
                (void) r;
                (void) fsetxattr(fd, "user.fuzz", "yes", 3, 0);
                close(fd);
        }
        fd = openat(dfd, "empty", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0)
                close(fd);
        (void) linkat(dfd, "payload", dfd, "hardlink", 0);
        (void) symlinkat("payload", dfd, "link");
        (void) mkdirat(dfd, "sub", 0755);
        fd = openat(dfd, "sub", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) {
                int nfd = openat(fd, "nested", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
                if (nfd >= 0) {
                        write_all(nfd, data, size > 64 ? 64 : size);
                        close(nfd);
                }
                close(fd);
        }
        (void) mkfifoat(dfd, "fifo", 0644);
        close(dfd);

        snprintf(path, sizeof(path), "%s/payload", dir);
        keep((unsigned) is_dir(path, true));
        return 0;
}

static uint64_t unpriv_flags(void) {
        uint64_t flags = CA_FORMAT_DEFAULT;
        if (geteuid() != 0)
                flags &= ~(uint64_t) CA_FORMAT_WITH_PRIVILEGED;
        return flags;
}

static void note_sync(CaSync *s, int step) {
        char *path = NULL;
        mode_t mode = 0;
        uint64_t v = 0;
        const void *payload = NULL;
        size_t psz = 0;

        if (step == CA_SYNC_NEXT_FILE || step == CA_SYNC_DONE_FILE) {
                if (ca_sync_current_path(s, &path) >= 0)
                        free(path);
                (void) ca_sync_current_mode(s, &mode);
                (void) ca_sync_current_size(s, &v);
                (void) ca_sync_current_mtime(s, &v);
        }
        (void) ca_sync_current_archive_offset(s, &v);
        (void) ca_sync_current_archive_chunks(s, &v);
        if (step == CA_SYNC_PAYLOAD)
                (void) ca_sync_get_payload(s, &payload, &psz);
        keep(mode);
}

static int run_sync(CaSync *s) {
        int r = 0;

        for (int i = 0; i < 20000; i++) {
                r = ca_sync_step(s);
                if (r < 0)
                        return r;
                note_sync(s, r);
                if (r == CA_SYNC_FINISHED) {
                        CaChunkID id;
                        (void) ca_sync_get_archive_digest(s, &id);
                        (void) ca_sync_get_payload_digest(s, &id);
                        (void) ca_sync_get_hardlink_digest(s, &id);
                        return 0;
                }
                if (r == CA_SYNC_POLL)
                        return 0;
        }
        return 0;
}

static void sync_make_extract(const char *root, const uint8_t *data, size_t size) {
        char archive[512], index[512], blob[512], store[512], restored[512], file[512];
        uint64_t flags = unpriv_flags();
        CaCompressionType alg = (size & 1) ? CA_COMPRESSION_XZ : CA_COMPRESSION_GZIP;
        int r, fd;

        (void) data;
        snprintf(archive, sizeof(archive), "%s/out.catar", root);
        snprintf(index, sizeof(index), "%s/out.caidx", root);
        snprintf(blob, sizeof(blob), "%s/blob.caibx", root);
        snprintf(store, sizeof(store), "%s/store", root);
        snprintf(restored, sizeof(restored), "%s/restored", root);
        snprintf(file, sizeof(file), "%s/payload", root);
        (void) mkdir(store, 0755);
        (void) mkdir(restored, 0755);

        if (!compressor_is_supported(alg))
                alg = compressor_is_supported(CA_COMPRESSION_GZIP) ? CA_COMPRESSION_GZIP : CA_COMPRESSION_XZ;

        CaSync *enc = ca_sync_new_encode();
        if (!enc)
                return;
        fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
                ca_sync_unref(enc);
                return;
        }
        r = ca_sync_set_base_fd(enc, fd);
        if (r < 0) {
                close(fd);
                ca_sync_unref(enc);
                return;
        }
        (void) ca_sync_set_feature_flags(enc, flags);
        (void) ca_sync_set_compression_type(enc, alg);
        (void) ca_sync_set_chunk_size_max(enc, 4096);
        (void) ca_sync_set_chunk_size_avg(enc, 1024);
        (void) ca_sync_set_chunk_size_min(enc, 256);
        (void) ca_sync_enable_archive_digest(enc, true);
        (void) ca_sync_enable_payload_digest(enc, true);
        (void) ca_sync_enable_hardlink_digest(enc, true);
        (void) ca_sync_set_archive_path(enc, archive);
        (void) run_sync(enc);
        ca_sync_unref(enc);

        CaSync *dec = ca_sync_new_decode();
        if (dec) {
                (void) ca_sync_set_feature_flags(dec, flags);
                (void) ca_sync_set_hardlink(dec, true);
                (void) ca_sync_set_delete(dec, false);
                (void) ca_sync_set_punch_holes(dec, true);
                (void) ca_sync_enable_archive_digest(dec, true);
                (void) ca_sync_enable_payload_digest(dec, true);
                fd = open(restored, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (fd >= 0 && ca_sync_set_base_fd(dec, fd) >= 0 &&
                    ca_sync_set_archive_path(dec, archive) >= 0)
                        (void) run_sync(dec);
                else if (fd >= 0)
                        close(fd);
                ca_sync_unref(dec);
        }

        /* Chunk store path: this is where xz/gzip wrap individual chunks. */
        enc = ca_sync_new_encode();
        if (!enc)
                return;
        fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
                ca_sync_unref(enc);
                return;
        }
        if (ca_sync_set_base_fd(enc, fd) < 0) {
                close(fd);
                ca_sync_unref(enc);
                return;
        }
        (void) ca_sync_set_feature_flags(enc, flags);
        (void) ca_sync_set_compression_type(enc, alg);
        (void) ca_sync_set_store_path(enc, store);
        (void) ca_sync_set_index_path(enc, index);
        (void) ca_sync_enable_archive_digest(enc, true);
        (void) run_sync(enc);
        ca_sync_unref(enc);

        char restored2[512];
        snprintf(restored2, sizeof(restored2), "%s/restored-idx", root);
        (void) mkdir(restored2, 0755);
        dec = ca_sync_new_decode();
        if (dec) {
                (void) ca_sync_set_feature_flags(dec, flags);
                (void) ca_sync_set_store_path(dec, store);
                (void) ca_sync_set_index_path(dec, index);
                (void) ca_sync_set_hardlink(dec, true);
                fd = open(restored2, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (fd >= 0 && ca_sync_set_base_fd(dec, fd) >= 0)
                        (void) run_sync(dec);
                else if (fd >= 0)
                        close(fd);
                ca_sync_unref(dec);
        }

        /* Blob index of the regular file, other compressor. */
        CaCompressionType other = alg == CA_COMPRESSION_XZ ? CA_COMPRESSION_GZIP : CA_COMPRESSION_XZ;
        if (!compressor_is_supported(other))
                other = alg;
        enc = ca_sync_new_encode();
        if (!enc)
                return;
        fd = open(file, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                ca_sync_unref(enc);
                return;
        }
        if (ca_sync_set_base_fd(enc, fd) < 0) {
                close(fd);
                ca_sync_unref(enc);
                return;
        }
        (void) ca_sync_set_compression_type(enc, other);
        (void) ca_sync_set_store_path(enc, store);
        (void) ca_sync_set_index_path(enc, blob);
        (void) ca_sync_enable_payload_digest(enc, true);
        (void) run_sync(enc);
        ca_sync_unref(enc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        char tmpl[] = "/tmp/cafuzz.XXXXXX";
        char *root;

        if (!getenv("CASYNC_LOG_LEVEL"))
                set_log_level(LOG_CRIT);

        compress_roundtrip(CA_COMPRESSION_XZ, data, size);
        compress_roundtrip(CA_COMPRESSION_GZIP, data, size);
        compress_roundtrip(CA_COMPRESSION_ZSTD, data, size);
        exercise_utils(data, size);

        root = mkdtemp(tmpl);
        if (!root)
                return 0;
        if (add_tree(root, data, size) >= 0)
                sync_make_extract(root, data, size);
        (void) rm_rf(root, REMOVE_ROOT | REMOVE_PHYSICAL);
        return 0;
}
