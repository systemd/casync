/* SPDX-License-Identifier: LGPL-2.1+ */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>

#include "caformat-util.h"
#include "caformat.h"
#include "cafuse.h"
#include "caindex.h"
#include "canbd.h"
#include "caprotocol.h"
#include "caremote.h"
#include "castore.h"
#include "casync.h"
#include "def.h"
#include "gc.h"
#include "notify.h"
#include "parse-util.h"
#include "signal-handler.h"
#include "util.h"

#if HAVE_UDEV
#include <libudev.h>
#include "udev-util.h"
#endif

static enum arg_what {
        WHAT_ARCHIVE,
        WHAT_ARCHIVE_INDEX,
        WHAT_BLOB,
        WHAT_BLOB_INDEX,
        WHAT_DIRECTORY,
        _WHAT_INVALID = -1,
} arg_what = _WHAT_INVALID;
static bool arg_verbose = false;
static bool arg_dry_run = false;
static bool arg_exclude_nodump = true;
static bool arg_exclude_submounts = false;
static bool arg_exclude_file = true;
static bool arg_reflink = true;
static bool arg_hardlink = false;
static bool arg_punch_holes = true;
static bool arg_delete = true;
static bool arg_undo_immutable = false;
static bool arg_recursive = true;
static bool arg_seed_output = true;
static char *arg_store = NULL;
static char **arg_extra_stores = NULL;
static char **arg_seeds = NULL;
static char *arg_cache = NULL;
static bool arg_cache_auto = false;
static size_t arg_chunk_size_min = 0;
static size_t arg_chunk_size_avg = 0;
static size_t arg_chunk_size_max = 0;
static uint64_t arg_rate_limit_bps = UINT64_MAX;
static uint64_t arg_with = 0;
static uint64_t arg_without = 0;
static uid_t arg_uid_shift = 0, arg_uid_range = 0x10000U;
static bool arg_uid_shift_apply = false;
static bool arg_mkdir = true;
static CaDigestType arg_digest = CA_DIGEST_DEFAULT;
static CaCompressionType arg_compression = CA_COMPRESSION_DEFAULT;

static void help(void) {
        printf("%1$s [OPTIONS...] make [ARCHIVE|ARCHIVE_INDEX|BLOB_INDEX] [PATH]\n"
               "%1$s [OPTIONS...] extract [ARCHIVE|ARCHIVE_INDEX|BLOB_INDEX] [PATH]\n"
               "%1$s [OPTIONS...] list [ARCHIVE|ARCHIVE_INDEX|DIRECTORY]\n"
               "%1$s [OPTIONS...] mtree [ARCHIVE|ARCHIVE_INDEX|DIRECTORY]\n"
               "%1$s [OPTIONS...] stat [ARCHIVE|ARCHIVE_INDEX|DIRECTORY] [PATH]\n"
               "%1$s [OPTIONS...] digest [ARCHIVE|BLOB|ARCHIVE_INDEX|BLOB_INDEX|DIRECTORY]\n"
#if HAVE_FUSE
               "%1$s [OPTIONS...] mount [ARCHIVE|ARCHIVE_INDEX] PATH\n"
#endif
               "%1$s [OPTIONS...] mkdev [BLOB|BLOB_INDEX] [NODE]\n"
               "%1$s [OPTIONS...] gc BLOB_INDEX|ARCHIVE_INDEX...\n"
               "\n"
               "Content-Addressable Data Synchronization Tool\n\n"
               "  -h --help                  Show this help\n"
               "     --version               Show brief version information\n"
               "  -v --verbose               Show terse status information during runtime\n"
               "  -n --dry-run               When garbage collecting, only print what would\n"
               "                             be done\n"
               "     --store=PATH            The primary chunk store to use\n"
               "     --extra-store=PATH      Additional chunk store to look for chunks in\n"
               "     --chunk-size=[MIN:]AVG[:MAX]\n"
               "                             The minimal/average/maximum number of bytes in a\n"
               "                             chunk\n"
               "     --digest=DIGEST         Pick digest algorithm (sha512-256 or sha256)\n"
               "     --compression=COMPRESSION\n"
               "                             Pick compression algorithm (zstd, xz or gzip)\n"
               "     --seed=PATH             Additional file or directory to use as seed\n"
               "     --cache=PATH            Directory to use as encoder cache\n"
               "  -c --cache-auto            Pick encoder cache directory automatically\n"
               "     --rate-limit-bps=LIMIT  Maximum bandwidth in bytes/s for remote\n"
               "                             communication\n"
               "     --exclude-nodump=no     Don't exclude files with chattr(1)'s +d 'nodump'\n"
               "                             flag when creating archive\n"
               "     --exclude-submounts=yes Exclude submounts when creating archive\n"
               "     --exclude-file=no       Don't respect .caexclude files in file tree\n"
               "     --reflink=no            Don't create reflinks from seeds when extracting\n"
               "     --hardlink=yes          Create hardlinks from seeds when extracting\n"
               "     --punch-holes=no        Don't create sparse files when extracting\n"
               "     --delete=no             Don't delete existing files not listed in archive\n"
               "                             after extraction\n"
               "     --undo-immutable=yes    When removing existing files, undo chattr(1)'s +i\n"
               "                             'immutable' flag when extracting\n"
               "     --seed-output=no        Don't implicitly add pre-existing output as seed\n"
               "                             when extracting\n"
               "     --recursive=no          List non-recursively\n"
#if HAVE_FUSE
               "     --mkdir=no              Don't automatically create mount directory if it\n"
               "                             is missing\n"
#endif
               "     --uid-shift=yes|SHIFT   Shift UIDs/GIDs\n"
               "     --uid-range=RANGE       Restrict UIDs/GIDs to range\n\n"
               "Input/output selector:\n"
               "     --what=archive          Operate on archive file\n"
               "     --what=archive-index    Operate on archive index file\n"
               "     --what=blob             Operate on blob file\n"
               "     --what=blob-index       Operate on blob index file\n"
               "     --what=directory        Operate on directory\n\n"
               "     --what=help             Print allowed values\n\n"
               "Archive feature sets:\n"
               "     --with=best             Store most accurate information\n"
               "     --with=unix             Store UNIX baseline information\n"
               "     --with=fat              Store FAT information\n"
               "     --with=chattr           Store chattr(1) file attributes\n"
               "     --with=fat-attrs        Store FAT file attributes\n"
               "     --with=privileged       Store file data that requires privileges to\n"
               "                             restore\n"
               "     --with=fuse             Store file data that can exposed again via\n"
               "                             'casync mount'\n"
               "     (and similar: --without=fat-attrs, --without=privileged, ...)\n"
               "     --without=all           Disable all optional attributes\n\n"
               "Individual archive features:\n"
               "     --with=16bit-uids       Store reduced 16bit UID/GID information\n"
               "     --with=32bit-uids       Store full 32bit UID/GID information\n"
               "     --with=user-names       Store user and group names\n"
               "     --with=sec-time         Store timestamps with 1s granularity\n"
               "     --with=usec-time        Store timestamps with 1µs granularity\n"
               "     --with=nsec-time        Store timestamps with 1ns granularity\n"
               "     --with=2sec-time        Store timestamps with 2s granularity\n"
               "     --with=read-only        Store per-file read only flag\n"
               "     --with=permissions      Store full per-file UNIX permissions\n"
               "     --with=symlinks         Store symbolic links\n"
               "     --with=device-nodes     Store block and character device nodes\n"
               "     --with=fifos            Store named pipe nodes\n"
               "     --with=sockets          Store AF_UNIX file system socket nodes\n"
               "     --with=flag-hidden      Store FAT \"hidden\" file flag\n"
               "     --with=flag-system      Store FAT \"system\" file flag\n"
               "     --with=flag-archive     Store FAT \"archive\" file flag\n"
               "     --with=flag-append      Store \"append-only\" file flag\n"
               "     --with=flag-noatime     Store \"disable access time\" file flag\n"
               "     --with=flag-compr       Store \"enable compression\" file flag\n"
               "     --with=flag-nocow       Store \"disable copy-on-write\" file flag\n"
               "     --with=flag-nodump      Store \"disable dumping\" file flag\n"
               "     --with=flag-dirsync     Store \"synchronous\" directory flag\n"
               "     --with=flag-immutable   Store \"immutable\" file flag\n"
               "     --with=flag-sync        Store \"synchronous\" file flag\n"
               "     --with=flag-nocomp      Store \"disable compression\" file flag\n"
               "     --with=flag-projinherit Store \"project quota inheritance\" flag\n"
               "     --with=subvolume        Store btrfs subvolume information\n"
               "     --with=subvolume-ro     Store btrfs subvolume read-only property\n"
               "     --with=xattrs           Store extended file attributes\n"
               "     --with=acl              Store file access control lists\n"
               "     --with=selinux          Store SELinux file labels\n"
               "     --with=fcaps            Store file capabilities\n"
               "     --with=quota-projid     Store ext4/XFS quota project ID\n"
               "     (and similar: --without=16bit-uids, --without=32bit-uids, ...)\n",
               program_invocation_short_name);
}

static void version(void) {
        printf("%s " PACKAGE_VERSION "\n",
               program_invocation_short_name);
}

static int parse_chunk_sizes(const char *v, size_t *ret_min, size_t *ret_avg, size_t *ret_max) {
        uint64_t a, b, c;
        char *k;
        int r;

        assert(v);
        assert(ret_min);
        assert(ret_max);

        if (streq(v, "auto")) {
                *ret_min = 0;
                *ret_avg = 0;
                *ret_max = 0;

                return 0;
        }

        k = strchr(v, ':');
        if (k) {
                char *j, *p;

                j = strchr(k+1, ':');
                if (!j) {
                        log_error("--chunk-size= requires either a single average chunk size or a triplet of minimum, average and maximum chunk size.");
                        return -EINVAL;
                }

                p = strndupa(v, k - v);
                r = parse_size(p, &a);
                if (r < 0)
                        return log_error_errno(r, "Can't parse minimum chunk size: %s", v);
                if (a < CA_CHUNK_SIZE_LIMIT_MIN) {
                        log_error("Minimum chunk size must be >= %zu.", CA_CHUNK_SIZE_LIMIT_MIN);
                        return -ERANGE;
                }

                p = strndupa(k + 1, j - k - 1);
                r = parse_size(p, &b);
                if (r < 0)
                        return log_error_errno(r, "Can't parse average chunk size: %s", v);
                if (b < a) {
                        log_error("Average chunk size must be larger than minimum chunk size.");
                        return -EINVAL;
                }

                r = parse_size(j + 1, &c);
                if (r < 0)
                        return log_error_errno(r, "Can't parse maximum chunk size: %s", v);
                if (c < b) {
                        log_error("Average chunk size must be smaller than maximum chunk size.");
                        return -EINVAL;
                }
                if (c > CA_CHUNK_SIZE_LIMIT_MAX) {
                        log_error("Maximum chunk size must be <= %zu.", CA_CHUNK_SIZE_LIMIT_MAX);
                        return -ERANGE;
                }
        } else {

                r = parse_size(v, &b);
                if (r < 0)
                        return log_error_errno(r, "Can't parse average chunk size: %s", v);
                if (b < CA_CHUNK_SIZE_LIMIT_MIN) {
                        log_error("Average chunk size must be >= %zu.", CA_CHUNK_SIZE_LIMIT_MIN);
                        return -ERANGE;
                }
                if (b > CA_CHUNK_SIZE_LIMIT_MAX) {
                        log_error("Average chunk size must be <= %zu.", CA_CHUNK_SIZE_LIMIT_MAX);
                        return -ERANGE;
                }

                a = 0;
                c = 0;
        }

        *ret_min = a;
        *ret_avg = b;
        *ret_max = c;

        return 0;
}

static int parse_what_selector(const char *arg, enum arg_what *what) {
        if (streq(arg, "archive"))
                *what = WHAT_ARCHIVE;
        else if (streq(arg, "archive-index"))
                *what = WHAT_ARCHIVE_INDEX;
        else if (streq(arg, "blob"))
                *what = WHAT_BLOB;
        else if (streq(arg, "blob-index"))
                *what = WHAT_BLOB_INDEX;
        else if (streq(arg, "directory"))
                *what = WHAT_DIRECTORY;
        else if (streq(arg, "help")) {
                printf("Allowed --what= selectors:\n"
                       "archive-index\n"
                       "blob\n"
                       "blob-index\n"
                       "directory\n");
                return 0;
        } else {
                log_error("Failed to parse --what= selector: %s", arg);
                return -EINVAL;
        }

        return 1;
}

static int dump_with_flags(void) {
        uint64_t i;
        int r;

        puts("Supported --with= and --without= flags:");

        for (i = 0; i < sizeof(uint64_t)*8; i++) {
                _cleanup_free_ char *s = NULL;
                uint64_t flag = UINT64_C(1) << i;

                if (!(flag & SUPPORTED_WITH_MASK))
                        continue;

                r = ca_with_feature_flags_format(flag, &s);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert feature flag to string: %m");

                puts(s);
        }

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_STORE = 0x100,
                ARG_EXTRA_STORE,
                ARG_CHUNK_SIZE,
                ARG_SEED,
                ARG_CACHE,
                ARG_RATE_LIMIT_BPS,
                ARG_WITH,
                ARG_WITHOUT,
                ARG_WHAT,
                ARG_EXCLUDE_NODUMP,
                ARG_EXCLUDE_SUBMOUNTS,
                ARG_EXCLUDE_FILE,
                ARG_UNDO_IMMUTABLE,
                ARG_PUNCH_HOLES,
                ARG_REFLINK,
                ARG_HARDLINK,
                ARG_SEED_OUTPUT,
                ARG_DELETE,
                ARG_UID_SHIFT,
                ARG_UID_RANGE,
                ARG_RECURSIVE,
                ARG_MKDIR,
                ARG_DIGEST,
                ARG_COMPRESSION,
                ARG_VERSION,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                   },
                { "version",           no_argument,       NULL, ARG_VERSION           },
                { "verbose",           no_argument,       NULL, 'v'                   },
                { "dry-run",           no_argument,       NULL, 'n'                   },
                { "store",             required_argument, NULL, ARG_STORE             },
                { "extra-store",       required_argument, NULL, ARG_EXTRA_STORE       },
                { "chunk-size",        required_argument, NULL, ARG_CHUNK_SIZE        },
                { "seed",              required_argument, NULL, ARG_SEED              },
                { "cache",             required_argument, NULL, ARG_CACHE             },
                { "cache-auto",        no_argument,       NULL, 'c'                   },
                { "rate-limit-bps",    required_argument, NULL, ARG_RATE_LIMIT_BPS    },
                { "with",              required_argument, NULL, ARG_WITH              },
                { "without",           required_argument, NULL, ARG_WITHOUT           },
                { "what",              required_argument, NULL, ARG_WHAT              },
                { "exclude-nodump",    required_argument, NULL, ARG_EXCLUDE_NODUMP    },
                { "exclude-submounts", required_argument, NULL, ARG_EXCLUDE_SUBMOUNTS },
                { "exclude-file",      required_argument, NULL, ARG_EXCLUDE_FILE      },
                { "undo-immutable",    required_argument, NULL, ARG_UNDO_IMMUTABLE    },
                { "delete",            required_argument, NULL, ARG_DELETE            },
                { "punch-holes",       required_argument, NULL, ARG_PUNCH_HOLES       },
                { "reflink",           required_argument, NULL, ARG_REFLINK           },
                { "hardlink",          required_argument, NULL, ARG_HARDLINK          },
                { "seed-output",       required_argument, NULL, ARG_SEED_OUTPUT       },
                { "uid-shift",         required_argument, NULL, ARG_UID_SHIFT         },
                { "uid-range",         required_argument, NULL, ARG_UID_RANGE         },
                { "recursive",         required_argument, NULL, ARG_RECURSIVE         },
                { "mkdir",             required_argument, NULL, ARG_MKDIR             },
                { "digest",            required_argument, NULL, ARG_DIGEST            },
                { "compression",       required_argument, NULL, ARG_COMPRESSION       },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        if (getenv_bool("CASYNC_VERBOSE") > 0)
                arg_verbose = true;

        while ((c = getopt_long(argc, argv, "hvnc", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        version();
                        return 0;

                case 'v':
                        arg_verbose = true;
                        break;

                case 'n':
                        arg_dry_run = true;
                        break;

                case ARG_STORE:
                        r = free_and_strdup(&arg_store, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_EXTRA_STORE:

                        r = strv_extend(&arg_extra_stores, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_CHUNK_SIZE:

                        r = parse_chunk_sizes(optarg,
                                              &arg_chunk_size_min,
                                              &arg_chunk_size_avg,
                                              &arg_chunk_size_max);
                        if (r < 0)
                                return r;

                        break;

                case ARG_SEED:
                        r = strv_extend(&arg_seeds, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_CACHE:
                        r = free_and_strdup(&arg_cache, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case 'c':
                        arg_cache_auto = true;
                        break;

                case ARG_RATE_LIMIT_BPS:
                        r = parse_size(optarg, &arg_rate_limit_bps);
                        if (r < 0)
                                return log_error_errno(r, "Unable to parse rate limit %s: %m", optarg);
                        if (arg_rate_limit_bps == 0) {
                                log_error("Rate limit size cannot be zero.");
                                return -EINVAL;
                        }

                        break;

                case ARG_WITH: {
                        uint64_t u;

                        if (streq(optarg, "help"))
                                return dump_with_flags();

                        r = ca_with_feature_flags_parse_one(optarg, &u);
                        if (r < 0) {
                                log_error("Failed to parse --with= feature flag: %s", optarg);
                                return -EINVAL;
                        }

                        arg_with |= u;
                        break;
                }

                case ARG_WITHOUT: {
                        uint64_t u;

                        if (streq(optarg, "help"))
                                return dump_with_flags();

                        r = ca_with_feature_flags_parse_one(optarg, &u);
                        if (r < 0) {
                                log_error("Failed to parse --without= feature flag: %s", optarg);
                                return -EINVAL;
                        }

                        arg_without |= u;
                        break;
                }

                case ARG_WHAT:
                        r = parse_what_selector(optarg, &arg_what);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_EXCLUDE_NODUMP:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --exclude-nodump= parameter: %s", optarg);

                        arg_exclude_nodump = r;
                        break;

                case ARG_EXCLUDE_SUBMOUNTS:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --exclude-submounts= parameter: %s", optarg);

                        arg_exclude_submounts = r;
                        break;

                case ARG_EXCLUDE_FILE:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --exclude-file= parameter: %s", optarg);

                        arg_exclude_file = r;
                        break;

                case ARG_UNDO_IMMUTABLE:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --undo-immutable= parameter: %s", optarg);
                                return r;
                        }

                        arg_undo_immutable = r;
                        break;

                case ARG_PUNCH_HOLES:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --punch-holes= parameter: %s", optarg);
                                return r;
                        }

                        arg_punch_holes = r;
                        break;

                case ARG_REFLINK:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --reflink= parameter: %s", optarg);
                                return r;
                        }

                        arg_reflink = r;
                        break;

                case ARG_HARDLINK:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --hardlink= parameter: %s", optarg);
                                return r;
                        }

                        arg_hardlink = r;
                        break;

                case ARG_DELETE:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --delete= parameter: %s", optarg);
                                return r;
                        }

                        arg_delete = r;
                        break;

                case ARG_SEED_OUTPUT:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --seed-output= parameter: %s", optarg);
                                return r;
                        }

                        arg_seed_output = r;
                        break;

                case ARG_MKDIR:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --mkdir= parameter: %s", optarg);

                        arg_mkdir = r;
                        break;

                case ARG_UID_SHIFT: {
                        uid_t uid;

                        r = parse_uid(optarg, &uid);
                        if (r < 0) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --uid-shift= parameter: %s", optarg);

                                arg_uid_shift_apply = r;
                        } else {
                                arg_uid_shift = uid;
                                arg_uid_shift_apply = true;
                        }

                        break;
                }

                case ARG_UID_RANGE: {
                        uint64_t u;

                        /* The valid values for the range are 1..0x100000000. However, we store this in a 32bit uid_t,
                         * which requires us to map 0x100000000 to 0. */
                        r = safe_atou64(optarg, &u);
                        if (r < 0 || u == 0 || u > UINT64_C(0x100000000)) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --uid-range= parameter: %s", optarg);

                                arg_uid_shift_apply = r;

                        } else {

                                if (u == UINT64_C(0x100000000))
                                        arg_uid_range = 0;
                                else
                                        arg_uid_range = (uid_t) u;

                                arg_uid_shift_apply = true;
                        }

                        break;
                }

                case ARG_RECURSIVE:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --recursive= parameter: %s", optarg);

                        arg_recursive = r;
                        break;

                case ARG_DIGEST: {
                        CaDigestType t;

                        t = ca_digest_type_from_string(optarg);
                        if (t < 0)
                                return log_error_errno(t, "Failed to parse --digest= parameter: %s", optarg);

                        arg_digest = t;
                        break;
                }

                case ARG_COMPRESSION: {
                        CaCompressionType cc;

                        cc = ca_compression_type_from_string(optarg);
                        if (cc < 0)
                                return log_error_errno(cc, "Failed to parse --compression= parameter: %s", optarg);

                        arg_compression = cc;
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert(false);
                }
        }

        /* Propagate our verbose setting to helpers we fork off */
        if (arg_verbose)
                (void) putenv((char*) "CASYNC_VERBOSE=1");
        else
                unsetenv("CASYNC_VERBOSE");

        return 1;
}

static int set_default_store(const char *index_path) {
        const char *e;
        int r;

        if (arg_store)
                return 0;

        e = getenv("CASYNC_STORE");
        if (e)
                /* If the default store is set via an environment variable, use that */
                arg_store = strdup(e);
        else if (index_path) {

                /* Otherwise, derive it from the index file path */

                r = ca_locator_patch_last_component(index_path, "default.castr", &arg_store);
                if (r < 0)
                        return log_error_errno(r, "Failed to automatically derive store location from index: %m");
        } else
                /* And if we don't know any, then place it in the current directory */
                arg_store = strdup("default.castr");

        if (!arg_store)
                return log_oom();

        return 1;
}

static int load_seeds_and_extra_stores(CaSync *s) {
        char **i;
        int r;

        assert(s);

        STRV_FOREACH(i, arg_extra_stores) {
                r = ca_sync_add_store_auto(s, *i);
                if (r < 0)
                        log_error("Failed to add extra store %s, ignoring: %m", *i);
        }

        STRV_FOREACH(i, arg_seeds) {
                r = ca_sync_add_seed_path(s, *i);
                if (r < 0)
                        log_error("Failed to add seed %s, ignoring: %m", *i);
        }

        return 0;
}

static uint64_t combined_with_flags(uint64_t default_with_flags) {
        return (arg_with == 0 ? default_with_flags : arg_with) & ~arg_without;
}

static int load_feature_flags(CaSync *s, uint64_t default_with_flags) {
        uint64_t flags;
        int r;

        assert(s);

        flags = combined_with_flags(default_with_flags);

        if (arg_exclude_nodump)
                flags |= CA_FORMAT_EXCLUDE_NODUMP;
        if (arg_exclude_submounts)
                flags |= CA_FORMAT_EXCLUDE_SUBMOUNTS;
        if (arg_exclude_file)
                flags |= CA_FORMAT_EXCLUDE_FILE;

        flags |= ca_feature_flags_from_digest_type(arg_digest);

        r = ca_sync_set_feature_flags(s, flags);
        if (r < 0 && r != -ENOTTY) /* only encoder syncs have a feature flags field */
                return log_error_errno(r, "Failed to set feature flags: %m");

        r = ca_sync_set_feature_flags_mask(s, flags);
        if (r < 0 && r != -ENOTTY) /* only decoder syncs have a feature flags mask field */
                return log_error_errno(r, "Failed to set feature flags mask: %m");

        if (arg_uid_shift_apply) {
                r = ca_sync_set_uid_shift(s, arg_uid_shift);
                if (r < 0)
                        return log_error_errno(r, "Failed to set UID shift: %m");

                r = ca_sync_set_uid_range(s, arg_uid_range);
                if (r < 0)
                        return log_error_errno(r, "Failed to set UID range: %m");
        }

        r = ca_sync_set_undo_immutable(s, arg_undo_immutable);
        if (r < 0 && r != -ENOTTY)
                return log_error_errno(r, "Failed to set undo immutable flag: %m");

        r = ca_sync_set_compression_type(s, arg_compression);
        if (r < 0 && r != -ENOTTY)
                return log_error_errno(r, "Failed to set compression: %m");

        r = ca_sync_set_delete(s, arg_delete);
        if (r < 0 && r != -ENOTTY)
                return log_error_errno(r, "Failed to set deletion flag: %m");

        return 0;
}

static int load_chunk_size(CaSync *s) {
        uint64_t cavg, cmin, cmax;
        int r;

        if (arg_chunk_size_avg != 0) {
                r = ca_sync_set_chunk_size_avg(s, arg_chunk_size_avg);
                if (r < 0)
                        return log_error_errno(r, "Failed to set average chunk size to %zu: %m", arg_chunk_size_avg);
        }

        if (arg_chunk_size_min != 0) {
                r = ca_sync_set_chunk_size_min(s, arg_chunk_size_min);
                if (r < 0)
                        return log_error_errno(r, "Failed to set minimum chunk size to %zu: %m", arg_chunk_size_min);
        }

        if (arg_chunk_size_max != 0) {
                r = ca_sync_set_chunk_size_max(s, arg_chunk_size_max);
                if (r < 0)
                        return log_error_errno(r, "Failed to set maximum chunk size to %zu: %m", arg_chunk_size_max);
        }

        if (!arg_verbose)
                return 1;

        r = ca_sync_get_chunk_size_avg(s, &cavg);
        if (r < 0)
                return log_error_errno(r, "Failed to read average chunk size: %m");

        r = ca_sync_get_chunk_size_min(s, &cmin);
        if (r < 0)
                return log_error_errno(r, "Failed to read minimum chunk size: %m");

        r = ca_sync_get_chunk_size_max(s, &cmax);
        if (r < 0)
                return log_error_errno(r, "Failed to read maximum chunk size: %m");

        log_info("Selected chunk sizes: min=%" PRIu64 "..avg=%" PRIu64 "..max=%" PRIu64, cmin, cavg, cmax);
        return 1;
}

static int verbose_print_feature_flags(CaSync *s) {
        static bool printed = false;
        uint64_t flags;
        _cleanup_free_ char *t = NULL;
        int r;

        assert(s);

        if (!arg_verbose)
                return 0;
        if (printed)
                return 0;

        r = ca_sync_get_feature_flags(s, &flags);
        if (r == -ENODATA) /* we don't know them yet? */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to query feature flags: %m");

        r = ca_with_feature_flags_format(flags, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to format feature flags: %m");

        log_info("Using feature flags: %s", strnone(t));
        log_info("Excluding files and directories with chattr(1) -d flag: %s", yes_no(flags & CA_FORMAT_EXCLUDE_NODUMP));
        log_info("Excluding submounts: %s", yes_no(flags & CA_FORMAT_EXCLUDE_SUBMOUNTS));
        log_info("Excluding files and directories listed in .caexclude: %s", yes_no(flags & CA_FORMAT_EXCLUDE_FILE));
        log_info("Digest algorithm: %s", ca_digest_type_to_string(ca_feature_flags_to_digest_type(flags)));

        printed = true;

        return 0;
}

static int verbose_print_path(CaSync *s, const char *verb) {
        _cleanup_free_ char *path = NULL;
        int r;

        if (!arg_verbose)
                return 0;

        r = ca_sync_current_path(s, &path);
        if (r == -ENOTDIR) /* Root isn't a directory */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to query current path: %m");

        log_info("%s%s%s", verb ?: "", verb ? " " : "", isempty(path) ? "./" : path);
        return 1;
}

static int verbose_print_done_make(CaSync *s) {
        uint64_t n_chunks = UINT64_MAX, size = UINT64_MAX, n_reused = UINT64_MAX, covering,
                n_cache_hits = UINT64_MAX, n_cache_misses = UINT64_MAX, n_cache_invalidated = UINT64_MAX, n_cache_added = UINT64_MAX;
        char buffer[FORMAT_BYTES_MAX];
        int r;

        assert(s);

        if (!arg_verbose)
                return 0;

        r = ca_sync_get_covering_feature_flags(s, &covering);
        if (r != -ENODATA) {
                _cleanup_free_ char *t = NULL;
                uint64_t selected, too_much;

                if (r < 0)
                        return log_error_errno(r, "Failed to determine covering flags: %m");

                r = ca_sync_get_feature_flags(s, &selected);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine used flags: %m");

                r = ca_with_feature_flags_format(selected, &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to format feature flags: %m");

                log_info("Selected feature flags: %s", strnone(t));

                too_much = selected & ~covering;
                if (too_much != 0) {
                        t = mfree(t);

                        r = ca_with_feature_flags_format(too_much, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format feature flags: %m");

                        log_info("Selected feature flags not actually applicable to backing file systems: %s", strnone(t));
                }
        }

        r = ca_sync_current_archive_chunks(s, &n_chunks);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to determine number of chunks: %m");

        r = ca_sync_current_archive_reused_chunks(s, &n_reused);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to determine number of reused chunks: %m");

        r = ca_sync_current_archive_offset(s, &size);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to determine archive size: %m");

        if (size != UINT64_MAX)
                log_info("Archive size: %s", format_bytes(buffer, sizeof(buffer), size));
        if (n_chunks != UINT64_MAX)
                log_info("Number of chunks: %" PRIu64, n_chunks);
        if (n_reused != UINT64_MAX) {
                if (n_chunks != UINT64_MAX && n_chunks > 0)
                        log_info("Reused (non-cached) chunks: %"PRIu64 " (%"PRIu64 "%%)",
                                 n_reused, n_reused * 100U / n_chunks);
                else
                        log_info("Reused (non-cached) chunks: %" PRIu64, n_reused);
        }

        if (size != UINT64_MAX && n_chunks != UINT64_MAX)
                log_info("Effective average chunk size: %s", format_bytes(buffer, sizeof(buffer), size / n_chunks));

        r = ca_sync_current_cache_hits(s, &n_cache_hits);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to read number of cache hits: %m");

        r = ca_sync_current_cache_misses(s, &n_cache_misses);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to read number of cache misses: %m");

        r = ca_sync_current_cache_invalidated(s, &n_cache_invalidated);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to read number of invalidated cache items: %m");

        r = ca_sync_current_cache_added(s, &n_cache_added);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to read number of added cache items: %m");

        if (n_cache_hits != UINT64_MAX && n_cache_misses != UINT64_MAX && n_cache_invalidated != UINT64_MAX && n_cache_added != UINT64_MAX)
                log_info("Cache hits: %" PRIu64 ", misses: %" PRIu64 ", invalidated: %" PRIu64 ", added: %" PRIu64, n_cache_hits, n_cache_misses, n_cache_invalidated, n_cache_added);

        return 1;
}

static int verbose_print_done_extract(CaSync *s) {
        char buffer[FORMAT_BYTES_MAX];
        uint64_t n_bytes, n_requests;
        uint64_t n_local_requests = UINT64_MAX, n_seed_requests = UINT64_MAX, n_remote_requests = UINT64_MAX;
        uint64_t n_local_bytes = UINT64_MAX, n_seed_bytes = UINT64_MAX, n_remote_bytes = UINT64_MAX;
        uint64_t total_requests = 0, total_bytes = 0;
        int r;

        if (!arg_verbose)
                return 0;

        r = ca_sync_get_punch_holes_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine number of punch holes bytes: %m");

                log_info("Zero bytes written as sparse files: %s", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_reflink_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine number of reflink bytes: %m");

                log_info("Bytes cloned through reflinks: %s", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_hardlink_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine number of hardlink bytes: %m");

                log_info("Bytes cloned through hardlinks: %s", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_local_requests(s, &n_requests);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine number of successful local store requests: %m");

                n_local_requests = n_requests;
                total_requests += n_requests;
        }

        r = ca_sync_get_local_request_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine size of successful local store requests: %m");

                n_local_bytes = n_bytes;
                total_bytes += n_bytes;
        }

        r = ca_sync_get_seed_requests(s, &n_requests);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine number of successful local seed requests: %m");

                n_seed_requests = n_requests;
                total_requests += n_requests;
        }

        r = ca_sync_get_seed_request_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine size of successful local seed requests: %m");

                n_seed_bytes = n_bytes;
                total_bytes += n_bytes;
        }

        r = ca_sync_get_remote_requests(s, &n_requests);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine number of successful remote store requests: %m");

                n_remote_requests = n_requests;
                total_requests += n_requests;
        }

        r = ca_sync_get_remote_request_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0)
                        return log_error_errno(r, "Failed to determine size of successful remote store requests: %m");

                n_remote_bytes = n_bytes;
                total_bytes += n_bytes;
        }

        if (n_local_requests != UINT64_MAX)
                log_info("Chunk requests fulfilled from local store: %" PRIu64 " (%" PRIu64 "%%)",
                         n_local_requests,
                         total_requests > 0 ? n_local_requests * 100U / total_requests : 0);
        if (n_local_bytes != UINT64_MAX)
                log_info("Bytes used from local store: %s (%" PRIu64 "%%)",
                         format_bytes(buffer, sizeof(buffer), n_local_bytes),
                         total_bytes > 0 ? n_local_bytes * 100U / total_bytes : 0);
        if (n_seed_requests != UINT64_MAX)
                log_info("Chunk requests fulfilled from local seed: %" PRIu64 " (%" PRIu64 "%%)",
                         n_seed_requests,
                         total_requests > 0 ? n_seed_requests * 100U / total_requests : 0);
        if (n_seed_bytes != UINT64_MAX)
                log_info("Bytes used from local seed: %s (%" PRIu64 "%%)",
                         format_bytes(buffer, sizeof(buffer), n_seed_bytes),
                         total_bytes > 0 ? n_seed_bytes * 100U / total_bytes : 0);
        if (n_remote_requests != UINT64_MAX)
                log_info("Chunk requests fulfilled from remote store: %" PRIu64 " (%" PRIu64 "%%)",
                         n_remote_requests,
                         total_requests > 0 ? n_remote_requests * 100U / total_requests : 0);
        if (n_remote_bytes != UINT64_MAX)
                log_info("Bytes used from remote store: %s (%" PRIu64 "%%)",
                         format_bytes(buffer, sizeof(buffer), n_remote_bytes),
                         total_bytes > 0 ? n_remote_bytes * 100U / total_bytes : 0);

        return 1;
}

static int process_step_generic(CaSync *s, int step, bool quit_ok) {
        int r;

        assert(s);

        switch (step) {

        case CA_SYNC_FINISHED:
        case CA_SYNC_STEP:
        case CA_SYNC_PAYLOAD:
        case CA_SYNC_FOUND:
                return 0;

        case CA_SYNC_NEXT_FILE:
                return verbose_print_path(s, "Processing");

        case CA_SYNC_DONE_FILE:
                return verbose_print_path(s, "Processed");

        case CA_SYNC_SEED_NEXT_FILE:
                return verbose_print_path(s, "Seeding");

        case CA_SYNC_SEED_DONE_FILE:
                return verbose_print_path(s, "Seeded");

        case CA_SYNC_POLL:
                r = sync_poll_sigset(s);
                if (r == -ESHUTDOWN) {
                        if (!quit_ok)
                                log_error("Got exit signal, quitting.");
                } else if (r < 0)
                        log_error_errno(r, "Failed to poll synchronizer: %m");

                return r;

        case CA_SYNC_NOT_FOUND:
                log_error("Seek path not available in archive.");
                return -ENOENT;
        }

        assert(false);
}

static int verb_make(int argc, char *argv[]) {

        typedef enum MakeOperation {
                MAKE_ARCHIVE,
                MAKE_ARCHIVE_INDEX,
                MAKE_BLOB_INDEX,
                _MAKE_OPERATION_INVALID = -1,
        } MakeOperation;

        MakeOperation operation = _MAKE_OPERATION_INVALID;
        _cleanup_free_ char *input = NULL, *output = NULL;
        _cleanup_(safe_close_nonstdp) int input_fd = -1;
        int r;
        _cleanup_(ca_sync_unrefp) CaSync *s = NULL;
        struct stat st;

        if (argc > 3) {
                log_error("A pair of output and input path/URL expected.");
                return -EINVAL;
        }

        if (argc > 1) {
                output = ca_strip_file_url(argv[1]);
                if (!output)
                        return log_oom();
        }

        if (argc > 2) {
                input = ca_strip_file_url(argv[2]);
                if (!input)
                        return log_oom();
        }

        if (arg_what == WHAT_ARCHIVE)
                operation = MAKE_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = MAKE_ARCHIVE_INDEX;
        else if (arg_what == WHAT_BLOB_INDEX)
                operation = MAKE_BLOB_INDEX;
        else if (arg_what != _WHAT_INVALID) {
                log_error("\"make\" operation may only be combined with --what=archive, --what=archive-index or --what=blob-index.");
                return -EINVAL;
        }

        if (operation == _MAKE_OPERATION_INVALID && output && !streq(output, "-")) {
                if (ca_locator_has_suffix(output, ".catar"))
                        operation = MAKE_ARCHIVE;
                else if (ca_locator_has_suffix(output, ".caidx"))
                        operation = MAKE_ARCHIVE_INDEX;
                else if (ca_locator_has_suffix(output, ".caibx"))
                        operation = MAKE_BLOB_INDEX;
                else {
                        log_error("File to create does not have valid suffix, refusing. (May be one of: .catar, .caidx, .caibx)");
                        return -EINVAL;
                }
        }

        if (!input && IN_SET(operation, MAKE_ARCHIVE, MAKE_ARCHIVE_INDEX)) {
                input = strdup(".");
                if (!input)
                        return log_oom();
        }

        if (!input || streq(input, "-")) {
                input_fd = STDIN_FILENO;
                input = NULL;
        } else {
                CaLocatorClass input_class;

                input_class = ca_classify_locator(input);
                if (input_class < 0) {
                        log_error("Failed to determine class of locator: %s", input);
                        return -EINVAL;
                }

                if (input_class != CA_LOCATOR_PATH) {
                        log_error("Input must be local path: %s", input);
                        return -EINVAL;
                }

                input_fd = open(input, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                if (input_fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", input);
        }

        if (fstat(input_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat input: %m");

        if (S_ISDIR(st.st_mode)) {

                if (operation == _MAKE_OPERATION_INVALID)
                        operation = MAKE_ARCHIVE;
                else if (!IN_SET(operation, MAKE_ARCHIVE, MAKE_ARCHIVE_INDEX)) {
                        log_error("Input is a directory, but attempted to make blob index. Refusing.");
                        return -EINVAL;
                }

        } else if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode)) {

                if (operation == _MAKE_OPERATION_INVALID)
                        operation = MAKE_BLOB_INDEX;
                else if (operation != MAKE_BLOB_INDEX) {
                        log_error("Input is a regular file or block device, but attempted to make a directory archive. Refusing.");
                        return -EINVAL;
                }
        } else {
                log_error("Input is a neither a directory, a regular file, nor a block device. Refusing.");
                return -EINVAL;
        }

        if (streq_ptr(output, "-"))
                output = mfree(output);

        if (operation == _MAKE_OPERATION_INVALID) {
                log_error("Failed to determine what to make. Use --what=archive, --what=archive-index or --what=blob-index.");
                return -EINVAL;
        }

        if (!IN_SET(operation, MAKE_ARCHIVE_INDEX, MAKE_ARCHIVE) && (arg_cache_auto || arg_cache)) {
                log_error("Caching only supported when archiving files trees.");
                return -EOPNOTSUPP;
        }

        if (IN_SET(operation, MAKE_ARCHIVE_INDEX, MAKE_BLOB_INDEX)) {
                r = set_default_store(output);
                if (r < 0)
                        return r;
        }

        s = ca_sync_new_encode();
        if (!s)
                return log_oom();

        r = load_chunk_size(s);
        if (r < 0)
                return r;

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_sync_set_rate_limit_bps(s, arg_rate_limit_bps);
                if (r < 0)
                        return log_error_errno(r, "Failed to set rate limit: %m");
        }

        r = ca_sync_set_base_fd(s, input_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to set sync base: %m");
        input_fd = -1;

        if (output) {
                r = ca_sync_set_make_mode(s, st.st_mode & 0666);
                if (r < 0)
                        return log_error_errno(r, "Failed to set make permission mode: %m");
        }

        if (operation == MAKE_ARCHIVE) {
                if (output)
                        r = ca_sync_set_archive_auto(s, output);
                else
                        r = ca_sync_set_archive_fd(s, STDOUT_FILENO);
                if (r < 0)
                        return log_error_errno(r, "Failed to set sync archive: %m");
        } else {
                if (output)
                        r = ca_sync_set_index_auto(s, output);
                else
                        r = ca_sync_set_index_fd(s, STDOUT_FILENO);
                if (r < 0)
                        return log_error_errno(r, "Failed to set sync index: %m");
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0)
                        return log_error_errno(r, "Failed to set store: %m");
        }

        r = load_feature_flags(s, operation == MAKE_BLOB_INDEX ? 0 : SUPPORTED_WITH_MASK);
        if (r < 0)
                return r;

        if (arg_cache_auto && !arg_cache) {
                if (!input) {
                        log_error("Can't automatically derive cache path if no input path is given.");
                        return -EOPNOTSUPP;
                }

                arg_cache = strjoin(input, "/.cacac");
                if (!arg_cache)
                        return log_oom();
        }

        r = ca_sync_enable_archive_digest(s, !arg_cache);
        if (r < 0)
                return log_error_errno(r, "Failed to enable archive digest: %m");

        if (arg_cache) {
                r = ca_sync_set_cache_path(s, arg_cache);
                if (r < 0)
                        return log_error_errno(r, "Failed to set cache: %m");
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        log_info("Got exit signal, quitting.");
                        return -ESHUTDOWN;
                }

                r = ca_sync_step(s);
                if (r < 0)
                        return log_error_errno(r, "Failed to run synchronizer: %m");

                switch (r) {

                case CA_SYNC_FINISHED: {
                        CaChunkID digest;
                        char t[CA_CHUNK_ID_FORMAT_MAX];

                        verbose_print_done_make(s);

                        r = ca_sync_get_archive_digest(s, &digest);
                        if (r >= 0)
                                printf("%s\n", ca_chunk_id_format(&digest, t));
                        else if (r != -ENOMEDIUM)
                                return log_debug_errno(r, "Failed to query archive digest: %m");

                        return 0;
                }

                case CA_SYNC_NEXT_FILE:
                        r = verbose_print_path(s, "Packing");
                        if (r < 0)
                                return r;
                        break;

                case CA_SYNC_DONE_FILE:
                        r = verbose_print_path(s, "Packed");
                        if (r < 0)
                                return r;
                        break;

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_POLL:
                        r = process_step_generic(s, r, false);
                        if (r < 0)
                                return r;

                        break;

                case CA_SYNC_FOUND:
                case CA_SYNC_NOT_FOUND:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                default:
                        assert(false);
                }

                verbose_print_feature_flags(s);

                if (arg_verbose)
                        progress();
        }

        return r;
}

static const char *normalize_seek_path(const char *p) {

        /* Normalizes the seek path. Specifically, if the seek path is specified as root directory or empty, we'll
         * simply suppress it entirely. */

        if (!p)
                return p;

        p += strspn(p, "/");

        if (isempty(p))
                return NULL;

        return p;
}

static int verb_extract(int argc, char *argv[]) {

        typedef enum ExtractOperation {
                EXTRACT_ARCHIVE,
                EXTRACT_ARCHIVE_INDEX,
                EXTRACT_BLOB_INDEX,
                _EXTRACT_OPERATION_INVALID = -1,
        } ExtractOperation;

        ExtractOperation operation = _EXTRACT_OPERATION_INVALID;
        int r;
        _cleanup_(safe_close_nonstdp) int output_fd = -1, input_fd = -1;
        _cleanup_free_ char *input = NULL, *output = NULL;
        const char *seek_path = NULL;
        _cleanup_(ca_sync_unrefp) CaSync *s = NULL;

        if (argc > 4) {
                log_error("Input path/URL, output path, and subtree path expected.");
                return -EINVAL;
        }

        if (argc > 1) {
                input = ca_strip_file_url(argv[1]);
                if (!input)
                        return log_oom();
        }

        if (argc > 2) {
                output = ca_strip_file_url(argv[2]);
                if (!output)
                        return log_oom();
        }

        if (argc > 3)
                seek_path = argv[3];

        if (arg_what == WHAT_ARCHIVE)
                operation = EXTRACT_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = EXTRACT_ARCHIVE_INDEX;
        else if (arg_what == WHAT_BLOB_INDEX)
                operation = EXTRACT_BLOB_INDEX;
        else if (arg_what != _WHAT_INVALID) {
                log_error("\"extract\" operation may only be combined with --what=archive, --what=archive-index, --what=blob-index.");
                return -EINVAL;
        }

        if (operation == _EXTRACT_OPERATION_INVALID && input && !streq(input, "-")) {

                if (ca_locator_has_suffix(input, ".catar"))
                        operation = EXTRACT_ARCHIVE;
                else if (ca_locator_has_suffix(input, ".caidx"))
                        operation = EXTRACT_ARCHIVE_INDEX;
                else if (ca_locator_has_suffix(input, ".caibx"))
                        operation = EXTRACT_BLOB_INDEX;
                else {
                        log_error("File to read from does not have valid suffix, refusing. (May be one of: .catar, .caidx, .caibx)");
                        return -EINVAL;
                }
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;

        if (!output && IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX)) {
                output = strdup(".");
                if (!output)
                        return log_oom();
        }

        if (!output || streq(output, "-")) {
                output_fd = STDOUT_FILENO;
                output = NULL;
        } else {
                CaLocatorClass output_class;

                output_class = ca_classify_locator(output);
                if (output_class < 0) {
                        log_error("Failed to determine locator class: %s", output);
                        return -EINVAL;
                }

                if (output_class != CA_LOCATOR_PATH) {
                        log_error("Output must be local path: %s", output);
                        return -EINVAL;
                }

                output_fd = open(output, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                if (output_fd < 0 && errno == EISDIR)
                        output_fd = open(output, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_DIRECTORY);

                if (output_fd < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", output);
        }

        if (output_fd >= 0) {
                struct stat st;

                if (fstat(output_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat output: %m");

                if (S_ISDIR(st.st_mode)) {

                        if (operation == _EXTRACT_OPERATION_INVALID)
                                operation = EXTRACT_ARCHIVE_INDEX;
                        else if (!IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX)) {
                                log_error("Output is a directory, but attempted to extract blob index. Refusing.");
                                return -EINVAL;
                        }

                } else if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode)) {

                        if (operation == _EXTRACT_OPERATION_INVALID)
                                operation = EXTRACT_BLOB_INDEX;
                        else if (operation != EXTRACT_BLOB_INDEX) {
                                log_error("Output is a regular file or block device, but attempted to extract an archive.");
                                return -EINVAL;
                        }
                } else {
                        log_error("Output is neither a directory, a regular file, nor a block device. Refusing.");
                        return -EINVAL;
                }
        }

        if (operation == _EXTRACT_OPERATION_INVALID) {
                log_error("Couldn't figure out what to extract. Refusing. Use --what=archive, --what=archive-index or --what=blob-index.");
                return -EINVAL;
        }

        if (!IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX) && seek_path) {
                log_error("Subtree path only supported when extracting archive or archive index.");
                return -EINVAL;
        }

        seek_path = normalize_seek_path(seek_path);

        s = ca_sync_new_decode();
        if (!s)
                return log_oom();

        if (IN_SET(operation, EXTRACT_ARCHIVE_INDEX, EXTRACT_BLOB_INDEX)) {
                r = set_default_store(input);
                if (r < 0)
                        return r;

                if (arg_seed_output) {
                        r = ca_sync_add_seed_path(s, output);
                        if (r < 0 && r != -ENOENT)
                                log_error_errno(r, "Failed to add existing file as seed %s, ignoring: %m", output);
                }
        }

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_sync_set_rate_limit_bps(s, arg_rate_limit_bps);
                if (r < 0)
                        return log_error_errno(r, "Failed to set rate limit: %m");
        }

        if (seek_path) {
                if (output_fd >= 0)
                        r = ca_sync_set_boundary_fd(s, output_fd);
                else
                        r = ca_sync_set_boundary_path(s, output);
        } else {
                if (output_fd >= 0)
                        r = ca_sync_set_base_fd(s, output_fd);
                else {
                        r = ca_sync_set_base_mode(s, IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX) ? S_IFDIR : S_IFREG);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set base mode to directory: %m");

                        r = ca_sync_set_base_path(s, output);
                }
        }
        if (r < 0)
                return log_error_errno(r, "Failed to set sync base: %m");

        output_fd = -1;

        if (operation == EXTRACT_ARCHIVE) {
                if (input_fd >= 0)
                        r = ca_sync_set_archive_fd(s, input_fd);
                else
                        r = ca_sync_set_archive_auto(s, input);
                if (r < 0)
                        return log_error_errno(r, "Failed to set sync archive: %m");

        } else {
                if (input_fd >= 0)
                        r = ca_sync_set_index_fd(s, input_fd);
                else
                        r = ca_sync_set_index_auto(s, input);
                if (r < 0)
                        return log_error_errno(r, "Failed to set sync index: %m");
        }
        input_fd = -1;

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0)
                        return log_error_errno(r, "Failed to set store: %m");
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                return r;

        r = load_feature_flags(s, SUPPORTED_WITH_MASK);
        if (r < 0)
                return r;

        r = ca_sync_set_punch_holes(s, arg_punch_holes);
        if (r < 0)
                return log_error_errno(r, "Failed to configure hole punching: %m");

        r = ca_sync_set_reflink(s, arg_reflink);
        if (r < 0)
                return log_error_errno(r, "Failed to configure reflinking: %m");

        r = ca_sync_set_hardlink(s, arg_hardlink);
        if (r < 0)
                return log_error_errno(r, "Failed to configure hardlinking: %m");

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to %s: %m", seek_path);
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        log_error("Got exit signal, quitting.");
                        return -ESHUTDOWN;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM)
                        return log_error_errno(r, "File, URL or resource not found.");
                if (r < 0)
                        return log_error_errno(r, "Failed to run synchronizer: %m");

                switch (r) {

                case CA_SYNC_FINISHED:
                        verbose_print_done_extract(s);
                        return 0;

                case CA_SYNC_NEXT_FILE:
                        r = verbose_print_path(s, "Extracting");
                        if (r < 0)
                                return r;
                        break;

                case CA_SYNC_DONE_FILE:
                        r = verbose_print_path(s, "Extracted");
                        if (r < 0)
                                return r;
                        break;

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_POLL:
                case CA_SYNC_FOUND:
                case CA_SYNC_NOT_FOUND:
                        r = process_step_generic(s, r, false);
                        if (r < 0)
                                return r;
                        break;

                default:
                        assert(false);
                }

                verbose_print_feature_flags(s);

                if (arg_verbose)
                        progress();
        }

        return r;
}

static int mtree_escape_full(const char *p, size_t l, char **ret) {
        const char *a;
        char *n, *b;

        assert(p);
        assert(ret);

        if (l == (size_t) -1)
                l = strlen(p);

        n = new(char, l*4+1);
        if (!n)
                return -ENOMEM;

        for (a = p, b = n; a < p + l; a++) {

                if ((uint8_t) *a <= (uint8_t) ' ' ||
                    (uint8_t) *a >= 127U ||
                    IN_SET(*a, '\\', '#')) {

                        *(b++) = '\\';
                        *(b++) = octchar((uint8_t) *a / 64U);
                        *(b++) = octchar(((uint8_t) *a / 8U) % 8U);
                        *(b++) = octchar((uint8_t) *a % 8U);
                } else
                        *(b++) = *a;
        }

        *b = 0;
        *ret = n;

        return 0;
}

static int mtree_escape(const char *p, char **ret) {
        return mtree_escape_full(p, (size_t) -1, ret);
}

static const char *empty_to_dot(const char *p) {
        /* Internally, we encode the top-level archived path as "", let's output it as "." since empty strings are hard
         * to handle for users. */

        return isempty(p) ? "." : p;
}

static int list_one_file(const char *arg0, CaSync *s, bool *toplevel_shown) {
        _cleanup_free_ char *path = NULL, *escaped = NULL;
        mode_t mode;
        int r;

        r = ca_sync_current_mode(s, &mode);
        if (r < 0)
                return log_error_errno(r, "Failed to query current mode: %m");

        r = ca_sync_current_path(s, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to query current path: %m");

        r = mtree_escape(path, &escaped);
        if (r < 0)
                return log_oom();

        if (streq(arg0, "list")) {
                char ls_mode[LS_FORMAT_MODE_MAX];

                printf("%s %s\n", ls_format_mode(mode, ls_mode), empty_to_dot(escaped));

                if (!arg_recursive && *toplevel_shown) {
                        r = ca_sync_seek_next_sibling(s);
                        if (r < 0)
                                return log_error_errno(r, "Failed to seek to next sibling: %m");
                }

                *toplevel_shown = true;

        } else if (streq(arg0, "mtree")) {

                const char *target = NULL, *user = NULL, *group = NULL;
                uint64_t mtime = UINT64_MAX, size = UINT64_MAX;
                uid_t uid = UID_INVALID;
                gid_t gid = GID_INVALID;
                dev_t rdev = (dev_t) -1;
                unsigned flags = (unsigned) -1;
                uint32_t fat_attrs = (uint32_t) -1;
                uint64_t features;
                size_t i;

                r = ca_sync_get_feature_flags(s, &features);
                if (r < 0)
                        return log_error_errno(r, "Failed to read feature flags: %m");

                (void) ca_sync_current_target(s, &target);
                (void) ca_sync_current_mtime(s, &mtime);
                (void) ca_sync_current_size(s, &size);
                (void) ca_sync_current_uid(s, &uid);
                (void) ca_sync_current_gid(s, &gid);
                (void) ca_sync_current_user(s, &user);
                (void) ca_sync_current_group(s, &group);
                (void) ca_sync_current_rdev(s, &rdev);
                (void) ca_sync_current_chattr(s, &flags);
                (void) ca_sync_current_fat_attrs(s, &fat_attrs);

                fputs(empty_to_dot(escaped), stdout);

                if (S_ISLNK(mode))
                        fputs(" type=link", stdout);
                else if (S_ISDIR(mode))
                        fputs(" type=dir", stdout);
                else if (S_ISREG(mode))
                        fputs(" type=file", stdout);
                else if (S_ISSOCK(mode))
                        fputs(" type=socket", stdout);
                else if (S_ISCHR(mode))
                        fputs(" type=char", stdout);
                else if (S_ISBLK(mode))
                        fputs(" type=block", stdout);
                else if (S_ISFIFO(mode))
                        fputs(" type=fifo", stdout);

                printf(" mode=%04o",  mode & 07777);

                if (size != UINT64_MAX)
                        printf(" size=%" PRIu64, size);

                if (target) {
                        escaped = mfree(escaped);

                        if (mtree_escape(target, &escaped) < 0)
                                return log_oom();

                        printf(" link=%s", escaped);
                }

                if (rdev != (dev_t) -1)
                        printf(" device=linux,%" PRIu32 ",%" PRIu32,
                               (uint32_t) major(rdev),
                               (uint32_t) minor(rdev));

                if (uid_is_valid(uid))
                        printf(" uid=" UID_FMT, uid);
                if (uid_is_valid(gid))
                        printf(" gid=" GID_FMT, gid);

                if (user) {
                        escaped = mfree(escaped);

                        if (mtree_escape(user, &escaped) < 0)
                                return log_oom();

                        printf(" uname=%s", escaped);
                }

                if (group) {
                        escaped = mfree(escaped);

                        if (mtree_escape(group, &escaped) < 0)
                                return log_oom();

                        printf(" gname=%s", escaped);
                }

                if (features & (CA_FORMAT_WITH_FLAG_HIDDEN|CA_FORMAT_WITH_FLAG_SYSTEM|CA_FORMAT_WITH_FLAG_ARCHIVE|
                                CA_FORMAT_WITH_FLAG_APPEND|CA_FORMAT_WITH_FLAG_NODUMP|CA_FORMAT_WITH_FLAG_IMMUTABLE)) {

                        static const struct {
                                uint64_t flag;
                                const char *name;
                        } table[] = {
                                { CA_FORMAT_WITH_FLAG_HIDDEN,    "hidden"     },
                                { CA_FORMAT_WITH_FLAG_SYSTEM,    "system"     },
                                { CA_FORMAT_WITH_FLAG_ARCHIVE,   "archive"    },
                                { CA_FORMAT_WITH_FLAG_APPEND,    "sappend"    },
                                { CA_FORMAT_WITH_FLAG_NODUMP,    "nodump"     },
                                { CA_FORMAT_WITH_FLAG_IMMUTABLE, "simmutable" },
                        };

                        const char *comma = "";

                        printf(" flags=");

                        for (i = 0; i < ELEMENTSOF(table); i++) {
                                bool b;

                                if ((features & table[i].flag) == 0)
                                        continue;

                                if (table[i].flag & CA_FORMAT_WITH_FAT_ATTRS)
                                        b = fat_attrs & ca_feature_flags_to_fat_attrs(table[i].flag);
                                else if (table[i].flag & CA_FORMAT_WITH_CHATTR)
                                        b = flags & ca_feature_flags_to_chattr(table[i].flag);
                                else
                                        assert_not_reached("Flag table bogus");

                                printf("%s%s%s", comma, b ? "" : "no", table[i].name);
                                comma = ",";
                        }
                }

                if (mtime != UINT64_MAX)
                        printf(" time=%" PRIu64 ".%09" PRIu64,
                               mtime / UINT64_C(1000000000),
                               mtime % UINT64_C(1000000000));

                if (!S_ISREG(mode))
                        /* End this in a newline — unless this is a regular file,
                         * in which case we'll print the payload checksum shortly */
                        putchar('\n');
        } else {
                const char *target = NULL, *user = NULL, *group = NULL;
                uint64_t mtime = UINT64_MAX, size = UINT64_MAX, offset = UINT64_MAX;
                char ls_mode[LS_FORMAT_MODE_MAX], ls_flags[LS_FORMAT_CHATTR_MAX], ls_fat_attrs[LS_FORMAT_FAT_ATTRS_MAX];
                uid_t uid = UID_INVALID;
                gid_t gid = GID_INVALID;
                uint32_t quota_projid;
                bool has_quota_projid;
                dev_t rdev = (dev_t) -1;
                unsigned flags = (unsigned) -1;
                uint32_t fat_attrs = (uint32_t) -1;
                const char *xname;
                const void *xvalue;
                size_t xsize;

                assert(streq(arg0, "stat"));

                (void) ca_sync_current_target(s, &target);
                (void) ca_sync_current_mtime(s, &mtime);
                (void) ca_sync_current_size(s, &size);
                (void) ca_sync_current_uid(s, &uid);
                (void) ca_sync_current_gid(s, &gid);
                (void) ca_sync_current_user(s, &user);
                (void) ca_sync_current_group(s, &group);
                (void) ca_sync_current_rdev(s, &rdev);
                (void) ca_sync_current_chattr(s, &flags);
                (void) ca_sync_current_fat_attrs(s, &fat_attrs);
                (void) ca_sync_current_archive_offset(s, &offset);

                has_quota_projid = ca_sync_current_quota_projid(s, &quota_projid) >= 0;

                printf("    File: %s\n"
                       "    Mode: %s\n",
                       empty_to_dot(escaped),
                       strna(ls_format_mode(mode, ls_mode)));

                if (flags != (unsigned) -1)
                        printf("FileAttr: %s\n", strna(ls_format_chattr(flags, ls_flags)));

                if (fat_attrs != (uint32_t) -1)
                        printf(" FATAttr: %s\n", strna(ls_format_fat_attrs(fat_attrs, ls_fat_attrs)));

                if (offset != UINT64_MAX)
                        printf("  Offset: %" PRIu64 "\n", offset);

                if (mtime != UINT64_MAX) {
                        char d[128];
                        time_t t;
                        struct tm tm;

                        t = (time_t) (mtime / UINT64_C(1000000000));
                        if (localtime_r(&t, &tm) &&
                            strftime(d, sizeof(d), "%Y-%m-%d %H:%M:%S", &tm) > 0)
                                printf("    Time: %s.%09" PRIu64"\n", d, mtime % UINT64_C(1000000000));
                }

                if (size != UINT64_MAX)
                        printf("    Size: %" PRIu64 "\n", size);

                if (uid_is_valid(uid) || user) {
                        printf("    User: ");

                        if (user) {
                                escaped = mfree(escaped);

                                if (mtree_escape(user, &escaped) < 0)
                                        return log_oom();
                        }

                        if (uid_is_valid(uid) && user)
                                printf("%s (" UID_FMT ")\n", escaped, uid);
                        else if (uid_is_valid(uid))
                                printf(UID_FMT "\n", uid);
                        else
                                printf("%s\n", escaped);
                }

                if (gid_is_valid(gid) || group) {
                        printf("   Group: ");

                        if (group) {
                                escaped = mfree(escaped);

                                if (mtree_escape(group, &escaped) < 0)
                                        return log_oom();
                        }

                        if (gid_is_valid(gid) && group)
                                printf("%s (" GID_FMT ")\n", escaped, gid);
                        else if (gid_is_valid(gid))
                                printf(GID_FMT "\n", gid);
                        else
                                printf("%s\n", escaped);
                }

                if (has_quota_projid)
                        printf("  ProjID: %" PRIu32 "\n", quota_projid);

                if (target) {
                        escaped = mfree(escaped);

                        if (mtree_escape(target, &escaped) < 0)
                                return log_oom();

                        printf("  Target: %s\n", escaped);
                }

                if (rdev != (dev_t) -1)
                        printf("  Device: %lu:%lu\n", (unsigned long) major(rdev), (unsigned long) minor(rdev));

                r = ca_sync_current_xattr(s, CA_ITERATE_FIRST, &xname, &xvalue, &xsize);
                for (;;) {
                        _cleanup_free_ char *n = NULL, *v = NULL;

                        if (r < 0)
                                return log_error_errno(r, "Failed to enumerate extended attributes: %m");
                        if (r == 0)
                                break;

                        if (mtree_escape(xname, &n) < 0)
                                return log_oom();

                        if (mtree_escape_full(xvalue, xsize, &v) < 0)
                                return log_oom();

                        printf("   XAttr: %s → %s\n", n, v);
                        r = ca_sync_current_xattr(s, CA_ITERATE_NEXT, &xname, &xvalue, &xsize);
                }

                if (S_ISDIR(mode))
                        /* If this is a directory, we are done now. Otherwise, continue
                         * so that we can show the payload and hardlink digests */
                        return 0;
        }

        return 1;
}

static int verb_list(int argc, char *argv[]) {

        typedef enum ListOperation {
                LIST_ARCHIVE,
                LIST_ARCHIVE_INDEX,
                LIST_DIRECTORY,
                _LIST_OPERATION_INVALID = -1
        } ListOperation;

        ListOperation operation = _LIST_OPERATION_INVALID;
        const char *seek_path = NULL;
        _cleanup_(safe_close_nonstdp) int input_fd = -1;
        _cleanup_free_ char *input = NULL;
        _cleanup_(ca_sync_unrefp) CaSync *s = NULL;
        bool toplevel_shown = false;
        int r;

        if (argc > 3) {
                log_error("Input path/URL and subtree path expected.");
                return -EINVAL;
        }

        if (argc > 1) {
                input = ca_strip_file_url(argv[1]);
                if (!input)
                        return log_oom();
        }

        if (argc > 2)
                seek_path = argv[2];

        if (arg_what == WHAT_ARCHIVE)
                operation = LIST_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = LIST_ARCHIVE_INDEX;
        else if (arg_what == WHAT_DIRECTORY)
                operation = LIST_DIRECTORY;
        else if (arg_what != _WHAT_INVALID) {
                log_error("\"%s\" operation may only be combined with --what=archive, archive-index, or directory.", argv[0]);
                return -EINVAL;
        }

        if (operation == _LIST_OPERATION_INVALID && input && !streq(input, "-")) {
                if (ca_locator_has_suffix(input, ".catar"))
                        operation = LIST_ARCHIVE;
                else if (ca_locator_has_suffix(input, ".caidx"))
                        operation = LIST_ARCHIVE_INDEX;
        }

        if (!input && IN_SET(operation, LIST_DIRECTORY, _LIST_OPERATION_INVALID)) {
                input = strdup(".");
                if (!input)
                        return log_oom();
        }

        if (!input || streq(input, "-")) {
                input_fd = STDIN_FILENO;
                input = NULL;
        } else {
                CaLocatorClass input_class = _CA_LOCATOR_CLASS_INVALID;

                input_class = ca_classify_locator(input);
                if (input_class < 0) {
                        log_error("Failed to determine type of locator: %s", input);
                        return -EINVAL;
                }

                if (operation == LIST_DIRECTORY && input_class != CA_LOCATOR_PATH) {
                        log_error("Input must be local path: %s", input);
                        return -EINVAL;
                }

                if (input_class == CA_LOCATOR_PATH) {
                        input_fd = open(input, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                        if (input_fd < 0)
                                return log_error_errno(errno, "Failed to open \"%s\": %m", input);
                }
        }

        if (input_fd >= 0) {
                struct stat st;

                if (fstat(input_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat input: %m");

                if (S_ISDIR(st.st_mode)) {
                        if (operation == _LIST_OPERATION_INVALID)
                                operation = LIST_DIRECTORY;
                        else if (operation != LIST_DIRECTORY) {
                                log_error("Input is a directory, but attempted to list archive or index.");
                                return -EINVAL;
                        }

                } else if (S_ISREG(st.st_mode)) {

                        if (operation == _LIST_OPERATION_INVALID) {

                                /* If the user specified an input file name to a regular file, and the suffix is
                                 * neither .catar nor .caidx then he probably expected us to treat the file as source
                                 * rather then encoded file. But we don't support this really: we only support
                                 * directories as input. Eventually we should probably do something smarter here, for
                                 * example implying as source the path's parent directory, and then seek to the file
                                 * passed. For now, let's prohibit this, so that all options are open. */

                                if (input) {
                                        log_error("Input should be a directory, .catar or .caidx file. Refusing.");
                                        return -EINVAL;
                                }

                                operation = LIST_ARCHIVE;

                        } else if (!IN_SET(operation, LIST_ARCHIVE, LIST_ARCHIVE_INDEX)) {
                                log_error("Input is a regular file, but attempted to list it as directory.");
                                return -EINVAL;
                        }
                } else {
                        log_error("Input is neither a file or directory. Refusing.");
                        return -EINVAL;
                }
        }

        if (operation == _LIST_OPERATION_INVALID) {
                log_error("Failed to determine what to list. Use --what=archive, archive-index, or directory.");
                return -EINVAL;
        }

        if (!IN_SET(operation, LIST_ARCHIVE, LIST_ARCHIVE_INDEX) && seek_path) {
                log_error("Subtree path only supported when listing archive or archive index.");
                return -EINVAL;
        }

        seek_path = normalize_seek_path(seek_path);

        if (operation == LIST_ARCHIVE_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        return r;
        }

        if (operation == LIST_DIRECTORY)
                s = ca_sync_new_encode();
        else
                s = ca_sync_new_decode();
        if (!s)
                return log_oom();

        r = load_chunk_size(s);
        if (r < 0)
                return r;

        if (operation == LIST_ARCHIVE) {
                if (input_fd >= 0)
                        r = ca_sync_set_archive_fd(s, input_fd);
                else
                        r = ca_sync_set_archive_auto(s, input);
        } else if (operation == LIST_ARCHIVE_INDEX) {
                if (input_fd >= 0)
                        r = ca_sync_set_index_fd(s, input_fd);
                else
                        r = ca_sync_set_index_auto(s, input);
        } else if (operation == LIST_DIRECTORY)
                r = ca_sync_set_base_fd(s, input_fd);
        else
                assert(false);
        if (r < 0)
                return log_error_errno(r, "Failed to set sync input: %m");
        input_fd = -1;

        if (operation != LIST_DIRECTORY) {
                r = ca_sync_set_base_mode(s, S_IFDIR);
                if (r < 0)
                        return log_error_errno(r, "Failed to set base mode to directory: %m");
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0)
                        return log_error_errno(r, "Failed to set store: %m");
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                return r;

        r = load_feature_flags(s, SUPPORTED_WITH_MASK);
        if (r < 0)
                return r;

        if (operation != LIST_DIRECTORY) {
                r = ca_sync_set_payload(s, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable skipping over payload: %m");
        }

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to %s: %m", seek_path);
        }

        if (STR_IN_SET(argv[0], "mtree", "stat")) {
                r = ca_sync_enable_payload_digest(s, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable payload digest: %m");
        }

        if (streq(argv[0], "stat")) {
                r = ca_sync_enable_hardlink_digest(s, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable hardlink digest: %m");
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        log_info("Got exit signal, quitting.");
                        return -ESHUTDOWN;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM)
                        return log_error_errno(r, "File, URL or resource not found.");
                if (r < 0)
                        return log_error_errno(r, "Failed to run synchronizer: %m");

                switch (r) {

                case CA_SYNC_FINISHED:
                        return 0;

                case CA_SYNC_NEXT_FILE: {
                        r = list_one_file(argv[0], s, &toplevel_shown);
                        if (r <= 0)
                                return r;
                        break;
                }

                case CA_SYNC_DONE_FILE: {
                        mode_t mode;

                        r = ca_sync_current_mode(s, &mode);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query current mode: %m");

                        if (streq(argv[0], "mtree") && S_ISREG(mode)) {
                                static const char * const table[_CA_DIGEST_TYPE_MAX] = {
                                        [CA_DIGEST_SHA256] = "sha256digest",
                                        [CA_DIGEST_SHA512_256] = "sha512256digest",
                                };

                                CaChunkID digest;
                                char v[CA_CHUNK_ID_FORMAT_MAX];

                                r = ca_sync_get_payload_digest(s, &digest);
                                if (r < 0) {
                                        log_error("Failed to read digest.");
                                        return -EINVAL;
                                }

                                printf(" %s=%s\n", table[arg_digest], ca_chunk_id_format(&digest, v));

                        } else if (streq(argv[0], "stat") && !S_ISDIR(mode)) {
                                CaChunkID payload_digest, hardlink_digest;
                                char v[CA_CHUNK_ID_FORMAT_MAX];

                                r = ca_sync_get_payload_digest(s, &payload_digest);
                                if (r >= 0)
                                        printf("  Digest: %s\n", ca_chunk_id_format(&payload_digest, v));

                                r = ca_sync_get_hardlink_digest(s, &hardlink_digest);
                                if (r >= 0)
                                        printf("HLDigest: %s\n", ca_chunk_id_format(&hardlink_digest, v));

                                return 0;
                        }

                        break;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_POLL:
                case CA_SYNC_FOUND:
                case CA_SYNC_NOT_FOUND:

                        r = process_step_generic(s, r, false);
                        if (r < 0)
                                return r;

                        break;

                default:
                        assert(false);
                }

                verbose_print_feature_flags(s);

                if (arg_verbose)
                        progress();
        }

        return r;
}

static int verb_digest(int argc, char *argv[]) {

        typedef enum DigestOperation {
                DIGEST_ARCHIVE,
                DIGEST_ARCHIVE_INDEX,
                DIGEST_BLOB,
                DIGEST_BLOB_INDEX,
                DIGEST_DIRECTORY,
                _DIGEST_OPERATION_INVALID = -1,
        } DigestOperation;

        DigestOperation operation = _DIGEST_OPERATION_INVALID;
        bool set_base_mode = false;
        const char *seek_path = NULL;
        int r;
        _cleanup_(safe_close_nonstdp) int input_fd = -1;
        _cleanup_free_ char *input = NULL;
        _cleanup_(ca_sync_unrefp) CaSync *s = NULL;
        bool show_payload_digest = false;
        int seeking = false;

        if (argc > 3) {
                log_error("Input path/URL and subtree path expected.");
                return -EINVAL;
        }

        if (argc > 1) {
                input = ca_strip_file_url(argv[1]);
                if (!input)
                        return log_oom();
        }

        if (argc > 2)
                seek_path = argv[2];

        if (arg_what == WHAT_ARCHIVE)
                operation = DIGEST_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = DIGEST_ARCHIVE_INDEX;
        else if (arg_what == WHAT_BLOB)
                operation = DIGEST_BLOB;
        else if (arg_what == WHAT_BLOB_INDEX)
                operation = DIGEST_BLOB_INDEX;
        else if (arg_what == WHAT_DIRECTORY)
                operation = DIGEST_DIRECTORY;
        else if (arg_what != _WHAT_INVALID) {
                log_error("\"make\" operation may only be combined with --what=archive, --what=blob, --what=archive-index, --what=blob-index or --what=directory.");
                return -EINVAL;
        }

        if (operation == _DIGEST_OPERATION_INVALID && input && !streq(input, "-")) {

                if (ca_locator_has_suffix(input, ".catar"))
                        operation = DIGEST_ARCHIVE;
                else if (ca_locator_has_suffix(input, ".caidx"))
                        operation = DIGEST_ARCHIVE_INDEX;
                else if (ca_locator_has_suffix(input, ".caibx"))
                        operation = DIGEST_BLOB_INDEX;
        }

        if (!input && IN_SET(operation, DIGEST_DIRECTORY, _DIGEST_OPERATION_INVALID)) {
                input = strdup(".");
                if (!input)
                        return log_oom();
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
                CaLocatorClass input_class;

                input_class = ca_classify_locator(input);
                if (input_class < 0) {
                        log_error("Failed to determine class of locator: %s", input);
                        return -EINVAL;
                }

                if (operation == DIGEST_DIRECTORY && input_class != CA_LOCATOR_PATH) {
                        log_error("Input must be local path: %s", input);
                        return -EINVAL;
                }

                if (input_class == CA_LOCATOR_PATH) {
                        input_fd = open(input, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                        if (input_fd < 0)
                                return log_error_errno(errno, "Failed to open %s: %m", input);
                }
        }

        if (input_fd >= 0) {
                struct stat st;

                if (fstat(input_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat input: %m");

                if (S_ISDIR(st.st_mode)) {

                        if (operation == _DIGEST_OPERATION_INVALID)
                                operation = DIGEST_DIRECTORY;
                        else if (operation != DIGEST_DIRECTORY) {
                                log_error("Input is a directory, but attempted to list as blob. Refusing.");
                                return -EINVAL;
                        }

                } else if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode)) {

                        if (operation == _DIGEST_OPERATION_INVALID)
                                operation = seek_path ? DIGEST_ARCHIVE : DIGEST_BLOB;
                        else if (!IN_SET(operation, DIGEST_ARCHIVE, DIGEST_BLOB, DIGEST_ARCHIVE_INDEX, DIGEST_BLOB_INDEX)) {
                                log_error("Input is not a regular file or block device, but attempted to list as one. Refusing.");
                                return -EINVAL;
                        }
                } else {
                        log_error("Input is a neither a directory, a regular file, nor a block device. Refusing.");
                        return -EINVAL;
                }
        }

        if (streq_ptr(input, "-"))
                input = mfree(input);

        if (operation == _DIGEST_OPERATION_INVALID) {
                log_error("Failed to determine what to calculate digest of. Use --what=archive, --what=blob, --what=archive-index, --what=blob-index or --what=directory.");
                return -EINVAL;
        }

        if (!IN_SET(operation, DIGEST_ARCHIVE, DIGEST_ARCHIVE_INDEX) && seek_path) {
                log_error("Subtree path only supported when calculating message digest of archive or archive index.");
                return -EINVAL;
        }

        seek_path = normalize_seek_path(seek_path);

        if (IN_SET(operation, DIGEST_ARCHIVE_INDEX, DIGEST_BLOB_INDEX)) {
                r = set_default_store(input);
                if (r < 0)
                        return r;
        }

        if (operation == DIGEST_DIRECTORY || (operation == DIGEST_BLOB && input_fd >= 0))
                s = ca_sync_new_encode();
        else
                s = ca_sync_new_decode();
        if (!s)
                return log_oom();

        r = load_chunk_size(s);
        if (r < 0)
                return r;

        if (operation == DIGEST_DIRECTORY || (operation == DIGEST_BLOB && input_fd >= 0))
                r = ca_sync_set_base_fd(s, input_fd);
        else if (IN_SET(operation, DIGEST_ARCHIVE_INDEX, DIGEST_BLOB_INDEX)) {
                if (input_fd >= 0)
                        r = ca_sync_set_index_fd(s, input_fd);
                else
                        r = ca_sync_set_index_auto(s, input);

                set_base_mode = true;
        } else {
                assert(IN_SET(operation, DIGEST_BLOB, DIGEST_ARCHIVE));

                set_base_mode = true;

                r = ca_sync_set_archive_auto(s, input);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to set sync input: %s", strerror(-r));
        input_fd = -1;

        if (set_base_mode) {
                r = ca_sync_set_base_mode(s, IN_SET(operation, DIGEST_ARCHIVE, DIGEST_ARCHIVE_INDEX) ? S_IFDIR : S_IFREG);
                if (r < 0)
                        return log_error_errno(r, "Failed to set base mode to regular file: %m");
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0)
                        return log_error_errno(r, "Failed to set store: %m");
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                return r;

        r = load_feature_flags(s, IN_SET(operation, DIGEST_BLOB, DIGEST_BLOB_INDEX) ? 0 : SUPPORTED_WITH_MASK);
        if (r < 0)
                return r;

        r = ca_sync_enable_archive_digest(s, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable archive digest: %m");

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to %s: %m", seek_path);

                seeking = true;
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        log_error("Got exit signal, quitting.");
                        return -ESHUTDOWN;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM)
                        return log_error_errno(r, "File, URL or resource not found.");
                if (r < 0)
                        return log_error_errno(r, "Failed to run synchronizer: %m");

                switch (r) {

                case CA_SYNC_FINISHED:

                        if (!show_payload_digest) { /* When we calc the digest of a directory tree (or top-level blob), show the archive digest */
                                CaChunkID digest;
                                char t[CA_CHUNK_ID_FORMAT_MAX];

                                r = ca_sync_get_archive_digest(s, &digest);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to get archive digest: %m");

                                printf("%s\n", ca_chunk_id_format(&digest, t));
                                return 0;
                        }

                        break;

                case CA_SYNC_NEXT_FILE:

                        if (seeking) {
                                mode_t mode;

                                /* If we are seeking to a specific path in our archive, then check here if it is a regular file
                                 * (in which case we show the payload checksum) or a directory (in which case we show the
                                 * archive checksum from here. If it is neither, we return failure. */

                                r = ca_sync_current_mode(s, &mode);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to get current mode: %m");

                                if (S_ISREG(mode)) {
                                        show_payload_digest = true;

                                        r = ca_sync_enable_payload_digest(s, true);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to enable payload digest: %m");

                                } else if (S_ISDIR(mode))
                                        show_payload_digest = false;
                                else {
                                        log_error("Path %s does not refer to a file or directory: %m", seek_path);
                                        return -ENOTTY;
                                }

                                seeking = false;
                        }

                        r = process_step_generic(s, r, false);
                        if (r < 0)
                                return r;

                        break;

                case CA_SYNC_DONE_FILE:

                        if (show_payload_digest) { /* When we calc the digest of a file, show the payload digest */
                                CaChunkID digest;
                                char t[CA_CHUNK_ID_FORMAT_MAX];

                                r = ca_sync_get_payload_digest(s, &digest);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to get payload digest: %m");

                                printf("%s\n", ca_chunk_id_format(&digest, t));
                                return 0;
                        }

                        /* fall through */

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_POLL:
                case CA_SYNC_FOUND:
                case CA_SYNC_NOT_FOUND:
                        r = process_step_generic(s, r, false);
                        if (r < 0)
                                return r;
                        break;

                default:
                        assert(false);
                }

                verbose_print_feature_flags(s);

                if (arg_verbose)
                        progress();
        }

        return r;
}

static int verb_mount(int argc, char *argv[]) {
#if HAVE_FUSE
        typedef enum MountOperation {
                MOUNT_ARCHIVE,
                MOUNT_ARCHIVE_INDEX,
                _MOUNT_OPERATION_INVALID = -1,
        } MountOperation;
        MountOperation operation = _MOUNT_OPERATION_INVALID;
        const char *mount_path = NULL;
        int r;
        _cleanup_(safe_close_nonstdp) int input_fd = -1;
        _cleanup_free_ char *input = NULL;
        _cleanup_(ca_sync_unrefp) CaSync *s = NULL;

        if (argc > 3 || argc < 2) {
                log_error("An archive path/URL expected, followed by a mount path.");
                return -EINVAL;
        }

        if (argc > 2) {
                input = ca_strip_file_url(argv[1]);
                if (!input)
                        return log_oom();

                mount_path = argv[2];
        } else
                mount_path = argv[1];

        if (arg_what == WHAT_ARCHIVE)
                operation = MOUNT_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = MOUNT_ARCHIVE_INDEX;
        else if (arg_what != _WHAT_INVALID) {
                log_error("\"mount\" operation may only be combined with --what=archive and --what=archive-index.");
                return -EINVAL;
        }

        if (operation == _MOUNT_OPERATION_INVALID && input && !streq(input, "-")) {
                if (ca_locator_has_suffix(input, ".caidx"))
                        operation = MOUNT_ARCHIVE_INDEX;
        }

        if (operation == _MOUNT_OPERATION_INVALID)
                operation = MOUNT_ARCHIVE;

        s = ca_sync_new_decode();
        if (!s)
                return log_oom();

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;

        if (operation == MOUNT_ARCHIVE_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        return r;
        }

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_sync_set_rate_limit_bps(s, arg_rate_limit_bps);
                if (r < 0)
                        return log_error_errno(r, "Failed to set rate limit: %m");
        }

        if (operation == MOUNT_ARCHIVE) {
                if (input_fd >= 0)
                        r = ca_sync_set_archive_fd(s, input_fd);
                else
                        r = ca_sync_set_archive_auto(s, input);

        } else if (operation == MOUNT_ARCHIVE_INDEX) {
                if (input_fd >= 0)
                        r = ca_sync_set_index_fd(s, input_fd);
                else
                        r = ca_sync_set_index_auto(s, input);
        } else
                assert(false);
        if (r < 0)
                return log_error_errno(r, "Failed to set sync input: %m");

        input_fd = -1;

        r = ca_sync_set_base_mode(s, S_IFDIR);
        if (r < 0)
                return log_error_errno(r, "Failed to set base mode to directory: %m");

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0)
                        return log_error_errno(r, "Failed to set store: %m");
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                return r;

        return ca_fuse_run(s, input, mount_path, arg_mkdir);
#else
        log_error("Compiled without support for fuse.");
        return -ENOSYS;
#endif
}

static int verb_mkdev(int argc, char *argv[]) {

        typedef enum MkDevOperation {
                MKDEV_BLOB,
                MKDEV_BLOB_INDEX,
                _MKDEV_OPERATION_INVALID = -1,
        } MkDevOperation;

        MkDevOperation operation = _MKDEV_OPERATION_INVALID;
        _cleanup_(ca_block_device_unrefp) CaBlockDevice *nbd = NULL;
        _cleanup_(realloc_buffer_free) ReallocBuffer buffer = {};
        _cleanup_(safe_close_nonstdp) int input_fd = -1;
        bool make_symlink = false, rm_symlink = false;
        _cleanup_(ca_sync_unrefp) CaSync *s = NULL;
        const char *path = NULL, *name = NULL;
        _cleanup_free_ char *input = NULL;
        bool initialized, sent_ready = false;
        dev_t devnum;
        int r;

#if HAVE_UDEV
        _cleanup_(udev_monitor_unrefp) struct udev_monitor *monitor = NULL;
        _cleanup_(udev_device_unrefp) struct udev_device *d = NULL;
        _cleanup_(udev_unrefp) struct udev *udev = NULL;
#endif

        if (argc > 3) {
                log_error("An blob path/URL expected, possibly followed by a device or symlink name.");
                return -EINVAL;
        }

        if (argc > 1) {
                input = ca_strip_file_url(argv[1]);
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (argc > 2)
                name = argv[2];

        if (arg_what == WHAT_BLOB)
                operation = MKDEV_BLOB;
        else if (arg_what == WHAT_BLOB_INDEX)
                operation = MKDEV_BLOB_INDEX;
        else if (arg_what != _WHAT_INVALID) {
                log_error("\"mkdev\" operation may only be combined with --what=blob and --what=blob-index.");
                r = -EINVAL;
                goto finish;
        }

        if (operation == _MKDEV_OPERATION_INVALID && input && !streq(input, "-")) {
                if (ca_locator_has_suffix(input, ".caibx"))
                        operation = MKDEV_BLOB_INDEX;
        }

        if (operation == _MKDEV_OPERATION_INVALID)
                operation = MKDEV_BLOB;

        s = ca_sync_new_decode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;

        if (operation == MKDEV_BLOB_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        goto finish;
        }

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_sync_set_rate_limit_bps(s, arg_rate_limit_bps);
                if (r < 0)
                        return log_error_errno(r, "Failed to set rate limit: %m");
        }

        if (operation == MKDEV_BLOB) {
                if (input_fd >= 0)
                        r = ca_sync_set_archive_fd(s, input_fd);
                else
                        r = ca_sync_set_archive_auto(s, input);

        } else if (operation == MKDEV_BLOB_INDEX) {
                if (input_fd >= 0)
                        r = ca_sync_set_index_fd(s, input_fd);
                else
                        r = ca_sync_set_index_auto(s, input);
        } else
                assert(false);
        if (r < 0) {
                log_error_errno(r, "Failed to set sync input: %m");
                goto finish;
        }

        input_fd = -1;

        r = ca_sync_set_base_mode(s, S_IFREG);
        if (r < 0) {
                log_error_errno(r, "Failed to set base mode to regular file: %m");
                goto finish;
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0) {
                        log_error_errno(r, "Failed to set store: %m");
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                goto finish;

        nbd = ca_block_device_new();
        if (!nbd) {
                r = log_oom();
                goto finish;
        }

        if (name) {
                r = ca_block_device_test_nbd(name);
                if (r < 0) {
                        log_error_errno(r, "Failed to test whether %s is an nbd device: %m", name);
                        goto finish;
                } else if (r > 0) {
                        r = ca_block_device_set_path(nbd, name);
                        if (r < 0) {
                                log_error_errno(r, "Failed to set device path to %s: %m", name);
                                goto finish;
                        }
                } else {
                        const char *k;

                        k = path_startswith(name, "/dev");
                        if (k) {
                                r = ca_block_device_set_friendly_name(nbd, k);
                                if (r < 0) {
                                        log_error("Failed to set friendly name to %s: %m", k);
                                        goto finish;
                                }
                        } else
                                make_symlink = true;
                }
        }

        /* First loop: process as enough so that we can figure out the size of the blob */
        for (;;) {
                uint64_t size;

                if (quit) {
                        r = 0;
                        goto finish;
                }

                r = ca_sync_get_archive_size(s, &size);
                if (r >= 0) {
                        r = ca_block_device_set_size(nbd, (size + 511) & ~511);
                        if (r < 0) {
                                log_error_errno(r, "Failed to set NBD size: %m");
                                goto finish;
                        }
                        break;
                }
                if (r == -ESPIPE) {
                        log_error_errno(r, "Seekable archive required.");
                        goto finish;
                }
                if (r != -EAGAIN) {
                        log_error_errno(r, "Failed to determine archive size: %m");
                        goto finish;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM) {
                        log_error_errno(r, "File, URL or resource not found.");
                        goto finish;
                }
                if (r < 0) {
                        log_error_errno(r, "Failed to run synchronizer: %m");
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED:
                        log_error("Premature end of archive.");
                        r = -EBADMSG;
                        goto finish;

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_SEED_NEXT_FILE:
                case CA_SYNC_SEED_DONE_FILE:
                case CA_SYNC_POLL:
                        r = process_step_generic(s, r, true);
                        if (r < 0)
                                goto finish;
                        break;

                default:
                        assert(false);
                }
        }

        r = ca_block_device_open(nbd);
        if (r < 0) {
                log_error_errno(r, "Failed to open NBD device: %m");
                goto finish;
        }

        r = ca_block_device_get_path(nbd, &path);
        if (r < 0) {
                log_error_errno(r, "Failed to determine NBD device path: %m");
                goto finish;
        }

        r = ca_block_device_get_devnum(nbd, &devnum);
        if (r < 0) {
                log_error_errno(r, "Failed to get device ID: %m");
                goto finish;
        }

#if HAVE_UDEV
        udev = udev_new();
        if (!udev) {
                r = log_error_errno(errno, "Failed to allocate udev context: %m");
                goto finish;
        }

        monitor = udev_monitor_new_from_netlink(udev, "udev");
        if (!monitor) {
                r = log_error_errno(errno, "Failed to acquire udev monitor: %m");
                goto finish;
        }

        r = udev_monitor_filter_add_match_subsystem_devtype(monitor, "block", NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to add udev match: %m");
                goto finish;
        }

        r = udev_monitor_enable_receiving(monitor);
        if (r < 0) {
                log_error_errno(r, "Failed to start udev monitor: %m");
                goto finish;
        }

        d = udev_device_new_from_devnum(udev, 'b', devnum);
        if (!d) {
                r = log_error_errno(errno, "Failed to get NBD udev device: %m");
                goto finish;
        }

        initialized = udev_device_get_is_initialized(d) != 0;
        d = udev_device_unref(d);
#else
        initialized = true;
#endif

        if (make_symlink) {
                if (symlink(path, name) < 0) {
                        r = log_error_errno(errno, "Failed to create symlink %s → %s: %m", name, path);
                        goto finish;
                }

                rm_symlink = true;
        }

        printf("Attached: %s\n", name ?: path);

        for (;;) {
                uint64_t req_offset = 0, req_size = 0;

                if (quit) {
                        r = 0; /* for the "mkdev" verb quitting does not indicate an incomplete operation, hence return success */
                        goto finish;
                }

#if HAVE_UDEV
                if (!initialized) {
                        _cleanup_(udev_device_unrefp) struct udev_device *t = NULL;

                        t = udev_monitor_receive_device(monitor);
                        if (t && udev_device_get_devnum(t) == devnum)
                                initialized = true;
                }
#endif

                if (initialized && !sent_ready) {
                        _cleanup_free_ char *t = NULL;

#if HAVE_UDEV
                        monitor = udev_monitor_unref(monitor);
                        udev = udev_unref(udev);
#endif

                        t = strjoin("READY=1\n"
                                    "DEVICE=", path, "\n");
                        if (!t) {
                                r = log_oom();
                                goto finish;
                        }

                        (void) send_notify(t);
                        sent_ready = true;
                }

                r = ca_block_device_step(nbd);
                if (r < 0) {
                        log_error_errno(r, "Failed to read NBD request: %m");
                        goto finish;
                }

                if (r == CA_BLOCK_DEVICE_CLOSED)
                        break;

                if (r == CA_BLOCK_DEVICE_POLL) {
                        sigset_t ss;
                        int nbd_poll_fd, udev_fd;

                        nbd_poll_fd = ca_block_device_get_poll_fd(nbd);
                        if (nbd_poll_fd < 0) {
                                r = log_error_errno(nbd_poll_fd, "Failed to acquire NBD poll file descriptor: %m");
                                goto finish;
                        }


#if HAVE_UDEV
                        if (monitor) {
                                udev_fd = udev_monitor_get_fd(monitor);
                                if (udev_fd < 0) {
                                        r = log_error_errno(udev_fd, "Failed to acquire udev monitor fd: %m");
                                        goto finish;
                                }
                        } else
#endif
                                udev_fd = -1;

                        block_exit_handler(SIG_BLOCK, &ss);

                        if (quit)
                                r = -ESHUTDOWN;
                        else {
                                struct pollfd p[2] = {
                                        [0] = { .fd = nbd_poll_fd, .events = POLLIN },
                                        [1] = { .fd = udev_fd, .events = POLLIN },
                                };

                                r = ppoll(p, udev_fd < 0 ? 1 : 2, NULL, &ss);
                                if ((r >= 0 || errno == EINTR) && quit)
                                        r = -ESHUTDOWN;
                                else if (r < 0)
                                        r = -errno;
                                else
                                        r = 0;
                        }

                        block_exit_handler(SIG_UNBLOCK, NULL);

                        if (r == -ESHUTDOWN) {
                                r = 0;
                                goto finish;
                        } else if (r < 0) {
                                log_error_errno(r, "Failed to poll for NBD requests: %m");
                                goto finish;
                        }

                        continue;
                }

                assert(r == CA_BLOCK_DEVICE_REQUEST);

                r = ca_block_device_get_request_offset(nbd, &req_offset);
                if (r < 0) {
                        log_error_errno(r, "Failed to get NBD request offset: %m");
                        goto finish;
                }

                r = ca_block_device_get_request_size(nbd, &req_size);
                if (r < 0) {
                        log_error_errno(r, "Failed to get NBD request size: %m");
                        goto finish;
                }

                r = ca_sync_seek_offset(s, req_offset);
                if (r < 0) {
                        log_error_errno(r, "Failed to seek: %m");
                        goto finish;
                }

                realloc_buffer_empty(&buffer);

                for (;;) {
                        bool done = false;

                        if (quit) {
                                r = 0;
                                goto finish;
                        }

                        r = ca_sync_step(s);
                        if (r == -ENOMEDIUM) {
                                log_error_errno(r, "File, URL or resource not found.");
                                goto finish;
                        }
                        if (r < 0) {
                                log_error_errno(r, "Failed to run synchronizer: %m");
                                goto finish;
                        }

                        switch (r) {

                        case CA_SYNC_FINISHED:
                                /* We hit EOF but the reply is not yet completed, in this case, fill up with zeroes */

                                assert(realloc_buffer_size(&buffer) < req_size);

                                if (!realloc_buffer_extend0(&buffer, req_size - realloc_buffer_size(&buffer))) {
                                        r = log_oom();
                                        goto finish;
                                }

                                r = ca_block_device_put_data(nbd, req_offset, realloc_buffer_data(&buffer), req_size);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to send reply: %m");
                                        goto finish;
                                }

                                r = realloc_buffer_advance(&buffer, req_size);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to advance buffer: %m");
                                        goto finish;
                                }

                                done = true;
                                break;

                        case CA_SYNC_PAYLOAD: {
                                const void *p;
                                size_t sz;

                                r = ca_sync_get_payload(s, &p, &sz);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to retrieve synchronizer payload: %m");
                                        goto finish;
                                }

                                if (realloc_buffer_size(&buffer) == 0 && sz >= req_size) {
                                        /* If this is a full reply, then propagate this directly */

                                        r = ca_block_device_put_data(nbd, req_offset, p, MIN(sz, req_size));
                                        if (r < 0) {
                                                log_error_errno(r, "Failed to send reply: %m");
                                                goto finish;
                                        }

                                        done = true;

                                } else {

                                        if (!realloc_buffer_append(&buffer, p, sz)) {
                                                r = log_oom();
                                                goto finish;
                                        }

                                        if (realloc_buffer_size(&buffer) >= req_size) {
                                                r = ca_block_device_put_data(nbd, req_offset, realloc_buffer_data(&buffer), req_size);
                                                if (r < 0) {
                                                        log_error_errno(r, "Failed to send reply: %m");
                                                        goto finish;
                                                }

                                                r = realloc_buffer_advance(&buffer, req_size);
                                                if (r < 0) {
                                                        log_error_errno(r, "Failed to advance buffer: %m");
                                                        goto finish;
                                                }

                                                done = true;
                                        }
                                }

                                break;
                        }

                        case CA_SYNC_STEP:
                        case CA_SYNC_SEED_NEXT_FILE:
                        case CA_SYNC_SEED_DONE_FILE:
                        case CA_SYNC_POLL:
                        case CA_SYNC_FOUND:
                        case CA_SYNC_NOT_FOUND:
                                r = process_step_generic(s, r, true);
                                if (r == -ESHUTDOWN) {
                                        r = 0;
                                        goto finish;
                                }
                                if (r < 0)
                                        goto finish;

                                break;

                        default:
                                assert(false);
                        }

                        if (done)
                                break;
                }
        }

finish:
        if (rm_symlink)
                (void) unlink(name);

        return r;
}

static void free_stores(CaStore **stores, size_t n_stores) {
        size_t i;

        assert(stores || n_stores == 0);

        for (i = 0; i < n_stores; i++)
                ca_store_unref(stores[i]);
        free(stores);
}

typedef struct {
        CaStore **stores;
        size_t n_stores;
} CaStoresCleanup;

static void free_storesp(CaStoresCleanup *stores_cleanup) {
        free_stores(stores_cleanup->stores, stores_cleanup->n_stores);
}

static int allocate_stores(
                const char *wstore_path,
                char **rstore_paths,
                size_t n_rstores,
                CaStore ***ret,
                size_t *ret_n) {

        _cleanup_(free_storesp) CaStoresCleanup stores = {};
        size_t n = 0;
        char **rstore_path;
        int r;

        assert(ret);
        assert(ret_n);

        stores.n_stores = !!wstore_path + n_rstores;

        if (stores.n_stores > 0) {
                stores.stores = new0(CaStore*, stores.n_stores);
                if (!stores.stores)
                        return log_oom();
        }

        if (wstore_path) {
                stores.stores[n] = ca_store_new();
                if (!stores.stores[n])
                        return log_oom();
                n++;

                r = ca_store_set_path(stores.stores[n-1], wstore_path);
                if (r < 0)
                        return log_error_errno(r, "Unable to set store path %s: %m", wstore_path);
        }

        STRV_FOREACH(rstore_path, rstore_paths) {
                stores.stores[n] = ca_store_new();
                if (!stores.stores[n])
                        return log_oom();
                n++;

                r = ca_store_set_path(stores.stores[n-1], *rstore_path);
                if (r < 0)
                        return log_error_errno(r, "Unable to set store path %s: %m", *rstore_path);
        }

        *ret = stores.stores;
        *ret_n = n;
        stores = (CaStoresCleanup) {}; /* prevent freeing */

        return 0;
}

static int verb_pull(int argc, char *argv[]) {
        const char *base_path, *archive_path, *index_path, *wstore_path;
        size_t i;
        _cleanup_(free_storesp) CaStoresCleanup stores = {};
        _cleanup_(ca_remote_unrefp) CaRemote *rr = NULL;
        int r;

        if (argc < 5) {
                log_error("Expected at least 5 arguments.");
                return -EINVAL;
        }

        base_path = empty_or_dash_to_null(argv[1]);
        archive_path = empty_or_dash_to_null(argv[2]);
        index_path = empty_or_dash_to_null(argv[3]);
        wstore_path = empty_or_dash_to_null(argv[4]);

        stores.n_stores = !!wstore_path + (argc - 5);

        if (base_path) {
                log_error("Pull from base or archive not yet supported.");
                return -EOPNOTSUPP;
        }

        if (!archive_path && !index_path && stores.n_stores == 0) {
                log_error("Nothing to do.");
                return -EINVAL;
        }

        /* fprintf(stderr, "pull archive: %s index: %s wstore: %s\n", strna(archive_path), strna(index_path), strna(wstore_path)); */

        rr = ca_remote_new();
        if (!rr)
                return log_oom();

        r = ca_remote_set_local_feature_flags(rr,
                                              (stores.n_stores > 0 ? CA_PROTOCOL_READABLE_STORE : 0) |
                                              (index_path ? CA_PROTOCOL_READABLE_INDEX : 0) |
                                              (archive_path ? CA_PROTOCOL_READABLE_ARCHIVE : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to set feature flags: %m");

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_remote_set_rate_limit_bps(rr, arg_rate_limit_bps);
                if (r < 0)
                        return log_error_errno(r, "Failed to set rate limit: %m");
        }

        r = ca_remote_set_io_fds(rr, STDIN_FILENO, STDOUT_FILENO);
        if (r < 0)
                return log_error_errno(r, "Failed to set I/O file descriptors: %m");

        if (index_path) {
                r = ca_remote_set_index_path(rr, index_path);
                if (r < 0)
                        return log_error_errno(r, "Unable to set index file %s: %m", index_path);
        }

        if (archive_path) {
                r = ca_remote_set_archive_path(rr, archive_path);
                if (r < 0)
                        return log_error_errno(r, "Unable to set archive file %s: %m", archive_path);
        }

        r = allocate_stores(wstore_path, argv + 5, argc - 5, &stores.stores, &stores.n_stores);
        if (r < 0)
                return r;

        for (;;) {
                unsigned put_count;
                sigset_t ss;
                int step;

                if (quit) {
                        log_info("Got exit signal, quitting.");
                        return -ESHUTDOWN;
                }

                step = ca_remote_step(rr);
                if (step == -EPIPE || step == CA_REMOTE_FINISHED) /* When somebody pulls from us, he's welcome to terminate any time he likes */
                        break;
                if (step < 0)
                        return log_error_errno(step, "Failed to process remote: %m");

                put_count = 0;
                for (;;) {
                        CaChunkCompression compression;
                        bool found = false;
                        const void *p;
                        CaChunkID id;
                        uint64_t l;

                        r = ca_remote_can_put_chunk(rr);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether there's buffer space for sending: %m");
                        if (r == 0) /* No space to put more */
                                break;

                        r = ca_remote_next_request(rr, &id);
                        if (r == -ENODATA) /* No data requested */
                                break;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine which chunk to send next: %m");

                        for (i = 0; i < stores.n_stores; i++) {
                                r = ca_store_get(stores.stores[i], &id, CA_CHUNK_COMPRESSED, &p, &l, &compression);
                                if (r >= 0) {
                                        found = true;
                                        break;
                                }
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Failed to query store: %m");
                        }

                        if (found)
                                r = ca_remote_put_chunk(rr, &id, compression, p, l);
                        else
                                r = ca_remote_put_missing(rr, &id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to enqueue response: %m");

                        put_count ++;
                }

                if (put_count > 0) /* We enqueued more, let's do another step, maybe the remoter wants to write this mow */
                        continue;

                if (step != CA_REMOTE_POLL)
                        continue;

                block_exit_handler(SIG_BLOCK, &ss);

                if (quit)
                        r = -ESHUTDOWN;
                else {
                        r = ca_remote_poll(rr, UINT64_MAX, &ss);
                        if ((r == -EINTR || r >= 0) && quit)
                                r = -ESHUTDOWN;
                }

                block_exit_handler(SIG_UNBLOCK, NULL);

                if (r == -ESHUTDOWN)
                        return log_error_errno(r, "Got exit signal, quitting.");
                if (r < 0)
                        return log_error_errno(r, "Failed to poll remoting engine: %m");
        }

        return 0;
}

static int verb_push(int argc, char *argv[]) {

        const char *base_path, *archive_path, *index_path, *wstore_path;
        bool index_processed = false, index_written = false, archive_written = false;
        _cleanup_(ca_index_unrefp) CaIndex *index = NULL;
        _cleanup_(ca_remote_unrefp) CaRemote *rr = NULL;
        _cleanup_(free_storesp) CaStoresCleanup stores = {};
        int r;

        if (argc < 5) {
                log_error("Expected at least 5 arguments.");
                return -EINVAL;
        }

        base_path = empty_or_dash_to_null(argv[1]);
        archive_path = empty_or_dash_to_null(argv[2]);
        index_path = empty_or_dash_to_null(argv[3]);
        wstore_path = empty_or_dash_to_null(argv[4]);

        stores.n_stores = !!wstore_path + (argc - 5);

        if (base_path) {
                log_error("Push to base not yet supported.");
                return -EOPNOTSUPP;
        }

        if (!archive_path && !index_path && stores.n_stores == 0) {
                log_error("Nothing to do.");
                return -EINVAL;
        }

        /* log_error("push archive: %s index: %s wstore: %s", strna(archive_path), strna(index_path), strna(wstore_path)); */

        rr = ca_remote_new();
        if (!rr)
                return log_oom();

        r = ca_remote_set_local_feature_flags(rr,
                                              (wstore_path ? CA_PROTOCOL_WRITABLE_STORE : 0) |
                                              (index_path ? CA_PROTOCOL_WRITABLE_INDEX : 0) |
                                              (archive_path ? CA_PROTOCOL_WRITABLE_ARCHIVE : 0));
        if (r < 0)
                log_error_errno(r, "Failed to set feature flags: %m");

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_remote_set_rate_limit_bps(rr, arg_rate_limit_bps);
                if (r < 0)
                        log_error_errno(r, "Failed to set rate limit: %m");
        }

        r = ca_remote_set_io_fds(rr, STDIN_FILENO, STDOUT_FILENO);
        if (r < 0)
                log_error_errno(r, "Failed to set I/O file descriptors: %m");

        if (index_path) {
                index = ca_index_new_incremental_read();
                if (!index)
                        return log_oom();

                r = ca_index_set_path(index, index_path);
                if (r < 0)
                        return log_error_errno(r, "Unable to set index file %s: %m", index_path);

                r = ca_index_open(index);
                if (r < 0)
                        return log_error_errno(r, "Failed to open index file %s: %m", index_path);
        }

        if (archive_path) {
                r = ca_remote_set_archive_path(rr, archive_path);
                if (r < 0)
                        return log_error_errno(r, "Unable to set archive file %s: %m", archive_path);
        }

        r = allocate_stores(wstore_path, argv + 5, argc - 5, &stores.stores, &stores.n_stores);
        if (r < 0)
                return r;

        for (;;) {
                bool finished;
                int step;

                if (quit) {
                        log_error("Got exit signal, quitting.");
                        return -ESHUTDOWN;
                }

                step = ca_remote_step(rr);
                if (step < 0)
                        return log_error_errno(step, "Failed to process remote: %m");

                if (step == CA_REMOTE_FINISHED)
                        break;

                switch (step) {

                case CA_REMOTE_POLL: {
                        sigset_t ss;

                        block_exit_handler(SIG_BLOCK, &ss);

                        if (quit)
                                r = -ESHUTDOWN;
                        else {
                                r = ca_remote_poll(rr, UINT64_MAX, &ss);
                                if ((r == -EINTR || r >= 0) && quit)
                                        r = -ESHUTDOWN;
                        }

                        block_exit_handler(SIG_UNBLOCK, NULL);

                        if (r == -ESHUTDOWN)
                                return log_info_errno(r, "Got exit signal, quitting.");
                        if (r < 0)
                                return log_error_errno(r, "Failed to run remoting engine: %m");

                        break;
                }

                case CA_REMOTE_STEP:
                case CA_REMOTE_READ_ARCHIVE:
                        break;

                case CA_REMOTE_READ_ARCHIVE_EOF:
                        archive_written = true;
                        break;

                case CA_REMOTE_READ_INDEX: {
                        const void *p;
                        size_t n;

                        r = ca_remote_read_index(rr, &p, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read index data: %m");

                        r = ca_index_incremental_write(index, p, n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write index data: %m");

                        break;
                }

                case CA_REMOTE_READ_INDEX_EOF:
                        r = ca_index_incremental_eof(index);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write index EOF: %m");

                        index_written = true;
                        break;

                case CA_REMOTE_CHUNK: {
                        CaChunkCompression compression;
                        const void *p;
                        CaChunkID id;
                        size_t n;

                        r = ca_remote_next_chunk(rr, CA_CHUNK_AS_IS, &id, &p, &n, &compression);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine most recent chunk: %m");

                        r = ca_store_put(stores.stores[0], &id, compression, p, n); /* Write to wstore */
                        if (r < 0 && r != -EEXIST)
                                return log_error_errno(r, "Failed to write chunk to store: %m");

                        r = ca_remote_forget_chunk(rr, &id);
                        if (r < 0 && r != -ENOENT)
                                return log_error_errno(r, "Failed to forget chunk: %m");

                        break;
                }

                default:
                        assert(false);
                }

                /* Request all chunks from the client that the index it just send us listed but we don't have locally yet. */
                for (;;) {
                        /* char ids[CA_CHUNK_ID_FORMAT_MAX]; */
                        uint64_t remote_flags;
                        CaChunkID id;
                        size_t i;

                        if (!index)
                                break;
                        if (index_processed)
                                break;
                        if (!wstore_path)
                                break;

                        r = ca_remote_get_remote_feature_flags(rr, &remote_flags);
                        if (r == -ENODATA)
                                break;
                        if (r < 0)
                                return log_error_errno(r, "Failed to get remote feature flags: %m");

                        /* Only request chunks if this is requested by the client side */
                        if ((remote_flags & CA_PROTOCOL_PUSH_INDEX_CHUNKS) == 0) {
                                index_processed = true;
                                break;
                        }

                        r = ca_index_read_chunk(index, &id, NULL, NULL);
                        if (r == -EAGAIN) /* Not read enough yet */
                                break;
                        if (r < 0)
                                return log_error_errno(r, "Failed to read index: %m");
                        if (r == 0) { /* EOF */
                                index_processed = true;
                                break;
                        }

                        /* fprintf(stderr, "Need %s\n", ca_chunk_id_format(&id, ids)); */

                        r = 0;
                        for (i = 0; i < stores.n_stores; i++) {
                                r = ca_store_has(stores.stores[i], &id);
                                if (r < 0)
                                        log_error_errno(r, "Failed to test whether chunk exists locally already: %m");
                                if (r > 0)
                                        break;
                        }
                        if (r > 0) {
                                /* fprintf(stderr, "Already have %s\n", ca_chunk_id_format(&id, ids)); */
                                continue;
                        }

                        /* fprintf(stderr, "Requesting %s\n", ca_chunk_id_format(&id, ids)); */

                        r = ca_remote_request_async(rr, &id, false);
                        if (r < 0 && r != -EALREADY && r != -EAGAIN)
                                return log_error_errno(r, "Failed to request chunk: %m");

                        /* if (r > 0) */
                        /*         fprintf(stderr, "New request for %s\n", ca_chunk_id_format(&id, ids)); */
                }

                finished = true;

                /* If the index isn't written yet, don't finish yet */
                if (index_path && (!index_written || !index_processed))
                        finished = false;

                /* If the archive isn't written yet, don't finish yet */
                if (archive_path && !archive_written)
                        finished = false;

                /* If there are any chunks queued still, don't finish yet */
                r = ca_remote_has_chunks(rr);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine if further requests are pending: %m");
                if (r > 0)
                        finished = false;

                if (finished) {
                        r = ca_remote_goodbye(rr);
                        if (r < 0 && r != -EALREADY)
                                return log_error_errno(r, "Failed to enqueue goodbye: %m");
                }
        }

        if (index) {
                r = ca_index_install(index);
                if (r < 0)
                        return log_error_errno(r, "Failed to install index on location: %m");
        }

        return 0;
}

static int verb_udev(int argc, char *argv[]) {
        const char *e;
        char pretty[FILENAME_MAX+1];
        const char *p;
        _cleanup_(safe_closep) int fd = -1;
        ssize_t n;

        if (argc != 2) {
                log_error("Expected one argument.");
                return -EINVAL;
        }

        e = path_startswith(argv[1], "/dev");
        if (!e || !filename_is_valid(e)) {
                log_error("Argument is not a valid device node path: %s.", argv[2]);
                return -EINVAL;
        }

        p = strjoina("/run/casync/", e);
        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", p);
        }

        if (flock(fd, LOCK_SH|LOCK_NB) < 0) {

                if (errno != EWOULDBLOCK)
                        return log_error_errno(errno, "Failed to check if %s is locked: %m", p);

                /* If we got EWOULDBLOCK, everything is good, there's a casync locking this */

        } else {
                /* Uh? We managed to lock this file? in that case casync behind it died, let's ignore this, and quit immediately. */
                fd = safe_close(fd);
                return 0;
        }

        n = read(fd, pretty, sizeof(pretty));
        if (n < 0)
                return log_error_errno(errno, "Failed to read from %s: %m", p);
        if ((size_t) n >= sizeof(pretty)) {
                log_error("Stored name read from %s too long.", p);
                return -EINVAL;
        }
        if ((size_t) n <= 0 || pretty[n-1] != '\n') {
                log_error("Stored name not newline terminated.");
                return -EINVAL;
        }

        pretty[n-1] = 0;
        if (!filename_is_valid(pretty)) {
                log_error("Stored name is invalid: %s", pretty);
                return -EINVAL;
        }

        printf("CASYNC_NAME=%s\n", pretty);
        return 0;
}

static int verb_gc(int argc, char *argv[]) {
        int i, r;
        _cleanup_(ca_chunk_collection_unrefp) CaChunkCollection *coll = NULL;
        _cleanup_(ca_store_unrefp) CaStore *store = NULL;

        if (argc < 2) {
                log_error("Expected at least one argument.");
                return -EINVAL;
        }

        coll = ca_chunk_collection_new();
        if (!coll)
                return log_oom();

        /* This sets the same store for all indices, based on the first index. */
        r = set_default_store(argv[1]);
        if (r < 0)
                return r;

        if (!arg_store) {
                log_error("Failed to determine store, use --store= to set store.");
                return -EINVAL;
        }

        store = ca_store_new();
        if (!store)
                return log_oom();

        r = ca_store_set_path(store, arg_store);
        if (r < 0) {
                fprintf(stderr, "Set to set store to \"%s\": %s", arg_store, strerror(-r));
                return r;
        }

        for (i = 1; i < argc; i++) {
                const char *path = argv[i];

                r = ca_chunk_collection_add_index(coll, path);
                if (r < 0)
                        return r;
        }

        {
                size_t usage, size;

                assert_se(ca_chunk_collection_usage(coll, &usage) == 0);
                assert_se(ca_chunk_collection_size(coll, &size) == 0);
                if (arg_verbose)
                        printf("Chunk store usage: %zu references, %zu chunks\n", usage, size);
        }

        r = ca_gc_cleanup_unused(store, coll,
                                 arg_verbose * CA_GC_VERBOSE |
                                 arg_dry_run * CA_GC_DRY_RUN);
        if (r < 0)
                log_error_errno(r, "Chunk cleanup failed: %m");

        return r;
}


static int dispatch_verb(int argc, char *argv[]) {
        int r;

        if (argc < 1) {
                log_error("Missing verb. (Invoke '%s --help' for a list of available verbs.)", program_invocation_short_name);
                return -EINVAL;
        }

        if (streq(argv[0], "help")) {
                help();
                r = 0;
        } else if (streq(argv[0], "make"))
                r = verb_make(argc, argv);
        else if (streq(argv[0], "extract"))
                r = verb_extract(argc, argv);
        else if (STR_IN_SET(argv[0], "list", "mtree", "stat"))
                r = verb_list(argc, argv);
        else if (streq(argv[0], "digest"))
                r = verb_digest(argc, argv);
        else if (streq(argv[0], "mkdev"))
                r = verb_mkdev(argc, argv);
        else if (streq(argv[0], "mount"))
                r = verb_mount(argc, argv);
        else if (streq(argv[0], "pull")) /* "Secret" verb, only to be called by ssh-based remoting. */
                r = verb_pull(argc, argv);
        else if (streq(argv[0], "push")) /* Same here. */
                r = verb_push(argc, argv);
        else if (streq(argv[0], "udev")) /* "Secret" verb, only to be called by the udev nbd rules */
                r = verb_udev(argc, argv);
        else if (streq(argv[0], "gc"))
                r = verb_gc(argc, argv);
        else {
                log_error("Unknown verb '%s'. (Invoke '%s --help' for a list of available verbs.)", argv[0], program_invocation_short_name);
                r = -EINVAL;
        }

        return r;
}

int main(int argc, char *argv[]) {
        int r;

        disable_sigpipe();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        install_exit_handler(NULL);
        block_exit_handler(SIG_UNBLOCK, NULL);

        r = dispatch_verb(argc - optind, argv + optind);
        install_exit_handler(SIG_DFL);

finish:
        free(arg_store);
        free(arg_cache);
        strv_free(arg_extra_stores);
        strv_free(arg_seeds);

        /* fprintf(stderr, PID_FMT ": exiting with error code: %m", getpid()); */

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
