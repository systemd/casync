#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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
#include "notify.h"
#include "parse-util.h"
#include "signal-handler.h"
#include "util.h"

static enum {
        WHAT_ARCHIVE,
        WHAT_ARCHIVE_INDEX,
        WHAT_BLOB,
        WHAT_BLOB_INDEX,
        WHAT_DIRECTORY,
        _WHAT_INVALID = -1,
} arg_what = _WHAT_INVALID;
static bool arg_verbose = false;
static bool arg_exclude_nodump = true;
static bool arg_exclude_submounts = false;
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
               "%1$s [OPTIONS...] mkdev [BLOB|BLOB_INDEX] [NODE]\n\n"
               "Content-Addressable Data Synchronization Tool\n\n"
               "  -h --help                  Show this help\n"
               "     --version               Show brief version information\n"
               "  -v --verbose               Show terse status information during runtime\n"
               "     --store=PATH            The primary chunk store to use\n"
               "     --extra-store=PATH      Additional chunk store to look for chunks in\n"
               "     --chunk-size=[MIN:]AVG[:MAX]\n"
               "                             The minimal/average/maximum number of bytes in a\n"
               "                             chunk\n"
               "     --digest=DIGEST         Pick digest algorithm (sha512-256 or sha256)\n"
               "     --compression=COMPRESSION\n"
               "                             Pick compression algorithm (zstd, xz or gzip)\n"
               "     --seed=PATH             Additional file or directory to use as seed\n"
               "     --rate-limit-bps=LIMIT  Maximum bandwidth in bytes/s for remote\n"
               "                             communication\n"
               "     --exclude-nodump=no     Don't exclude files with chattr(1)'s +d 'nodump'\n"
               "                             flag when creating archive\n"
               "     --exclude-submounts=yes Exclude submounts when creating archive\n"
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
               "     (and similar: --without=fat-attrs, --without=privileged, ...)\n\n"
               "Individual archive features:\n"
               "     --with=16bit-uids       Store reduced 16bit UID/GID information\n"
               "     --with=32bit-uids       Store full 32bit UID/GID information\n"
               "     --with=user-names       Store user/group names\n"
               "     --with=sec-time         Store timestamps in 1s granularity\n"
               "     --with=usec-time        Store timestamps in 1µs granularity\n"
               "     --with=nsec-time        Store timestamps in 1ns granularity\n"
               "     --with=2sec-time        Store timestamps in 2s granularity\n"
               "     --with=read-only        Store per-file read only flag\n"
               "     --with=permissions      Store full per-file UNIX permissions\n"
               "     --with=symlinks         Store symbolic links\n"
               "     --with=device-nodes     Store block and character device nodes\n"
               "     --with=fifos            Store named pipe nodes\n"
               "     --with=sockets          Store AF_UNIX file system socket nodes\n"
               "     --with=flag-hidden      Store FAT hidden file flag\n"
               "     --with=flag-system      Store FAT system file flag\n"
               "     --with=flag-archive     Store FAT archive file flag\n"
               "     --with=flag-append      Store append-only file flag\n"
               "     --with=flag-noatime     Store disable access time file flag\n"
               "     --with=flag-compr       Store enable compression file flag\n"
               "     --with=flag-nocow       Store disable copy-on-write file flag\n"
               "     --with=flag-nodump      Store disable dumping file flag\n"
               "     --with=flag-dirsync     Store synchronous directory flag\n"
               "     --with=flag-immutable   Store immutable file flag\n"
               "     --with=flag-sync        Store synchronous file flag\n"
               "     --with=flag-nocomp      Store disable compression file flag\n"
               "     --with=flag-projinherit Store project quota inheritance flag\n"
               "     --with=subvolume        Store btrfs subvolume information\n"
               "     --with=subvolume-ro     Store btrfs subvolume read-only property\n"
               "     --with=xattrs           Store extended file attributes\n"
               "     --with=acl              Store file access control lists\n"
               "     --with=selinux          Store SELinux file labels\n"
               "     --with=fcaps            Store file capabilities\n"
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
                        fprintf(stderr, "--chunk-size= requires either a single average chunk size or a triplet of minimum, average and maximum chunk size.\n");
                        return -EINVAL;
                }

                p = strndupa(v, k - v);
                r = parse_size(p, &a);
                if (r < 0) {
                        fprintf(stderr, "Can't parse minimum chunk size: %s\n", v);
                        return r;
                }
                if (a < CA_CHUNK_SIZE_LIMIT_MIN) {
                        fprintf(stderr, "Minimum chunk size must be >= %zu.\n", CA_CHUNK_SIZE_LIMIT_MIN);
                        return -ERANGE;
                }

                p = strndupa(k + 1, j - k - 1);
                r = parse_size(p, &b);
                if (r < 0) {
                        fprintf(stderr, "Can't parse average chunk size: %s\n", v);
                        return r;
                }
                if (b < a) {
                        fprintf(stderr, "Average chunk size must be larger than minimum chunk size.\n");
                        return -EINVAL;
                }

                r = parse_size(j + 1, &c);
                if (r < 0) {
                        fprintf(stderr, "Can't parse maximum chunk size: %s\n", v);
                        return r;
                }
                if (c < b) {
                        fprintf(stderr, "Average chunk size must be smaller than maximum chunk size.\n");
                        return -EINVAL;
                }
                if (c > CA_CHUNK_SIZE_LIMIT_MAX) {
                        fprintf(stderr, "Maximum chunk size must be <= %zu.\n", CA_CHUNK_SIZE_LIMIT_MAX);
                        return -ERANGE;
                }
        } else {

                r = parse_size(v, &b);
                if (r < 0) {
                        fprintf(stderr, "Can't parse average chunk size: %s\n", v);
                        return r;
                }
                if (b < CA_CHUNK_SIZE_LIMIT_MIN) {
                        fprintf(stderr, "Average chunk size must be >= %zu.\n", CA_CHUNK_SIZE_LIMIT_MIN);
                        return -ERANGE;
                }
                if (b > CA_CHUNK_SIZE_LIMIT_MAX) {
                        fprintf(stderr, "Average chunk size must be <= %zu.\n", CA_CHUNK_SIZE_LIMIT_MAX);
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

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_STORE = 0x100,
                ARG_EXTRA_STORE,
                ARG_CHUNK_SIZE,
                ARG_SEED,
                ARG_RATE_LIMIT_BPS,
                ARG_WITH,
                ARG_WITHOUT,
                ARG_WHAT,
                ARG_EXCLUDE_NODUMP,
                ARG_EXCLUDE_SUBMOUNTS,
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
                { "store",             required_argument, NULL, ARG_STORE             },
                { "extra-store",       required_argument, NULL, ARG_EXTRA_STORE       },
                { "chunk-size",        required_argument, NULL, ARG_CHUNK_SIZE        },
                { "seed",              required_argument, NULL, ARG_SEED              },
                { "rate-limit-bps",    required_argument, NULL, ARG_RATE_LIMIT_BPS    },
                { "with",              required_argument, NULL, ARG_WITH              },
                { "without",           required_argument, NULL, ARG_WITHOUT           },
                { "what",              required_argument, NULL, ARG_WHAT              },
                { "exclude-nodump",    required_argument, NULL, ARG_EXCLUDE_NODUMP    },
                { "exclude-submounts", required_argument, NULL, ARG_EXCLUDE_SUBMOUNTS },
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

        while ((c = getopt_long(argc, argv, "hv", options, NULL)) >= 0) {

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

                case ARG_STORE: {
                        char *p;

                        p = strdup(optarg);
                        if (!p)
                                return log_oom();

                        free(arg_store);
                        arg_store = p;
                        break;
                }

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

                case ARG_RATE_LIMIT_BPS:
                        r = parse_size(optarg, &arg_rate_limit_bps);
                        if (r < 0) {
                                fprintf(stderr, "Unable to parse rate limit %s: %s\n", optarg, strerror(-r));
                                return r;
                        }
                        if (arg_rate_limit_bps == 0) {
                                fprintf(stderr, "Rate limit size cannot be zero.\n");
                                return -EINVAL;
                        }

                        break;

                case ARG_WITH: {
                        uint64_t u;

                        r = ca_with_feature_flags_parse_one(optarg, &u);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --with= feature flag: %s\n", optarg);
                                return -EINVAL;
                        }

                        arg_with |= u;
                        break;
                }

                case ARG_WITHOUT: {
                        uint64_t u;

                        r = ca_with_feature_flags_parse_one(optarg, &u);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --without= feature flag: %s\n", optarg);
                                return -EINVAL;
                        }

                        arg_without |= u;
                        break;
                }

                case ARG_WHAT:
                        if (streq(optarg, "archive"))
                                arg_what = WHAT_ARCHIVE;
                        else if (streq(optarg, "archive-index"))
                                arg_what = WHAT_ARCHIVE_INDEX;
                        else if (streq(optarg, "blob"))
                                arg_what = WHAT_BLOB;
                        else if (streq(optarg, "blob-index"))
                                arg_what = WHAT_BLOB_INDEX;
                        else if (streq(optarg, "directory"))
                                arg_what = WHAT_DIRECTORY;
                        else {
                                fprintf(stderr, "Failed to parse --what= selector: %s\n", optarg);
                                return -EINVAL;
                        }

                        break;

                case ARG_EXCLUDE_NODUMP:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --exclude-nodump= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_exclude_nodump = r;
                        break;

                case ARG_EXCLUDE_SUBMOUNTS:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --exclude-submounts= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_exclude_submounts = r;
                        break;

                case ARG_UNDO_IMMUTABLE:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --undo-immutable= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_undo_immutable = r;
                        break;

                case ARG_PUNCH_HOLES:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --punch-holes= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_punch_holes = r;
                        break;

                case ARG_REFLINK:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --reflink= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_reflink = r;
                        break;

                case ARG_HARDLINK:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --hardlink= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_hardlink = r;
                        break;

                case ARG_DELETE:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --delete= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_delete = r;
                        break;

                case ARG_SEED_OUTPUT:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --seed-output= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_seed_output = r;
                        break;

                case ARG_MKDIR:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --mkdir= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_mkdir = r;
                        break;

                case ARG_UID_SHIFT: {
                        uid_t uid;

                        r = parse_uid(optarg, &uid);
                        if (r < 0) {
                                r = parse_boolean(optarg);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to parse --uid-shift= parameter: %s\n", optarg);
                                        return r;
                                }

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
                                if (r < 0) {
                                        fprintf(stderr, "Failed to parse --uid-range= parameter: %s\n", optarg);
                                        return r;
                                }

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
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --recursive= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_recursive = r;
                        break;

                case ARG_DIGEST: {
                        CaDigestType t;

                        t = ca_digest_type_from_string(optarg);
                        if (t < 0) {
                                fprintf(stderr, "Failed to parse --digest= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_digest = t;
                        break;
                }

                case ARG_COMPRESSION: {
                        CaCompressionType cc;

                        cc = ca_compression_type_from_string(optarg);
                        if (cc < 0) {
                                fprintf(stderr, "Failed to parse --compression= parameter: %s\n", optarg);
                                return r;
                        }

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
                if (r < 0) {
                        fprintf(stderr, "Failed to automatically derive store location from index: %s\n", strerror(-r));
                        return r;
                }
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
                        fprintf(stderr, "Failed to add extra store %s, ignoring: %s\n", *i, strerror(-r));
        }

        STRV_FOREACH(i, arg_seeds) {
                r = ca_sync_add_seed_path(s, *i);
                if (r < 0)
                        fprintf(stderr, "Failed to add seed %s, ignoring: %s\n", *i, strerror(-r));
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

        flags |= ca_feature_flags_from_digest_type(arg_digest);

        r = ca_sync_set_feature_flags(s, flags);
        if (r < 0 && r != -ENOTTY) { /* only encoder syncs have a feature flags field */
                fprintf(stderr, "Failed to set feature flags: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_set_feature_flags_mask(s, flags);
        if (r < 0 && r != -ENOTTY) { /* only decoder syncs have a feature flags mask field */
                fprintf(stderr, "Failed to set feature flags mask: %s\n", strerror(-r));
                return r;
        }

        if (arg_uid_shift_apply) {
                r = ca_sync_set_uid_shift(s, arg_uid_shift);
                if (r < 0) {
                        fprintf(stderr, "Failed to set UID shift: %s\n", strerror(-r));
                        return r;
                }

                r = ca_sync_set_uid_range(s, arg_uid_range);
                if (r < 0) {
                        fprintf(stderr, "Failed to set UID range: %s\n", strerror(-r));
                        return r;
                }
        }

        r = ca_sync_set_undo_immutable(s, arg_undo_immutable);
        if (r < 0 && r != -ENOTTY) {
                fprintf(stderr, "Failed to set undo immutable flag: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_set_compression_type(s, arg_compression);
        if (r < 0 && r != -ENOTTY) {
                fprintf(stderr, "Failed to set compression: %s\n", strerror(-r));
                return r;
        }

        return 0;
}

static int load_chunk_size(CaSync *s) {
        uint64_t cavg, cmin, cmax;
        int r;

        if (arg_chunk_size_avg != 0) {
                r = ca_sync_set_chunk_size_avg(s, arg_chunk_size_avg);
                if (r < 0) {
                        fprintf(stderr, "Failed to set average chunk size to %zu: %s\n", arg_chunk_size_avg, strerror(-r));
                        return r;
                }
        }

        if (arg_chunk_size_min != 0) {
                r = ca_sync_set_chunk_size_min(s, arg_chunk_size_min);
                if (r < 0) {
                        fprintf(stderr, "Failed to set minimum chunk size to %zu: %s\n", arg_chunk_size_min, strerror(-r));
                        return r;
                }
        }

        if (arg_chunk_size_max != 0) {
                r = ca_sync_set_chunk_size_max(s, arg_chunk_size_max);
                if (r < 0) {
                        fprintf(stderr, "Failed to set minimum chunk size to %zu: %s\n", arg_chunk_size_min, strerror(-r));
                        return r;
                }
        }

        if (!arg_verbose)
                return 1;

        r = ca_sync_get_chunk_size_avg(s, &cavg);
        if (r < 0) {
                fprintf(stderr, "Failed to read average chunk size: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_get_chunk_size_min(s, &cmin);
        if (r < 0) {
                fprintf(stderr, "Failed to read minimum chunk size: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_get_chunk_size_max(s, &cmax);
        if (r < 0) {
                fprintf(stderr, "Failed to read maximum chunk size: %s\n", strerror(-r));
                return r;
        }

        fprintf(stderr, "Selected chunk sizes: min=%"PRIu64"..avg=%"PRIu64"..max=%"PRIu64"\n", cmin, cavg, cmax);
        return 1;
}

static int verbose_print_feature_flags(CaSync *s) {
        static bool printed = false;
        uint64_t flags;
        char *t;
        int r;

        assert(s);

        if (!arg_verbose)
                return 0;
        if (printed)
                return 0;

        r = ca_sync_get_feature_flags(s, &flags);
        if (r == -ENODATA) /* we don't know them yet? */
                return 0;
        if (r < 0) {
                fprintf(stderr, "Failed to query feature flags: %s\n", strerror(-r));
                return r;
        }

        r = ca_with_feature_flags_format(flags, &t);
        if (r < 0) {
                fprintf(stderr, "Failed to format feature flags: %s\n", strerror(-r));
                return r;
        }

        fprintf(stderr, "Using feature flags: %s\n", strnone(t));
        fprintf(stderr, "Excluding files with chattr(1) -d flag: %s\n", yes_no(flags & CA_FORMAT_EXCLUDE_NODUMP));
        fprintf(stderr, "Excluding submounts: %s\n", yes_no(flags & CA_FORMAT_EXCLUDE_SUBMOUNTS));
        fprintf(stderr, "Digest algorithm: %s\n", ca_digest_type_to_string(ca_feature_flags_to_digest_type(flags)));

        free(t);

        printed = true;

        return 0;
}

static int verbose_print_path(CaSync *s, const char *verb) {
        char *path;
        int r;

        if (!arg_verbose)
                return 0;

        r = ca_sync_current_path(s, &path);
        if (r == -ENOTDIR) /* Root isn't a directory */
                return 0;

        if (r < 0) {
                fprintf(stderr, "Failed to query current path: %s\n", strerror(-r));
                return r;
        }

        if (verb) {
                fputs(verb, stderr);
                fputc(' ', stderr);
        }

        fprintf(stderr, "%s\n", isempty(path) ? "./" : path);
        free(path);

        return 1;
}

static int verbose_print_done_make(CaSync *s) {
        uint64_t n_chunks = UINT64_MAX, size = UINT64_MAX, n_reused = UINT64_MAX, covering;
        char buffer[FORMAT_BYTES_MAX];
        int r;

        assert(s);

        if (!arg_verbose)
                return 0;

        r = ca_sync_get_covering_feature_flags(s, &covering);
        if (r != -ENODATA) {
                uint64_t selected, too_much;

                if (r < 0) {
                        fprintf(stderr, "Failed to determine covering flags: %s\n", strerror(-r));
                        return r;
                }

                r = ca_sync_get_feature_flags(s, &selected);
                if (r < 0) {
                        fprintf(stderr, "Failed to determine used flags: %s\n", strerror(-r));
                        return r;
                }

                too_much = selected & ~covering;
                if (too_much != 0) {
                        char *t;

                        r = ca_with_feature_flags_format(too_much, &t);
                        if (r < 0) {
                                fprintf(stderr, "Failed to format feature flags: %s\n", strerror(-r));
                                return r;
                        }

                        fprintf(stderr, "Selected feature flags not actually applicable to backing file systems: %s\n", strnone(t));
                        free(t);
                }
        }

        r = ca_sync_current_archive_chunks(s, &n_chunks);
        if (r < 0 && r != -ENODATA) {
                fprintf(stderr, "Failed to determine number of chunks: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_current_archive_reused_chunks(s, &n_reused);
        if (r < 0 && r != -ENODATA) {
                fprintf(stderr, "Failed to determine number of reused chunks: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_current_archive_offset(s, &size);
        if (r < 0 && r != -ENODATA) {
                fprintf(stderr, "Failed to determine archive size: %s\n", strerror(-r));
                return r;
        }

        if (size != UINT64_MAX)
                fprintf(stderr, "Archive size: %s\n", format_bytes(buffer, sizeof(buffer), size));
        if (n_chunks != UINT64_MAX)
                fprintf(stderr, "Number of chunks: %" PRIu64 "\n", n_chunks);
        if (n_reused != UINT64_MAX) {
                fprintf(stderr, "Reused chunks: %" PRIu64, n_reused);
                if (n_chunks != UINT64_MAX && n_chunks > 0)
                        fprintf(stderr, " (%" PRIu64 "%%)\n", (n_reused*100U/n_chunks));
                else
                        fputc('\n', stderr);
        }

        if (size != UINT64_MAX && n_chunks != UINT64_MAX)
                fprintf(stderr, "Effective average chunk size: %s\n", format_bytes(buffer, sizeof(buffer), size/n_chunks));

        return 1;
}

static int verbose_print_done_extract(CaSync *s) {
        char buffer[FORMAT_BYTES_MAX];
        uint64_t n_bytes, n_requests;
        int r;

        if (!arg_verbose)
                return 0;

        r = ca_sync_get_punch_holes_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of punch holes bytes: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Zero bytes written as sparse files: %s\n", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_reflink_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of reflink bytes: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Bytes cloned through reflinks: %s\n", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_hardlink_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of hardlink bytes: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Bytes cloned through hardlinks: %s\n", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_local_requests(s, &n_requests);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of successful local store requests: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Chunk requests fulfilled from local store: %" PRIu64 "\n", n_requests);
        }

        r = ca_sync_get_local_request_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine size of successful local store requests: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Bytes used from local store: %s\n", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_seed_requests(s, &n_requests);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of successful local seed requests: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Chunk requests fulfilled from local seed: %" PRIu64 "\n", n_requests);
        }

        r = ca_sync_get_seed_request_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine size of successful local seed requests: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Bytes used from local seed: %s\n", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

        r = ca_sync_get_remote_requests(s, &n_requests);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of successful remote store requests: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Chunk requests fulfilled from remote store: %" PRIu64 "\n", n_requests);
        }

        r = ca_sync_get_remote_request_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine size of successful remote store requests: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Bytes used from remote store: %s\n", format_bytes(buffer, sizeof(buffer), n_bytes));
        }

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
                                fprintf(stderr, "Got exit signal, quitting.\n");
                } else if (r < 0)
                        fprintf(stderr, "Failed to poll synchronizer: %s\n", strerror(-r));

                return r;

        case CA_SYNC_NOT_FOUND:
                fprintf(stderr, "Seek path not available in archive.\n");
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
        char *input = NULL, *output = NULL;
        int r, input_fd = -1;
        CaSync *s = NULL;
        struct stat st;

        if (argc > 3) {
                fprintf(stderr, "A pair of output and input path/URL expected.\n");
                r = -EINVAL;
                goto finish;
        }

        if (argc > 1) {
                output = ca_strip_file_url(argv[1]);
                if (!output) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (argc > 2) {
                input = ca_strip_file_url(argv[2]);
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (arg_what == WHAT_ARCHIVE)
                operation = MAKE_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = MAKE_ARCHIVE_INDEX;
        else if (arg_what == WHAT_BLOB_INDEX)
                operation = MAKE_BLOB_INDEX;
        else if (arg_what != _WHAT_INVALID) {
                fprintf(stderr, "\"make\" operation may only be combined with --what=archive, --what=archive-index or --what=blob-index.\n");
                r = -EINVAL;
                goto finish;
        }

        if (operation == _MAKE_OPERATION_INVALID && output && !streq(output, "-")) {
                if (ca_locator_has_suffix(output, ".catar"))
                        operation = MAKE_ARCHIVE;
                else if (ca_locator_has_suffix(output, ".caidx"))
                        operation = MAKE_ARCHIVE_INDEX;
                else if (ca_locator_has_suffix(output, ".caibx"))
                        operation = MAKE_BLOB_INDEX;
                else {
                        fprintf(stderr, "File to create does not have valid suffix, refusing. (May be one of: .catar, .caidx, .caibx)\n");
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (!input && IN_SET(operation, MAKE_ARCHIVE, MAKE_ARCHIVE_INDEX)) {
                input = strdup(".");
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
                CaLocatorClass input_class;

                input_class = ca_classify_locator(input);
                if (input_class < 0) {
                        fprintf(stderr, "Failed to determine class of locator: %s\n", input);
                        r = -EINVAL;
                        goto finish;
                }

                if (input_class != CA_LOCATOR_PATH) {
                        fprintf(stderr, "Input must be local path: %s\n", input);
                        r = -EINVAL;
                        goto finish;
                }

                input_fd = open(input, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                if (input_fd < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to open %s: %s\n", input, strerror(-r));
                        goto finish;
                }
        }

        if (fstat(input_fd, &st) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to stat input: %s\n", strerror(-r));
                goto finish;
        }

        if (S_ISDIR(st.st_mode)) {

                if (operation == _MAKE_OPERATION_INVALID)
                        operation = MAKE_ARCHIVE;
                else if (!IN_SET(operation, MAKE_ARCHIVE, MAKE_ARCHIVE_INDEX)) {
                        fprintf(stderr, "Input is a directory, but attempted to make blob index. Refusing.\n");
                        r = -EINVAL;
                        goto finish;
                }

        } else if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode)) {

                if (operation == _MAKE_OPERATION_INVALID)
                        operation = MAKE_BLOB_INDEX;
                else if (operation != MAKE_BLOB_INDEX) {
                        fprintf(stderr, "Input is a regular file or block device, but attempted to make a directory archive. Refusing.\n");
                        r = -EINVAL;
                        goto finish;
                }
        } else {
                fprintf(stderr, "Input is a neither a directory, a regular file, nor a block device. Refusing.\n");
                r = -EINVAL;
                goto finish;
        }

        if (streq_ptr(output, "-"))
                output = NULL;

        if (operation == _MAKE_OPERATION_INVALID) {
                fprintf(stderr, "Failed to determine what to make. Use --what=archive, --what=archive-index or --what=blob-index.\n");
                r = -EINVAL;
                goto finish;
        }

        if (IN_SET(operation, MAKE_ARCHIVE_INDEX, MAKE_BLOB_INDEX)) {
                r = set_default_store(output);
                if (r < 0)
                        goto finish;
        }

        s = ca_sync_new_encode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        r = load_chunk_size(s);
        if (r < 0)
                goto finish;

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_sync_set_rate_limit_bps(s, arg_rate_limit_bps);
                if (r < 0) {
                        fprintf(stderr, "Failed to set rate limit: %s\n", strerror(-r));
                        return r;
                }
        }

        r = ca_sync_set_base_fd(s, input_fd);
        if (r < 0) {
                fprintf(stderr, "Failed to set sync base: %s\n", strerror(-r));
                goto finish;
        }
        input_fd = -1;

        if (output) {
                r = ca_sync_set_make_mode(s, st.st_mode & 0666);
                if (r < 0) {
                        fprintf(stderr, "Failed to set make permission mode: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (operation == MAKE_ARCHIVE) {
                if (output)
                        r = ca_sync_set_archive_auto(s, output);
                else
                        r = ca_sync_set_archive_fd(s, STDOUT_FILENO);
                if (r < 0) {
                        fprintf(stderr, "Failed to set sync archive: %s\n", strerror(-r));
                        goto finish;
                }
        } else {
                if (output)
                        r = ca_sync_set_index_auto(s, output);
                else
                        r = ca_sync_set_index_fd(s, STDOUT_FILENO);
                if (r < 0) {
                        fprintf(stderr, "Failed to set sync index: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_feature_flags(s, operation == MAKE_BLOB_INDEX ? 0 : CA_FORMAT_WITH_MASK);
        if (r < 0)
                goto finish;

        r = ca_sync_enable_archive_digest(s, true);
        if (r < 0) {
                fprintf(stderr, "Failed to enable archive digest: %s\n", strerror(-r));
                goto finish;
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        fprintf(stderr, "Got exit signal, quitting.\n");
                        r = -ESHUTDOWN;
                        goto finish;
                }

                r = ca_sync_step(s);
                if (r < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED: {
                        CaChunkID digest;
                        char t[CA_CHUNK_ID_FORMAT_MAX];

                        verbose_print_done_make(s);

                        assert_se(ca_sync_get_archive_digest(s, &digest) >= 0);
                        printf("%s\n", ca_chunk_id_format(&digest, t));

                        r = 0;
                        goto finish;
                }

                case CA_SYNC_NEXT_FILE:
                        r = verbose_print_path(s, "Packing");
                        if (r < 0)
                                goto finish;
                        break;

                case CA_SYNC_DONE_FILE:
                        r = verbose_print_path(s, "Packed");
                        if (r < 0)
                                goto finish;
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

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);

        free(input);
        free(output);

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
        int r, output_fd = -1, input_fd = -1;
        char *input = NULL, *output = NULL;
        const char *seek_path = NULL;
        CaSync *s = NULL;

        if (argc > 4) {
                fprintf(stderr, "Input path/URL, output path, and subtree path expected.\n");
                return -EINVAL;
        }

        if (argc > 1) {
                input = ca_strip_file_url(argv[1]);
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (argc > 2) {
                output = ca_strip_file_url(argv[2]);
                if (!output) {
                        r = log_oom();
                        goto finish;
                }
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
                fprintf(stderr, "\"extract\" operation may only be combined with --what=archive, --what=archive-index, --what=blob-index.\n");
                r = -EINVAL;
                goto finish;
        }

        if (operation == _EXTRACT_OPERATION_INVALID && input && !streq(input, "-")) {

                if (ca_locator_has_suffix(input, ".catar"))
                        operation = EXTRACT_ARCHIVE;
                else if (ca_locator_has_suffix(input, ".caidx"))
                        operation = EXTRACT_ARCHIVE_INDEX;
                else if (ca_locator_has_suffix(input, ".caibx"))
                        operation = EXTRACT_BLOB_INDEX;
                else {
                        fprintf(stderr, "File to read from does not have valid suffix, refusing. (May be one of: .catar, .caidx, .caibx)\n");
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;

        if (!output && IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX)) {
                output = strdup(".");
                if (!output) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (!output || streq(output, "-")) {
                output_fd = STDOUT_FILENO;
                output = NULL;
        } else {
                CaLocatorClass output_class;

                output_class = ca_classify_locator(output);
                if (output_class < 0) {
                        fprintf(stderr, "Failed to determine locator class: %s\n", output);
                        r = -EINVAL;
                        goto finish;
                }

                if (output_class != CA_LOCATOR_PATH) {
                        fprintf(stderr, "Output must be local path: %s\n", output);
                        r = -EINVAL;
                        goto finish;
                }

                output_fd = open(output, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                if (output_fd < 0 && errno == EISDIR)
                        output_fd = open(output, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_DIRECTORY);

                if (output_fd < 0 && errno != ENOENT) {
                        r = -errno;
                        fprintf(stderr, "Failed to open %s: %s\n", output, strerror(-r));
                        goto finish;
                }
        }

        if (output_fd >= 0) {
                struct stat st;

                if (fstat(output_fd, &st) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to stat output: %s\n", strerror(-r));
                        goto finish;
                }

                if (S_ISDIR(st.st_mode)) {

                        if (operation == _EXTRACT_OPERATION_INVALID)
                                operation = EXTRACT_ARCHIVE_INDEX;
                        else if (!IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX)) {
                                fprintf(stderr, "Output is a directory, but attempted to extract blob index. Refusing.\n");
                                r = -EINVAL;
                                goto finish;
                        }

                } else if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode)) {

                        if (operation == _EXTRACT_OPERATION_INVALID)
                                operation = EXTRACT_BLOB_INDEX;
                        else if (operation != EXTRACT_BLOB_INDEX) {
                                fprintf(stderr, "Output is a regular file or block device, but attempted to extract an archive.\n");
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        fprintf(stderr, "Output is neither a directory, a regular file, nor a block device. Refusing.\n");
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (operation == _EXTRACT_OPERATION_INVALID) {
                fprintf(stderr, "Couldn't figure out what to extract. Refusing. Use --what=archive, --what=archive-index or --what=blob-index.\n");
                r = -EINVAL;
                goto finish;
        }

        if (!IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX) && seek_path) {
                fprintf(stderr, "Subtree path only supported when extracting archive or archive index.\n");
                r = -EINVAL;
                goto finish;
        }

        seek_path = normalize_seek_path(seek_path);

        s = ca_sync_new_decode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        if (IN_SET(operation, EXTRACT_ARCHIVE_INDEX, EXTRACT_BLOB_INDEX)) {
                r = set_default_store(input);
                if (r < 0)
                        goto finish;

                if (arg_seed_output) {
                        r = ca_sync_add_seed_path(s, output);
                        if (r < 0 && r != -ENOENT)
                                fprintf(stderr, "Failed to add existing file as seed %s, ignoring: %s\n", output, strerror(-r));
                }
        }

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_sync_set_rate_limit_bps(s, arg_rate_limit_bps);
                if (r < 0) {
                        fprintf(stderr, "Failed to set rate limit: %s\n", strerror(-r));
                        goto finish;
                }
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
                        if (r < 0) {
                                fprintf(stderr, "Failed to set base mode to directory: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = ca_sync_set_base_path(s, output);
                }
        }
        if (r < 0) {
                fprintf(stderr, "Failed to set sync base: %s\n", strerror(-r));
                goto finish;
        }

        output_fd = -1;

        if (operation == EXTRACT_ARCHIVE) {
                if (input_fd >= 0)
                        r = ca_sync_set_archive_fd(s, input_fd);
                else
                        r = ca_sync_set_archive_auto(s, input);
                if (r < 0) {
                        fprintf(stderr, "Failed to set sync archive: %s\n", strerror(-r));
                        goto finish;
                }

        } else {
                if (input_fd >= 0)
                        r = ca_sync_set_index_fd(s, input_fd);
                else
                        r = ca_sync_set_index_auto(s, input);
                if (r < 0) {
                        fprintf(stderr, "Failed to set sync index: %s\n", strerror(-r));
                        goto finish;
                }
        }
        input_fd = -1;

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                goto finish;

        r = load_feature_flags(s, CA_FORMAT_WITH_MASK);
        if (r < 0)
                goto finish;

        r = ca_sync_set_punch_holes(s, arg_punch_holes);
        if (r < 0) {
                fprintf(stderr, "Failed to configure hole punching: %s\n", strerror(-r));
                goto finish;
        }

        r = ca_sync_set_reflink(s, arg_reflink);
        if (r < 0) {
                fprintf(stderr, "Failed to configure reflinking: %s\n", strerror(-r));
                goto finish;
        }

        r = ca_sync_set_hardlink(s, arg_hardlink);
        if (r < 0) {
                fprintf(stderr, "Failed to configure hardlinking: %s\n", strerror(-r));
                goto finish;
        }

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0) {
                        fprintf(stderr, "Failed to seek to %s: %s\n", seek_path, strerror(-r));
                        goto finish;
                }
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        fprintf(stderr, "Got exit signal, quitting.\n");
                        r = -ESHUTDOWN;
                        goto finish;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM) {
                        fprintf(stderr, "File, URL or resource not found.\n");
                        goto finish;
                }
                if (r < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED:
                        verbose_print_done_extract(s);
                        r = 0;
                        goto finish;

                case CA_SYNC_NEXT_FILE:
                        r = verbose_print_path(s, "Extracting");
                        if (r < 0)
                                goto finish;

                        break;

                case CA_SYNC_DONE_FILE:
                        r = verbose_print_path(s, "Extracted");
                        if (r < 0)
                                goto finish;

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
                                goto finish;
                        break;

                default:
                        assert(false);
                }

                verbose_print_feature_flags(s);

                if (arg_verbose)
                        progress();
        }

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);
        if (output_fd >= 3)
                (void) close(output_fd);

        free(input);
        free(output);

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

static int verb_list(int argc, char *argv[]) {

        typedef enum ListOperation {
                LIST_ARCHIVE,
                LIST_ARCHIVE_INDEX,
                LIST_DIRECTORY,
                _LIST_OPERATION_INVALID = -1
        } ListOperation;

        ListOperation operation = _LIST_OPERATION_INVALID;
        const char *seek_path = NULL;
        int r, input_fd = -1;
        char *input = NULL;
        CaSync *s = NULL;
        bool toplevel_shown = false;

        if (argc > 3) {
                fprintf(stderr, "Input path/URL and subtree path expected.\n");
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
                seek_path = argv[2];

        if (arg_what == WHAT_ARCHIVE)
                operation = LIST_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = LIST_ARCHIVE_INDEX;
        else if (arg_what == WHAT_DIRECTORY)
                operation = LIST_DIRECTORY;
        else if (arg_what != _WHAT_INVALID) {
                fprintf(stderr, "\"list\" operation may only be combined with --what=archive, --what=archive-index or --what=directory.\n");
                r = -EINVAL;
                goto finish;
        }

        if (operation == _LIST_OPERATION_INVALID && input && !streq(input, "-")) {
                if (ca_locator_has_suffix(input, ".catar"))
                        operation = LIST_ARCHIVE;
                else if (ca_locator_has_suffix(input, ".caidx"))
                        operation = LIST_ARCHIVE_INDEX;
        }

        if (!input && IN_SET(operation, LIST_DIRECTORY, _LIST_OPERATION_INVALID)) {
                input = strdup(".");
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
                CaLocatorClass input_class = _CA_LOCATOR_CLASS_INVALID;

                input_class = ca_classify_locator(input);
                if (input_class < 0) {
                        fprintf(stderr, "Failed to determine type of locator: %s\n", input);
                        r = -EINVAL;
                        goto finish;
                }

                if (operation == LIST_DIRECTORY && input_class != CA_LOCATOR_PATH) {
                        fprintf(stderr, "Input must be local path: %s\n", input);
                        r = -EINVAL;
                        goto finish;
                }

                if (input_class == CA_LOCATOR_PATH) {
                        input_fd = open(input, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                        if (input_fd < 0) {
                                r = -errno;
                                fprintf(stderr, "Failed to open %s: %s\n", input, strerror(-r));
                                goto finish;
                        }
                }
        }

        if (input_fd >= 0) {
                struct stat st;

                if (fstat(input_fd, &st) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to stat input: %s\n", strerror(-r));
                        goto finish;
                }

                if (S_ISDIR(st.st_mode)) {
                        if (operation == _LIST_OPERATION_INVALID)
                                operation = LIST_DIRECTORY;
                        else if (operation != LIST_DIRECTORY) {
                                fprintf(stderr, "Input is a directory, but attempted to list archive or index.\n");
                                r = -EINVAL;
                                goto finish;
                        }

                } else if (S_ISREG(st.st_mode)) {

                        if (operation == _LIST_OPERATION_INVALID)
                                operation = LIST_ARCHIVE;
                        else if (!IN_SET(operation, LIST_ARCHIVE, LIST_ARCHIVE_INDEX)) {
                                fprintf(stderr, "Input is a regular file, but attempted to list it as directory.\n");
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        fprintf(stderr, "Input is neither a file or directory. Refusing.\n");
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (streq_ptr(input, "-"))
                input = NULL;

        if (operation == _LIST_OPERATION_INVALID) {
                fprintf(stderr, "Failed to determine what to list. Use --what=archive, --what=archive-index or --what=directory.\n");
                r = -EINVAL;
                goto finish;
        }

        if (!IN_SET(operation, LIST_ARCHIVE, LIST_ARCHIVE_INDEX) && seek_path) {
                fprintf(stderr, "Subtree path only supported when listing archive or archive index.\n");
                r = -EINVAL;
                goto finish;
        }

        seek_path = normalize_seek_path(seek_path);

        if (operation == LIST_ARCHIVE_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        goto finish;
        }

        if (operation == LIST_DIRECTORY)
                s = ca_sync_new_encode();
        else
                s = ca_sync_new_decode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        r = load_chunk_size(s);
        if (r < 0)
                goto finish;

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
        if (r < 0) {
                fprintf(stderr, "Failed to set sync input: %s\n", strerror(-r));
                goto finish;
        }
        input_fd = -1;

        if (operation != LIST_DIRECTORY) {
                r = ca_sync_set_base_mode(s, S_IFDIR);
                if (r < 0) {
                        fprintf(stderr, "Failed to set base mode to directory: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                goto finish;

        r = load_feature_flags(s, CA_FORMAT_WITH_MASK);
        if (r < 0)
                goto finish;

        if (operation != LIST_DIRECTORY) {
                r = ca_sync_set_payload(s, false);
                if (r < 0) {
                        fprintf(stderr, "Failed to enable skipping over payload: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0) {
                        fprintf(stderr, "Failed to seek to %s: %s\n", seek_path, strerror(-r));
                        goto finish;
                }
        }

        if (STR_IN_SET(argv[0], "mtree", "stat")) {
                r = ca_sync_enable_payload_digest(s, true);
                if (r < 0) {
                        fprintf(stderr, "Failed to enable payload digest: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (streq(argv[0], "stat")) {
                r = ca_sync_enable_hardlink_digest(s, true);
                if (r < 0) {
                        fprintf(stderr, "Failed to enable hardlink digest: %s\n", strerror(-r));
                        goto finish;
                }
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        fprintf(stderr, "Got exit signal, quitting.\n");
                        r = -ESHUTDOWN;
                        goto finish;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM) {
                        fprintf(stderr, "File, URL or resource not found.\n");
                        goto finish;
                }
                if (r < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED:
                        r = 0;
                        goto finish;

                case CA_SYNC_NEXT_FILE: {
                        char *path;
                        mode_t mode;

                        r = ca_sync_current_mode(s, &mode);
                        if (r < 0) {
                                fprintf(stderr, "Failed to query current mode: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = ca_sync_current_path(s, &path);
                        if (r < 0) {
                                fprintf(stderr, "Failed to query current path: %s\n", strerror(-r));
                                goto finish;
                        }

                        if (streq(argv[0], "list")) {
                                char ls_mode[LS_FORMAT_MODE_MAX];

                                printf("%s %s\n", ls_format_mode(mode, ls_mode), path);

                                if (!arg_recursive && toplevel_shown) {
                                        r = ca_sync_seek_next_sibling(s);
                                        if (r < 0) {
                                                fprintf(stderr, "Failed to seek to next sibling: %s\n", strerror(-r));
                                                free(path);
                                                goto finish;
                                        }
                                }

                                toplevel_shown = true;

                        } else if (streq(argv[0], "mtree")) {

                                const char *target = NULL, *user = NULL, *group = NULL;
                                uint64_t mtime = UINT64_MAX, size = UINT64_MAX;
                                uid_t uid = UID_INVALID;
                                gid_t gid = GID_INVALID;
                                dev_t rdev = (dev_t) -1;
                                char *escaped;

                                assert(streq(argv[0], "mtree"));

                                (void) ca_sync_current_target(s, &target);
                                (void) ca_sync_current_mtime(s, &mtime);
                                (void) ca_sync_current_size(s, &size);
                                (void) ca_sync_current_uid(s, &uid);
                                (void) ca_sync_current_gid(s, &gid);
                                (void) ca_sync_current_user(s, &user);
                                (void) ca_sync_current_group(s, &group);
                                (void) ca_sync_current_rdev(s, &rdev);

                                r = mtree_escape(path, &escaped);
                                if (r < 0) {
                                        free(path);
                                        log_oom();
                                        goto finish;
                                }

                                fputs(isempty(escaped) ? "." : escaped, stdout);
                                free(escaped);

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
                                        r = mtree_escape(target, &escaped);
                                        if (r < 0) {
                                                free(path);
                                                log_oom();
                                                goto finish;
                                        }

                                        printf(" link=%s", escaped);
                                        free(escaped);
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
                                        r = mtree_escape(user, &escaped);
                                        if (r < 0) {
                                                free(path);
                                                log_oom();
                                                goto finish;
                                        }

                                        printf(" uname=%s", escaped);
                                        free(escaped);
                                }

                                if (group) {
                                        r = mtree_escape(group, &escaped);
                                        if (r < 0) {
                                                free(path);
                                                log_oom();
                                                goto finish;
                                        }

                                        printf(" gname=%s", escaped);
                                        free(escaped);
                                }

                                if (mtime != UINT64_MAX)
                                        printf(" time=%" PRIu64 ".%09" PRIu64,
                                               mtime / UINT64_C(1000000000),
                                               mtime % UINT64_C(1000000000));

                                if (!S_ISREG(mode)) /* End this in a newline — unless this is a regular file, in which case we'll print the payload checksum shortly */
                                        putchar('\n');
                        } else {
                                const char *target = NULL, *user = NULL, *group = NULL;
                                uint64_t mtime = UINT64_MAX, size = UINT64_MAX, offset = UINT64_MAX;
                                char ls_mode[LS_FORMAT_MODE_MAX], ls_flags[LS_FORMAT_CHATTR_MAX], ls_fat_attrs[LS_FORMAT_FAT_ATTRS_MAX];
                                uid_t uid = UID_INVALID;
                                gid_t gid = GID_INVALID;
                                dev_t rdev = (dev_t) -1;
                                unsigned flags = (unsigned) -1;
                                uint32_t fat_attrs = (uint32_t) -1;
                                char *escaped = NULL;
                                const char *xname;
                                const void *xvalue;
                                size_t xsize;

                                /* stat */

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

                                r = mtree_escape(path, &escaped);
                                free(path);
                                if (r < 0) {
                                        log_oom();
                                        goto finish;
                                }

                                printf("    File: %s\n"
                                       "    Mode: %s\n",
                                       isempty(escaped) ? "." : escaped,
                                       strna(ls_format_mode(mode, ls_mode)));

                                escaped = mfree(escaped);

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

                                        if (uid == 0)
                                                user = "root";

                                        if (user) {
                                                r = mtree_escape(user, &escaped);
                                                if (r < 0) {
                                                        log_oom();
                                                        goto finish;
                                                }
                                        }

                                        if (uid_is_valid(uid) && user)
                                                printf("%s (" UID_FMT ")\n", escaped, uid);
                                        else if (uid_is_valid(uid))
                                                printf(UID_FMT "\n", uid);
                                        else
                                                printf("%s\n", escaped);

                                        escaped = mfree(escaped);
                                }

                                if (gid_is_valid(gid) || group) {
                                        printf("   Group: ");

                                        if (gid == 0)
                                                group = "root";

                                        if (group) {
                                                r = mtree_escape(group, &escaped);
                                                if (r < 0) {
                                                        log_oom();
                                                        goto finish;
                                                }
                                        }

                                        if (gid_is_valid(gid) && group)
                                                printf("%s (" GID_FMT ")\n", escaped, gid);
                                        else if (gid_is_valid(gid))
                                                printf(GID_FMT "\n", gid);
                                        else
                                                printf("%s\n", escaped);

                                        escaped = mfree(escaped);
                                }

                                if (target) {
                                        r = mtree_escape(target, &escaped);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }

                                        printf("  Target: %s\n", escaped);
                                        escaped = mfree(escaped);
                                }

                                if (rdev != (dev_t) -1)
                                        printf("  Device: %lu:%lu\n", (unsigned long) major(rdev), (unsigned long) minor(rdev));

                                r = ca_sync_current_xattr(s, CA_ITERATE_FIRST, &xname, &xvalue, &xsize);
                                for (;;) {
                                        char *n, *v;

                                        if (r < 0) {
                                                fprintf(stderr, "Failed to enumerate extended attributes: %s\n", strerror(-r));
                                                goto finish;
                                        }
                                        if (r == 0)
                                                break;

                                        r = mtree_escape(xname, &n);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }

                                        r = mtree_escape_full(xvalue, xsize, &v);
                                        if (r < 0) {
                                                free(n);
                                                log_oom();
                                                goto finish;
                                        }

                                        printf("   XAttr: %s → %s\n", n, v);
                                        free(n);
                                        free(v);

                                        r = ca_sync_current_xattr(s, CA_ITERATE_NEXT, &xname, &xvalue, &xsize);
                                }

                                if (S_ISDIR(mode)) {
                                        /* If this is a directory, we are done now. Otherwise, continue so that we can show the payload and hardlink digests */
                                        r = 0;
                                        goto finish;
                                }
                        }

                        free(path);
                        break;
                }

                case CA_SYNC_DONE_FILE: {
                        mode_t mode;

                        r = ca_sync_current_mode(s, &mode);
                        if (r < 0) {
                                fprintf(stderr, "Failed to query current mode: %s\n", strerror(-r));
                                goto finish;
                        }

                        if (streq(argv[0], "mtree") && S_ISREG(mode)) {
                                static const char * const table[_CA_DIGEST_TYPE_MAX] = {
                                        [CA_DIGEST_SHA256] = "sha256digest",
                                        [CA_DIGEST_SHA512_256] = "sha512256digest",
                                };

                                CaChunkID digest;
                                char v[CA_CHUNK_ID_FORMAT_MAX];

                                r = ca_sync_get_payload_digest(s, &digest);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to read digest.\n");
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

                                r = 0;
                                goto finish;
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
                                goto finish;

                        break;

                default:
                        assert(false);
                }

                verbose_print_feature_flags(s);

                if (arg_verbose)
                        progress();
        }

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);

        free(input);
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
        int r, input_fd = -1;
        char *input = NULL;
        CaSync *s = NULL;
        bool show_payload_digest = false;
        int seeking = false;

        if (argc > 3) {
                fprintf(stderr, "Input path/URL and subtree path expected.\n");
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
                fprintf(stderr, "\"make\" operation may only be combined with --what=archive, --what=blob, --what=archive-index, --what=blob-index or --what=directory.\n");
                r = -EINVAL;
                goto finish;
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
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
                CaLocatorClass input_class;

                input_class = ca_classify_locator(input);
                if (input_class < 0) {
                        fprintf(stderr, "Failed to determine class of locator: %s\n", input);
                        r = -EINVAL;
                        goto finish;
                }

                if (operation == DIGEST_DIRECTORY && input_class != CA_LOCATOR_PATH) {
                        fprintf(stderr, "Input must be local path: %s\n", input);
                        r = -EINVAL;
                        goto finish;
                }

                if (input_class == CA_LOCATOR_PATH) {
                        input_fd = open(input, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                        if (input_fd < 0) {
                                r = -errno;
                                fprintf(stderr, "Failed to open %s: %s\n", input, strerror(-r));
                                goto finish;
                        }
                }
        }

        if (input_fd >= 0) {
                struct stat st;

                if (fstat(input_fd, &st) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to stat input: %s\n", strerror(-r));
                        goto finish;
                }

                if (S_ISDIR(st.st_mode)) {

                        if (operation == _DIGEST_OPERATION_INVALID)
                                operation = DIGEST_DIRECTORY;
                        else if (operation != DIGEST_DIRECTORY) {
                                fprintf(stderr, "Input is a directory, but attempted to list as blob. Refusing.\n");
                                r = -EINVAL;
                                goto finish;
                        }

                } else if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode)) {

                        if (operation == _DIGEST_OPERATION_INVALID)
                                operation = seek_path ? DIGEST_ARCHIVE : DIGEST_BLOB;
                        else if (!IN_SET(operation, DIGEST_ARCHIVE, DIGEST_BLOB, DIGEST_ARCHIVE_INDEX, DIGEST_BLOB_INDEX)) {
                                fprintf(stderr, "Input is not a regular file or block device, but attempted to list as one. Refusing.\n");
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        fprintf(stderr, "Input is a neither a directory, a regular file, nor a block device. Refusing.\n");
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (streq_ptr(input, "-"))
                input = NULL;

        if (operation == _DIGEST_OPERATION_INVALID) {
                fprintf(stderr, "Failed to determine what to calculate digest of. Use --what=archive, --what=blob, --what=archive-index, --what=blob-index or --what=directory.\n");
                r = -EINVAL;
                goto finish;
        }

        if (!IN_SET(operation, DIGEST_ARCHIVE, DIGEST_ARCHIVE_INDEX) && seek_path) {
                fprintf(stderr, "Subtree path only supported when calculating message digest of archive or archive index.\n");
                r = -EINVAL;
                goto finish;
        }

        seek_path = normalize_seek_path(seek_path);

        if (IN_SET(operation, DIGEST_ARCHIVE_INDEX, DIGEST_BLOB_INDEX)) {
                r = set_default_store(input);
                if (r < 0)
                        goto finish;
        }

        if (operation == DIGEST_DIRECTORY || (operation == DIGEST_BLOB && input_fd >= 0))
                s = ca_sync_new_encode();
        else
                s = ca_sync_new_decode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        r = load_chunk_size(s);
        if (r < 0)
                goto finish;

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
        if (r < 0) {
                fprintf(stderr, "Failed to set sync input: %s", strerror(-r));
                goto finish;
        }
        input_fd = -1;

        if (set_base_mode) {
                r = ca_sync_set_base_mode(s, IN_SET(operation, DIGEST_ARCHIVE, DIGEST_ARCHIVE_INDEX) ? S_IFDIR : S_IFREG);
                if (r < 0) {
                        fprintf(stderr, "Failed to set base mode to regular file: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                goto finish;

        r = load_feature_flags(s, IN_SET(operation, DIGEST_BLOB, DIGEST_BLOB_INDEX) ? 0 : CA_FORMAT_WITH_MASK);
        if (r < 0)
                goto finish;

        r = ca_sync_enable_archive_digest(s, true);
        if (r < 0) {
                fprintf(stderr, "Failed to enable archive digest: %s\n", strerror(-r));
                goto finish;
        }

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0) {
                        fprintf(stderr, "Failed to seek to %s: %s\n", seek_path, strerror(-r));
                        goto finish;
                }

                seeking = true;
        }

        (void) send_notify("READY=1");

        for (;;) {
                if (quit) {
                        fprintf(stderr, "Got exit signal, quitting.\n");
                        r = -ESHUTDOWN;
                        goto finish;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM) {
                        fprintf(stderr, "File, URL or resource not found.\n");
                        goto finish;
                }
                if (r < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED:

                        if (!show_payload_digest) { /* When we calc the digest of a directory tree (or top-level blob), show the archive digest */
                                CaChunkID digest;
                                char t[CA_CHUNK_ID_FORMAT_MAX];

                                r = ca_sync_get_archive_digest(s, &digest);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to get archive digest: %s\n", strerror(-r));
                                        goto finish;
                                }

                                printf("%s\n", ca_chunk_id_format(&digest, t));
                                r = 0;
                                goto finish;
                        }

                        break;

                case CA_SYNC_NEXT_FILE:

                        if (seeking) {
                                mode_t mode;

                                /* If we are seeking to a specific path in our archive, then check here if it is a regular file
                                 * (in which case we show the payload checksum) or a directory (in which case we show the
                                 * archive checksum from here. If it is neither, we return failure. */

                                r = ca_sync_current_mode(s, &mode);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to get current mode: %s\n", strerror(-r));
                                        goto finish;
                                }

                                if (S_ISREG(mode)) {
                                        show_payload_digest = true;

                                        r = ca_sync_enable_payload_digest(s, true);
                                        if (r < 0) {
                                                fprintf(stderr, "Failed to enable payload digest: %s\n", strerror(-r));
                                                goto finish;
                                        }

                                } else if (S_ISDIR(mode))
                                        show_payload_digest = false;
                                else {
                                        fprintf(stderr, "Path %s does not refer to a file or directory: %s\n", seek_path, strerror(-r));
                                        r = -ENOTTY;
                                        goto finish;
                                }

                                seeking = false;
                        }

                        r = process_step_generic(s, r, false);
                        if (r < 0)
                                goto finish;

                        break;

                case CA_SYNC_DONE_FILE:

                        if (show_payload_digest) { /* When we calc the digest of a file, show the payload digest */
                                CaChunkID digest;
                                char t[CA_CHUNK_ID_FORMAT_MAX];

                                r = ca_sync_get_payload_digest(s, &digest);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to get payload digest: %s\n", strerror(-r));
                                        goto finish;
                                }

                                printf("%s\n", ca_chunk_id_format(&digest, t));
                                r = 0;
                                goto finish;
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
                                goto finish;
                        break;

                default:
                        assert(false);
                }

                verbose_print_feature_flags(s);

                if (arg_verbose)
                        progress();
        }

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);

        free(input);

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
        int r, input_fd = -1;
        char *input = NULL;
        CaSync *s = NULL;

        if (argc > 3 || argc < 2) {
                fprintf(stderr, "An archive path/URL expected, followed by a mount path.\n");
                return -EINVAL;
        }

        if (argc > 2) {
                input = ca_strip_file_url(argv[1]);
                if (!input) {
                        r = log_oom();
                        goto finish;
                }

                mount_path = argv[2];
        } else
                mount_path = argv[1];

        if (arg_what == WHAT_ARCHIVE)
                operation = MOUNT_ARCHIVE;
        else if (arg_what == WHAT_ARCHIVE_INDEX)
                operation = MOUNT_ARCHIVE_INDEX;
        else if (arg_what != _WHAT_INVALID) {
                fprintf(stderr, "\"mount\" operation may only be combined with --what=archive and --what=archive-index.\n");
                r = -EINVAL;
                goto finish;
        }

        if (operation == _MOUNT_OPERATION_INVALID && input && !streq(input, "-")) {
                if (ca_locator_has_suffix(input, ".caidx"))
                        operation = MOUNT_ARCHIVE_INDEX;
        }

        if (operation == _MOUNT_OPERATION_INVALID)
                operation = MOUNT_ARCHIVE;

        s = ca_sync_new_decode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;

        if (operation == MOUNT_ARCHIVE_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        goto finish;
        }

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_sync_set_rate_limit_bps(s, arg_rate_limit_bps);
                if (r < 0) {
                        fprintf(stderr, "Failed to set rate limit: %s\n", strerror(-r));
                        goto finish;
                }
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
        if (r < 0) {
                fprintf(stderr, "Failed to set sync input: %s\n", strerror(-r));
                goto finish;
        }

        input_fd = -1;

        r = ca_sync_set_base_mode(s, S_IFDIR);
        if (r < 0) {
                fprintf(stderr, "Failed to set base mode to directory: %s\n", strerror(-r));
                goto finish;
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                goto finish;

        r = ca_fuse_run(s, input, mount_path, arg_mkdir);

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);

        free(input);

        return r;
#else
        fprintf(stderr, "Compiled without support for fuse.\n");
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
        ReallocBuffer buffer = {};
        CaBlockDevice *nbd = NULL;
        const char *path = NULL, *name = NULL;
        bool make_symlink = false, rm_symlink = false;
        int r, input_fd = -1;
        char *input = NULL;
        CaSync *s = NULL;

        if (argc > 3) {
                fprintf(stderr, "An blob path/URL expected, possibly followed by a device or symlink name.\n");
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
                fprintf(stderr, "\"mkdev\" operation may only be combined with --what=blob and --what=blob-index.\n");
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
                if (r < 0) {
                        fprintf(stderr, "Failed to set rate limit: %s\n", strerror(-r));
                        goto finish;
                }
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
                fprintf(stderr, "Failed to set sync input: %s\n", strerror(-r));
                goto finish;
        }

        input_fd = -1;

        r = ca_sync_set_base_mode(s, S_IFREG);
        if (r < 0) {
                fprintf(stderr, "Failed to set base mode to regular file: %s\n", strerror(-r));
                goto finish;
        }

        if (arg_store) {
                r = ca_sync_set_store_auto(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
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
                        fprintf(stderr, "Failed to test whether %s is an nbd device: %s\n", name, strerror(-r));
                        goto finish;
                } else if (r > 0) {
                        r = ca_block_device_set_path(nbd, name);
                        if (r < 0) {
                                fprintf(stderr, "Failed to set device path to %s: %s\n", name, strerror(-r));
                                goto finish;
                        }
                } else {
                        const char *k;

                        k = path_startswith(name, "/dev");
                        if (k) {
                                r = ca_block_device_set_friendly_name(nbd, k);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to set friendly name to %s: %s\n", k, strerror(-r));
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
                                fprintf(stderr, "Failed to set NBD size: %s\n", strerror(-r));
                                goto finish;
                        }
                        break;
                }
                if (r == -ESPIPE) {
                        fprintf(stderr, "Seekable archive required.\n");
                        goto finish;
                }
                if (r != -EAGAIN) {
                        fprintf(stderr, "Failed to determine archive size: %s\n", strerror(-r));
                        goto finish;
                }

                r = ca_sync_step(s);
                if (r == -ENOMEDIUM) {
                        fprintf(stderr, "File, URL or resource not found.\n");
                        goto finish;
                }
                if (r < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED:
                        fprintf(stderr, "Premature end of archive.\n");
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
                fprintf(stderr, "Failed to open NBD device: %s\n", strerror(-r));
                goto finish;
        }

        r = ca_block_device_get_path(nbd, &path);
        if (r < 0) {
                fprintf(stderr, "Failed to determine NBD device path: %s\n", strerror(-r));
                goto finish;
        }

        if (make_symlink) {
                if (symlink(path, name) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to create symlink %s → %s: %s\n", name, path, strerror(-r));
                        goto finish;
                }

                rm_symlink = true;
        }

        printf("Attached: %s\n", name ?: path);

        (void) send_notify("READY=1");

        for (;;) {
                uint64_t req_offset = 0, req_size = 0;

                if (quit) {
                        r = 0; /* for the "mkdev" verb quitting does not indicate an incomplete operation, hence return success */
                        goto finish;
                }

                r = ca_block_device_step(nbd);
                if (r < 0) {
                        fprintf(stderr, "Failed to read NBD request: %s\n", strerror(-r));
                        goto finish;
                }

                if (r == CA_BLOCK_DEVICE_CLOSED)
                        break;

                if (r == CA_BLOCK_DEVICE_POLL) {
                        sigset_t ss;

                        block_exit_handler(SIG_BLOCK, &ss);

                        if (quit)
                                r = -ESHUTDOWN;
                        else {
                                r = ca_block_device_poll(nbd, UINT64_MAX, &ss);
                                if ((r == -EINTR || r >= 0) && quit)
                                        r = -ESHUTDOWN;
                        }

                        block_exit_handler(SIG_UNBLOCK, NULL);

                        if (r == -ESHUTDOWN) {
                                r = 0;
                                goto finish;
                        } else if (r < 0) {
                                fprintf(stderr, "Failed to poll for NBD requests: %s\n", strerror(-r));
                                goto finish;
                        }

                        continue;
                }

                assert(r == CA_BLOCK_DEVICE_REQUEST);

                r = ca_block_device_get_request_offset(nbd, &req_offset);
                if (r < 0) {
                        fprintf(stderr, "Failed to get NBD request offset: %s\n", strerror(-r));
                        goto finish;
                }

                r = ca_block_device_get_request_size(nbd, &req_size);
                if (r < 0) {
                        fprintf(stderr, "Failed to get NBD request size: %s\n", strerror(-r));
                        goto finish;
                }

                r = ca_sync_seek_offset(s, req_offset);
                if (r < 0) {
                        fprintf(stderr, "Failed to seek: %s\n", strerror(-r));
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
                                fprintf(stderr, "File, URL or resource not found.\n");
                                goto finish;
                        }
                        if (r < 0) {
                                fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
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
                                        fprintf(stderr, "Failed to send reply: %s\n", strerror(-r));
                                        goto finish;
                                }

                                r = realloc_buffer_advance(&buffer, req_size);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to advance buffer: %s\n", strerror(-r));
                                        goto finish;
                                }

                                done = true;
                                break;

                        case CA_SYNC_PAYLOAD: {
                                const void *p;
                                size_t sz;

                                r = ca_sync_get_payload(s, &p, &sz);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to retrieve synchronizer payload: %s\n", strerror(-r));
                                        goto finish;
                                }

                                if (realloc_buffer_size(&buffer) == 0 && sz >= req_size) {
                                        /* If this is a full reply, then propagate this directly */

                                        r = ca_block_device_put_data(nbd, req_offset, p, MIN(sz, req_size));
                                        if (r < 0) {
                                                fprintf(stderr, "Failed to send reply: %s\n", strerror(-r));
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
                                                        fprintf(stderr, "Failed to send reply: %s\n", strerror(-r));
                                                        goto finish;
                                                }

                                                r = realloc_buffer_advance(&buffer, req_size);
                                                if (r < 0) {
                                                        fprintf(stderr, "Failed to advance buffer: %s\n", strerror(-r));
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
        realloc_buffer_free(&buffer);

        ca_sync_unref(s);
        ca_block_device_unref(nbd);

        if (rm_symlink)
                (void) unlink(name);

        if (input_fd >= 3)
                (void) close(input_fd);

        free(input);

        return r;
}

static void free_stores(CaStore **stores, size_t n_stores) {
        size_t i;

        assert(stores || n_stores == 0);

        for (i = 0; i < n_stores; i++)
                ca_store_unref(stores[i]);
        free(stores);
}

static int allocate_stores(
                const char *wstore_path,
                char **rstore_paths,
                size_t n_rstores,
                CaStore ***ret,
                size_t *ret_n) {

        CaStore **stores = NULL;
        size_t n_stores, n = 0;
        char **rstore_path;
        int r;

        assert(ret);
        assert(ret_n);

        n_stores = !!wstore_path + n_rstores;

        if (n_stores > 0) {
                stores = new0(CaStore*, n_stores);
                if (!stores) {
                        r = log_oom();
                        goto fail;
                }
        }

        if (wstore_path) {
                stores[n] = ca_store_new();
                if (!stores[n]) {
                        r = log_oom();
                        goto fail;
                }
                n++;

                r = ca_store_set_path(stores[n-1], wstore_path);
                if (r < 0) {
                        fprintf(stderr, "Unable to set store path %s: %s\n", wstore_path, strerror(-r));
                        goto fail;
                }
        }

        STRV_FOREACH(rstore_path, rstore_paths) {
                stores[n] = ca_store_new();
                if (!stores[n]) {
                        r = log_oom();
                        goto fail;
                }
                n++;

                r = ca_store_set_path(stores[n-1], *rstore_path);
                if (r < 0) {
                        fprintf(stderr, "Unable to set store path %s: %s\n", *rstore_path, strerror(-r));
                        goto fail;
                }
        }

        *ret = stores;
        *ret_n = n;

        return 0;

fail:
        free_stores(stores, n);

        return r;
}

static int verb_pull(int argc, char *argv[]) {
        const char *base_path, *archive_path, *index_path, *wstore_path;
        size_t n_stores = 0, i;
        CaStore **stores = NULL;
        CaRemote *rr;
        int r;

        if (argc < 5) {
                fprintf(stderr, "Expected at least 5 arguments.\n");
                return -EINVAL;
        }

        base_path = empty_or_dash_to_null(argv[1]);
        archive_path = empty_or_dash_to_null(argv[2]);
        index_path = empty_or_dash_to_null(argv[3]);
        wstore_path = empty_or_dash_to_null(argv[4]);

        n_stores = !!wstore_path + (argc - 5);

        if (base_path) {
                fprintf(stderr, "Pull from base or archive not yet supported.\n");
                return -EOPNOTSUPP;
        }

        if (!archive_path && !index_path && n_stores == 0) {
                fprintf(stderr, "Nothing to do.\n");
                return -EINVAL;
        }

        /* fprintf(stderr, "pull archive: %s index: %s wstore: %s\n", strna(archive_path), strna(index_path), strna(wstore_path)); */

        rr = ca_remote_new();
        if (!rr)
                return log_oom();

        r = ca_remote_set_local_feature_flags(rr,
                                              (n_stores > 0 ? CA_PROTOCOL_READABLE_STORE : 0) |
                                              (index_path ? CA_PROTOCOL_READABLE_INDEX : 0) |
                                              (archive_path ? CA_PROTOCOL_READABLE_ARCHIVE : 0));
        if (r < 0) {
                fprintf(stderr, "Failed to set feature flags: %s\n", strerror(-r));
                return r;
        }

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_remote_set_rate_limit_bps(rr, arg_rate_limit_bps);
                if (r < 0) {
                        fprintf(stderr, "Failed to set rate limit: %s\n", strerror(-r));
                        return r;
                }
        }

        r = ca_remote_set_io_fds(rr, STDIN_FILENO, STDOUT_FILENO);
        if (r < 0) {
                fprintf(stderr, "Failed to set I/O file descriptors: %s\n", strerror(-r));
                return r;
        }

        if (index_path) {
                r = ca_remote_set_index_path(rr, index_path);
                if (r < 0) {
                        fprintf(stderr, "Unable to set index file %s: %s\n", index_path, strerror(-r));
                        goto finish;
                }
        }

        if (archive_path) {
                r = ca_remote_set_archive_path(rr, archive_path);
                if (r < 0) {
                        fprintf(stderr, "Unable to set archive file %s: %s\n", archive_path, strerror(-r));
                        goto finish;
                }
        }

        r = allocate_stores(wstore_path, argv + 5, argc - 5, &stores, &n_stores);
        if (r < 0)
                goto finish;

        for (;;) {
                unsigned put_count;
                sigset_t ss;
                int step;

                if (quit) {
                        fprintf(stderr, "Got exit signal, quitting.\n");
                        r = -ESHUTDOWN;
                        goto finish;
                }

                step = ca_remote_step(rr);
                if (step == -EPIPE || step == CA_REMOTE_FINISHED) /* When somebody pulls from us, he's welcome to terminate any time he likes */
                        break;
                if (step < 0) {
                        fprintf(stderr, "Failed to process remote: %s\n", strerror(-step));
                        r = step;
                        goto finish;
                }

                put_count = 0;
                for (;;) {
                        CaChunkCompression compression;
                        bool found = false;
                        const void *p;
                        CaChunkID id;
                        uint64_t l;

                        r = ca_remote_can_put_chunk(rr);
                        if (r < 0) {
                                fprintf(stderr, "Failed to determine whether there's buffer space for sending: %s\n", strerror(-r));
                                goto finish;
                        }
                        if (r == 0) /* No space to put more */
                                break;

                        r = ca_remote_next_request(rr, &id);
                        if (r == -ENODATA) /* No data requested */
                                break;
                        if (r < 0) {
                                fprintf(stderr, "Failed to determine which chunk to send next: %s\n", strerror(-r));
                                goto finish;
                        }

                        for (i = 0; i < n_stores; i++) {
                                r = ca_store_get(stores[i], &id, CA_CHUNK_COMPRESSED, &p, &l, &compression);
                                if (r >= 0) {
                                        found = true;
                                        break;
                                }
                                if (r != -ENOENT) {
                                        fprintf(stderr, "Failed to query store: %s\n", strerror(-r));
                                        goto finish;
                                }
                        }

                        if (found)
                                r = ca_remote_put_chunk(rr, &id, compression, p, l);
                        else
                                r = ca_remote_put_missing(rr, &id);
                        if (r < 0) {
                                fprintf(stderr, "Failed to enqueue response: %s\n", strerror(-r));
                                goto finish;
                        }

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

                if (r == -ESHUTDOWN) {
                        fprintf(stderr, "Got exit signal, quitting.\n");
                        goto finish;
                }
                if (r < 0) {
                        fprintf(stderr, "Failed to poll remoting engine: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = 0;

finish:
        free_stores(stores, n_stores);
        ca_remote_unref(rr);

        return r;
}

static int verb_push(int argc, char *argv[]) {

        const char *base_path, *archive_path, *index_path, *wstore_path;
        bool index_processed = false, index_written = false, archive_written = false;
        CaStore **stores = NULL;
        CaIndex *index = NULL;
        CaRemote *rr = NULL;
        size_t n_stores = 0;
        int r;

        if (argc < 5) {
                fprintf(stderr, "Expected at least 5 arguments.\n");
                return -EINVAL;
        }

        base_path = empty_or_dash_to_null(argv[1]);
        archive_path = empty_or_dash_to_null(argv[2]);
        index_path = empty_or_dash_to_null(argv[3]);
        wstore_path = empty_or_dash_to_null(argv[4]);

        n_stores = !!wstore_path + (argc - 5);

        if (base_path) {
                fprintf(stderr, "Push to base not yet supported.\n");
                return -EOPNOTSUPP;
        }

        if (!archive_path && !index_path && n_stores == 0) {
                fprintf(stderr, "Nothing to do.\n");
                return -EINVAL;
        }

        /* fprintf(stderr, "push archive: %s index: %s wstore: %s\n", strna(archive_path), strna(index_path), strna(wstore_path)); */

        rr = ca_remote_new();
        if (!rr)
                return log_oom();

        r = ca_remote_set_local_feature_flags(rr,
                                              (wstore_path ? CA_PROTOCOL_WRITABLE_STORE : 0) |
                                              (index_path ? CA_PROTOCOL_WRITABLE_INDEX : 0) |
                                              (archive_path ? CA_PROTOCOL_WRITABLE_ARCHIVE : 0));
        if (r < 0) {
                fprintf(stderr, "Failed to set feature flags: %s\n", strerror(-r));
                return r;
        }

        if (arg_rate_limit_bps != UINT64_MAX) {
                r = ca_remote_set_rate_limit_bps(rr, arg_rate_limit_bps);
                if (r < 0) {
                        fprintf(stderr, "Failed to set rate limit: %s\n", strerror(-r));
                        return r;
                }
        }

        r = ca_remote_set_io_fds(rr, STDIN_FILENO, STDOUT_FILENO);
        if (r < 0) {
                fprintf(stderr, "Failed to set I/O file descriptors: %s\n", strerror(-r));
                return r;
        }

        if (index_path) {
                index = ca_index_new_incremental_read();
                if (!index) {
                        r = log_oom();
                        goto finish;
                }

                r = ca_index_set_path(index, index_path);
                if (r < 0) {
                        fprintf(stderr, "Unable to set index file %s: %s\n", index_path, strerror(-r));
                        goto finish;
                }

                r = ca_index_open(index);
                if (r < 0) {
                        fprintf(stderr, "Failed to open index file %s: %s\n", index_path, strerror(-r));
                        goto finish;
                }
        }

        if (archive_path) {
                r = ca_remote_set_archive_path(rr, archive_path);
                if (r < 0) {
                        fprintf(stderr, "Unable to set archive file %s: %s\n", archive_path, strerror(-r));
                        goto finish;
                }
        }

        r = allocate_stores(wstore_path, argv + 5, argc - 5, &stores, &n_stores);
        if (r < 0)
                goto finish;

        for (;;) {
                bool finished;
                int step;

                if (quit) {
                        fprintf(stderr, "Got exit signal, quitting.\n");
                        r = -ESHUTDOWN;
                        goto finish;
                }

                step = ca_remote_step(rr);
                if (step < 0) {
                        fprintf(stderr, "Failed to process remote: %s\n", strerror(-step));
                        r = step;
                        goto finish;
                }

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

                        if (r == -ESHUTDOWN) {
                                fprintf(stderr, "Got exit signal, quitting.\n");
                                goto finish;
                        }
                        if (r < 0) {
                                fprintf(stderr, "Failed to run remoting engine: %s\n", strerror(-r));
                                goto finish;
                        }

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
                        if (r < 0) {
                                fprintf(stderr, "Failed to read index data: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = ca_index_incremental_write(index, p, n);
                        if (r < 0) {
                                fprintf(stderr, "Failed to write index data: %s\n", strerror(-r));
                                goto finish;
                        }

                        break;
                }

                case CA_REMOTE_READ_INDEX_EOF:
                        r = ca_index_incremental_eof(index);
                        if (r < 0) {
                                fprintf(stderr, "Failed to write index EOF: %s\n", strerror(-r));
                                goto finish;
                        }

                        index_written = true;
                        break;

                case CA_REMOTE_CHUNK: {
                        CaChunkCompression compression;
                        const void *p;
                        CaChunkID id;
                        size_t n;

                        r = ca_remote_next_chunk(rr, CA_CHUNK_AS_IS, &id, &p, &n, &compression);
                        if (r < 0) {
                                fprintf(stderr, "Failed to determine most recent chunk: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = ca_store_put(stores[0], &id, compression, p, n); /* Write to wstore */
                        if (r < 0 && r != -EEXIST) {
                                fprintf(stderr, "Failed to write chunk to store: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = ca_remote_forget_chunk(rr, &id);
                        if (r < 0 && r != -ENOENT) {
                                fprintf(stderr, "Failed to forget chunk: %s\n", strerror(-r));
                                goto finish;
                        }

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
                        if (r < 0) {
                                fprintf(stderr, "Failed to get remote feature flags: %s\n", strerror(-r));
                                goto finish;
                        }

                        /* Only request chunks if this is requested by the client side */
                        if ((remote_flags & CA_PROTOCOL_PUSH_INDEX_CHUNKS) == 0) {
                                index_processed = true;
                                break;
                        }

                        r = ca_index_read_chunk(index, &id, NULL, NULL);
                        if (r == -EAGAIN) /* Not read enough yet */
                                break;
                        if (r < 0) {
                                fprintf(stderr, "Failed to read index: %s\n", strerror(-r));
                                goto finish;
                        }
                        if (r == 0) { /* EOF */
                                index_processed = true;
                                break;
                        }

                        /* fprintf(stderr, "Need %s\n", ca_chunk_id_format(&id, ids)); */

                        r = 0;
                        for (i = 0; i < n_stores; i++) {
                                r = ca_store_has(stores[i], &id);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to test whether chunk exists locally already: %s\n", strerror(-r));
                                        goto finish;
                                }
                                if (r > 0)
                                        break;
                        }
                        if (r > 0) {
                                /* fprintf(stderr, "Already have %s\n", ca_chunk_id_format(&id, ids)); */
                                continue;
                        }

                        /* fprintf(stderr, "Requesting %s\n", ca_chunk_id_format(&id, ids)); */

                        r = ca_remote_request_async(rr, &id, false);
                        if (r < 0 && r != -EALREADY && r != -EAGAIN) {
                                fprintf(stderr, "Failed to request chunk: %s\n", strerror(-r));
                                goto finish;
                        }

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
                if (r < 0) {
                        fprintf(stderr, "Failed to determine if further requests are pending: %s\n", strerror(-r));
                        goto finish;
                }
                if (r > 0)
                        finished = false;

                if (finished) {
                        r = ca_remote_goodbye(rr);
                        if (r < 0 && r != -EALREADY) {
                                fprintf(stderr, "Failed to enqueue goodbye: %s\n", strerror(-r));
                                goto finish;
                        }
                }
        }

        if (index) {
                r = ca_index_install(index);
                if (r < 0) {
                        fprintf(stderr, "Failed to install index on location: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = 0;

finish:
        free_stores(stores, n_stores);
        ca_remote_unref(rr);
        ca_index_unref(index);

        return r;
}

static int verb_udev(int argc, char *argv[]) {
        const char *e;
        char pretty[FILENAME_MAX+1];
        const char *p;
        int fd, r;
        ssize_t n;

        if (argc != 2) {
                fprintf(stderr, "Expected one argument.\n");
                return -EINVAL;
        }

        e = path_startswith(argv[1], "/dev");
        if (!e || !filename_is_valid(e)) {
                fprintf(stderr, "Argument is not a valid device node path: %s.\n", argv[2]);
                return -EINVAL;
        }

        p = strjoina("/run/casync/", e);
        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;

                r = -errno;
                fprintf(stderr, "Failed to open %s: %s\n", p, strerror(-r));
                return r;
        }

        if (flock(fd, LOCK_SH|LOCK_NB) < 0) {

                if (errno != EWOULDBLOCK) {
                        r = -errno;
                        fprintf(stderr, "Failed to check if %s is locked: %s\n", p, strerror(-r));
                        return r;
                }

                /* If we got EWOULDBLOCK, everything is good, there's a casync locking this */

        } else {
                /* Uh? We managed to lock this file? in that case casync behind it died, let's ignore this, and quit immediately. */
                safe_close(fd);
                return 0;
        }

        n = read(fd, pretty, sizeof(pretty));
        safe_close(fd);

        if (n < 0) {
                r = -errno;
                fprintf(stderr, "Failed to read from %s: %s\n", p, strerror(-r));
                return r;
        }
        if ((size_t) n >= sizeof(pretty)) {
                fprintf(stderr, "Stored name read from %s too long.\n", p);
                return -EINVAL;
        }
        if ((size_t) n <= 0 || pretty[n-1] != '\n') {
                fprintf(stderr, "Stored name not newline terminated.\n");
                return -EINVAL;
        }

        pretty[n-1] = 0;
        if (!filename_is_valid(pretty)) {
                fprintf(stderr, "Stored name is invalid: %s\n", pretty);
                return -EINVAL;
        }

        printf("CASYNC_NAME=%s\n", pretty);
        return 0;
}

static int dispatch_verb(int argc, char *argv[]) {
        int r;

        if (argc < 1) {
                fprintf(stderr, "Missing verb. (Invoke '%s --help' for a list of available verbs.)\n", program_invocation_short_name);
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
        else {
                fprintf(stderr, "Unknown verb '%s'. (Invoke '%s --help' for a list of available verbs.)\n", argv[0], program_invocation_short_name);
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
        strv_free(arg_extra_stores);
        strv_free(arg_seeds);

        /* fprintf(stderr, PID_FMT ": exiting with error code: %s\n", getpid(), strerror(-r)); */

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
