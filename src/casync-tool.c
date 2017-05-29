#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>

#include "cachunk.h"
#include "caformat-util.h"
#include "caformat.h"
#include "cafuse.h"
#include "caindex.h"
#include "canbd.h"
#include "caprotocol.h"
#include "caremote.h"
#include "castore.h"
#include "casync.h"
#include "gcrypt-util.h"
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
static bool arg_respect_nodump = true;
static bool arg_undo_immutable = false;
static bool arg_delete = true;
static bool arg_punch_holes = true;
static bool arg_reflink = true;
static bool arg_seed_output = true;
static bool arg_recursive = true;
static char *arg_store = NULL;
static char **arg_extra_stores = NULL;
static char **arg_seeds = NULL;
static size_t arg_chunk_size_avg = 0;
static uint64_t arg_rate_limit_bps = UINT64_MAX;
static uint64_t arg_with = 0;
static uint64_t arg_without = 0;
static uid_t arg_uid_shift = 0, arg_uid_range = 0x10000U;
static bool arg_uid_shift_apply = false;
static bool arg_mkdir = true;

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
               "  -v --verbose               Show terse status information during runtime\n"
               "     --store=PATH            The primary chunk store to use\n"
               "     --extra-store=PATH      Additional chunk store to look for chunks in\n"
               "     --chunk-size-avg=SIZE   The average number of bytes for a chunk file\n"
               "     --seed=PATH             Additional file or directory to use as seed\n"
               "     --recursive=no          List non-recursively\n"
               "     --rate-limit-bps=LIMIT  Maximum bandwidth in bytes/s for remote communication\n"
               "     --respect-nodump=no     Don't respect chattr(1)'s +d 'nodump' flag\n"
               "     --delete=no             Don't delete existing files not listed in archive after extraction\n"
               "     --undo-immutable=yes    When removing existing files, undo chattr(1)'s +i 'immutable' flag\n"
               "     --punch-holes=no        Don't create sparse files\n"
               "     --reflink=no            Don't create reflinks from seeds\n"
               "     --seed-output=no        Don't implicitly add pre-existing output as seed\n"
#if HAVE_FUSE
               "     --mkdir=no              Don't automatically create mount directory if it is missing\n"
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
               "     --with=privileged       Store file data that requires privileges to restore\n"
               "     --with=fuse             Store file data that can exposed again via 'casync mount'\n"
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
               "     --with=xattrs           Store extended file attributes\n"
               "     --with=acl              Store file access control lists\n"
               "     --with=fcaps            Store file capabilities\n"
               "     (and similar: --without=16bit-uids, --without=32bit-uids, ...)\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_STORE = 0x100,
                ARG_EXTRA_STORE,
                ARG_CHUNK_SIZE_AVG,
                ARG_SEED,
                ARG_RATE_LIMIT_BPS,
                ARG_WITH,
                ARG_WITHOUT,
                ARG_WHAT,
                ARG_RESPECT_NODUMP,
                ARG_UNDO_IMMUTABLE,
                ARG_PUNCH_HOLES,
                ARG_REFLINK,
                ARG_SEED_OUTPUT,
                ARG_DELETE,
                ARG_UID_SHIFT,
                ARG_UID_RANGE,
                ARG_RECURSIVE,
                ARG_MKDIR,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "verbose",        no_argument,       NULL, 'v'                },
                { "store",          required_argument, NULL, ARG_STORE          },
                { "extra-store",    required_argument, NULL, ARG_EXTRA_STORE    },
                { "chunk-size-avg", required_argument, NULL, ARG_CHUNK_SIZE_AVG },
                { "seed",           required_argument, NULL, ARG_SEED           },
                { "rate-limit-bps", required_argument, NULL, ARG_RATE_LIMIT_BPS },
                { "with",           required_argument, NULL, ARG_WITH           },
                { "without",        required_argument, NULL, ARG_WITHOUT        },
                { "what",           required_argument, NULL, ARG_WHAT           },
                { "respect-nodump", required_argument, NULL, ARG_RESPECT_NODUMP },
                { "undo-immutable", required_argument, NULL, ARG_UNDO_IMMUTABLE },
                { "delete",         required_argument, NULL, ARG_DELETE         },
                { "punch-holes",    required_argument, NULL, ARG_PUNCH_HOLES    },
                { "reflink",        required_argument, NULL, ARG_REFLINK        },
                { "seed-output",    required_argument, NULL, ARG_SEED_OUTPUT    },
                { "uid-shift",      required_argument, NULL, ARG_UID_SHIFT      },
                { "uid-range",      required_argument, NULL, ARG_UID_RANGE      },
                { "recursive",      required_argument, NULL, ARG_RECURSIVE      },
                { "mkdir",          required_argument, NULL, ARG_MKDIR          },
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

                case ARG_CHUNK_SIZE_AVG:
                        r = parse_size(optarg, &arg_chunk_size_avg);
                        if (r < 0) {
                                fprintf(stderr, "Unable to parse size %s: %s\n", optarg, strerror(-r));
                                return r;
                        }
                        if (arg_chunk_size_avg == 0) {
                                fprintf(stderr, "Chunk size cannot be zero.\n");
                                return -EINVAL;
                        }

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

                case ARG_RESPECT_NODUMP:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --respect-nodump= parameter: %s\n", optarg);
                                return r;
                        }

                        arg_respect_nodump = r;
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

        if (arg_store)
                return 0;

        e = getenv("CASYNC_STORE");
        if (e)
                /* If the default store is set via an environment variable, use that */
                arg_store = strdup(e);
        else if (index_path) {
                char *d;
                CaLocatorClass c;

                /* Otherwise, derive it from the index file path */

                c = ca_classify_locator(index_path);
                if (c < 0) {
                        fprintf(stderr, "Failed to automatically derive store location: %s\n", index_path);
                        return -EINVAL;
                }

                if (c == CA_LOCATOR_URL) {
                        const char *p;

                        p = index_path + strcspn(index_path, ";?");
                        for (;;) {
                                if (p <= index_path)
                                        break;

                                if (p[-1] == '/')
                                        break;

                                p--;
                        }

                        d = strndupa(index_path, p - index_path);
                        arg_store = strjoin(d, "default.castr");
                } else {
                        d = dirname_malloc(index_path);
                        if (!d)
                                return log_oom();
                        arg_store = strjoin(d, "/default.castr");
                        free(d);
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

static uint64_t combined_with_flags(void) {
        return (arg_with == 0 ? CA_FORMAT_WITH_BEST : arg_with) & ~arg_without;
}

static int load_feature_flags(CaSync *s) {
        uint64_t flags;
        int r;

        assert(s);

        flags = combined_with_flags();

        if (arg_respect_nodump)
                flags |= CA_FORMAT_RESPECT_FLAG_NODUMP;

        r = ca_sync_set_feature_flags(s, flags);
        if (r < 0 && r != -ENOTTY) { /* sync object does not have an encoder */
                fprintf(stderr, "Failed to set feature flags: %s\n", strerror(-r));
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
                fprintf(stderr, "Failed to set undo immutable flags: %s\n", strerror(-r));
                return r;
        }

        return 0;
}

static int load_chunk_size(CaSync *s) {
        size_t cavg, cmin, cmax;
        int r;

        if (arg_chunk_size_avg == 0)
                return 0;

        r = ca_sync_set_chunk_size_avg(s, arg_chunk_size_avg);
        if (r < 0) {
                fprintf(stderr, "Failed to set average chunk size to %zu: %s\n", arg_chunk_size_avg, strerror(-r));
                return r;
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

        fprintf(stderr, "Selected chunk sizes: min=%zu..avg=%zu..max=%zu\n", cmin, cavg, cmax);
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

        fprintf(stderr, "Using feature flags: %s\n", t);
        fprintf(stderr, "Respecting chattr(1) -d flag: %s\n", yes_no(flags & CA_FORMAT_RESPECT_FLAG_NODUMP));

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

        fprintf(stderr, "%s\n", path);
        free(path);

        return 1;
}

static int verbose_print_done_make(CaSync *s) {
        uint64_t n_chunks = UINT64_MAX, size = UINT64_MAX, n_reused = UINT64_MAX, covering;
        char buffer[128];
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

                        fprintf(stderr, "Specified feature flags not covered by backing file systems: %s\n", t);
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
        uint64_t n_bytes;
        int r;

        if (!arg_verbose)
                return 0;

        r = ca_sync_get_punch_holes_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of punch holes bytes: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Zero bytes written as sparse files: %" PRIu64 "\n", n_bytes);
        }

        r = ca_sync_get_reflink_bytes(s, &n_bytes);
        if (!IN_SET(r, -ENODATA, -ENOTTY)) {
                if (r < 0) {
                        fprintf(stderr, "Failed to determine number of reflink bytes: %s\n", strerror(-r));
                        return r;
                }

                fprintf(stderr, "Bytes cloned through reflinks: %" PRIu64 "\n", n_bytes);
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

        r = load_feature_flags(s);
        if (r < 0)
                goto finish;

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

                        assert_se(ca_sync_get_digest(s, &digest) >= 0);
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

        r = load_feature_flags(s);
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

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0) {
                        fprintf(stderr, "Failed to seek to %s: %s\n", seek_path, strerror(-r));
                        goto finish;
                }
        }

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

static int do_print_digest(gcry_md_hd_t digest) {
        const void *q;
        char *h;

        assert(digest);

        q = gcry_md_read(digest, GCRY_MD_SHA256);
        if (!q) {
                fprintf(stderr, "Failed to read SHA256 sum.\n");
                return -EINVAL;
        }

        h = hexmem(q, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
        if (!h)
                return log_oom();

        printf(" sha256digest=%s\n", h);
        free(h);

        return 0;
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
        gcry_md_hd_t digest = NULL;
        bool print_digest = false;
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

        r = load_feature_flags(s);
        if (r < 0)
                goto finish;

        if (streq(argv[0], "list") && operation != LIST_DIRECTORY) {
                /* If we shall just list the archive contents we don't need the payload contents, hence let's skip over it */
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

        initialize_libgcrypt();

        if (streq(argv[0], "mtree")) {
                if (gcry_md_open(&digest, GCRY_MD_SHA256, 0) != 0) {
                        fprintf(stderr, "Couldn't allocate SHA256 digest.\n");
                        r = -EIO;
                        goto finish;
                }
        }

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

                case CA_SYNC_PAYLOAD: {
                        const void *p;
                        size_t sz;

                        if (!digest)
                                break;

                        r = ca_sync_get_payload(s, &p, &sz);
                        if (r < 0) {
                                fprintf(stderr, "Failed to acquire payload: %s\n", strerror(-r));
                                goto finish;
                        }

                        gcry_md_write(digest, p, sz);
                        break;
                }

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
                                print_digest = false;

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

                                print_digest = S_ISREG(mode);

                                if (print_digest)
                                        gcry_md_reset(digest);
                                else
                                        putchar('\n');
                        } else {
                                const char *target = NULL, *user = NULL, *group = NULL;
                                uint64_t mtime = UINT64_MAX, size = UINT64_MAX, offset = UINT64_MAX;
                                char ls_mode[LS_FORMAT_MODE_MAX], ls_flags[LS_FORMAT_CHATTR_MAX];
                                uid_t uid = UID_INVALID;
                                gid_t gid = GID_INVALID;
                                dev_t rdev = (dev_t) -1;
                                unsigned flags = (unsigned) -1;
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

                                r = 0;
                                goto finish;
                        }

                        free(path);
                        break;
                }

                case CA_SYNC_DONE_FILE:

                        if (print_digest) {
                                r = do_print_digest(digest);
                                if (r < 0)
                                        goto finish;

                                print_digest = false;
                        }

                        break;

                case CA_SYNC_STEP:
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
        if (print_digest)
                putchar('\n');

        if (digest)
                gcry_md_close(digest);

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

        r = load_feature_flags(s);
        if (r < 0)
                goto finish;

        if (seek_path) {
                r = ca_sync_seek_path(s, seek_path);
                if (r < 0) {
                        fprintf(stderr, "Failed to seek to %s: %s\n", seek_path, strerror(-r));
                        goto finish;
                }
        }

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

                case CA_SYNC_FINISHED: {
                        CaChunkID digest;
                        char t[CA_CHUNK_ID_FORMAT_MAX];

                        assert_se(ca_sync_get_digest(s, &digest) >= 0);
                        printf("%s\n", ca_chunk_id_format(&digest, t));
                        r = 0;
                        goto finish;
                }

                case CA_SYNC_STEP:
                case CA_SYNC_PAYLOAD:
                case CA_SYNC_NEXT_FILE:
                case CA_SYNC_DONE_FILE:
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
                        fprintf(stderr, "Failed to test whether %s is an nbd device: %m\n", strerror(-r));
                        goto finish;
                } else if (r > 0) {
                        r = ca_block_device_set_path(nbd, name);
                        if (r < 0) {
                                fprintf(stderr, "Failed to set device path to %s: %m\n", strerror(-r));
                                goto finish;
                        }
                } else
                        make_symlink = true;
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

        printf("Attached: %s\n", path);

        if (make_symlink) {
                if (symlink(path, name) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to create symlink %s → %s: %s\n", name, path, strerror(-r));
                        goto finish;
                }

                rm_symlink = true;
        }

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
                        size_t l;

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

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
