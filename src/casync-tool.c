#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "cachunk.h"
#include "caformat-util.h"
#include "caformat.h"
#include "caindex.h"
#include "caprotocol.h"
#include "caremote.h"
#include "castore.h"
#include "casync.h"
#include "parse-util.h"
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
static char *arg_store = NULL;
static char **arg_extra_stores = NULL;
static char **arg_seeds = NULL;
static size_t arg_chunk_size_avg = 0;
static uint64_t arg_with = 0;
static uint64_t arg_without = 0;

static void help(void) {
        printf("%1$s [OPTIONS...] make ARCHIVE|ARCHIVE_INDEX|BLOB_INDEX PATH\n"
               "%1$s [OPTIONS...] extract ARCHIVE|ARCHIVE_INDEX|BLOB_INDEX PATH\n"
               "%1$s [OPTIONS...] list ARCHIVE|ARCHIVE_INDEX|DIRECTORY\n"
               "%1$s [OPTIONS...] digest ARCHIVE|BLOB|ARCHIVE_INDEX|BLOB_INDEX|DIRECTORY\n\n"
               "Content-Addressable Data Synchronization Tool\n\n"
               "  -h --help                  Show this help\n"
               "  -v --verbose               Show terse status information during runtime\n"
               "     --store=PATH            The primary chunk store to use\n"
               "     --extra-store=PATH      Additional chunk store to look for chunks in\n"
               "     --chunk-size-avg=SIZE   The average number of bytes for a chunk file\n"
               "     --seed=PATH             Additional file or directory to use as seed\n\n"
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
               "     --with=chattr           Store chattr(1) file attributes\n\n"
               "Individual archive features:\n"
               "     --with=16bit-uids       Store reduced 16bit UID/GID information\n"
               "     --with=32bit-uids       Store full 32bit UID/GID information\n"
               "     --with=user-names       Store user/group names\n"
               "     --with=sec-time         Store timestamps in 1s granularity\n"
               "     --with=usec-time        Store timestamps in 1µs granularity\n"
               "     --with=nsec-time        Store timestamps in 1ns granularity\n"
               "     --with=2sec-time        Store timestamps in 2s granularity\n"
               "     --with=read-only        Store per-file read only flags\n"
               "     --with=permissions      Store full per-file UNIX permissions\n"
               "     --with=symlinks         Store symbolic links\n"
               "     --with=device-nodes     Store block and character device nodes\n"
               "     --with=fifos            Store named pipe nodes\n"
               "     --with=sockets          Store AF_UNIX file system socket nodes\n"
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
               "     (and similar: --without=16bit-uids, --without=32bit-uids, ...)\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_STORE = 0x100,
                ARG_EXTRA_STORE,
                ARG_CHUNK_SIZE_AVG,
                ARG_SEED,
                ARG_WITH,
                ARG_WITHOUT,
                ARG_WHAT,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "verbose",        no_argument,       NULL, 'v'                },
                { "store",          required_argument, NULL, ARG_STORE          },
                { "extra-store",    required_argument, NULL, ARG_EXTRA_STORE    },
                { "chunk-size-avg", required_argument, NULL, ARG_CHUNK_SIZE_AVG },
                { "seed",           required_argument, NULL, ARG_SEED           },
                { "with",           required_argument, NULL, ARG_WITH           },
                { "without",        required_argument, NULL, ARG_WITHOUT        },
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

                case ARG_WITH: {
                        uint64_t u;

                        r = ca_feature_flags_parse_one(optarg, &u);
                        if (r < 0) {
                                fprintf(stderr, "Failed to parse --with= feature flag: %s\n", optarg);
                                return -EINVAL;
                        }

                        arg_with |= u;
                        break;
                }

                case ARG_WITHOUT: {
                        uint64_t u;

                        r = ca_feature_flags_parse_one(optarg, &u);
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

static int load_feature_flags(CaSync *s) {
        uint64_t flags;
        int r;

        assert(s);

        flags = (arg_with == 0 ? CA_FORMAT_WITH_BEST : arg_with) & ~arg_without;

        r = ca_sync_set_feature_flags(s, flags);
        if (r == -ENOTTY) /* sync object does not have an encoder */
                return 0;

        if (r < 0) {
                fprintf(stderr, "Failed to set feature flags: %s\n", strerror(-r));
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

        r = ca_feature_flags_format(flags, &t);
        if (r < 0) {
                fprintf(stderr, "Failed to format feature flags: %s\n", strerror(-r));
                return r;
        }

        fprintf(stderr, "Using feature flags: %s\n", t);
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

static int verbose_print_size(CaSync *s) {
        uint64_t n_chunks = 0, size = 0;
        char buffer[128];
        int r;

        assert(s);

        if (!arg_verbose)
                return 0;

        r = ca_sync_current_archive_chunks(s, &n_chunks);
        if (r < 0 && r != -ENODATA) {
                fprintf(stderr, "Failed to determine number of chunks: %s\n", strerror(-r));
                return r;
        }

        r = ca_sync_current_archive_offset(s, &size);
        if (r < 0 && r != -ENODATA) {
                fprintf(stderr, "Failed to determine archive size: %s\n", strerror(-r));
                return r;
        }

        if (size > 0)
                fprintf(stderr, "Archive size: %s\n", format_bytes(buffer, sizeof(buffer), size));
        if (n_chunks > 0)
                fprintf(stderr, "Number of chunks: %" PRIu64 "\n", n_chunks);

        if (size > 0 && n_chunks > 0)
                fprintf(stderr, "Effective average chunk size: %s\n", format_bytes(buffer, sizeof(buffer), size/n_chunks));

        return 1;
}

static int make(int argc, char *argv[]) {

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
                        r = ca_sync_set_archive_path(s, output);
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
                r = ca_sync_step(s);
                if (r < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED: {
                        CaChunkID digest;
                        char t[CA_CHUNK_ID_FORMAT_MAX];

                        verbose_print_size(s);

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

                case CA_SYNC_STEP:
                        break;

                case CA_SYNC_POLL:
                        r = ca_sync_poll(s, UINT64_MAX);
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
        free(output);

        return r;
}

static int extract(int argc, char *argv[]) {

        typedef enum ExtractOperation {
                EXTRACT_ARCHIVE,
                EXTRACT_ARCHIVE_INDEX,
                EXTRACT_BLOB_INDEX,
                _EXTRACT_OPERATION_INVALID = -1,
        } ExtractOperation;

        ExtractOperation operation = _EXTRACT_OPERATION_INVALID;
        int r, output_fd = -1, input_fd = -1;
        char *input = NULL, *output = NULL;
        CaSync *s = NULL;

        if (argc > 3) {
                fprintf(stderr, "A pair of output and input path/URL expected.\n");
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

        if (!output || streq(output, "-"))
                output_fd = STDOUT_FILENO;
        else {
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

        if (IN_SET(operation, EXTRACT_ARCHIVE_INDEX, EXTRACT_BLOB_INDEX)) {
                r = set_default_store(input);
                if (r < 0)
                        goto finish;
        }

        s = ca_sync_new_decode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        if (output_fd >= 0)
                r = ca_sync_set_base_fd(s, output_fd);
        else {
                assert(output);

                r = ca_sync_set_base_path(s, output);
        }
        if (r < 0) {
                fprintf(stderr, "Failed to set sync base: %s\n", strerror(-r));
                goto finish;
        }

        if (output_fd < 0) {
                r = ca_sync_set_base_mode(s, IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX) ? S_IFDIR : S_IFREG);
                if (r < 0) {
                        fprintf(stderr, "Failed to set base mode to directory: %s\n", strerror(-r));
                        goto finish;
                }
        } else
                output_fd = -1;

        if (operation == EXTRACT_ARCHIVE) {
                if (input_fd >= 0)
                        r = ca_sync_set_archive_fd(s, input_fd);
                else
                        r = ca_sync_set_archive_path(s, input);
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

        for (;;) {
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

                case CA_SYNC_STEP:
                        break;

                case CA_SYNC_NEXT_FILE: {
                        r = verbose_print_path(s, "Extracting");
                        if (r < 0)
                                goto finish;

                        break;
                }

                case CA_SYNC_SEED_NEXT_FILE: {
                        r = verbose_print_path(s, "Seeding");
                        if (r < 0)
                                goto finish;

                        break;
                }

                case CA_SYNC_POLL:
                        r = ca_sync_poll(s, UINT64_MAX);
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

static int list(int argc, char *argv[]) {

        typedef enum ListOperation {
                LIST_ARCHIVE,
                LIST_ARCHIVE_INDEX,
                LIST_DIRECTORY,
                _LIST_OPERATION_INVALID = -1
        } ListOperation;

        CaLocatorClass input_class = _CA_LOCATOR_CLASS_INVALID;
        ListOperation operation = _LIST_OPERATION_INVALID;
        int r, input_fd = -1;
        char *input = NULL;
        CaSync *s = NULL;

        if (argc > 2) {
                fprintf(stderr, "A single input file name expected.\n");
                return -EINVAL;
        }

        if (argc > 1) {
                input = ca_strip_file_url(argv[1]);
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

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
                input_class = ca_classify_locator(input);
                if (input_class < 0) {
                        fprintf(stderr, "Failed to determine type of locator: %s\n", input);
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

        if (operation == LIST_ARCHIVE)
                r = ca_sync_set_archive_fd(s, input_fd);
        else if (operation == LIST_ARCHIVE_INDEX) {
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

        for (;;) {
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

                case CA_SYNC_STEP:
                        break;

                case CA_SYNC_NEXT_FILE: {
                        char *path, ls_mode[LS_FORMAT_MODE_MAX];
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

                        printf("%s %s\n", ls_format_mode(mode, ls_mode), path);
                        free(path);
                        break;
                }

                case CA_SYNC_SEED_NEXT_FILE: {
                        r = verbose_print_path(s, "Seeding");
                        if (r < 0)
                                goto finish;

                        break;
                }

                case CA_SYNC_POLL:
                        r = ca_sync_poll(s, UINT64_MAX);
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

static int digest(int argc, char *argv[]) {

        typedef enum DigestOperation {
                DIGEST_BLOB,
                DIGEST_INDEX,
                DIGEST_DIRECTORY,
                _DIGEST_OPERATION_INVALID = -1,
        } DigestOperation;

        DigestOperation operation = _DIGEST_OPERATION_INVALID;
        int r, input_fd = -1;
        char *input = NULL;
        CaSync *s = NULL;

        if (argc > 2) {
                fprintf(stderr, "A single input file name expected.\n");
                return -EINVAL;
        }

        if (argc > 1) {
                input = ca_strip_file_url(argv[1]);
                if (!input) {
                        r = log_oom();
                        goto finish;
                }
        }

        if (IN_SET(arg_what, WHAT_ARCHIVE, WHAT_BLOB))
                operation = DIGEST_BLOB;
        else if (IN_SET(arg_what, WHAT_ARCHIVE_INDEX, WHAT_BLOB_INDEX))
                operation = DIGEST_INDEX;
        else if (arg_what == WHAT_DIRECTORY)
                operation = DIGEST_DIRECTORY;
        else if (arg_what != _WHAT_INVALID) {
                fprintf(stderr, "\"make\" operation may only be combined with --what=archive, --what=blob, --what=archive-index, --what=blob-index or --what=directory.\n");
                r = -EINVAL;
                goto finish;
        }

        if (input && !streq(input, "-")) {

                if (ca_locator_has_suffix(input, ".catar"))
                        operation = DIGEST_BLOB;
                else if (ca_locator_has_suffix(input, ".caidx") || ca_locator_has_suffix(input, ".caibx"))
                        operation = DIGEST_INDEX;
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
                                operation = DIGEST_BLOB;
                        else if (!IN_SET(operation, DIGEST_BLOB, DIGEST_INDEX)) {
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

        if (operation == DIGEST_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        goto finish;
        }

        if (operation == DIGEST_DIRECTORY)
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

        if (operation == DIGEST_DIRECTORY)
                r = ca_sync_set_base_fd(s, input_fd);
        else if (operation == DIGEST_INDEX) {
                if (input_fd >= 0)
                        r = ca_sync_set_index_fd(s, input_fd);
                else
                        r = ca_sync_set_index_auto(s, input);
        } else {
                assert(operation == DIGEST_BLOB);

                if (input_fd >= 0)
                        r = ca_sync_set_archive_fd(s, input_fd);
                else
                        r = ca_sync_set_archive_path(s, input);
        }
        if (r < 0) {
                fprintf(stderr, "Failed to set sync input: %s", strerror(-r));
                goto finish;
        }
        input_fd = -1;

        if (IN_SET(operation, DIGEST_INDEX, DIGEST_BLOB)) {
                r = ca_sync_set_base_mode(s, S_IFREG);
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

        for (;;) {
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
                        break;

                case CA_SYNC_NEXT_FILE:
                        r = verbose_print_path(s, "Processing");
                        if (r < 0)
                                goto finish;
                        break;

                case CA_SYNC_SEED_NEXT_FILE: {
                        r = verbose_print_path(s, "Seeding");
                        if (r < 0)
                                goto finish;

                        break;
                }

                case CA_SYNC_POLL:
                        r = ca_sync_poll(s, UINT64_MAX);
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

static int pull(int argc, char *argv[]) {
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

        if (base_path || archive_path) {
                fprintf(stderr, "Pull from base or archive not yet supported.\n");
                return -EOPNOTSUPP;
        }

        if (!index_path && n_stores == 0) {
                fprintf(stderr, "Nothing to do.\n");
                return -EINVAL;
        }

        /* fprintf(stderr, "pull index: %s wstore: %s\n", strna(index_path), strna(wstore_path)); */

        rr = ca_remote_new();
        if (!rr)
                return log_oom();

        r = ca_remote_set_local_feature_flags(rr,
                                              (n_stores > 0 ? CA_PROTOCOL_READABLE_STORE : 0) |
                                              (index_path ? CA_PROTOCOL_READABLE_INDEX : 0));
        if (r < 0) {
                fprintf(stderr, "Failed to set feature flags: %s\n", strerror(-r));
                return r;
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

        r = allocate_stores(wstore_path, argv + 5, argc - 5, &stores, &n_stores);
        if (r < 0)
                goto finish;

        for (;;) {
                unsigned put_count;
                int step;

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

                r = ca_remote_poll(rr, UINT64_MAX);
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

static int push(int argc, char *argv[]) {

        const char *base_path, *archive_path, *index_path, *wstore_path;
        bool index_processed = false, index_written = false;
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

        if (base_path || archive_path) {
                fprintf(stderr, "Push to base or archive not yet supported.\n");
                return -EOPNOTSUPP;
        }

        if (!index_path && n_stores == 0) {
                fprintf(stderr, "Nothing to do.\n");
                return -EINVAL;
        }

        /* fprintf(stderr, "push index: %s wstore: %s\n", strna(index_path), strna(wstore_path)); */

        rr = ca_remote_new();
        if (!rr)
                return log_oom();

        r = ca_remote_set_local_feature_flags(rr,
                                              (wstore_path ? CA_PROTOCOL_WRITABLE_STORE : 0) |
                                              (index_path ? CA_PROTOCOL_WRITABLE_INDEX : 0));
        if (r < 0) {
                fprintf(stderr, "Failed to set feature flags: %s\n", strerror(-r));
                return r;
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

        r = allocate_stores(wstore_path, argv + 5, argc - 5, &stores, &n_stores);
        if (r < 0)
                goto finish;

        for (;;) {
                int step;

                step = ca_remote_step(rr);
                if (step < 0) {
                        fprintf(stderr, "Failed to process remote: %s\n", strerror(-step));
                        r = step;
                        goto finish;
                }

                if (step == CA_REMOTE_FINISHED)
                        break;

                switch (step) {

                case CA_REMOTE_POLL:
                        r = ca_remote_poll(rr, UINT64_MAX);
                        if (r < 0) {
                                fprintf(stderr, "Failed to run remoting engine: %s\n", strerror(-r));
                                goto finish;
                        }

                        break;

                case CA_REMOTE_STEP:
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

                        break;
                }

                default:
                        assert(false);
                }

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

                        r = ca_index_read_chunk(index, &id, NULL);
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

                if (index && index_written && index_processed) {

                        r = ca_remote_has_pending_requests(rr);
                        if (r < 0) {
                                fprintf(stderr, "Failed to determine if further requests are pending: %s\n", strerror(-r));
                                goto finish;
                        }

                        if (r == 0) {
                                r = ca_remote_goodbye(rr);
                                if (r < 0 && r != -EALREADY) {
                                        fprintf(stderr, "Failed to enqueue goodbye: %s\n", strerror(-r));
                                        goto finish;
                                }
                        }
                }
        }

        r = ca_index_install(index);
        if (r < 0) {
                fprintf(stderr, "Failed to install index on location: %s\n", strerror(-r));
                goto finish;
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
                fprintf(stderr, "Missing verb.\n");
                return -EINVAL;
        }

        if (streq(argv[0], "help")) {
                help();
                r = 0;
        } else if (streq(argv[0], "make"))
                r = make(argc, argv);
        else if (streq(argv[0], "extract"))
                r = extract(argc, argv);
        else if (streq(argv[0], "list"))
                r = list(argc, argv);
        else if (streq(argv[0], "digest"))
                r = digest(argc, argv);
        else if (streq(argv[0], "pull")) /* "Secret" verb, only to be called by ssh-based remoting. */
                r = pull(argc, argv);
        else if (streq(argv[0], "push")) /* Same here. */
                r = push(argc, argv);
        else {
                fprintf(stderr, "Unknown verb.\n");
                r = -EINVAL;
        }

        return r;
}

int main(int argc, char *argv[]) {
        static const struct sigaction sa = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_RESTART,
        };

        int r;

        assert_se(sigaction(SIGPIPE, &sa, NULL) >= 0);

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = dispatch_verb(argc - optind, argv + optind);

finish:
        free(arg_store);
        strv_free(arg_extra_stores);
        strv_free(arg_seeds);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
