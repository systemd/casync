#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "casync.h"
#include "util.h"

static bool arg_verbose = false;
static char *arg_store = NULL;
static char **arg_extra_stores = NULL;
static char **arg_seeds = NULL;

static void help(void) {
        printf("%1$s [OPTIONS...] make ARCHIVE|ARCHIVE_INDEX|BLOB_INDEX PATH\n"
               "%1$s [OPTIONS...] extract ARCHIVE|ARCHIVE_INDEX|BLOB_INDEX PATH\n"
               "%1$s [OPTIONS...] list ARCHIVE|ARCHIVE_INDEX|DIRECTORY\n"
               "%1$s [OPTIONS...] digest ARCHIVE|BLOB|ARCHIVE_INDEX|BLOB_INDEX|DIRECTORY\n\n"
               "Content-Addressable Data Synchronization Tool\n\n"
               "  -h --help                Show this help\n"
               "  -v --verbose             Show terse status information during runtime\n"
               "     --store=PATH          The primary object store to use\n"
               "     --extra-store=PATH    Additional object store to look for objects in\n"
               "     --seed=PATH           Additional file or directory to use as seed\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_STORE = 0x100,
                ARG_EXTRA_STORE,
                ARG_SEED,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'             },
                { "verbose",     no_argument,       NULL, 'v'             },
                { "store",       required_argument, NULL, ARG_STORE       },
                { "extra-store", required_argument, NULL, ARG_EXTRA_STORE },
                { "seed",        required_argument, NULL, ARG_SEED        },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

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

                case ARG_SEED:
                        r = strv_extend(&arg_seeds, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert(false);
                }
        }

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

                /* Otherwise, derive it from the index file path */
                d = dirname_malloc(index_path);
                if (!d)
                        return log_oom();

                arg_store = strjoin(d, "/default.castr");
                free(d);
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
                r = ca_sync_add_store(s, *i);
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

static int make(int argc, char *argv[]) {

        typedef enum MakeOperation {
                MAKE_ARCHIVE,
                MAKE_ARCHIVE_INDEX,
                MAKE_BLOB_INDEX,
                _MAKE_OPERATION_INVALID = -1,
        } MakeOperation;

        MakeOperation operation = _MAKE_OPERATION_INVALID;
        const char *input, *output;
        int r, input_fd = -1;
        CaSync *s = NULL;
        struct stat st;

        if (argc > 3) {
                fprintf(stderr, "A pair of output and input path expected.\n");
                return -EINVAL;
        }

        output = argc > 1 ? argv[1] : NULL;
        input = argc > 2 ? argv[2] : NULL;

        if (output && !streq(output, "-")) {
                if (endswith(output, ".catar"))
                        operation = MAKE_ARCHIVE;
                else if (endswith(output, ".caidx"))
                        operation = MAKE_ARCHIVE_INDEX;
                else if (endswith(output, ".caibx"))
                        operation = MAKE_BLOB_INDEX;
                else {
                        fprintf(stderr, "File to create does not have valid suffix, refusing. (May be one of: .catar, .caidx, .caibx)\n");
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (!input && IN_SET(operation, MAKE_ARCHIVE, MAKE_ARCHIVE_INDEX))
                input =  ".";

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
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

        r = ca_sync_set_base_fd(s, input_fd);
        if (r < 0) {
                fprintf(stderr, "Failed to set sync base: %s\n", strerror(-r));
                goto finish;
        }
        input_fd = -1;

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
                        r = ca_sync_set_index_path(s, output);
                else
                        r = ca_sync_set_index_fd(s, STDOUT_FILENO);
                if (r < 0) {
                        fprintf(stderr, "Failed to set sync index: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (arg_store) {
                r = ca_sync_set_store(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        for (;;) {
                r = ca_sync_step(s);
                if (r < 0) {
                        fprintf(stderr, "Failed to run synchronizer: %s\n", strerror(-r));
                        goto finish;
                }

                switch (r) {

                case CA_SYNC_FINISHED: {
                        CaObjectID digest;
                        char t[CA_OBJECT_ID_FORMAT_MAX];

                        assert_se(ca_sync_get_digest(s, &digest) >= 0);
                        printf("%s\n", ca_object_id_format(&digest, t));

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

                default:
                        assert(false);
                }

                if (arg_verbose)
                        progress();
        }

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);

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
        const char *input, *output;
        CaSync *s = NULL;

        if (argc > 3) {
                fprintf(stderr, "A pairt of output and input path expected.\n");
                return -EINVAL;
        }

        input = argc > 1 ? argv[1] : NULL;
        output = argc > 2 ? argv[2] : NULL;

        if (!input || streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
                if (endswith(input, ".catar"))
                        operation = EXTRACT_ARCHIVE;
                else if (endswith(input, ".caidx"))
                        operation = EXTRACT_ARCHIVE_INDEX;
                else if (endswith(input, ".caibx"))
                        operation = EXTRACT_BLOB_INDEX;
                else {
                        fprintf(stderr, "File to read from does not have valid suffix, refusing. (May be one of: .catar, .caidx, .caibx)\n");
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

        if (!output && IN_SET(operation, EXTRACT_ARCHIVE, EXTRACT_ARCHIVE_INDEX))
                output = ".";

        if (!output || streq(output, "-"))
                output_fd = STDOUT_FILENO;
        else {
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
                fprintf(stderr, "Couldn't figure out operation to execute. Refusing.\n");
                r = -EINVAL;
                goto finish;
        }

        if (IN_SET(operation, EXTRACT_ARCHIVE_INDEX, EXTRACT_BLOB_INDEX)) {
                r = set_default_store(output);
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
                assert(input_fd >= 0);

                r = ca_sync_set_archive_fd(s, input_fd);
                if (r < 0) {
                        fprintf(stderr, "Failed to set sync archive: %s\n", strerror(-r));
                        goto finish;
                }

        } else {
                r = ca_sync_set_index_fd(s, input_fd);
                if (r < 0) {
                        fprintf(stderr, "Failed to set sync index: %s\n", strerror(-r));
                        goto finish;
                }
        }
        input_fd = -1;

        if (arg_store) {
                r = ca_sync_set_store(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                goto finish;

        for (;;) {
                r = ca_sync_step(s);
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

                case CA_SYNC_SEED_STEP:
                        break;

                case CA_SYNC_SEED_NEXT_FILE: {
                        r = verbose_print_path(s, "Seeding");
                        if (r < 0)
                                goto finish;

                        break;
                }

                default:
                        assert(false);
                }

                if (arg_verbose)
                        progress();
        }

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);
        if (output_fd >= 3)
                (void) close(output_fd);

        return r;
}

static int list(int argc, char *argv[]) {

        typedef enum ListOperation {
                LIST_ARCHIVE,
                LIST_ARCHIVE_INDEX,
                LIST_DIRECTORY,
                _LIST_OPERATION_INVALID = -1
        } ListOperation;

        ListOperation operation = _LIST_OPERATION_INVALID;
        const char *input;
        int r, input_fd = -1;
        CaSync *s = NULL;
        struct stat st;

        if (argc > 2) {
                fprintf(stderr, "A single input file name expected.\n");
                return -EINVAL;
        }

        input = argc > 1 ? argv[1] : NULL;

        if (input && !streq(input, "-")) {

                if (endswith(input, ".catar"))
                        operation = LIST_ARCHIVE;
                else if (endswith(input, ".caidx"))
                        operation = LIST_ARCHIVE_INDEX;
        }

        if (!input)
                input = ".";

        if (streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
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

        if (streq_ptr(input, "-"))
                input = NULL;

        if (operation == LIST_ARCHIVE_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        return r;
        }

        if (operation == LIST_DIRECTORY)
                s = ca_sync_new_encode();
        else
                s = ca_sync_new_decode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        if (operation == LIST_ARCHIVE)
                r = ca_sync_set_archive_fd(s, input_fd);
        else if (operation == LIST_ARCHIVE_INDEX)
                r = ca_sync_set_index_fd(s, input_fd);
        else if (operation == LIST_DIRECTORY)
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
                r = ca_sync_set_store(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
        if (r < 0)
                goto finish;

        for (;;) {
                r = ca_sync_step(s);
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

                case CA_SYNC_SEED_STEP:
                        break;

                case CA_SYNC_SEED_NEXT_FILE: {
                        r = verbose_print_path(s, "Seeding");
                        if (r < 0)
                                goto finish;

                        break;
                }
                default:
                        assert(false);
                }

                if (arg_verbose)
                        progress();
        }

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);

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
        const char *input;
        CaSync *s = NULL;
        struct stat st;

        if (argc > 2) {
                fprintf(stderr, "A single input file name expected.\n");
                return -EINVAL;
        }

        input = argc > 1 ? argv[1] : NULL;

        if (input && !streq(input, "-")) {

                if (endswith(input, ".catar"))
                        operation = DIGEST_BLOB;
                else if (endswith(input, ".caidx") || endswith(input, ".caibx"))
                        operation = DIGEST_INDEX;
        }

        if (!input)
                input = ".";

        if (streq(input, "-"))
                input_fd = STDIN_FILENO;
        else {
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

        if (streq_ptr(input, "-"))
                input = NULL;

        if (operation == DIGEST_INDEX) {
                r = set_default_store(input);
                if (r < 0)
                        return r;
        }

        if (operation == DIGEST_INDEX)
                s = ca_sync_new_decode();
        else
                s = ca_sync_new_encode();
        if (!s) {
                r = log_oom();
                goto finish;
        }

        if (IN_SET(operation, DIGEST_BLOB, DIGEST_DIRECTORY))
                r = ca_sync_set_base_fd(s, input_fd);
        else if (operation == DIGEST_INDEX)
                r = ca_sync_set_index_fd(s, input_fd);
        else
                assert(false);
        if (r < 0) {
                fprintf(stderr, "Failed to set sync input: %s", strerror(-r));
                goto finish;
        }
        input_fd = -1;

        if (operation == DIGEST_INDEX) {
                r = ca_sync_set_base_mode(s, S_IFREG);
                if (r < 0) {
                        fprintf(stderr, "Failed to set base mode to regular file: %s\n", strerror(-r));
                        goto finish;
                }
        }

        if (arg_store) {
                r = ca_sync_set_store(s, arg_store);
                if (r < 0) {
                        fprintf(stderr, "Failed to set store: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = load_seeds_and_extra_stores(s);
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
                        CaObjectID digest;
                        char t[CA_OBJECT_ID_FORMAT_MAX];

                        assert_se(ca_sync_get_digest(s, &digest) >= 0);
                        printf("%s\n", ca_object_id_format(&digest, t));
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

                case CA_SYNC_SEED_STEP:
                        break;

                case CA_SYNC_SEED_NEXT_FILE: {
                        r = verbose_print_path(s, "Seeding");
                        if (r < 0)
                                goto finish;

                        break;
                }
                default:
                        assert(false);
                }

                if (arg_verbose)
                        progress();
        }

finish:
        ca_sync_unref(s);

        if (input_fd >= 3)
                (void) close(input_fd);

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
        else {
                fprintf(stderr, "Unknown verb.\n");
                r = -EINVAL;
        }

        return r;
}

int main(int argc, char *argv[]) {
        int r;

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
