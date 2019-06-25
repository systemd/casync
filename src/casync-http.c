/* SPDX-License-Identifier: LGPL-2.1+ */

#include <curl/curl.h>
#include <getopt.h>
#include <stddef.h>
#include <unistd.h>

#include "caprotocol.h"
#include "caremote.h"
#include "cautil.h"
#include "realloc-buffer.h"
#include "util.h"

static volatile sig_atomic_t quit = false;

static bool arg_verbose = false;
static curl_off_t arg_rate_limit_bps = 0;

typedef enum Protocol {
        PROTOCOL_HTTP,
        PROTOCOL_FTP,
        PROTOCOL_HTTPS,
        PROTOCOL_SFTP,
        _PROTOCOL_INVALID = -1,
} Protocol;

static Protocol arg_protocol = _PROTOCOL_INVALID;

typedef enum ProcessUntil {
        PROCESS_UNTIL_WRITTEN,
        PROCESS_UNTIL_CAN_PUT_CHUNK,
        PROCESS_UNTIL_CAN_PUT_INDEX,
        PROCESS_UNTIL_CAN_PUT_ARCHIVE,
        PROCESS_UNTIL_HAVE_REQUEST,
        PROCESS_UNTIL_FINISHED,
} ProcessUntil;

/*
 * protocol helpers
 */

static const char *protocol_str(Protocol protocol) {
        switch (protocol) {
        case PROTOCOL_HTTP:
                return "HTTP";
        case PROTOCOL_FTP:
                return "FTP";
        case PROTOCOL_HTTPS:
                return "HTTPS";
        case PROTOCOL_SFTP:
                return "SFTP";
        default:
                assert_not_reached("Unknown protocol");
        }
}

static bool protocol_status_ok(Protocol protocol, long protocol_status) {
        switch (protocol) {
        case PROTOCOL_HTTP:
        case PROTOCOL_HTTPS:
                if (protocol_status == 200)
                        return true;
                break;
        case PROTOCOL_FTP:
                if (protocol_status >= 200 && protocol_status <= 299)
                        return true;
                break;
        case PROTOCOL_SFTP:
                if (protocol_status == 0)
                        return true;
                break;
        default:
                assert_not_reached("Unknown protocol");
                break;
        }
        return false;
}

/*
 * curl helpers
 */

DEFINE_TRIVIAL_CLEANUP_FUNC(CURL*, curl_easy_cleanup);

#define log_error_curle(code, fmt, ...)                                 \
        log_error_errno(-EIO, fmt ": %s", ##__VA_ARGS__, curl_easy_strerror(code))

#define CURL_SETOPT_EASY(handle, option, value)                         \
        ({                                                              \
                CURLcode _c;                                            \
                _c = curl_easy_setopt(handle, option, (value));         \
                if (_c != CURLE_OK)                                     \
                        return log_error_curle(_c, "Failed to set " #option); \
        })

#define CURL_SETOPT_EASY_CANFAIL(handle, option, value)                 \
        ({                                                              \
                CURLcode _c;                                            \
                _c = curl_easy_setopt(handle, option, (value));         \
                if (_c != CURLE_OK)                                     \
                        log_error_curle(_c, "Failed to set " #option);  \
        })

static inline const char *get_curl_effective_url(CURL *handle) {
        CURLcode c;
        char *effective_url;

        c = curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &effective_url);
        if (c != CURLE_OK) {
                log_error_curle(c, "Failed to get CURLINFO_EFFECTIVE_URL");
                return NULL;
        }

        return effective_url;
}

static int configure_curl_easy_handle(CURL *handle, const char *url) {
        assert(handle);
        assert(url);

        CURL_SETOPT_EASY(handle, CURLOPT_URL, url);

        return 0;
}

typedef size_t (*ca_curl_write_callback_t)(const void *, size_t, size_t, void *);

static int make_curl_easy_handle(CURL **ret,
                                 ca_curl_write_callback_t write_callback,
                                 void *write_data, void *private) {
        _cleanup_(curl_easy_cleanupp) CURL *h = NULL;

        assert(ret);
        assert(write_callback);
        assert(write_data);
        /* private is optional and can be null */

        h = curl_easy_init();
        if (!h)
                return log_oom();

        CURL_SETOPT_EASY(h, CURLOPT_FOLLOWLOCATION, 1L);
        CURL_SETOPT_EASY(h, CURLOPT_PROTOCOLS,
                         arg_protocol == PROTOCOL_FTP ? CURLPROTO_FTP :
                         arg_protocol == PROTOCOL_SFTP ? CURLPROTO_SFTP :
                         CURLPROTO_HTTP | CURLPROTO_HTTPS);

        if (arg_protocol == PROTOCOL_SFTP) {
                /* activate the ssh agent. For this to work you need
                   to have ssh-agent running (type set | grep SSH_AGENT to check) */
                CURL_SETOPT_EASY_CANFAIL(h, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_AGENT);
        }

        if (arg_rate_limit_bps > 0) {
                CURL_SETOPT_EASY(h, CURLOPT_MAX_SEND_SPEED_LARGE, arg_rate_limit_bps);
                CURL_SETOPT_EASY(h, CURLOPT_MAX_RECV_SPEED_LARGE, arg_rate_limit_bps);
        }

        CURL_SETOPT_EASY(h, CURLOPT_WRITEFUNCTION, write_callback);
        CURL_SETOPT_EASY(h, CURLOPT_WRITEDATA, write_data);

        if (private)
                CURL_SETOPT_EASY(h, CURLOPT_PRIVATE, private);

        /* CURL_SETOPT_EASY(h, CURLOPT_VERBOSE, 1L); */

        *ret = TAKE_PTR(h);
        return 0;
}

static CURLcode robust_curl_easy_perform(CURL *curl) {
        uint64_t sleep_base_usec = 100 * 1000;
        unsigned trial = 1;
        unsigned limit = 10;
        CURLcode c;

        assert(curl);

        while (trial < limit) {

                c = curl_easy_perform(curl);

                switch (c) {

                case CURLE_COULDNT_CONNECT: {
                        uint64_t sleep_usec;

                        /* Although this is not considered as a transient error by curl,
                         * this error can happen momentarily while casync is retrieving
                         * all the chunks from a remote. In this case we want to give
                         * a break to the server and retry later.
                         */

                        sleep_usec = sleep_base_usec * trial;
                        log_info("Could not connect, retrying in %" PRIu64 " ms", sleep_usec / 1000);
                        usleep(sleep_usec);
                        trial++;
                        break;
                }

                default:
                        return c;
                        break;
                }
        }

        return c;
}

static int process_remote(CaRemote *rr, ProcessUntil until) {
        int r;

        assert(rr);

        for (;;) {

                switch (until) {

                case PROCESS_UNTIL_CAN_PUT_CHUNK:

                        r = ca_remote_can_put_chunk(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add a chunk to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_CAN_PUT_INDEX:

                        r = ca_remote_can_put_index(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add an index fragment to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_CAN_PUT_ARCHIVE:

                        r = ca_remote_can_put_archive(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add an archive fragment to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_HAVE_REQUEST:

                        r = ca_remote_has_pending_requests(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether there are pending requests.");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_WRITTEN:
                        r = ca_remote_has_unwritten(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether there's more data to write.");
                        if (r == 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_FINISHED:
                        break;

                default:
                        assert(false);
                }

                r = ca_remote_step(rr);
                if (r == -EPIPE || r == CA_REMOTE_FINISHED) {

                        if (until == PROCESS_UNTIL_FINISHED)
                                return 0;

                        return -EPIPE;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to process remoting engine: %m");

                if (r != CA_REMOTE_POLL)
                        continue;

                r = ca_remote_poll(rr, UINT64_MAX, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to poll remoting engine: %m");
        }
}

static size_t write_index(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        CaRemote *rr = userdata;
        size_t product;
        int r;

        product = size * nmemb;

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_INDEX);
        if (r < 0)
                return 0;

        r = ca_remote_put_index(rr, buffer, product);
        if (r < 0) {
                log_error("Failed to put index: %m");
                return 0;
        }

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return product;
}

static int write_index_eof(CaRemote *rr) {
        int r;

        assert(rr);

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_INDEX);
        if (r < 0)
                return r;

        r = ca_remote_put_index_eof(rr);
        if (r < 0)
                return log_error_errno(r, "Failed to put index EOF: %m");

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return 0;
}

static size_t write_archive(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        CaRemote *rr = userdata;
        size_t product;
        int r;

        product = size * nmemb;

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_ARCHIVE);
        if (r < 0)
                return 0;

        r = ca_remote_put_archive(rr, buffer, product);
        if (r < 0) {
                log_error("Failed to put archive: %m");
                return 0;
        }

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return product;
}

static int write_archive_eof(CaRemote *rr) {
        int r;

        assert(rr);

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_ARCHIVE);
        if (r < 0)
                return r;

        r = ca_remote_put_archive_eof(rr);
        if (r < 0)
                return log_error_errno(r, "Failed to put archive EOF: %m");

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return 0;
}

static size_t write_chunk(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        ReallocBuffer *chunk_buffer = userdata;
        size_t product, z;

        product = size * nmemb;

        z = realloc_buffer_size(chunk_buffer) + product;
        if (z < realloc_buffer_size(chunk_buffer)) {
                log_error("Overflow");
                return 0;
        }

        if (z > (CA_PROTOCOL_SIZE_MAX - offsetof(CaProtocolChunk, data))) {
                log_error("Chunk too large");
                return 0;
        }

        if (!realloc_buffer_append(chunk_buffer, buffer, product)) {
                log_oom();
                return 0;
        }

        return product;
}

static char *chunk_url(const char *store_url, const CaChunkID *id) {
        char ids[CA_CHUNK_ID_FORMAT_MAX], *buffer;
        const char *suffix;
        size_t n;

        /* Chop off URL arguments and multiple trailing dashes, then append the chunk ID and ".cacnk" */

        suffix = ca_compressed_chunk_suffix();

        n = strcspn(store_url, "?;");
        while (n > 0 && store_url[n-1] == '/')
                n--;

        buffer = new(char, n + 1 + 4 + 1 + CA_CHUNK_ID_FORMAT_MAX-1 + strlen(suffix) + 1);
        if (!buffer)
                return NULL;

        ca_chunk_id_format(id, ids);

        strcpy(mempcpy(mempcpy(mempcpy(mempcpy(mempcpy(buffer, store_url, n), "/", 1), ids, 4), "/", 1), ids, CA_CHUNK_ID_FORMAT_MAX-1), suffix);

        return buffer;
}

static int acquire_file(CaRemote *rr, CURL *handle) {
        long protocol_status;
        const char *url;

	url = get_curl_effective_url(handle);
        assert(url);

        log_debug("Acquiring %s...", url);

        if (robust_curl_easy_perform(handle) != CURLE_OK) {
                log_error("Failed to acquire %s", url);
                return -EIO;
        }

        if (curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &protocol_status) != CURLE_OK) {
                log_error("Failed to query response code");
                return -EIO;
        }

        if (!protocol_status_ok(arg_protocol, protocol_status)) {
                _cleanup_free_ char *m = NULL;
                int abort_code;

                if (arg_verbose)
                        log_error("%s server failure %li while requesting %s",
                                  protocol_str(arg_protocol), protocol_status, url);

                if (asprintf(&m, "%s request on %s failed with status %li",
                             protocol_str(arg_protocol), url, protocol_status) < 0)
                        return log_oom();

                if (IN_SET(arg_protocol, PROTOCOL_HTTP, PROTOCOL_HTTPS) && protocol_status == 404)
                        abort_code = ENOMEDIUM;
                else
                        abort_code = EBADR;

                (void) ca_remote_abort(rr, abort_code, m);
                return 0;
        }

        return 1;
}

static int run(int argc, char *argv[]) {
        const char *base_url, *archive_url, *index_url, *wstore_url;
        size_t n_stores = 0, current_store = 0;
        CURL *curl = NULL;
        _cleanup_(ca_remote_unrefp) CaRemote *rr = NULL;
        _cleanup_(realloc_buffer_free) ReallocBuffer chunk_buffer = {};
        _cleanup_free_ char *url_buffer = NULL;
        long protocol_status;
        int r;

        if (argc < _CA_REMOTE_ARG_MAX) {
                log_error("Expected at least %d arguments.", _CA_REMOTE_ARG_MAX);
                return -EINVAL;
        }

        /* fprintf(stderr, "base=%s archive=%s index=%s wstore=%s\n", argv[1], argv[2], argv[3], argv[4]); */

        base_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_BASE_URL]);
        archive_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_ARCHIVE_URL]);
        index_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_INDEX_URL]);
        wstore_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_WSTORE_URL]);

        n_stores = !!wstore_url + (argc - _CA_REMOTE_ARG_MAX);

        if (base_url) {
                log_error("Pushing/pulling to base via HTTP not yet supported.");
                return -EOPNOTSUPP;
        }

        if (!archive_url && !index_url && n_stores == 0) {
                log_error("Nothing to do.");
                return -EINVAL;
        }

        rr = ca_remote_new();
        if (!rr) {
                r = log_oom();
                goto finish;
        }

        r = ca_remote_set_local_feature_flags(rr,
                                              (n_stores > 0 ? CA_PROTOCOL_READABLE_STORE : 0) |
                                              (index_url ? CA_PROTOCOL_READABLE_INDEX : 0) |
                                              (archive_url ? CA_PROTOCOL_READABLE_ARCHIVE : 0));
        if (r < 0) {
                log_error("Failed to set feature flags: %m");
                goto finish;
        }

        r = ca_remote_set_io_fds(rr, STDIN_FILENO, STDOUT_FILENO);
        if (r < 0) {
                log_error("Failed to set I/O file descriptors: %m");
                goto finish;
        }

        if (archive_url) {
                _cleanup_(curl_easy_cleanupp) CURL *handle = NULL;

                r = make_curl_easy_handle(&handle, write_archive, rr, NULL);
                if (r < 0)
                        goto finish;

                r = configure_curl_easy_handle(handle, archive_url);
                if (r < 0)
                        goto finish;

                r = acquire_file(rr, handle);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        goto flush;

                r = write_archive_eof(rr);
                if (r < 0)
                        goto finish;
        }

        if (index_url) {
                _cleanup_(curl_easy_cleanupp) CURL *handle = NULL;

                r = make_curl_easy_handle(&handle, write_index, rr, NULL);
                if (r < 0)
                        goto finish;

                r = configure_curl_easy_handle(handle, index_url);
                if (r < 0)
                        goto finish;

                r = acquire_file(rr, handle);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        goto flush;

                r = write_index_eof(rr);
                if (r < 0)
                        goto finish;
        }

        for (;;) {
                const char *store_url;
                CaChunkID id;

                if (quit) {
                        log_info("Got exit signal, quitting.");
                        r = 0;
                        goto finish;
                }

                if (n_stores == 0)  /* No stores? Then we did all we could do */
                        break;

                if (!curl) {
                        r = make_curl_easy_handle(&curl, write_chunk, &chunk_buffer, NULL);
                        if (r < 0)
                                goto finish;
                }

                r = process_remote(rr, PROCESS_UNTIL_HAVE_REQUEST);
                if (r == -EPIPE) {
                        r = 0;
                        goto finish;
                }
                if (r < 0)
                        goto finish;

                r = ca_remote_next_request(rr, &id);
                if (r == -ENODATA)
                        continue;
                if (r < 0) {
                        log_error_errno(r, "Failed to determine next chunk to get: %m");
                        goto finish;
                }

                current_store = current_store % n_stores;
                if (wstore_url)
                        store_url = current_store == 0 ? wstore_url : argv[current_store + _CA_REMOTE_ARG_MAX - 1];
                else
                        store_url = argv[current_store + _CA_REMOTE_ARG_MAX];
                /* current_store++; */

                free(url_buffer);
                url_buffer = chunk_url(store_url, &id);
                if (!url_buffer) {
                        r = log_oom();
                        goto finish;
                }

                r = configure_curl_easy_handle(curl, url_buffer);
                if (r < 0)
                        goto finish;

                log_debug("Acquiring %s...", url_buffer);

                if (robust_curl_easy_perform(curl) != CURLE_OK) {
                        log_error("Failed to acquire %s", url_buffer);
                        r = -EIO;
                        goto finish;
                }

                if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &protocol_status) != CURLE_OK) {
                        log_error("Failed to query response code");
                        r = -EIO;
                        goto finish;
                }

                r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_CHUNK);
                if (r == -EPIPE) {
                        r = 0;
                        goto finish;
                }
                if (r < 0)
                        goto finish;

                if (protocol_status_ok(arg_protocol, protocol_status)) {
                        r = ca_remote_put_chunk(rr, &id, CA_CHUNK_COMPRESSED, realloc_buffer_data(&chunk_buffer), realloc_buffer_size(&chunk_buffer));
                        if (r < 0) {
                                log_error_errno(r, "Failed to write chunk: %m");
                                goto finish;
                        }

                } else {
                        if (arg_verbose)
                                log_error("%s server failure %ld while requesting %s",
                                          protocol_str(arg_protocol), protocol_status,
                                          url_buffer);

                        r = ca_remote_put_missing(rr, &id);
                        if (r < 0) {
                                log_error_errno(r, "Failed to write missing message: %m");
                                goto finish;
                        }
                }

                realloc_buffer_empty(&chunk_buffer);

                r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
                if (r == -EPIPE) {
                        r = 0;
                        goto finish;
                }
                if (r < 0)
                        goto finish;
        }

flush:
        r = process_remote(rr, PROCESS_UNTIL_FINISHED);

finish:
        if (curl)
                curl_easy_cleanup(curl);

        return r;
}

static void help(void) {
        printf("%s -- casync HTTP helper. Do not execute manually.\n", program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "verbose",        no_argument,       NULL, 'v'                },
                { "rate-limit-bps", required_argument, NULL, 'l'                },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        if (strstr(argv[0], "https"))
                arg_protocol = PROTOCOL_HTTPS;
        else if (strstr(argv[0], "http"))
                arg_protocol = PROTOCOL_HTTP;
        else if (strstr(argv[0], "sftp"))
                arg_protocol = PROTOCOL_SFTP;
        else if (strstr(argv[0], "ftp"))
                arg_protocol = PROTOCOL_FTP;
        else {
                log_error("Failed to determine set of protocols to use, refusing.");
                return -EINVAL;
        }

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

                case 'l':
                        arg_rate_limit_bps = strtoll(optarg, NULL, 10);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert(false);
                }
        }

        return 1;
}

static void exit_signal_handler(int signo) {
        quit = true;
}

int main(int argc, char* argv[]) {
        static const struct sigaction ign_sa = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_RESTART,
        };
        static const struct sigaction exit_sa = {
                .sa_handler = exit_signal_handler,
        };

        int r;

        assert_se(sigaction(SIGPIPE, &ign_sa, NULL) >= 0);
        assert_se(sigaction(SIGINT, &exit_sa, NULL) >= 0);
        assert_se(sigaction(SIGTERM, &exit_sa, NULL) >= 0);
        assert_se(sigaction(SIGHUP, &exit_sa, NULL) >= 0);

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (optind >= argc) {
                log_error("Verb expected.");
                r = -EINVAL;
                goto finish;
        }

        if (streq(argv[optind], "pull"))
                r = run(argc - optind, argv + optind);
        else {
                log_error("Unknown verb: %s", argv[optind]);
                r = -EINVAL;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
