/* SPDX-License-Identifier: LGPL-2.1+ */

#include <curl/curl.h>
#include <getopt.h>
#include <stddef.h>

#include "caprotocol.h"
#include "caremote.h"
#include "cautil.h"
#include "realloc-buffer.h"
#include "util.h"

static volatile sig_atomic_t quit = false;

static bool arg_verbose = false;
static curl_off_t arg_rate_limit_bps = 0;

static enum {
        ARG_PROTOCOL_HTTP,
        ARG_PROTOCOL_FTP,
        ARG_PROTOCOL_HTTPS,
        ARG_PROTOCOL_SFTP,
        _ARG_PROTOCOL_INVALID = -1,
} arg_protocol = _ARG_PROTOCOL_INVALID;

typedef enum ProcessUntil {
        PROCESS_UNTIL_WRITTEN,
        PROCESS_UNTIL_CAN_PUT_CHUNK,
        PROCESS_UNTIL_CAN_PUT_INDEX,
        PROCESS_UNTIL_CAN_PUT_ARCHIVE,
        PROCESS_UNTIL_HAVE_REQUEST,
        PROCESS_UNTIL_FINISHED,
} ProcessUntil;

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
                        if (r > 0)
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

static int acquire_file(CaRemote *rr,
                        CURL *curl,
                        const char *url,
                        size_t (*callback)(const void *p, size_t size, size_t nmemb, void *userdata)) {

        long protocol_status;

        assert(curl);
        assert(url);
        assert(callback);

        if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK) {
                log_error("Failed to set CURL URL to: %s", url);
                return -EIO;
        }

        if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback) != CURLE_OK) {
                log_error("Failed to set CURL callback function.");
                return -EIO;
        }

        if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, rr) != CURLE_OK) {
                log_error("Failed to set CURL private data.");
                return -EIO;
        }

        if (arg_verbose)
                log_info("Acquiring %s...", url);

        if (curl_easy_perform(curl) != CURLE_OK) {
                log_error("Failed to acquire %s", url);
                return -EIO;
        }

        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &protocol_status) != CURLE_OK) {
                log_error("Failed to query response code");
                return -EIO;
        }

        if (IN_SET(arg_protocol, ARG_PROTOCOL_HTTP, ARG_PROTOCOL_HTTPS) && protocol_status != 200) {
                char *m;

                if (arg_verbose)
                        log_error("HTTP server failure %li while requesting %s.", protocol_status, url);

                if (asprintf(&m, "HTTP request on %s failed with status %li", url, protocol_status) < 0)
                        return log_oom();

                (void) ca_remote_abort(rr, protocol_status == 404 ? ENOMEDIUM : EBADR, m);
                free(m);

                return 0;

        } else if (arg_protocol == ARG_PROTOCOL_FTP && (protocol_status < 200 || protocol_status > 299)) {
                char *m;

                if (arg_verbose)
                        log_error("FTP server failure %li while requesting %s.", protocol_status, url);

                if (asprintf(&m, "FTP request on %s failed with status %li", url, protocol_status) < 0)
                        return log_oom();

                (void) ca_remote_abort(rr, EBADR, m);
                free(m);
                return 0;
        } else if (arg_protocol == ARG_PROTOCOL_SFTP && (protocol_status != 0)) {
                char *m;

                if (arg_verbose)
                        log_error("SFTP server failure %li while requesting %s.", protocol_status, url);

                if (asprintf(&m, "SFTP request on %s failed with status %li", url, protocol_status) < 0)
                        return log_oom();

                (void) ca_remote_abort(rr, EBADR, m);
                free(m);
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

        curl = curl_easy_init();
        if (!curl) {
                r = log_oom();
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK) {
                log_error("Failed to turn on location following.");
                r = -EIO;
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_PROTOCOLS, arg_protocol == ARG_PROTOCOL_FTP ? CURLPROTO_FTP :
                                                      arg_protocol == ARG_PROTOCOL_SFTP? CURLPROTO_SFTP: CURLPROTO_HTTP|CURLPROTO_HTTPS) != CURLE_OK) {
                log_error("Failed to limit protocols to HTTP/HTTPS/FTP/SFTP.");
                r = -EIO;
                goto finish;
        }

        if (arg_protocol == ARG_PROTOCOL_SFTP) {
                /* activate the ssh agent. For this to work you need
                   to have ssh-agent running (type set | grep SSH_AGENT to check) */
                if (curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_AGENT) != CURLE_OK)
                        log_error("Failed to turn on ssh agent support, ignoring.");
        }

        if (arg_rate_limit_bps > 0) {
                if (curl_easy_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                        log_error("Failed to set CURL send speed limit.");
                        r = -EIO;
                        goto finish;
                }

                if (curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                        log_error("Failed to set CURL receive speed limit.");
                        r = -EIO;
                        goto finish;
                }
        }

        /* (void) curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); */

        if (archive_url) {
                r = acquire_file(rr, curl, archive_url, write_archive);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        goto flush;

                r = write_archive_eof(rr);
                if (r < 0)
                        goto finish;
        }

        if (index_url) {
                r = acquire_file(rr, curl, index_url, write_index);
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

                if (curl_easy_setopt(curl, CURLOPT_URL, url_buffer) != CURLE_OK) {
                        log_error("Failed to set CURL URL to: %s", index_url);
                        r = -EIO;
                        goto finish;
                }

                if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_chunk) != CURLE_OK) {
                        log_error("Failed to set CURL callback function.");
                        r = -EIO;
                        goto finish;
                }

                if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk_buffer) != CURLE_OK) {
                        log_error("Failed to set CURL private data.");
                        r = -EIO;
                        goto finish;
                }

                if (arg_rate_limit_bps > 0) {
                        if (curl_easy_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                                log_error("Failed to set CURL send speed limit.");
                                r = -EIO;
                                goto finish;
                        }

                        if (curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                                log_error("Failed to set CURL receive speed limit.");
                                r = -EIO;
                                goto finish;
                        }
                }

                if (arg_verbose)
                        log_info("Acquiring %s...", url_buffer);

                if (curl_easy_perform(curl) != CURLE_OK) {
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

                if ((IN_SET(arg_protocol, ARG_PROTOCOL_HTTP, ARG_PROTOCOL_HTTPS) && protocol_status == 200) ||
                    (arg_protocol == ARG_PROTOCOL_FTP && (protocol_status >= 200 && protocol_status <= 299))||
                    (arg_protocol == ARG_PROTOCOL_SFTP && (protocol_status == 0))) {

                        r = ca_remote_put_chunk(rr, &id, CA_CHUNK_COMPRESSED, realloc_buffer_data(&chunk_buffer), realloc_buffer_size(&chunk_buffer));
                        if (r < 0) {
                                log_error_errno(r, "Failed to write chunk: %m");
                                goto finish;
                        }

                } else {
                        if (arg_verbose)
                                log_error("HTTP/FTP/SFTP server failure %li while requesting %s.", protocol_status, url_buffer);

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
                arg_protocol = ARG_PROTOCOL_HTTPS;
        else if (strstr(argv[0], "http"))
                arg_protocol = ARG_PROTOCOL_HTTP;
        else if (strstr(argv[0], "sftp"))
                arg_protocol = ARG_PROTOCOL_SFTP;
        else if (strstr(argv[0], "ftp"))
                arg_protocol = ARG_PROTOCOL_FTP;
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
