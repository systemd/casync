/* SPDX-License-Identifier: LGPL-2.1+ */

#include <curl/curl.h>
#include <getopt.h>
#include <poll.h>
#include <stddef.h>
#include <unistd.h>

#include "caprotocol.h"
#include "caremote.h"
#include "cautil.h"
#include "realloc-buffer.h"
#include "util.h"
#include "list.h"

/* The maximum number of active chunks is defined as the sum of:
 * - number of chunks added to curl multi for download
 * - number of chunks downloaded, and waiting to be sent to remote
 *
 * In situations where the server is local and super fast (ie. we receive chunks
 * faster than we can send them to the remote), around 95% of the active chunks
 * are chunks waiting to be sent to remote, hence this number can be seen as
 * "maximum number of chunks sitting in ram".
 *
 * In situations where the server is away, around 95% of the active chunks are
 * chunks added to curl multi. It doesn't mean "being downloaded" though, it's more
 * a "maximum limit for concurrent downloads". The real number of running downloads
 * might be lower, because:
 * - if we're doing HTTP/1 and parallel connections, the hard limit is actually
 *   defined by `MAX_HOST_CONNECTIONS`.
 * - if we're doing HTTP/2 over a multiplexed connection, the number of parallel
 *   streams is negociated between client and server.
 *
 * In effect, *I think* it's best to make this number quite large, because we
 * don't want to underfeed libcurl and underperform. I think it's better to feed
 * too many handles to the curl multi, and let libcurl decide internally what's
 * best to do with it. Libcurl knows every details about the HTTP connection and
 * will handle (parallel/multiplex/whatever) downloads better than us.
 */
#define MAX_ACTIVE_CHUNKS 64

/* This is the maximum number of parallel connections per host. This should have
 * no effect in case we're doing HTTP/2 with one connection and multiplexing.
 * However, if we're doing HTTP/1, curl will open parallel connections, as HTTP/1
 * pipelining is no longer supported since libcurl 7.62.
 *
 * We want to make sure that we don't open too many parallel connections per host.
 * It seems that the norm for web browsers ranges from 6 to 8.
 */
#define MAX_HOST_CONNECTIONS 8

static volatile sig_atomic_t quit = false;

static int arg_log_level = -1;
static bool arg_verbose = false;
static curl_off_t arg_rate_limit_bps = 0;
static unsigned arg_max_active_chunks = MAX_ACTIVE_CHUNKS;
static unsigned arg_max_host_connections = MAX_HOST_CONNECTIONS;
static bool arg_ssl_trust_peer = false;

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
DEFINE_TRIVIAL_CLEANUP_FUNC(CURLM*, curl_multi_cleanup);

#define log_error_curle(code, fmt, ...)                                 \
        log_error_errno(-EIO, fmt ": %s", ##__VA_ARGS__, curl_easy_strerror(code))

#define log_error_curlm(code, fmt, ...)                                 \
        log_error_errno(-EIO, fmt ": %s", ##__VA_ARGS__, curl_multi_strerror(code))

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

#define CURL_SETOPT_MULTI(handle, option, value)                        \
        ({                                                              \
                CURLMcode _c;                                           \
                _c = curl_multi_setopt(handle, option, (value));        \
                if (_c != CURLM_OK)                                     \
                        return log_error_curlm(_c, "Failed to set " #option); \
        })

#define CURL_SETOPT_MULTI_CANFAIL(handle, option, value)                \
        ({                                                              \
                CURLMcode _c;                                           \
                _c = curl_multi_setopt(handle, option, (value));        \
                if (_c != CURLM_OK)                                     \
                        log_error_curlm(_c, "Failed to set " #option);  \
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

static inline void *get_curl_private(CURL *handle) {
        CURLcode c;
        void *private;

        c = curl_easy_getinfo(handle, CURLINFO_PRIVATE, &private);
        if (c != CURLE_OK) {
                log_error_curle(c, "Failed to get CURLINFO_PRIVATE");
                return NULL;
        }

        return private;
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

        if (arg_protocol == PROTOCOL_SFTP)
                CURL_SETOPT_EASY_CANFAIL(h, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_AGENT);

        if (IN_SET(arg_protocol, PROTOCOL_HTTP, PROTOCOL_HTTPS)) {
                /* Default since libcurl 7.62.0 */
                CURL_SETOPT_EASY_CANFAIL(h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
                CURL_SETOPT_EASY_CANFAIL(h, CURLOPT_PIPEWAIT, 1l);
        }

        if (arg_rate_limit_bps > 0) {
                CURL_SETOPT_EASY(h, CURLOPT_MAX_SEND_SPEED_LARGE, arg_rate_limit_bps);
                CURL_SETOPT_EASY(h, CURLOPT_MAX_RECV_SPEED_LARGE, arg_rate_limit_bps);
        }

        CURL_SETOPT_EASY(h, CURLOPT_WRITEFUNCTION, write_callback);
        CURL_SETOPT_EASY(h, CURLOPT_WRITEDATA, write_data);

        if (private)
                CURL_SETOPT_EASY(h, CURLOPT_PRIVATE, private);

        if (arg_ssl_trust_peer)
                CURL_SETOPT_EASY(h, CURLOPT_SSL_VERIFYPEER, false);

        CURL_SETOPT_EASY(h, CURLOPT_VERBOSE, arg_log_level > 4);

        *ret = TAKE_PTR(h);
        return 0;
}

static int make_curl_multi_handle(CURLM **ret) {
        _cleanup_(curl_multi_cleanup) CURLM *h = NULL;

        assert(ret);

        h = curl_multi_init();
        if (!h)
                return log_oom();

        CURL_SETOPT_MULTI(h, CURLMOPT_MAX_HOST_CONNECTIONS, arg_max_host_connections);

        /* Default since libcurl 7.62.0 */
        CURL_SETOPT_MULTI_CANFAIL(h, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

        *ret = TAKE_PTR(h);
        return 0;
}

/*
 * chunks data
 */

typedef struct ChunkData ChunkData;

struct ChunkData {
        size_t current_store;  /* set to SIZE_MAX if chunk is missing */
        CaChunkID id;
        ReallocBuffer buffer;
};

static void chunk_data_reset(ChunkData *cd, CaChunkID *id) {
        assert(cd);

        cd->id = *id;
        realloc_buffer_empty(&cd->buffer);
}

static void chunk_data_free(ChunkData *cd) {
        if (!cd)
                return;

        realloc_buffer_free(&cd->buffer);
        free(cd);
}

static ChunkData *chunk_data_new(void) {
        ChunkData *cd = NULL;

        cd = new0(ChunkData, 1);

        return cd;
}

/*
 * simple queue implementation
 */

typedef struct QueueItem QueueItem;

struct QueueItem {
        void *data;
        LIST_FIELDS(QueueItem, list);
};

typedef struct Queue {
        LIST_HEAD(QueueItem, head);
} Queue;

static int queue_push(Queue *q, void *data) {
        int r;
        QueueItem *qi;

        assert(q);
        assert(data);

        qi = new0(QueueItem, 1);
        if (!qi) {
                r = log_oom();
                return r;
        }

        qi->data = data;
        LIST_INIT(list, qi);
        LIST_APPEND(list, q->head, qi);

        return 0;
}

static void *queue_pop(Queue *q) {
        QueueItem *qi;
        void *data;

        assert(q);

        qi = q->head;
        if (!qi)
                return NULL;

        LIST_REMOVE(list, q->head, q->head);
        data = qi->data;
        free(qi);

        return data;
}

static void *queue_remove(Queue *q, void *data) {
        QueueItem *i, *n;

        assert(q);

        LIST_FOREACH_SAFE(list, i, n, q->head) {
                if (i->data == data)
                        break;
        }

        if (!i)
                return NULL;

        LIST_REMOVE(list, q->head, i);
        free(i);

        return data;
}

static bool queue_is_empty(Queue *q) {
        assert(q);

        return LIST_IS_EMPTY(q->head);
}

static void queue_free(Queue *q) {
        QueueItem *i, *n;

        if (q == NULL)
                return;

        LIST_FOREACH_SAFE(list, i, n, q->head) {
                free(i);
        }

        free(q);
}

static Queue *queue_new(void) {
        Queue *q;

        q = new0(Queue, 1);
        if (!q)
                return NULL;

        LIST_HEAD_INIT(q->head);
        return q;
}

/*
 * Chunk Downloader
 *
 * We re-use things as much as possible, which means that:
 * - CURL handles are allocated once at the beginning, then re-used all along.
 * - ChunkData objects (ie. ReallocBuffer) as well.
 *
 * During operations, our CURL handles move from one queue to another, ie:
 *   ready -> inprogress -> completed -> ready ...
 */

typedef struct CaChunkDownloader CaChunkDownloader;

struct CaChunkDownloader {
        CaRemote *remote;
        CURLM *multi;
        Queue *ready;       /* CURL handles waiting to be used */
        Queue *inprogress;  /* CURL handles in use (ie. added to curl multi) */
        Queue *completed;   /* CURL handles completed (ie. chunks waiting to be put to remote */

        char *store_url;
};

enum {
      CA_CHUNK_DOWNLOADER_FINISHED,
      CA_CHUNK_DOWNLOADER_POLL
};

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

static size_t write_chunk(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        ReallocBuffer *chunk_buffer = userdata;
        size_t product, z;

        product = size * nmemb;

        z = realloc_buffer_size(chunk_buffer) + product;
        if (z < realloc_buffer_size(chunk_buffer)) {
                log_error("Overflow");
                return 0;
        }

        if (z > CA_PROTOCOL_SIZE_MAX - offsetof(CaProtocolChunk, data)) {
                log_error("Chunk too large");
                return 0;
        }

        if (!realloc_buffer_append(chunk_buffer, buffer, product)) {
                log_oom();
                return 0;
        }

        return product;
}

static void ca_chunk_downloader_free(CaChunkDownloader *dl) {
        CURL *handle;

        if (dl == NULL)
                return;

        while ((handle = queue_pop(dl->inprogress))) {
                CURLMcode c;

                c = curl_multi_remove_handle(dl->multi, handle);
                if (c != CURLM_OK)
                        log_error_curlm(c, "Failed to remove handle");

                chunk_data_free(get_curl_private(handle));
                curl_easy_cleanup(handle);
        }

        while ((handle = queue_pop(dl->ready))) {
                chunk_data_free(get_curl_private(handle));
                curl_easy_cleanup(handle);
        }

        while ((handle = queue_pop(dl->completed))) {
                chunk_data_free(get_curl_private(handle));
                curl_easy_cleanup(handle);
        }

        free(dl->store_url);
        queue_free(dl->ready);
        queue_free(dl->inprogress);
        queue_free(dl->completed);
        curl_multi_cleanup(dl->multi);
        ca_remote_unref(dl->remote);

        free(dl);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(CaChunkDownloader*, ca_chunk_downloader_free);

static CaChunkDownloader *ca_chunk_downloader_new(CaRemote *rr, const char *store_url) {
        CaChunkDownloader *dl = NULL;
        uint64_t i;
        int r;

        dl = new0(CaChunkDownloader, 1);
        if (!dl)
                goto fail;

        dl->remote = ca_remote_ref(rr);

        r = make_curl_multi_handle(&dl->multi);
        if (r < 0)
                goto fail;

        dl->ready = queue_new();
        if (!dl->ready)
                goto fail;

        dl->inprogress = queue_new();
        if (!dl->inprogress)
                goto fail;

        dl->completed = queue_new();
        if (!dl->completed)
                goto fail;

        for (i = 0; i < arg_max_active_chunks; i++) {
                CURL *handle = NULL;
                ChunkData *cd = NULL;

                cd = chunk_data_new();
                if (!cd)
                        goto fail;

                r = make_curl_easy_handle(&handle, write_chunk, &cd->buffer, cd);
                if (r < 0)
                        goto fail;

                queue_push(dl->ready, handle);
        }

        dl->store_url = strdup(store_url);
        if (!dl->store_url)
                goto fail;

        return dl;

fail:
        ca_chunk_downloader_free(dl);
        return NULL;
}

static int configure_handle_for_chunk(CURL *handle, const char *store_url, CaChunkID *id) {
        int r;
        ChunkData *cd = NULL;
        _cleanup_free_ char *url_buffer = NULL;

        cd = get_curl_private(handle);
        if (!cd)
                return -EIO;

        chunk_data_reset(cd, id);

        url_buffer = chunk_url(store_url, id);
        if (!url_buffer)
                return log_oom();

        r = configure_curl_easy_handle(handle, url_buffer);
        if (r < 0)
                return r;

        return 0;
}

/* Get chunk requests from remote, configure curl handles accordingly,
 * add to curl multi, and return the number of chunk requests handled. */
static int ca_chunk_downloader_fetch_chunk_requests(CaChunkDownloader *dl) {
        QueueItem *i, *n;
        int num = 0;

        LIST_FOREACH_SAFE(list, i, n, dl->ready->head) {
                int r;
                CURLMcode c;
                CaChunkID id;
                CURL *handle;

                r = ca_remote_has_pending_requests(dl->remote);
                if (r < 0)
                        return log_error_errno(r, "Failed to query pending requests: %m");
                if (r == 0)
                        break;

                r = ca_remote_next_request(dl->remote, &id);
                /* Even though we just ensured that there is a pending request,
                 * it's possible that next_requests() returns -ENODATA */
                if (r == -ENODATA)
                        return 0;
                if (r == -EPIPE)
                        return r;
                if (r < 0)
                        return log_error_errno(r, "Failed to query next request: %m");

                handle = queue_pop(dl->ready);
                assert(handle);

                r = configure_handle_for_chunk(handle, dl->store_url, &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to configure handle: %m");

                log_debug("Acquiring chunk %s", get_curl_effective_url(handle));

                c = curl_multi_add_handle(dl->multi, handle);
                if (c != CURLM_OK)
                        return log_error_curlm(c, "Failed to add to multi handle");

                queue_push(dl->inprogress, handle);
                num++;
        }

        return num;
}

/* Do the communication with the remote, return a status code */
static int ca_chunk_downloader_remote_step(CaChunkDownloader *dl) {
        for (;;) {
                int r;

                r = ca_remote_step(dl->remote);
                if (r == -EPIPE)
                        return r;
                if (r < 0)
                        return log_error_errno(r, "Failed to process remoting engine: %m");

                switch (r) {
                case CA_REMOTE_POLL:
                        return CA_CHUNK_DOWNLOADER_POLL;
                case CA_REMOTE_FINISHED:
                        return CA_CHUNK_DOWNLOADER_FINISHED;
                case CA_REMOTE_STEP:
                case CA_REMOTE_REQUEST:
                        continue;
                default:
                        assert_not_reached("Unexpected step returned by remote_step()");
                        break;
                }
        }

        assert_not_reached("Should have returned");
}

/* Put chunk requests to the remote, return the number of chunks put */
static int ca_chunk_downloader_put_chunks(CaChunkDownloader *dl) {
        int i;

        for (i = 0; ; i++) {
                int r;
                CURL *handle;
                ChunkData *cd = NULL;

                if (queue_is_empty(dl->completed))
                        break;

                r = ca_remote_can_put_chunk(dl->remote);
                if (r == 0)
                        break;
                if (r == -EPIPE)
                        return r;
                if (r < 0)
                        return log_error_errno(r, "Failed to query can put chunk: %m");

                handle = queue_pop(dl->completed);
                assert(handle);

                cd = get_curl_private(handle);
                if (!cd)
                        return -EIO;

                if (cd->current_store == SIZE_MAX) {
                        r = ca_remote_put_missing(dl->remote, &cd->id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write missing message: %m");
                } else {
                        r = ca_remote_put_chunk(dl->remote, &cd->id, CA_CHUNK_COMPRESSED,
                                                realloc_buffer_data(&cd->buffer),
                                                realloc_buffer_size(&cd->buffer));
                        if (r < 0)
                                return log_error_errno(r, "Failed to write chunk: %m");
                }

                /* At this point, handle and chunk data are left "unconfigured"
                 * in the ready queue. They'll be reconfigured when re-used. */
                queue_push(dl->ready, handle);
        }

        return i;
}

/* Process chunks that were downloaded by curl, return the number of chunks handled */
static int ca_chunk_downloader_process_curl_multi(CaChunkDownloader *dl) {
        int i, n;
        CURLMcode cm;

        cm = curl_multi_perform(dl->multi, &n);
        if (cm != CURLM_OK)
                return log_error_curlm(cm, "Failed to perform curl multi");

        for (i = 0; ; i++) {
                CURLcode c;
                CURLMsg *msg;
                CURL *handle;
                long protocol_status;
                const char *effective_url;
                ChunkData *cd;

                msg = curl_multi_info_read(dl->multi, &n);
                if (!msg)
                        break;

                if (msg->msg != CURLMSG_DONE) {
                        log_error("Unexpected CURL message: %d", msg->msg);
                        return -EIO;
                }

                if (msg->data.result != CURLE_OK)
                        return log_error_curle(msg->data.result, "Failed to acquire chunk");

                handle = msg->easy_handle;

                effective_url = get_curl_effective_url(handle);
                if (!effective_url)
                        return -EIO;

                cd = get_curl_private(handle);
                if (!cd)
                        return -EIO;

                c = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &protocol_status);
                if (c != CURLE_OK)
                        return log_error_curle(c, "Failed to query response code");

                if (!protocol_status_ok(arg_protocol, protocol_status)) {
                        log_error("%s server failure %ld while requesting %s",
                                  protocol_str(arg_protocol), protocol_status,
                                  effective_url);

                        /* No more stores? Set current_store to a special value
                         * to indicate failure. */
                        cd->current_store = SIZE_MAX;
                }

                cm = curl_multi_remove_handle(dl->multi, handle);
                if (cm != CURLM_OK)
                        return log_error_curlm(cm, "Failed to remove curl handle");

                queue_remove(dl->inprogress, handle);
                queue_push(dl->completed, handle);
        }

        return i;
}

static int ca_chunk_downloader_step(CaChunkDownloader *dl) {
        int r;

        /* Handle curl activity */
        r = ca_chunk_downloader_process_curl_multi(dl);
        if (r < 0)
                return log_error_errno(r, "Failed while processing curl multi: %m");

        /* Step around */
        r = ca_chunk_downloader_remote_step(dl);
        if (r == -EPIPE)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed while processing remote engine: %m");
        if (r != CA_CHUNK_DOWNLOADER_POLL)
                return r;

        /* Put as many downloaded chunks as we can */
        r = ca_chunk_downloader_put_chunks(dl);
        if (r == -EPIPE)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed while putting chunks to remote: %m");

        /* Get as many chunk requests as we can */
        r = ca_chunk_downloader_fetch_chunk_requests(dl);
        if (r == -EPIPE)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed while querying remote for chunk requests: %m");

        return CA_CHUNK_DOWNLOADER_POLL;
}

static int get_remote_io_as_curl_waitfds(CaRemote *rr, struct curl_waitfd *ret_input,
                                         struct curl_waitfd *ret_output) {
        int r;
        int input_fd, output_fd;
        short input_poll_events, output_poll_events;
        short input_curl_events, output_curl_events;

        assert(rr);
        assert(ret_input);
        assert(ret_output);

        r = ca_remote_get_io_fds(rr, &input_fd, &output_fd);
        if (r < 0)
                return r;

        r = ca_remote_get_io_events(rr, &input_poll_events, &output_poll_events);
        if (r < 0)
                return r;

        input_curl_events = input_poll_events & POLLIN ? CURL_WAIT_POLLIN : 0;
        output_curl_events = output_poll_events & POLLOUT ? CURL_WAIT_POLLOUT : 0;

        *ret_input = (struct curl_waitfd) {
                .fd = input_fd,
                .events = input_curl_events,
        };

        *ret_output = (struct curl_waitfd) {
                .fd = output_fd,
                .events = output_curl_events,

        };

        return 0;
}

static int ca_chunk_downloader_wait(CaChunkDownloader *dl) {
        int n, r;
        CURLMcode c;
        int curl_timeout_ms = INT_MAX;
        struct curl_waitfd waitfds[2] = {};

        r = get_remote_io_as_curl_waitfds(dl->remote, &waitfds[0], &waitfds[1]);
        if (r < 0)
                return log_error_errno(r, "Failed to get remote io: %m");

        c = curl_multi_wait(dl->multi, waitfds, ELEMENTSOF(waitfds), curl_timeout_ms, &n);
        if (c != CURLM_OK)
                return log_error_curlm(c, "Failed to wait with curl multi");

        return 0;
}

static int download_chunks(CaChunkDownloader *dl) {
        for (;;) {
                int r;

                if (quit) {
                        log_info("Got exit signal, quitting");
                        return 0;
                }

                r = ca_chunk_downloader_step(dl);
                if (r < 0)
                        return r;
                if (r == CA_CHUNK_DOWNLOADER_FINISHED)
                        return 0;

                r = ca_chunk_downloader_wait(dl);
                if (r < 0)
                        return r;
        }
}

/*
 * archive/index download
 */

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
                log_error_errno(r, "Failed to put index: %m");
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
                log_error_errno(r, "Failed to put archive: %m");
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

static int acquire_file(CaRemote *rr, CURL *handle) {
        CURLcode c;
        long protocol_status;
        const char *url;

	url = get_curl_effective_url(handle);
        assert(url);

        log_debug("Acquiring %s...", url);

        c = curl_easy_perform(handle);
        if (c != CURLE_OK)
                return log_error_curle(c, "Failed to acquire %s", url);

        c = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &protocol_status);
        if (c != CURLE_OK)
                return log_error_curle(c, "Failed to query response code");

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
        _cleanup_(ca_remote_unrefp) CaRemote *rr = NULL;
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
        if (!rr)
                return log_oom();

        r = ca_remote_set_local_feature_flags(rr,
                                              (n_stores > 0 ? CA_PROTOCOL_READABLE_STORE : 0) |
                                              (index_url ? CA_PROTOCOL_READABLE_INDEX : 0) |
                                              (archive_url ? CA_PROTOCOL_READABLE_ARCHIVE : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to set feature flags: %m");

        r = ca_remote_set_io_fds(rr, STDIN_FILENO, STDOUT_FILENO);
        if (r < 0)
                return log_error_errno(r, "Failed to set I/O file descriptors: %m");

        if (archive_url) {
                _cleanup_(curl_easy_cleanupp) CURL *handle = NULL;

                r = make_curl_easy_handle(&handle, write_archive, rr, NULL);
                if (r < 0)
                        return r;

                r = configure_curl_easy_handle(handle, archive_url);
                if (r < 0)
                        return r;

                r = acquire_file(rr, handle);
                if (r < 0)
                        return r;
                if (r == 0)
                        goto flush;

                r = write_archive_eof(rr);
                if (r < 0)
                        return r;
        }

        if (index_url) {
                _cleanup_(curl_easy_cleanupp) CURL *handle = NULL;

                r = make_curl_easy_handle(&handle, write_index, rr, NULL);
                if (r < 0)
                        return r;

                r = configure_curl_easy_handle(handle, index_url);
                if (r < 0)
                        return r;

                r = acquire_file(rr, handle);
                if (r < 0)
                        return r;
                if (r == 0)
                        goto flush;

                r = write_index_eof(rr);
                if (r < 0)
                        return r;
        }

        if (n_stores > 0) {
                _cleanup_(ca_chunk_downloader_freep) CaChunkDownloader *dl = NULL;
                const char *store_url;

                current_store = current_store % n_stores;
                if (wstore_url)
                        store_url = current_store == 0 ? wstore_url : argv[current_store + _CA_REMOTE_ARG_MAX - 1];
                else
                        store_url = argv[current_store + _CA_REMOTE_ARG_MAX];
                /* current_store++; */

                dl = ca_chunk_downloader_new(rr, store_url);
                if (!dl)
                        return log_oom();

                r = download_chunks(dl);
                if (r == -EPIPE)
                        return 0;
                if (r < 0)
                        return r;
        }

flush:
        r = process_remote(rr, PROCESS_UNTIL_FINISHED);

        return r;
}

static void help(void) {
        printf("%s -- casync HTTP helper. Do not execute manually.\n", program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_RATE_LIMIT_BPS = 0x100,
                ARG_MAX_ACTIVE_CHUNKS,
                ARG_MAX_HOST_CONNECTIONS,
                ARG_SSL_TRUST_PEER,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "log-level",      required_argument, NULL, 'l'                },
                { "verbose",        no_argument,       NULL, 'v'                },
                { "rate-limit-bps", required_argument, NULL, ARG_RATE_LIMIT_BPS },
                { "max-active-chunks",    required_argument, NULL, ARG_MAX_ACTIVE_CHUNKS    },
                { "max-host-connections", required_argument, NULL, ARG_MAX_HOST_CONNECTIONS },
                { "ssl-trust-peer", no_argument,       NULL, ARG_SSL_TRUST_PEER },
                {}
        };

        int c, r;

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

        while ((c = getopt_long(argc, argv, "hl:v", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 'l':
                        r = set_log_level_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log level \"%s\": %m", optarg);

                        arg_log_level = r;

                        break;

                case 'v':
                        arg_verbose = true;
                        break;

                case ARG_RATE_LIMIT_BPS:
                        arg_rate_limit_bps = strtoll(optarg, NULL, 10);
                        break;

                case ARG_MAX_ACTIVE_CHUNKS:
                        r = safe_atou(optarg, &arg_max_active_chunks);
                        if (r < 0 || arg_max_active_chunks == 0) {
                                log_error("Invalid value for max-active-chunks, refusing");
                                return -EINVAL;
                        }
                        break;

                case ARG_MAX_HOST_CONNECTIONS:
                        r = safe_atou(optarg, &arg_max_host_connections);
                        if (r < 0 || arg_max_host_connections == 0) {
                                log_error("Invalid value for max-host-connections, refusing");
                                return -EINVAL;
                        }
                        break;

                case ARG_SSL_TRUST_PEER:
                        arg_ssl_trust_peer = true;
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
