#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include "caprotocol-util.h"
#include "caprotocol.h"
#include "caremote.h"
#include "cautil.h"
#include "def.h"
#include "realloc-buffer.h"
#include "util.h"

#define REMOTE_BUFFER_SIZE (1024*1024)
#define REMOTE_BUFFER_LOW (1024*4)

typedef enum CaRemoteState {
        CA_REMOTE_HELLO,
        CA_REMOTE_RUNNING,
        CA_REMOTE_EOF,
} CaRemoteState;

struct CaRemote {
        unsigned n_ref;

        CaRemoteState state;

        char *url_prefix;
        char *callout;

        /* char *base_url; */
        char *index_url;
        /* char *archive_url; */
        char *wstore_url; /* The "primary" store, where we write to */
        char **rstore_urls; /* Additional, "secondary" stores we check */

        char *cache_path;
        int cache_fd;
        bool remove_cache;

        int input_fd;
        int output_fd;

        ReallocBuffer input_buffer;
        ReallocBuffer output_buffer;
        ReallocBuffer chunk_buffer;
        ReallocBuffer index_buffer;

        uint64_t queue_start_high, queue_start_low;
        uint64_t queue_end_high, queue_end_low;

        char *index_path;
        char *temporary_index_path;
        int index_fd;

        uint64_t local_feature_flags;
        uint64_t remote_feature_flags;

        CaChunkID last_chunk;
        bool last_chunk_valid;

        pid_t pid;

        bool index_complete;
        bool sent_hello;
        bool sent_goodbye;
};

CaRemote* ca_remote_new(void) {
        CaRemote *rr;

        rr = new0(CaRemote, 1);
        if (!rr)
                return NULL;

        rr->n_ref = 1;

        rr->cache_fd = -1;
        rr->input_fd = -1;
        rr->output_fd = -1;
        rr->index_fd = -1;

        rr->local_feature_flags = UINT64_MAX;
        rr->remote_feature_flags = UINT64_MAX;

        return rr;
}

CaRemote* ca_remote_ref(CaRemote *rr) {
        if (!rr)
                return NULL;

        assert(rr->n_ref > 0);
        rr->n_ref++;

        return rr;
}

CaRemote* ca_remote_unref(CaRemote *rr) {
        if (!rr)
                return NULL;

        assert(rr->n_ref > 0);
        rr->n_ref--;

        if (rr->n_ref > 0)
                return NULL;

        free(rr->url_prefix);
        free(rr->callout);
        /* free(rr->base_url); */
        free(rr->index_url);
        /* free(rr->archive_url); */
        free(rr->wstore_url);
        strv_free(rr->rstore_urls);

        free(rr->cache_path);
        safe_close(rr->cache_fd);

        safe_close(rr->input_fd);
        safe_close(rr->output_fd);

        realloc_buffer_free(&rr->input_buffer);
        realloc_buffer_free(&rr->output_buffer);
        realloc_buffer_free(&rr->chunk_buffer);
        realloc_buffer_free(&rr->index_buffer);

        free(rr->index_path);
        safe_close(rr->index_fd);

        if (rr->temporary_index_path) {
                (void) unlink(rr->temporary_index_path);
                free(rr->temporary_index_path);
        }

        if (rr->pid > 1) {
                /* (void) kill(rr->pid, SIGTERM); */
                (void) wait_for_terminate(rr->pid, NULL);
        }

        return mfree(rr);
}

int ca_remote_set_local_feature_flags(CaRemote *rr, uint64_t flags) {
        if (!rr)
                return -EINVAL;
        if (flags == UINT64_MAX)
                return -EINVAL;
        if (flags & ~CA_PROTOCOL_FEATURE_FLAGS_MAX)
                return -EOPNOTSUPP;

        /* If I don't provide any services and don't want to do anything, then there's no point in all of this */
        if (flags == 0)
                return -EINVAL;
        if (rr->local_feature_flags != UINT64_MAX)
                return -EBUSY;
        if (rr->sent_hello)
                return -EBUSY;

        rr->local_feature_flags = flags;
        return 0;
}

int ca_remote_add_local_feature_flags(CaRemote *rr, uint64_t flags) {
        if (!rr)
                return -EINVAL;
        if (flags == UINT64_MAX)
                return -EINVAL;
        if (flags & ~CA_PROTOCOL_FEATURE_FLAGS_MAX)
                return -EOPNOTSUPP;

        if (flags == 0)
                return 0;
        if (rr->sent_hello)
                return -EBUSY;

        rr->local_feature_flags |= flags;
        return 0;
}

int ca_remote_get_local_feature_flags(CaRemote *rr, uint64_t* flags) {
        if (!rr)
                return -EINVAL;
        if (!flags)
                return -EINVAL;

        if (rr->local_feature_flags == UINT64_MAX)
                return -ENODATA;

        *flags = rr->local_feature_flags;
        return 0;
}

int ca_remote_get_remote_feature_flags(CaRemote *rr, uint64_t* flags) {
        if (!rr)
                return -EINVAL;
        if (!flags)
                return -EINVAL;

        if (rr->remote_feature_flags == UINT64_MAX)
                return -ENODATA;

        *flags = rr->remote_feature_flags;
        return 0;
}

int ca_remote_set_io_fds(CaRemote *rr, int input_fd, int output_fd) {
        if (!rr)
                return -EINVAL;
        if (input_fd < 0)
                return -EINVAL;
        if (output_fd < 0)
                return -EINVAL;

        if (rr->input_fd >= 0)
                return -EBUSY;
        if (rr->output_fd >= 0)
                return -EBUSY;

        rr->input_fd = input_fd;
        rr->output_fd = output_fd;

        return 0;
}

int ca_remote_get_io_fds(CaRemote *rr, int *ret_input_fd, int *ret_output_fd) {
        if (!rr)
                return -EINVAL;
        if (!ret_input_fd)
                return -EINVAL;
        if (!ret_output_fd)
                return -EINVAL;

        if (rr->input_fd < 0 || rr->output_fd < 0)
                return -EUNATCH;

        *ret_input_fd = rr->input_fd;
        *ret_output_fd = rr->output_fd;

        return 0;
}

int ca_remote_get_io_events(CaRemote *rr, short *ret_input_events, short *ret_output_events) {

        if (!rr)
                return -EINVAL;
        if (!ret_input_events)
                return -EINVAL;
        if (!ret_output_events)
                return -EINVAL;

        if (realloc_buffer_size(&rr->input_buffer) < REMOTE_BUFFER_SIZE)
                *ret_input_events = POLLIN;
        else
                *ret_input_events = 0;

        if (realloc_buffer_size(&rr->output_buffer) > 0)
                *ret_output_events = POLLOUT;
        else
                *ret_output_events = 0;

        return 0;
}

static int ca_remote_url_prefix_install(CaRemote *rr, const char *url) {
        const char *e;
        char *prefix;
        size_t n, k;

        assert(rr);
        assert(url);

        /* Explicitly mask out / and ./ as indicators for local directories */
        if (url[0] == '/')
                return -EINVAL;
        if (url[0] == '.' && url[1] == '/')
                return -EINVAL;

        if (!strchr(URL_PROTOCOL_FIRST, url[0]))
                return -EINVAL;

        n = 1 + strspn(url + 1, URL_PROTOCOL_CHARSET);

        e = startswith(url + n, "://");
        if (!e)
                return -EINVAL;

        k = strspn(e, HOSTNAME_CHARSET "@");
        if (k <= 0)
                return -EINVAL;

        if (e[k] != '/' && e[k] != 0)
                return -EINVAL;

        prefix = strndup(url, n + 3 + k);
        if (!prefix)
                return -ENOMEM;

        if (rr->url_prefix) {
                if (!streq(rr->url_prefix, prefix)) {
                        free(prefix);
                        return -EBUSY;
                }

                free(prefix);
                return 0;
        }

        assert(!rr->callout);
        rr->callout = strndup(url, n);
        if (!rr->callout) {
                free(prefix);
                return -ENOMEM;
        }

        rr->url_prefix = prefix;
        return 1;
}

static int ca_remote_ssh_prefix_install(CaRemote *rr, const char *url) {
        char *prefix;
        size_t n;

        assert(rr);
        assert(url);

        /* Explicitly mask out / and ./ as indicators for local directories */
        if (url[0] == '/')
                return -EINVAL;
        if (url[0] == '.' && url[1] == '/')
                return -EINVAL;

        n = strspn(url, HOSTNAME_CHARSET);
        if (n <= 0)
                return -EINVAL;

        if (url[n] == '@') {
                size_t k;

                k = strspn(url + n + 1, HOSTNAME_CHARSET);
                if (k <= 0)
                        return -EINVAL;

                if (url[n+1+k] != ':')
                        return -EINVAL;

                n += 1 + k;

        } else if (url[n] != ':')
                return -EINVAL;

        prefix = strndup(url, n + 1);
        if (!prefix)
                return -ENOMEM;

        if (rr->url_prefix) {
                if (!streq(rr->url_prefix, prefix)) {
                        free(prefix);
                        return -EBUSY;
                }

                free(prefix);
                return 0;
        }

        assert(!rr->callout);

        rr->url_prefix = prefix;
        return 0;
}

static int ca_remote_any_prefix_install(CaRemote *rr, const char *url) {
        int r;

        r = ca_remote_url_prefix_install(rr, url);
        if (r != -EINVAL)
                return r;

        return ca_remote_ssh_prefix_install(rr, url);
}

/* int ca_remote_set_base_url(CaRemote *rr, const char *url) { */
/*         int r; */

/*         if (!rr) */
/*                 return -EINVAL; */
/*         if (!url) */
/*                 return -EINVAL; */
/*         if (rr->base_url) */
/*                 return -EBUSY; */

/*         r = ca_remote_any_prefix_install(rr, url); */
/*         if (r < 0) */
/*                 return r; */

/*         rr->base_url = strdup(url); */
/*         if (!rr->base_url) */
/*                 return -ENOMEM; */

/*         return 0; */
/* } */

/* int ca_remote_set_archive_url(CaRemote *rr, const char *url) { */
/*         int r; */

/*         if (!rr) */
/*                 return -EINVAL; */
/*         if (!url) */
/*                 return -EINVAL; */
/*         if (rr->archive_url) */
/*                 return -EBUSY; */

/*         r = ca_remote_any_prefix_install(rr, url); */
/*         if (r < 0) */
/*                 return r; */

/*         rr->archive_url = strdup(url); */
/*         if (!rr->archive_url) */
/*                 return -ENOMEM; */

/*         return 0; */
/* } */

int ca_remote_set_index_url(CaRemote *rr, const char *url) {
        int r;

        if (!rr)
                return -EINVAL;
        if (!url)
                return -EINVAL;
        if (rr->index_url)
                return -EBUSY;

        r = ca_remote_any_prefix_install(rr, url);
        if (r < 0)
                return r;

        rr->index_url = strdup(url);
        if (!rr->index_url)
                return -ENOMEM;

        return 0;
}

int ca_remote_set_store_url(CaRemote *rr, const char *url) {
        int r;

        if (!rr)
                return -EINVAL;
        if (!url)
                return -EINVAL;
        if (rr->wstore_url)
                return -EBUSY;

        r = ca_remote_any_prefix_install(rr, url);
        if (r < 0)
                return r;

        rr->wstore_url = strdup(url);
        if (!rr->wstore_url)
                return -ENOMEM;

        return 0;
}

int ca_remote_add_store_url(CaRemote *rr, const char *url) {
        int r;

        if (!rr)
                return -EINVAL;
        if (!url)
                return -EINVAL;

        r = ca_remote_any_prefix_install(rr, url);
        if (r < 0)
                return r;

        return strv_extend(&rr->rstore_urls, url);
}

int ca_remote_set_cache_path(CaRemote *rr, const char *path) {
        if (!rr)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (rr->cache_path)
                return -EBUSY;
        if (rr->cache_fd >= 0)
                return -EBUSY;

        rr->cache_path = strdup(path);
        if (!rr->cache_path)
                return -ENOMEM;

        return 0;
}

int ca_remote_set_cache_fd(CaRemote *rr, int fd) {
        if (!rr)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (rr->cache_path)
                return -EBUSY;
        if (rr->cache_fd >= 0)
                return -EBUSY;

        rr->cache_fd = fd;
        return 0;
}

int ca_remote_set_index_path(CaRemote *rr, const char *path) {
        if (!rr)
                return -EINVAL;
        if (!path)
                return -EINVAL;

        if (rr->index_path)
                return -EBUSY;
        if (rr->index_fd >= 0)
                return -EBUSY;

        rr->index_path = strdup(path);
        if (!rr->index_path)
                return -ENOMEM;

        return 0;
}

int ca_remote_set_index_fd(CaRemote *rr, int fd) {
        if (!rr)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        if (rr->index_path)
                return -EBUSY;
        if (rr->index_fd >= 0)
                return -EBUSY;

        rr->index_fd = fd;
        return 0;
}

int ca_remote_open_index_fd(CaRemote *rr) {
        int fd;

        if (!rr)
                return -EINVAL;

        if (!rr->index_path)
                return -ENODATA;
        if (!rr->index_complete)
                return -ENODATA;

        fd = open(rr->index_path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        return fd;
}

static int ca_remote_remove_queue_item(CaRemote *rr, const char *queue_name, const CaChunkID *id) {
        char ids[CA_CHUNK_ID_FORMAT_MAX], *target;
        const char *f;

        assert(rr);
        assert(id);

        if (!ca_chunk_id_format(id, ids))
                return -EINVAL;

        f = strjoina(queue_name, ids, NULL);

        /* Drop position → hash link first */
        if (readlinkat_malloc(rr->cache_fd, f, &target) >= 0) {

                if (safe_atou64(target, NULL) >= 0) { /* Safety check: validate that this is indeed a position nr */
                        const char *g;

                        g = strjoina(queue_name, target, NULL);
                        (void) unlinkat(rr->cache_fd, g, 0);
                }

                free(target);
        }

        /* Drop hash → position link second */
        if (unlinkat(rr->cache_fd, f, 0) < 0)
                return -errno;

        return 0;
}

static int ca_remote_enqueue_request(CaRemote *rr, const CaChunkID *id, bool high_priority) {
        char ids[CA_CHUNK_ID_FORMAT_MAX];
        uint64_t position;
        const char *f, *queue_name;
        char *b;
        int r;

        assert(rr);
        assert(id);
        assert(rr->cache_fd >= 0);

        /* Enqueues a GET request. We maintain a 2-level priority queue on disk for this, in two directories
         * "low-priority" and "high-priority". This could be much easier if we could maintain this entirely in memory,
         * but given that the list might be quite large we use a symlink farm instead. For each queued GET request we
         * create two symlinks: one pointing from the queue position to the chunk hash, and one the other way. That
         * way we can easily enqueue, dequeue and check whether a specific chunk is already queued. */

        if (!ca_chunk_id_format(id, ids))
                return -EINVAL;

        if (high_priority) {
                queue_name = "high-priority/";
                position = rr->queue_end_high;
        } else {
                /* If this is a low-priority request, then check if it is already queued as high-priority, before
                 * enqueuing as low priority. */

                f = strjoina("high-priority/", ids, NULL);
                if (faccessat(rr->cache_fd, f, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                        return 0;

                queue_name = "low-priority/";
                position = rr->queue_end_low;
        }

        if (position == 0)
                (void) mkdirat(rr->cache_fd, queue_name, 0777);

        f = strjoina(queue_name, ids, NULL);
        if (asprintf(&b, "%s%" PRIu64, queue_name, position) < 0)
                return -ENOMEM;

        /* Link the hash → queue position. This way we can easily check if a block is already queued */
        if (symlinkat(b + strlen(queue_name), rr->cache_fd, f) < 0) {
                free(b);
                return errno == EEXIST ? 0 : -errno;
        }

        /* Link the queue position → hash. This way we know what to get next */
        r = symlinkat(ids, rr->cache_fd, b) < 0 ? -errno : 0;
        free(b);
        if (r < 0) {
                (void) unlinkat(rr->cache_fd, f, 0);
                return r;
        }

        if (high_priority) {
                rr->queue_end_high++;

                /* If we enqueued this as high priority, make sure to drop it as low priority. First drop the ID
                 * symlink. */
                (void) ca_remote_remove_queue_item(rr, "low-priority/", id);
        } else
                rr->queue_end_low++;

        /* fprintf(stderr, PID_FMT ": Enqueued request for %s\n", getpid(), ids); */

        return 1;
}

static int ca_remote_dequeue_request(CaRemote *rr, int only_high_priority, CaChunkID *ret, bool *ret_high_priority) {
        const char *queue_name;
        uint64_t position;
        char *target, *b;
        CaChunkID id;
        bool hp;
        int r;

        assert(rr);
        assert(ret);
        assert(rr->cache_fd >= 0);

        if (rr->queue_start_high < rr->queue_end_high && only_high_priority != 0) {
                hp = true;
                position = rr->queue_start_high;
                queue_name = "high-priority/";
        } else if (rr->queue_start_low < rr->queue_end_low && only_high_priority <= 0) {
                hp = false;
                position = rr->queue_start_low;
                queue_name = "low-priority/";
        } else
                return -ENODATA;

        if (asprintf(&b, "%s%" PRIu64, queue_name, position) < 0)
                return -ENOMEM;

        r = readlinkat_malloc(rr->cache_fd, b, &target);
        free(b);
        if (r < 0)
                return r;

        if (!ca_chunk_id_parse(target, &id)) {
                free(target);
                return -EINVAL;
        }

        /* fprintf(stderr, PID_FMT ": Dequeued request for %s\n", getpid(), target); */

        free(target);

        if (hp)
                rr->queue_start_high++;
        else
                rr->queue_start_low++;

        *ret = id;

        if (ret_high_priority)
                *ret_high_priority = hp;

        return 0;
}

static int ca_remote_drop_request(CaRemote *rr, const CaChunkID *id) {
        int r, q;

        assert(rr);
        assert(id);

        r = ca_remote_remove_queue_item(rr, "low-priority/", id);
        q = ca_remote_remove_queue_item(rr, "high-priority/", id);

        if (r != -ENOENT)
                return r;

        return q;
}

/* static int ca_remote_get_queued(CaRemote *rr) { */
/*         assert(rr); */

/*         return (rr->queue_start_high < rr->queue_end_high) || */
/*                 (rr->queue_start_low < rr->queue_end_low); */
/* } */

static int ca_remote_start(CaRemote *rr) {
        int r;

        assert(rr);

        if (rr->local_feature_flags == UINT64_MAX)
                return -EUNATCH;

        if (rr->input_fd < 0 || rr->output_fd < 0) {
                int pair1[2], pair2[2];

                if (/* isempty(rr->base_url) && */
                    /* isempty(rr->archive_url) && */
                    isempty(rr->index_url) &&
                    isempty(rr->wstore_url) &&
                    strv_isempty(rr->rstore_urls))
                        return -EUNATCH;

                assert(rr->input_fd < 0);
                assert(rr->output_fd < 0);
                assert(rr->pid <= 1);

                if (pipe2(pair1, O_CLOEXEC|O_NONBLOCK) < 0)
                        return -errno;

                if (pipe2(pair2, O_CLOEXEC|O_NONBLOCK) < 0) {
                        safe_close_pair(pair1);
                        return -errno;
                }

                rr->pid = fork();
                if (rr->pid < 0) {
                        safe_close_pair(pair1);
                        safe_close_pair(pair2);
                        return -errno;
                }

                if (rr->pid == 0) {
                        size_t i = 0, skip;
                        char **args, **u;

                        /* Child */
                        safe_close(pair1[0]);
                        safe_close(pair2[1]);

                        if (dup3(pair2[0], STDIN_FILENO, 0) < 0) {
                                fprintf(stderr, "Failed to duplicate to STDIN: %s\n", strerror(errno));
                                goto child_fail;
                        }

                        safe_close(pair2[0]);

                        if (dup3(pair1[1], STDOUT_FILENO, 0) < 0) {
                                fprintf(stderr, "Failed to duplicate to STDOUT: %s\n", strerror(errno));
                                goto child_fail;
                        }

                        safe_close(pair1[1]);

                        (void) prctl(PR_SET_PDEATHSIG, SIGTERM);

                        args = newa(char*, (rr->callout ? 1 : 3) + 5 + strv_length(rr->rstore_urls) + 1);

                        if (rr->callout) {
                                const char *e;

                                e = getenv("CASYNC_PROTOCOL_PATH");
                                if (!e)
                                        e = CASYNC_PROTOCOL_PATH;

                                args[i++] = strjoina(e, "/casync-", rr->callout);

                                skip = 0;
                        } else {
                                const char *ssh, *remote_casync;

                                skip = strlen(rr->url_prefix);

                                ssh = getenv("CASYNC_SSH_PATH");
                                if (!ssh)
                                        ssh = "ssh";
                                remote_casync = getenv("CASYNC_REMOTE_PATH");
                                if (!remote_casync)
                                        remote_casync = "casync";

                                args[i++] = (char*) ssh;
                                args[i++] = strndupa(rr->url_prefix, skip - 1);
                                args[i++] = (char*) remote_casync;
                        }

                        args[i++] = (char*) ((rr->local_feature_flags & (CA_PROTOCOL_PUSH_CHUNKS|CA_PROTOCOL_PUSH_INDEX)) ? "push" : "pull");
                        args[i++] = /* rr->base_url ? rr->base_url + skip :*/ (char*) "-";
                        args[i++] = /* rr->archive_url ? rr->archive_url + skip :*/ (char*) "-";
                        args[i++] = rr->index_url ? rr->index_url + skip : (char*) "-";
                        args[i++] = rr->wstore_url ? rr->wstore_url + skip: (char*) "-";

                        STRV_FOREACH(u, rr->rstore_urls)
                                args[i++] = *u + skip;

                        args[i] = NULL;

                        if (rr->callout)
                                execv(args[0], args);
                        else
                                execvp(args[0], args);

                        fprintf(stderr, "Failed to execute %s: %s\n", args[0], strerror(errno));
                child_fail:
                        _exit(EXIT_FAILURE);
                }

                rr->input_fd = pair1[0];
                rr->output_fd = pair2[1];

                safe_close(pair1[1]);
                safe_close(pair2[0]);
        }

        if (rr->cache_fd < 0) {
                if (!rr->cache_path) {
                        if (asprintf(&rr->cache_path, "/var/tmp/casync-remote-%" PRIu64, random_u64()) < 0)
                                return -ENOMEM;

                        rr->remove_cache = true;
                }

                (void) mkdir(rr->cache_path, 0777);

                rr->cache_fd = open(rr->cache_path, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (rr->cache_fd < 0)
                        return -errno;
        }

        if (rr->index_fd < 0 && rr->index_path) {
                bool do_open = false;
                int flags = O_CLOEXEC|O_NOCTTY;

                /* We support either a readable or a writable index, not both. */
                if ((rr->local_feature_flags & CA_PROTOCOL_READABLE_INDEX) &&
                    (rr->local_feature_flags & CA_PROTOCOL_WRITABLE_INDEX))
                        return -EINVAL;

                if ((rr->remote_feature_flags & CA_PROTOCOL_PULL_INDEX) ||
                    (rr->local_feature_flags & CA_PROTOCOL_PUSH_INDEX)) {
                        do_open = true;
                        flags |= O_RDONLY;
                } else if ((rr->remote_feature_flags & CA_PROTOCOL_PUSH_INDEX) ||
                           (rr->local_feature_flags & CA_PROTOCOL_PULL_INDEX)) {
                        do_open = true;
                        flags |= O_WRONLY;
                }

                if (do_open) {
                        if ((flags & O_ACCMODE) == O_RDONLY) {
                                rr->index_fd = open(rr->index_path, flags);
                                if (rr->index_fd < 0)
                                        return -errno;
                        } else {
                                r = tempfn_random(rr->index_path, &rr->temporary_index_path);
                                if (r < 0)
                                        return r;

                                rr->index_fd = open(rr->temporary_index_path, flags|O_CREAT|O_EXCL|O_NOFOLLOW, 0666);
                                if (rr->index_fd < 0)
                                        return -errno;
                        }
                }
        }

        return CA_REMOTE_POLL;
}

static int ca_remote_read(CaRemote *rr) {
        size_t left;
        ssize_t n;
        void *p;

        assert(rr);

        if (realloc_buffer_size(&rr->input_buffer) >= REMOTE_BUFFER_SIZE)
                return CA_REMOTE_POLL;

        left = REMOTE_BUFFER_SIZE - realloc_buffer_size(&rr->input_buffer);

        p = realloc_buffer_extend(&rr->input_buffer, left);
        if (!p)
                return -ENOMEM;

        n = read(rr->input_fd, p, left);
        realloc_buffer_shorten(&rr->input_buffer, n < 0 ? left : left - n);
        if (n < 0)
                return errno == EAGAIN ? CA_REMOTE_POLL : -errno;
        if (n == 0)
                return -EPIPE;

        return CA_REMOTE_STEP;
}

static int ca_remote_write(CaRemote *rr) {
        ssize_t n;

        assert(rr);

        if (realloc_buffer_size(&rr->output_buffer) == 0)
                return CA_REMOTE_POLL;

        n = write(rr->output_fd, realloc_buffer_data(&rr->output_buffer), realloc_buffer_size(&rr->output_buffer));
        if (n < 0)
                return errno == EAGAIN ? CA_REMOTE_POLL : -errno;

        realloc_buffer_advance(&rr->output_buffer, n);

        if (rr->sent_goodbye && realloc_buffer_size(&rr->output_buffer) == 0)
                return CA_REMOTE_FINISHED;

        return CA_REMOTE_STEP;
}

static bool operations_and_services_compatible(uint64_t operations, uint64_t services) {

        if ((operations & CA_PROTOCOL_PULL_CHUNKS) && !(services & CA_PROTOCOL_READABLE_STORE))
                return false;
        if ((operations & CA_PROTOCOL_PULL_INDEX) && !(services & CA_PROTOCOL_READABLE_INDEX))
                return false;

        if ((operations & CA_PROTOCOL_PUSH_CHUNKS) && !(services & CA_PROTOCOL_WRITABLE_STORE))
                return false;
        if ((operations & CA_PROTOCOL_PUSH_INDEX) && !(services & CA_PROTOCOL_WRITABLE_INDEX))
                return false;

        return true;
}

static int ca_remote_process_hello(CaRemote *rr, const CaProtocolHello *hello) {
        uint64_t remote_flags;

        assert(rr);
        assert(hello);

        remote_flags = read_le64(&hello->feature_flags);

        if ((remote_flags & ~CA_PROTOCOL_FEATURE_FLAGS_MAX) != 0)
                return -EPROTONOSUPPORT;

        if ((remote_flags & CA_PROTOCOL_PUSH_INDEX_CHUNKS) && ((remote_flags & (CA_PROTOCOL_PUSH_INDEX|CA_PROTOCOL_PUSH_CHUNKS)) != (CA_PROTOCOL_PUSH_INDEX|CA_PROTOCOL_PUSH_CHUNKS)))
                return -EBADE;

        /* Check if what one side needs is provided by the other */
        if (!operations_and_services_compatible(remote_flags, rr->local_feature_flags))
                return -EBADE;
        if (!operations_and_services_compatible(rr->local_feature_flags, remote_flags))
                return -EBADE;

        /* Check that between both sides there are are any operations requested */
        if (((remote_flags | rr->local_feature_flags) & (CA_PROTOCOL_PULL_INDEX|CA_PROTOCOL_PULL_CHUNKS|CA_PROTOCOL_PUSH_CHUNKS|CA_PROTOCOL_PUSH_INDEX)) == 0)
                return -EBADE;

        rr->remote_feature_flags = remote_flags;
        rr->state = CA_REMOTE_RUNNING;

        return CA_REMOTE_STEP;
}

static int ca_remote_process_index(CaRemote *rr, const CaProtocolIndex *idx) {
        size_t sz;
        int r;

        assert(rr);
        assert(idx);

        if (rr->index_complete)
                return -EBADMSG;

        sz = read_le64(&idx->header.size) - offsetof(CaProtocolIndex, data);

        if (rr->index_fd >= 0) {
                r = loop_write(rr->index_fd, idx->data, sz);
                if (r < 0)
                        return r;
        } else {
                if (!realloc_buffer_append(&rr->index_buffer, idx->data, sz))
                        return -ENOMEM;
        }

        return CA_REMOTE_READ_INDEX;
}

static int ca_remote_process_index_eof(CaRemote *rr, const CaProtocolIndexEOF *eof) {
        assert(rr);
        assert(eof);

        rr->index_complete = true;
        return CA_REMOTE_READ_INDEX_EOF;
}

static int ca_remote_process_request(CaRemote *rr, const CaProtocolRequest *req) {
        const uint8_t *p;
        size_t ms;
        int r;

        assert(rr);
        assert(req);

        ms = le64toh(req->header.size) - offsetof(CaProtocolRequest, chunks);

        for (p = req->chunks; p < req->chunks + ms; p += CA_CHUNK_ID_SIZE) {
                r = ca_remote_enqueue_request(rr, (const CaChunkID*) p, le64toh(req->flags) & CA_PROTOCOL_REQUEST_HIGH_PRIORITY);
                if (r < 0)
                        return r;
        }

        return CA_REMOTE_REQUEST;
}

static int ca_remote_process_chunk(CaRemote *rr, const CaProtocolChunk *chunk) {
        size_t ms;
        int r;

        assert(rr);
        assert(chunk);

        if (rr->cache_fd < 0)
                return -ENOTTY;

        memcpy(&rr->last_chunk, chunk->chunk, CA_CHUNK_ID_SIZE);
        rr->last_chunk_valid = true;

        (void) ca_remote_drop_request(rr, &rr->last_chunk);

        ms = le64toh(chunk->header.size) - offsetof(CaProtocolChunk, data);

        r = ca_save_chunk_file(rr->cache_fd,
                               NULL,
                               &rr->last_chunk,
                               le64toh(chunk->flags) & CA_PROTOCOL_CHUNK_COMPRESSED,
                               chunk->data,
                               ms);
        if (r == -EEXIST)
                return CA_REMOTE_STEP;
        if (r < 0)
                return r;

        return CA_REMOTE_CHUNK;
}

static int ca_remote_process_missing(CaRemote *rr, const CaProtocolMissing *missing) {
        int r;

        assert(rr);
        assert(missing);

        if (rr->cache_fd < 0)
                return -ENOTTY;

        r = ca_save_chunk_missing(rr->cache_fd, NULL, (const CaChunkID*) missing->chunk);
        if (r == -EEXIST)
                return CA_REMOTE_STEP;
        if (r < 0)
                return r;

        return CA_REMOTE_CHUNK;
}

static int ca_remote_install_index_file(CaRemote *rr) {
        assert(rr);

        if (rr->index_complete &&
            rr->temporary_index_path &&
            rr->index_path) {

                if (rename(rr->temporary_index_path, rr->index_path) < 0)
                        return -errno;

                rr->temporary_index_path = mfree(rr->temporary_index_path);
        }

        return 0;
}

static int ca_remote_process_goodbye(CaRemote *rr, const CaProtocolGoodbye *goodbye) {
        int r;

        assert(rr);
        assert(goodbye);

        r = ca_remote_install_index_file(rr);
        if (r < 0)
                return r;

        rr->state = CA_REMOTE_EOF;

        return CA_REMOTE_FINISHED;
}

static int ca_remote_process_abort(CaRemote *rr, const CaProtocolAbort *a) {
        assert(rr);
        assert(a);

        return -ECONNABORTED;
}

static const CaProtocolHello* validate_hello(CaRemote *rr, const CaProtocolHeader *h) {
        const CaProtocolHello *hello;

        assert(rr);
        assert(h);

        if (read_le64(&h->size) != sizeof(CaProtocolHello))
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_HELLO)
                return NULL;

        hello = (const CaProtocolHello*) h;

        if (read_le64(&hello->feature_flags) == UINT64_MAX)
                return NULL;
        if (read_le64(&hello->feature_flags) == 0)
                return NULL; /* Other side doesn't provide anything, and doesn't want anything? */

        return (const CaProtocolHello*) h;
}

static const CaProtocolIndex* validate_index(CaRemote *rr, const CaProtocolHeader *h) {
        assert(rr);
        assert(h);

        if (read_le64(&h->size) < offsetof(CaProtocolIndex, data) + 1)
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_INDEX)
                return NULL;

        return (const CaProtocolIndex*) h;
}

static const CaProtocolIndexEOF* validate_index_eof(CaRemote *rr, const CaProtocolHeader *h) {
        assert(rr);
        assert(h);

        if (read_le64(&h->size) != sizeof(CaProtocolIndexEOF))
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_INDEX_EOF)
                return NULL;

        return (const CaProtocolIndexEOF*) h;
}

static const CaProtocolRequest* validate_request(CaRemote *rr, const CaProtocolHeader *h) {
        const CaProtocolRequest *req;

        assert(rr);
        assert(h);

        if (read_le64(&h->size) < offsetof(CaProtocolRequest, chunks) + CA_CHUNK_ID_SIZE)
                return NULL;
        if ((read_le64(&h->size) - offsetof(CaProtocolRequest, chunks)) % CA_CHUNK_ID_SIZE != 0)
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_REQUEST)
                return NULL;

        req = (const CaProtocolRequest*) h;
        if ((read_le64(&req->flags) & ~CA_PROTOCOL_REQUEST_FLAG_MAX) != 0)
                return NULL;

        return req;
}

static const CaProtocolChunk* validate_chunk(CaRemote *rr, const CaProtocolHeader *h) {
        const CaProtocolChunk *c;

        assert(rr);
        assert(h);

        if (read_le64(&h->size) < offsetof(CaProtocolChunk, data) + 1)
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_CHUNK)
                return NULL;

        c = (const CaProtocolChunk*) h;

        if (read_le64(&c->flags) & ~CA_PROTOCOL_CHUNK_FLAG_MAX)
                return NULL;

        return c;
}

static const CaProtocolMissing* validate_missing(CaRemote *rr, const CaProtocolHeader *h) {
        assert(rr);
        assert(h);

        if (read_le64(&h->size) != sizeof(CaProtocolMissing))
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_MISSING)
                return NULL;

        return (const CaProtocolMissing*) h;
}

static const CaProtocolGoodbye* validate_goodbye(CaRemote *rr, const CaProtocolHeader *h) {
        assert(rr);
        assert(h);

        if (read_le64(&h->size) != sizeof(CaProtocolGoodbye))
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_GOODBYE)
                return NULL;

        return (const CaProtocolGoodbye*) h;
}

static const CaProtocolAbort* validate_abort(CaRemote *rr, const CaProtocolHeader *h) {
        const CaProtocolAbort *a;
        const char *p;
        size_t n;

        assert(rr);

        if (read_le64(&h->size) < offsetof(CaProtocolAbort, reason) + 1)
                return NULL;
        if (read_le64(&h->type) != CA_PROTOCOL_ABORT)
                return NULL;

        a = (const CaProtocolAbort*) h;

        if (read_le64(&a->error) >= INT32_MAX)
                return NULL;

        n = read_le64(&h->size) - offsetof(CaProtocolAbort, reason);
        for (p = a->reason; p < a->reason + n - 1; p++) {
                if ((uint8_t) *p < (uint8_t) ' ')
                        return NULL;
        }

        if (a->reason[n-1] != 0)
                return NULL;

        return a;
}

static int ca_remote_process_message(CaRemote *rr) {
        const CaProtocolHeader *h;
        uint64_t size;
        int r, step;

        assert(rr);

        if (!IN_SET(rr->state, CA_REMOTE_HELLO, CA_REMOTE_RUNNING))
                return CA_REMOTE_POLL;

        if (realloc_buffer_size(&rr->input_buffer) < sizeof(CaProtocolHeader))
                return CA_REMOTE_POLL;

        h = realloc_buffer_data(&rr->input_buffer);

        size = read_le64(&h->size);
        if (size < CA_PROTOCOL_SIZE_MIN)
                return -EBADMSG;
        if (size > CA_PROTOCOL_SIZE_MAX)
                return -EBADMSG;

        if (realloc_buffer_size(&rr->input_buffer) < size)
                return CA_REMOTE_POLL;

        /* fprintf(stderr, PID_FMT " Got message: %s\n", getpid(), strna(ca_protocol_type_name(read_le64(&h->type)))); */

        switch (read_le64(&h->type)) {

        case CA_PROTOCOL_HELLO: {
                const CaProtocolHello *hello;

                if (rr->state != CA_REMOTE_HELLO)
                        return -EBADMSG;

                hello = validate_hello(rr, h);
                if (!hello)
                        return -EBADMSG;

                step = ca_remote_process_hello(rr, hello);
                break;
        }

        case CA_PROTOCOL_INDEX: {
                const CaProtocolIndex *idx;

                if (rr->state != CA_REMOTE_RUNNING)
                        return -EBADMSG;
                if (((rr->local_feature_flags & CA_PROTOCOL_PULL_INDEX) == 0) &&
                     ((rr->remote_feature_flags & CA_PROTOCOL_PUSH_INDEX) == 0))
                        return -EBADMSG;

                idx = validate_index(rr, h);
                if (!idx)
                        return -EBADMSG;

                step = ca_remote_process_index(rr, idx);
                break;
        }

        case CA_PROTOCOL_INDEX_EOF: {
                const CaProtocolIndexEOF *eof;

                if (rr->state != CA_REMOTE_RUNNING)
                        return -EBADMSG;
                if (((rr->local_feature_flags & CA_PROTOCOL_PULL_INDEX) == 0) &&
                    ((rr->remote_feature_flags & CA_PROTOCOL_PUSH_INDEX) == 0))
                        return -EBADMSG;

                eof = validate_index_eof(rr, h);
                if (!eof)
                        return -EBADMSG;

                step = ca_remote_process_index_eof(rr, eof);
                break;
        }

        case CA_PROTOCOL_REQUEST: {
                const CaProtocolRequest *req;

                if (rr->state != CA_REMOTE_RUNNING)
                        return -EBADMSG;
                if (((rr->local_feature_flags & CA_PROTOCOL_PUSH_CHUNKS) == 0) &&
                    ((rr->remote_feature_flags & CA_PROTOCOL_PULL_CHUNKS) == 0))
                        return -EBADMSG;

                req = validate_request(rr, h);
                if (!req)
                        return -EBADMSG;

                step = ca_remote_process_request(rr, req);
                break;
        }

        case CA_PROTOCOL_CHUNK: {
                const CaProtocolChunk *chunk;

                if (rr->state != CA_REMOTE_RUNNING)
                        return -EBADMSG;
                if (((rr->local_feature_flags & CA_PROTOCOL_PULL_CHUNKS) == 0) &&
                    ((rr->remote_feature_flags & CA_PROTOCOL_PUSH_CHUNKS) == 0))
                        return -EBADMSG;

                chunk = validate_chunk(rr, h);
                if (!chunk)
                        return -EBADMSG;

                step = ca_remote_process_chunk(rr, chunk);
                break;
        }

        case CA_PROTOCOL_MISSING: {
                const CaProtocolMissing *missing;

                if (rr->state != CA_REMOTE_RUNNING)
                        return -EBADMSG;
                if (((rr->local_feature_flags & CA_PROTOCOL_PULL_CHUNKS) == 0) &&
                    ((rr->remote_feature_flags & CA_PROTOCOL_PUSH_CHUNKS) == 0))
                        return -EBADMSG;

                missing = validate_missing(rr, h);
                if (!missing)
                        return -EBADMSG;

                step = ca_remote_process_missing(rr, missing);
                break;
        }

        case CA_PROTOCOL_GOODBYE: {
                const CaProtocolGoodbye *goodbye;

                if (rr->state != CA_REMOTE_RUNNING)
                        return -EBADMSG;

                goodbye = validate_goodbye(rr, h);
                if (!goodbye)
                        return -EBADMSG;

                step = ca_remote_process_goodbye(rr, goodbye);
                break;
        }

        case CA_PROTOCOL_ABORT: {
                const CaProtocolAbort *abort;

                abort = validate_abort(rr, h);
                if (!abort)
                        return -EBADMSG;

                step = ca_remote_process_abort(rr, abort);
                break;
        }

        default:
                return -EBADMSG;
        }

        if (step < 0)
                return step;

        r = realloc_buffer_advance(&rr->input_buffer, size);
        if (r < 0)
                return r;

        return step;
}

static int ca_remote_send_hello(CaRemote *rr) {
        CaProtocolHello *hello;

        assert(rr);

        if (rr->sent_hello)
                return CA_REMOTE_POLL;

        hello = realloc_buffer_extend0(&rr->output_buffer, sizeof(CaProtocolHello));
        if (!hello)
                return -ENOMEM;

        write_le64(&hello->header.size, sizeof(CaProtocolHello));
        write_le64(&hello->header.type, CA_PROTOCOL_HELLO);
        write_le64(&hello->feature_flags, rr->local_feature_flags);

        rr->sent_hello = true;
        return CA_REMOTE_STEP;
}

static int ca_remote_send_index(CaRemote *rr) {
        ssize_t n;
        void *p;
        int r;

        assert(rr);

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_INDEX) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_INDEX))
                return CA_REMOTE_POLL;

        if (rr->state != CA_REMOTE_RUNNING)
                return CA_REMOTE_POLL;

        if (rr->index_complete)
                return CA_REMOTE_POLL;

        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return CA_REMOTE_POLL;

        if (rr->index_fd < 0)
                return CA_REMOTE_WRITE_INDEX;

        p = realloc_buffer_extend(&rr->output_buffer, offsetof(CaProtocolIndex, data) + BUFFER_SIZE);
        if (!p)
                return -ENOMEM;

        n = read(rr->index_fd, (uint8_t*) p + offsetof(CaProtocolIndex, data), BUFFER_SIZE);
        if (n <= 0) {
                CaProtocolIndexEOF *eof;

                (void) realloc_buffer_shorten(&rr->output_buffer, offsetof(CaProtocolIndex, data) + BUFFER_SIZE);

                if (n < 0)
                        return -errno;

                p = realloc_buffer_extend(&rr->output_buffer, sizeof(CaProtocolIndexEOF));
                if (!p)
                        return -ENOMEM;

                eof = (CaProtocolIndexEOF*) p;
                write_le64(&eof->header.size, sizeof(CaProtocolIndexEOF));
                write_le64(&eof->header.type, CA_PROTOCOL_INDEX_EOF);

                rr->index_complete = true;
        } else {
                CaProtocolIndex *idx;

                r = realloc_buffer_shorten(&rr->output_buffer, BUFFER_SIZE - n);
                if (r < 0)
                        return r;

                idx = (CaProtocolIndex*) p;
                write_le64(&idx->header.size, offsetof(CaProtocolIndex, data) + n);
                write_le64(&idx->header.type, CA_PROTOCOL_INDEX);
        }

        return CA_REMOTE_STEP;
}

static int ca_remote_send_request(CaRemote *rr) {
        int only_high_priority = -1, r;
        CaProtocolRequest *req = NULL;

        assert(rr);
        assert(rr->cache_fd >= 0);

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PUSH_INDEX_CHUNKS) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PULL_CHUNKS))
                return CA_REMOTE_POLL;

        if (rr->state != CA_REMOTE_RUNNING)
                return CA_REMOTE_POLL;

        /* Only write out queue when the send queue is short */
        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return CA_REMOTE_POLL;

        for (;;) {
                bool high_priority;
                CaChunkID id;
                void *p;

                r = ca_remote_dequeue_request(rr, only_high_priority, &id, &high_priority);
                if (r == -ENODATA)
                        break;
                if (r < 0)
                        return r;

                if (!req) {
                        req = realloc_buffer_extend0(&rr->output_buffer, offsetof(CaProtocolRequest, chunks) + CA_CHUNK_ID_SIZE);
                        if (!req)
                                return -ENOMEM;

                        write_le64(&req->header.type, CA_PROTOCOL_REQUEST);
                        write_le64(&req->header.size, offsetof(CaProtocolRequest, chunks) + CA_CHUNK_ID_SIZE);
                        write_le64(&req->flags, high_priority ? CA_PROTOCOL_REQUEST_HIGH_PRIORITY : 0);

                        p = req->chunks;
                } else {
                        uint64_t new_size;

                        new_size = read_le64(&req->header.size) + CA_CHUNK_ID_SIZE;
                        if (new_size > offsetof(CaProtocolRequest, chunks) + BUFFER_SIZE)
                                break;

                        write_le64(&req->header.size, new_size);

                        p = realloc_buffer_extend(&rr->output_buffer, CA_CHUNK_ID_SIZE);
                        if (!p)
                                return -ENOMEM;
                }

                memcpy(p, &id, CA_CHUNK_ID_SIZE);

                only_high_priority = high_priority;
        }

        return req ? CA_REMOTE_STEP : CA_REMOTE_POLL;
}

int ca_remote_step(CaRemote *rr) {
        int r;

        if (!rr)
                return -EINVAL;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        realloc_buffer_empty(&rr->index_buffer);

        r = ca_remote_start(rr);
        if (r != CA_REMOTE_POLL)
                return r;

        r = ca_remote_write(rr);
        if (r != CA_REMOTE_POLL)
                return r;

        r = ca_remote_send_hello(rr);
        if (r != CA_REMOTE_POLL)
                return r;

        r = ca_remote_process_message(rr);
        if (r != CA_REMOTE_POLL)
                return r;

        r = ca_remote_send_request(rr);
        if (r != CA_REMOTE_POLL)
                return r;

        r = ca_remote_send_index(rr);
        if (r != CA_REMOTE_POLL)
                return r;

        r = ca_remote_read(rr);
        if (r != CA_REMOTE_POLL)
                return r;

        return CA_REMOTE_POLL;
}

int ca_remote_poll(CaRemote *rr, uint64_t timeout) {
        struct pollfd pollfd[2];
        size_t n = 0;

        if (!rr)
                return -EINVAL;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;
        if (rr->input_fd < 0 || rr->output_fd < 0)
                return -EUNATCH;

        if (realloc_buffer_size(&rr->input_buffer) < REMOTE_BUFFER_SIZE) {
                pollfd[n].fd = rr->input_fd;
                pollfd[n].events = POLLIN;
                n++;
        }

        if (realloc_buffer_size(&rr->output_buffer) > 0) {
                pollfd[n].fd = rr->output_fd;
                pollfd[n].events = POLLOUT;
                n++;
        }

        if (n == 0)
                return 0;

        if (poll(pollfd, n, timeout == UINT64_MAX ? -1 : (int) ((timeout+999U)/1000U)) < 0)
                return -errno;

        return 1;
}

int ca_remote_request(CaRemote *rr, const CaChunkID *chunk_id, bool high_priority, const void **ret, size_t *ret_size) {
        int r;

        if (!rr)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (!ret_size)
                return -EINVAL;

        if (!(rr->local_feature_flags & CA_PROTOCOL_PULL_CHUNKS))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;
        if (rr->cache_fd < 0)
                return -ENXIO;

        realloc_buffer_empty(&rr->chunk_buffer);

        r = ca_load_chunk_file(rr->cache_fd, NULL, chunk_id, &rr->chunk_buffer);
        if (r == -ENOENT) {
                /* We don't have it right now. Enqueue it */
                r = ca_remote_enqueue_request(rr, chunk_id, high_priority);
                if (r < 0)
                        return r;
                if (r > 0)
                        return -EAGAIN; /* Not a failure, but we don't have it right now, but have enqueued it. */

                return -EALREADY; /* Not a failure, but we don't have it right now, but it was already enqueued it. */
        }
        if (r == -EADDRNOTAVAIL) /* We really don't have this */
                return -ENOENT;
        if (r < 0)
                return r;

        *ret = realloc_buffer_data(&rr->chunk_buffer);
        *ret_size = realloc_buffer_size(&rr->chunk_buffer);
        return 1;
}

int ca_remote_request_async(CaRemote *rr, const CaChunkID *chunk_id, bool high_priority) {
        if (!rr)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;

        if (!(rr->local_feature_flags & CA_PROTOCOL_PULL_CHUNKS) &&
            !(rr->remote_feature_flags & CA_PROTOCOL_PUSH_INDEX_CHUNKS))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        return ca_remote_enqueue_request(rr, chunk_id, high_priority);
}

int ca_remote_next_request(CaRemote *rr, CaChunkID *ret) {
        if (!rr)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_CHUNKS) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_INDEX_CHUNKS))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        return ca_remote_dequeue_request(rr, -1, ret, NULL);
}

int ca_remote_can_put_chunk(CaRemote *rr) {
        if (!rr)
                return -EINVAL;

        /* Returns > 0 if there's buffer space to enqueue more chunks */

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_CHUNKS) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_CHUNKS))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        if (rr->state != CA_REMOTE_RUNNING)
                return 0;
        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return 0;

        return 1;
}

int ca_remote_put_chunk(CaRemote *rr, const CaChunkID *chunk_id, bool compressed, const void *data, size_t size) {
        CaProtocolChunk *chunk;
        uint64_t msz;

        if (!rr)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (size == 0)
                return -EINVAL;

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_CHUNKS) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_CHUNKS))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        if (rr->state != CA_REMOTE_RUNNING)
                return -EAGAIN; /* can't take your data right now. */
        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return -EAGAIN; /* won't take your data right now, already got enough in my queue */

        msz = offsetof(CaProtocolChunk, data) + size;
        if (msz < size) /* overflow? */
                return -EFBIG;
        if (msz > CA_PROTOCOL_SIZE_MAX)
                return -EFBIG;

        chunk = realloc_buffer_extend(&rr->output_buffer, msz);
        if (!chunk)
                return -ENOMEM;

        write_le64(&chunk->header.type, CA_PROTOCOL_CHUNK);
        write_le64(&chunk->header.size, msz);
        write_le64(&chunk->flags, compressed ? CA_PROTOCOL_CHUNK_COMPRESSED : 0);

        memcpy(chunk->chunk, chunk_id, CA_CHUNK_ID_SIZE);
        memcpy(chunk->data, data, size);

        (void) ca_remote_drop_request(rr, chunk_id);

        return 0;
}

int ca_remote_put_missing(CaRemote *rr, const CaChunkID *chunk_id) {
        CaProtocolMissing *missing;

        if (!rr)
                return -EINVAL;
        if (!chunk_id)
                return -EINVAL;

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_CHUNKS) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_CHUNKS))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        if (rr->state != CA_REMOTE_RUNNING)
                return -EAGAIN;
        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return -EAGAIN;

        missing = realloc_buffer_extend0(&rr->output_buffer, sizeof(CaProtocolMissing));
        if (!missing)
                return -ENOMEM;

        write_le64(&missing->header.type, CA_PROTOCOL_MISSING);
        write_le64(&missing->header.size, sizeof(CaProtocolMissing));

        memcpy(missing->chunk, chunk_id, CA_CHUNK_ID_SIZE);

        (void) ca_remote_drop_request(rr, chunk_id);

        return 0;
}

int ca_remote_can_put_index(CaRemote *rr) {
        if (!rr)
                return -EINVAL;

        /* Returns > 0 if there's buffer space to enqueue more index data */

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_INDEX) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_INDEX))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        if (rr->index_complete)
                return -EBUSY;

        if (rr->state != CA_REMOTE_RUNNING)
                return 0;
        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return 0;

        return 1;
}

int ca_remote_put_index(CaRemote *rr, const void *data, size_t size) {
        CaProtocolIndex *idx;
        size_t msz;

        if (!rr)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (size == 0)
                return -EINVAL;

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_INDEX) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_INDEX))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        if (rr->index_complete)
                return -EBUSY;

        if (rr->state != CA_REMOTE_RUNNING)
                return -EAGAIN;
        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return -EAGAIN;

        msz = offsetof(CaProtocolIndex, data) + size;
        if (msz < size) /* overflow? */
                return -EFBIG;
        if (msz > CA_PROTOCOL_SIZE_MAX)
                return -EFBIG;

        idx = realloc_buffer_extend(&rr->output_buffer, msz);
        if (!idx)
                return -ENOMEM;

        write_le64(&idx->header.type, CA_PROTOCOL_INDEX);
        write_le64(&idx->header.size, msz);

        memcpy(idx->data, data, size);

        return 0;
}

int ca_remote_put_index_eof(CaRemote *rr) {
        CaProtocolIndexEOF *eof;

        if (!rr)
                return -EINVAL;

        if (!(rr->remote_feature_flags & CA_PROTOCOL_PULL_INDEX) &&
            !(rr->local_feature_flags & CA_PROTOCOL_PUSH_INDEX))
                return -ENOTTY;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;

        if (rr->index_complete)
                return -EBUSY;

        if (rr->state != CA_REMOTE_RUNNING)
                return -EAGAIN;
        if (realloc_buffer_size(&rr->output_buffer) > REMOTE_BUFFER_LOW)
                return -EAGAIN;

        eof = realloc_buffer_extend(&rr->output_buffer, sizeof(CaProtocolIndexEOF));
        if (!eof)
                return -ENOMEM;

        write_le64(&eof->header.type, CA_PROTOCOL_INDEX_EOF);
        write_le64(&eof->header.size, sizeof(CaProtocolIndexEOF));

        rr->index_complete = true;

        return 0;
}

int ca_remote_read_index(CaRemote *rr, const void **ret, size_t *ret_size) {
        if (!rr)
                return -EINVAL;
        if (rr->index_fd >= 0)
                return -ENOTTY;

        if (realloc_buffer_size(&rr->index_buffer) == 0) {

                if (rr->index_complete) {
                        *ret = NULL;
                        *ret_size = 0;
                        return 0; /* eof */
                }

                return -EAGAIN;
        }

        *ret = realloc_buffer_data(&rr->index_buffer);
        *ret_size = realloc_buffer_size(&rr->index_buffer);

        return 1;
}

int ca_remote_goodbye(CaRemote *rr) {
        CaProtocolGoodbye *goodbye;
        int r;

        if (!rr)
                return -EINVAL;
        if (rr->state == CA_REMOTE_EOF)
                return -EPIPE;
        if (rr->sent_goodbye)
                return -EALREADY;

        r = ca_remote_install_index_file(rr);
        if (r < 0)
                return r;

        goodbye = realloc_buffer_extend(&rr->output_buffer, sizeof(CaProtocolGoodbye));
        if (!goodbye)
                return -ENOMEM;

        write_le64(&goodbye->header.type, CA_PROTOCOL_GOODBYE);
        write_le64(&goodbye->header.size, sizeof(CaProtocolGoodbye));

        rr->sent_goodbye = true;

        return 0;
}

int ca_remote_has_pending_requests(CaRemote *rr) {
        const char *qn;
        int r;

        if (!rr)
                return -EINVAL;

        /* Does this have locally queued requests? */
        if ((rr->queue_start_high < rr->queue_end_high) ||
            (rr->queue_start_low < rr->queue_end_low))
                return 1;

        /* Does it have remotely queued requests? */
        FOREACH_STRING(qn, "high-priority/", "low-priority/") {
                DIR *d;

                r = xopendirat(rr->cache_fd, qn, 0, &d);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                for (;;) {
                        struct dirent *de;

                        errno = 0;
                        de = readdir(d);
                        if (!de) {
                                if (errno != 0) {
                                        closedir(d);
                                        return -errno;
                                }

                                break;
                        }

                        if (STR_IN_SET(de->d_name, ".", ".."))
                                continue;

                        closedir(d);
                        return 1;
                }

                closedir(d);
        }

        return 0;
}

int ca_remote_next_chunk(CaRemote *rr, CaChunkID *ret_id, const void **ret_data, size_t *ret_size) {
        int r;

        if (!rr)
                return -EINVAL;
        if (!ret_id)
                return -EINVAL;
        if (!ret_data != !ret_size)
                return -EINVAL;

        if (!rr->last_chunk_valid)
                return -ENODATA;

        if (ret_data) {
                realloc_buffer_empty(&rr->chunk_buffer);

                r = ca_load_chunk_file(rr->cache_fd, NULL, &rr->last_chunk, &rr->chunk_buffer);
                if (r < 0)
                        return r;

                *ret_data = realloc_buffer_data(&rr->chunk_buffer);
                *ret_size = realloc_buffer_size(&rr->chunk_buffer);
        }

        *ret_id = rr->last_chunk;

        return r;
}
