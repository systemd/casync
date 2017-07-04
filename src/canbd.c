#include <fcntl.h>
#include <linux/fs.h>
#include <linux/nbd.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "canbd.h"
#include "util.h"

#define NBD_MAX 1024

struct CaBlockDevice {
        int device_fd;
        int socket_fd[2];

        char *device_path;

        pid_t ioctl_process;

        struct nbd_request last_request;

        uint64_t size;
};

CaBlockDevice *ca_block_device_new(void) {
        CaBlockDevice *d;

        d = new0(CaBlockDevice, 1);
        if (!d)
                return NULL;

        d->device_fd = d->socket_fd[0] = d->socket_fd[1] = -1;
        return d;
}

CaBlockDevice *ca_block_device_unref(CaBlockDevice *d) {
        if (!d)
                return NULL;

        safe_close_pair(d->socket_fd);

        if (d->device_fd >= 0) {
                (void) ioctl(d->device_fd, NBD_DISCONNECT);
                (void) ioctl(d->device_fd, NBD_CLEAR_SOCK);
                safe_close(d->device_fd);
        }

        if (d->ioctl_process != 0) {
                siginfo_t si = {};

                (void) kill(d->ioctl_process, SIGKILL);
                (void) waitid(P_PID, d->ioctl_process, &si, WEXITED);
        }

        free(d->device_path);

        return mfree(d);
}

int ca_block_device_set_size(CaBlockDevice *d, uint64_t size) {
        if (!d)
                return -EINVAL;
        if (size <= 0)
                return -EINVAL;
        if ((size & 511) != 0)
                return -EINVAL;

        if (d->device_fd >= 0)
                return -EBUSY;

        d->size = size;
        return 0;
}

int ca_block_device_open(CaBlockDevice *d) {
        static const int one = 1;
        bool free_device_path = false;
        int r;

        if (!d)
                return -EINVAL;
        if (d->device_fd >= 0)
                return -EBUSY;
        if (d->ioctl_process)
                return -EBUSY;

        if (d->size == 0)
                return -EUNATCH;

        assert((d->socket_fd[0] < 0) == (d->socket_fd[1] < 0));

        if (d->socket_fd[0] < 0) {
                if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, d->socket_fd) < 0)
                        return -errno;
        }

        if (d->device_path) {

                d->device_fd = open(d->device_path, O_CLOEXEC|O_RDWR|O_NONBLOCK|O_NOCTTY);
                if (d->device_fd < 0)
                        return -errno;

                if (ioctl(d->device_fd, NBD_SET_SOCK, d->socket_fd[1]) < 0) {
                        r = -errno;
                        goto fail;
                }

        } else {
                unsigned i = 0;
                r = -EBUSY;

                for (;;) {
                        char *path;

                        if (i >= NBD_MAX)
                                return r;

                        if (asprintf(&path, "/dev/nbd%u", i) < 0)
                                return -ENOMEM;

                        d->device_fd = open(path, O_CLOEXEC|O_RDWR|O_NONBLOCK|O_NOCTTY);
                        if (d->device_fd < 0) {
                                free(path);
                                r = -errno;
                                goto fail;
                        }

                        if (ioctl(d->device_fd, NBD_SET_SOCK, d->socket_fd[1]) >= 0) {
                                d->device_path = path;
                                free_device_path = true;
                                break;
                        }

                        r = -errno;
                        free(path);

                        /* If the ioctl() error is EBUSY or EINVAL somebody is using the device, in that case, go for the next */
                        if (!IN_SET(r, -EBUSY, -EINVAL))
                                goto fail;

                        d->device_fd = safe_close(d->device_fd);
                        i++;
                }
        }

        if (ioctl(d->device_fd, NBD_SET_BLKSIZE, (unsigned long) 512) < 0) {
                r = -errno;
                goto fail;
        }

        if (ioctl(d->device_fd, NBD_SET_SIZE_BLOCKS, (unsigned long) d->size / 512) < 0) {
                r = -errno;
                goto fail;
        }

        if (ioctl(d->device_fd, NBD_SET_FLAGS, (unsigned long) NBD_FLAG_READ_ONLY) < 0) {
                r = -errno;
                goto fail;
        }

        if (ioctl(d->device_fd, BLKROSET, (unsigned long) &one) < 0) {
                r = -errno;
                goto fail;
        }

        d->ioctl_process = fork();
        if (d->ioctl_process < 0) {
                r = -errno;
                goto fail;
        }

        if (d->ioctl_process == 0) {

                (void) prctl(PR_SET_PDEATHSIG, SIGKILL);
                (void) prctl(PR_SET_NAME, "nbd-ioctl");

                if (ioctl(d->device_fd, NBD_DO_IT) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        return 0;

fail:
        d->device_fd = safe_close(d->device_fd);
        safe_close_pair(d->socket_fd);

        if (free_device_path)
                d->device_path = mfree(d->device_path);

        return r;
}

int ca_block_device_step(CaBlockDevice *d) {
        ssize_t l;

        if (!d)
                return -EINVAL;

        if (d->last_request.magic != 0)
                return CA_BLOCK_DEVICE_REQUEST;

        l = read(d->socket_fd[0], &d->last_request, sizeof(d->last_request));
        if (l < 0) {
                if (errno == EAGAIN)
                        return CA_BLOCK_DEVICE_POLL;

                return -errno;
        }
        if (l != sizeof(d->last_request))
                return -EBADMSG;

        if (be32toh(d->last_request.magic) != NBD_REQUEST_MAGIC)
                return -EBADMSG;

        if (be32toh(d->last_request.type) != NBD_CMD_READ)
                return -EBADMSG;

        if (be32toh(d->last_request.len) == 0)
                return -EBADMSG;

        /* fprintf(stderr, "Got request for +%" PRIu64 " (%" PRIu32 ") fsize=%" PRIu64 "\n", */
        /*         be64toh(d->last_request.from), */
        /*         be32toh(d->last_request.len), */
        /*         d->size); */

        return CA_BLOCK_DEVICE_REQUEST;
}

int ca_block_device_get_request_offset(CaBlockDevice *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (d->last_request.magic == 0)
                return -ENODATA;

        *ret = be64toh(d->last_request.from);
        return 0;
}

int ca_block_device_get_request_size(CaBlockDevice *d, uint64_t *ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (d->last_request.magic == 0)
                return -ENODATA;

        *ret = be32toh(d->last_request.len);
        return 0;
}

int ca_block_device_put_data(CaBlockDevice *d, uint64_t offset, const void *data, size_t size) {
        struct nbd_reply reply = {
                .magic = htobe32(NBD_REPLY_MAGIC),
                .error = 0
        };
        int r;

        if (!d)
                return -EINVAL;
        if (size == 0)
                return -EINVAL;
        if (!data)
                return -EINVAL;

        if (d->last_request.magic == 0)
                return -EBADR;
        if (offset != be64toh(d->last_request.from))
                return -EBADR;
        if (size != be32toh(d->last_request.len))
                return -EBADR;

        memcpy(reply.handle, d->last_request.handle, sizeof(reply.handle));

        r = loop_write_block(d->socket_fd[0], &reply, sizeof(reply));
        if (r < 0)
                return r;

        r = loop_write_block(d->socket_fd[0], data, size);
        if (r < 0)
                return r;

        memset(&d->last_request, 0, sizeof(d->last_request));

        return 0;
}

int ca_block_device_poll(CaBlockDevice *d, uint64_t timeout_nsec, const sigset_t *ss) {
        struct pollfd pollfd;
        int r;

        if (!d)
                return -EINVAL;
        if (d->device_fd < 0)
                return -EUNATCH;
        if (d->socket_fd[0] < 0)
                return -EUNATCH;

        pollfd = (struct pollfd) {
                .fd = d->socket_fd[0],
                .events = POLLIN,
        };

        if (timeout_nsec != UINT64_MAX) {
                struct timespec ts;

                ts = nsec_to_timespec(timeout_nsec);

                r = ppoll(&pollfd, 1, &ts, ss);
        } else
                r = ppoll(&pollfd, 1, NULL, ss);
        if (r < 0)
                return -errno;

        return 1;
}

int ca_block_device_get_path(CaBlockDevice *d, const char **ret) {
        if (!d)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        if (!d->device_path)
                return -EUNATCH;

        *ret = d->device_path;
        return 0;
}

int ca_block_device_set_path(CaBlockDevice *d, const char *node) {
        char *c;

        if (!d)
                return -EINVAL;
        if (d->device_fd >= 0)
                return -EBUSY;

        if (streq_ptr(node, d->device_path))
                return 0;

        if (node) {
                c = strdup(node);
                if (!c)
                        return -ENOMEM;
        } else
                c = NULL;

        free(d->device_path);
        d->device_path = c;

        return 1;
}

int ca_block_device_test_nbd(const char *name) {
        unsigned u;
        size_t n;
        int r;

        if (!name)
                return -EINVAL;

        n = strspn(name, "/");
        if (n < 1)
                return 0;
        name += n;

        if (!startswith(name, "dev"))
                return 0;
        name += 3;

        n = strspn(name, "/");
        if (n < 1)
                return 0;
        name += n;

        if (!startswith(name, "nbd"))
                return 0;
        name += 3;

        r = safe_atou(name, &u);
        if (r < 0)
                return 0;

        return 1;
}
