/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <linux/fs.h>
#include <linux/nbd.h>
#include <poll.h>
#include <stddef.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "canbd.h"
#include "time-util.h"
#include "util.h"

#define NBD_MAX 1024

struct CaBlockDevice {
        int device_fd;
        int socket_fd[2];

        char *device_path;

        pid_t ioctl_process;

        struct nbd_request last_request;

        uint64_t size;

        int friendly_name_fd;
        char *friendly_name;
        char *friendly_name_path;

        dev_t devnum;
};

CaBlockDevice *ca_block_device_new(void) {
        CaBlockDevice *d;

        d = new0(CaBlockDevice, 1);
        if (!d)
                return NULL;

        d->device_fd = d->socket_fd[0] = d->socket_fd[1] = d->friendly_name_fd = -1;
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

        safe_close(d->friendly_name_fd);
        free(d->friendly_name);

        if (d->friendly_name_path) {
                (void) unlink(d->friendly_name_path);
                free(d->friendly_name_path);
                (void) rmdir("/run/casync");
        }

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

int ca_block_device_set_friendly_name(CaBlockDevice *d, const char *name) {
        char *m;

        if (!d)
                return -EINVAL;
        if (isempty(name))
                return -EINVAL;
        if (!filename_is_valid(name))
                return -EINVAL;
        if (strlen(name) > sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))
                return -EINVAL;

        if (d->friendly_name_fd >= 0)
                return -EBUSY;

        m = strdup(name);
        if (!m)
                return -ENOMEM;

        free(d->friendly_name);
        d->friendly_name = m;

        return 0;
}

static int ca_block_device_establish_friendly_name(CaBlockDevice *d) {

        int existing_fd = -1, r;
        char *t = NULL, nl = '\n';
        const char *e;
        unsigned i;
        ssize_t n;
        size_t l;

        if (!d)
                return -EINVAL;

        if (d->friendly_name_fd >= 0)
                return -EBUSY;
        if (!d->device_path)
                return -EUNATCH;
        if (!d->friendly_name)
                return 0;

        if (mkdir("/run/casync", 0755) < 0 && errno != EEXIST)
                return -errno;

        e = path_startswith(d->device_path, "/dev");
        if (!e) {
                r = -EINVAL;
                goto fail;
        }
        if (!filename_is_valid(e)) {
                r = -EINVAL;
                goto fail;
        }

        free(d->friendly_name_path);
        d->friendly_name_path = strjoin("/run/casync/", e);

        if (asprintf(&t, "/run/casync/.#%s.%" PRIx64 ".tmp", e, random_u64()) < 0) {
                r = -ENOMEM;
                goto fail;
        }

        d->friendly_name_fd = open(t, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC, 0644);
        if (d->friendly_name_fd < 0) {
                r = -errno;
                goto fail;
        }

        /* We use a BSD file lock here in a slightly creative way: the owning casync instance always owns a LOCK_EX
         * (exclusive) lock on it. When it dies this lock is released. Other instances or the udev rule tool may
         * attempt to take a LOCK_SH (shared) lock on it. If that succeeds, then the owning instance must be dead, and
         * the file invalid. If it fails with EWOULDBLOCK however, then the exclusive lock is still in place, and thus
         * the owning casync instance still running. */

        if (flock(d->friendly_name_fd, LOCK_EX) < 0) {
                r = -errno;
                goto fail;
        }

        l = strlen(d->friendly_name);
        n = writev(d->friendly_name_fd, (struct iovec[]) {
                        { .iov_base = d->friendly_name, .iov_len = l },
                        { .iov_base = &nl, .iov_len = 1 }}, 2);
        if (n < 0) {
                r = -errno;
                goto fail;
        }
        if ((size_t) n != l + 1U) {
                r = -EIO;
                goto fail;
        }

        for (i = 0; i < 10; i++) {
                struct stat st;

                r = rename_noreplace(AT_FDCWD, t, AT_FDCWD, d->friendly_name_path);
                if (r >= 0) {
                        t = mfree(t);
                        break;
                }
                if (r != -EEXIST)
                        goto fail;

                existing_fd = open(d->friendly_name_path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (existing_fd < 0) {
                        if (errno == ENOENT)
                                continue;

                        r = -errno;
                        goto fail;
                }

                if (flock(existing_fd, LOCK_SH|LOCK_NB) < 0) {

                        if (errno == EWOULDBLOCK) {

                                /* The file is locked exclusively? If so, strange, some other casync instance still owns this device... */
                                r = -EBUSY;
                                goto fail;
                        }

                        r = -errno;
                        goto fail;
                }

                /* We got the lock? This means the file isn't used anymore */

                if (fstat(existing_fd, &st) < 0) {
                        r = -errno;
                        goto fail;
                }

                if (!S_ISREG(st.st_mode)) {
                        r = -EINVAL;
                        goto fail;
                }

                if (st.st_nlink > 0) {
                        /* we own it, and it's not deleted already? then remove it, it's out of date */
                        if (unlink(d->friendly_name_path) < 0) {
                                r = -errno;
                                goto fail;
                        }
                }

                existing_fd = safe_close(existing_fd);
        }

        return 0;

fail:
        if (t) {
                if (d->friendly_name_fd >= 0)
                        (void) unlink(t);

                free(t);
        }

        if (existing_fd >= 0)
                safe_close(existing_fd);

        d->friendly_name_path = mfree(d->friendly_name_path);

        (void) rmdir("/run/casync");

        return r;
}

int ca_block_device_open(CaBlockDevice *d) {
        static const int one = 1;
        bool free_device_path = false;
        struct stat st;
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

                if (fstat(d->device_fd, &st) < 0) {
                        r = -errno;
                        goto fail;
                }

                if (!S_ISBLK(st.st_mode)) {
                        r = -ENOTBLK;
                        goto fail;
                }

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

                        if (fstat(d->device_fd, &st) < 0) {
                                r = -errno;
                                goto fail;
                        }

                        if (!S_ISBLK(st.st_mode)) {
                                r = -ENOTBLK;
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

        d->devnum = st.st_rdev;

        r = ca_block_device_establish_friendly_name(d);
        if (r < 0)
                goto fail;

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

int ca_block_device_get_poll_fd(CaBlockDevice *d) {
        if (!d)
                return -EINVAL;
        if (d->device_fd < 0)
                return -EUNATCH;
        if (d->socket_fd[0] < 0)
                return -EUNATCH;

        return d->socket_fd[0];
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


int ca_block_device_get_devnum(CaBlockDevice *d, dev_t *ret) {
        if (!d)
                return -EINVAL;

        if (d->device_fd < 0)
                return -EUNATCH;

        if (d->devnum == 0)
                return -EUNATCH;

        *ret = d->devnum;
        return 0;
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
