/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "time-util.h"
#include "util.h"

#define TIMEOUT_NSEC UINT64_C(30000000000)

static sig_atomic_t quit = false;

static void exit_signal_handler(int signo) {
        quit = true;
};

static void sigchld_signal_handler(int signo) {
        /* Nothing */
};

int main(int argc, char *argv[]) {
        int fd = -1;
        pid_t pid = 0;
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa = {
                .un.sun_family = AF_UNIX,
        };
        socklen_t salen = sizeof(sa);
        char *buffer = NULL, *e;
        size_t buffer_size = 0, allocate_at_least = strlen("READY=1\n");
        sigset_t ss, ss_poll;
        struct sigaction exit_sigaction = {
                .sa_handler = exit_signal_handler,
                .sa_flags = SA_RESTART,
        };
        struct sigaction sigchld_sigaction = {
                .sa_handler = sigchld_signal_handler,
                .sa_flags = SA_RESTART,
        };
        uint64_t timeout_at;
        int r;

        if (argc < 2) {
                r = -EINVAL;
                log_error("Command line to execute required as argument.");
                goto finish;
        }

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                r = -errno;
                log_error("Failed to create notification socket: %m");
                goto finish;
        }

        /* Bind the socket using the kernel's autobind functionality. */
        if (bind(fd, &sa.sa, sizeof(sa_family_t)) < 0) {
                r = -errno;
                log_error("Failed to bind notification socket: %m");
                goto finish;
        }

        if (getsockname(fd, &sa.sa, &salen) < 0) {
                r = -errno;
                log_error("Failed to determine bound socket address: %m");
                goto finish;
        }

        assert_se(salen > offsetof(struct sockaddr_un, sun_path) + 1);
        assert_se(sa.un.sun_family == AF_UNIX);
        assert_se(sa.un.sun_path[0] == 0);

        e = newa(char, salen - offsetof(struct sockaddr_un, sun_path) + 1);
        e[0] = '@';
        memcpy(e + 1, sa.un.sun_path + 1, salen - offsetof(struct sockaddr_un, sun_path) - 1);
        e[salen - offsetof(struct sockaddr_un, sun_path)] = 0;

        assert_se(sigemptyset(&ss) >= 0);
        assert_se(sigaddset(&ss, SIGINT) >= 0);
        assert_se(sigaddset(&ss, SIGTERM) >= 0);
        assert_se(sigaddset(&ss, SIGCHLD) >= 0);

        assert_se(sigprocmask(SIG_BLOCK, &ss, &ss_poll) >= 0);
        assert_se(sigdelset(&ss_poll, SIGINT) >= 0);
        assert_se(sigdelset(&ss_poll, SIGTERM) >= 0);
        assert_se(sigdelset(&ss_poll, SIGCHLD) >= 0);

        assert_se(sigaction(SIGTERM, &exit_sigaction, NULL) >= 0);
        assert_se(sigaction(SIGINT, &exit_sigaction, NULL) >= 0);

        assert_se(sigaction(SIGCHLD, &sigchld_sigaction, NULL) >= 0);

        timeout_at = now(CLOCK_MONOTONIC) + TIMEOUT_NSEC;

        pid = fork();
        if (pid < 0) {
                r = -errno;
                log_error("Failed to to fork(): %m");
                goto finish;
        }

        if (pid == 0) { /* Child? */
                int new_stdout;

                assert_se(sigprocmask(SIG_SETMASK, &ss_poll, NULL) >= 0);

                fd = safe_close(fd);

                /* Let's run the child with a new stdout, independent from the parent, so that the PID of we print below is followed by an EOF */
                new_stdout = open("/dev/tty", O_WRONLY);
                if (new_stdout < 0) {
                        r = -errno;

                        /* If that didn't work (which it won't if we are being run from "ninja test"), then let's use /dev/null */
                        new_stdout = open("/dev/null", O_WRONLY);
                        if (new_stdout < 0) {
                                log_error("Failed to open new STDOUT: %m");
                                goto inner_fail;
                        }
                }

                if (new_stdout != STDOUT_FILENO) {

                        if (dup2(new_stdout, STDOUT_FILENO) < 0) {
                                r = -errno;
                                log_error("Failed to duplicate STDOUT: %m");
                                goto inner_fail;
                        }

                        new_stdout = safe_close(new_stdout);
                }

                if (setenv("NOTIFY_SOCKET", e, 1) < 0) {
                        r = -errno;
                        log_error("Failed to set $NOTIFY_SOCKET: %m");
                        goto inner_fail;
                }

                execv(argv[1], argv + 1);
                r = -errno;
                log_error("Failed to execute child process: %m");

        inner_fail:
                _exit(EXIT_FAILURE);
        }

        for (;;) {
                siginfo_t si = {};
                const char *p;
                ssize_t n;
                struct pollfd pollfd = {
                        .fd = fd,
                        .events = POLLIN,
                };
                struct timespec ts;
                uint64_t nw;

                if (waitid(P_PID, pid, &si, WEXITED|WNOHANG) < 0) {
                        r = -errno;
                        log_error("Failed to wait for children: %m");
                        goto finish;
                }

                if (si.si_pid > 0) {

                        switch (si.si_code) {

                        case CLD_EXITED:
                                log_error("Process exited prematurely with status %i.", si.si_status);
                                r = -EPIPE;
                                pid = 0;
                                goto finish;

                        case CLD_KILLED:
                        case CLD_DUMPED:
                                log_error("Process killed with signal %i (%s).", si.si_status, strsignal(si.si_status));
                                r = -EPIPE;
                                pid = 0;
                                goto finish;

                        default:
                                assert_se(false);
                        }
                }

                for (;;) {
                        ssize_t k;

                        if (buffer_size < allocate_at_least) {
                                free(buffer);

                                buffer = new(char, allocate_at_least);
                                if (!buffer) {
                                        r = log_oom();
                                        goto finish;
                                }

                                buffer_size = allocate_at_least;
                        }

                        n = recv(fd, buffer, buffer_size, MSG_DONTWAIT|MSG_PEEK|MSG_TRUNC);
                        if (n < 0) {
                                if (errno == EAGAIN)
                                        goto wait_for_event;

                                r = log_error_errno(errno,
                                                    "Failed to read notification datagram: %m");
                                goto finish;
                        }
                        if ((size_t) n > buffer_size) {
                                allocate_at_least = n;
                                continue;
                        }

                        /* Now we know the message fit in the buffer, now read it properly. */
                        k = recv(fd, buffer, buffer_size, 0);
                        if (k < 0) {
                                r = log_error_errno(errno,
                                                    "Failed to consume notification datagram: %m");
                                goto finish;
                        }
                        if (k != n) {
                                r = log_error_errno(EIO,
                                                    "Consumed notification datagram has different size than original: %m");
                                goto finish;
                        }

                        /* Successfully acquired a message! */
                        break;
                }

                /* Too short for what we are looking for... */
                if ((size_t) n < strlen("READY=1"))
                        goto wait_for_event;

                p = startswith(buffer, "READY=1");
                if (!p) {
                        p = memmem(buffer, n, "\nREADY=1", strlen("\nREADY=1"));
                        if (!p)
                                goto wait_for_event; /* Doesn't contain a READY= stanza */

                        p += strlen("\nREADY=1");
                }

                if (p == buffer + n || *p == '\n') {
                        /* Got it! */
                        printf(PID_FMT "\n", pid);
                        pid = 0; /* don't kill on exit */
                        break;
                }

wait_for_event:
                if (quit) {
                        /* Got SIGINT or SIGTERM */
                        log_error("Exiting due to signal.");
                        break;
                }

                nw = now(CLOCK_MONOTONIC);
                ts = nsec_to_timespec(timeout_at > nw ? timeout_at - nw : 0);

                r = ppoll(&pollfd, 1, &ts, &ss_poll);
                if (r < 0) {
                        if (errno == EINTR) /* got a SIGCHLD or a SIGTERM/SIGINT? */
                                continue;

                        r = log_error_errno(errno, "Failed to ppoll(): %m");
                        goto finish;
                }

                if (r == 0) { /* timeout */
                        log_error("Timeout.");
                        r = -ETIMEDOUT;
                        goto finish;
                }
        }

        r = 0;

finish:
        if (pid > 1)
                (void) kill(pid, SIGTERM);

        free(buffer);
        safe_close(fd);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
