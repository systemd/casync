#include "signal-handler.h"
#include "util.h"

volatile sig_atomic_t quit = false;

void block_exit_handler(int how, sigset_t *old) {
        sigset_t ss;

        assert_se(sigemptyset(&ss) >= 0);
        assert_se(sigaddset(&ss, SIGINT) >= 0);
        assert_se(sigdelset(&ss, SIGTERM) >= 0);
        assert_se(sigaddset(&ss, SIGHUP) >= 0);
        assert_se(sigprocmask(how, &ss, old) >= 0);
}

void exit_signal_handler(int signo) {
        quit = true;
}

void install_exit_handler(void (*handler)(int)) {
        const struct sigaction sa = {
                .sa_handler = handler ?: exit_signal_handler,
        };

        assert_se(sigaction(SIGINT, &sa, NULL) >= 0);
        assert_se(sigaction(SIGTERM, &sa, NULL) >= 0);
        assert_se(sigaction(SIGHUP, &sa, NULL) >= 0);
}

int sync_poll_sigset(CaSync *s) {
        sigset_t ss;
        int r;

        /* Block SIGTERM/SIGINT for now */
        block_exit_handler(SIG_BLOCK, &ss);

        if (quit) /* Check if we are supposed to quit, if so, do so now */
                r = -ESHUTDOWN;
        else {
                /* Wait for an event, temporarily and atomically unblocking SIGTERM/SIGINT while doing so */
                r = ca_sync_poll(s, UINT64_MAX, &ss);
                if ((r == -EINTR || r >= 0) && quit)
                        r = -ESHUTDOWN;
        }

        /* Unblock SIGTERM/SIGINT again */
        block_exit_handler(SIG_UNBLOCK, NULL);

        return r;
}

void disable_sigpipe(void) {
        static const struct sigaction sa = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_RESTART,
        };

        assert_se(sigaction(SIGPIPE, &sa, NULL) >= 0);
}
