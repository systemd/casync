#ifndef foosignalhandlerhfoo

#include <signal.h>
#include <stdbool.h>

#include "casync.h"

extern volatile sig_atomic_t quit;

void exit_signal_handler(int signo);

void install_exit_handler(void (*handler)(int));
void block_exit_handler(int how, sigset_t *old);

int sync_poll_sigset(CaSync *s);

void disable_sigpipe(void);

#endif
