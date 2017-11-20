/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "notify.h"
#include "util.h"

int send_notify(const char *text) {
        const char *e;
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa = {
                .un.sun_family = AF_UNIX,
        };
        ssize_t n;
        size_t c;
        int fd, r;

        if (isempty(text))
                return 0;

        e = getenv("NOTIFY_SOCKET");
        if (!e)
                return 0;

        c = strlen(e);
        if (c < 2 || c > sizeof(sa.un.sun_path))
                return -EINVAL;
        if (!IN_SET(e[0], '/', '@'))
                return -EINVAL;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (e[0] == '@') {
                sa.un.sun_path[0] = 0;
                strncpy(sa.un.sun_path + 1, e + 1, sizeof(sa.un.sun_path) - 1);
        } else
                strncpy(sa.un.sun_path, e, sizeof(sa.un.sun_path));

        n = sendto(fd, text, strlen(text), MSG_NOSIGNAL, &sa.sa, SOCKADDR_UN_LEN(sa.un));
        if (n < 0) {
                r = -errno;
                goto finish;
        }

        r = 1;

finish:
        safe_close(fd);
        return r;
}
