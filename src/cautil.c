#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "cautil.h"
#include "util.h"

static bool ca_is_definitely_path(const char *s) {

        assert(s);

        /* We consider ".", ".." and everything starting with either "/" or "./" a file system path. */

        if (s[0] == '/')
                return true;

        if (s[0] == '.') {
                if (s[1] == 0)
                        return true;

                if (s[1] == '/')
                        return true;

                if (s[1] == '.' && s[2] == 0)
                        return true;
        }

        return false;
}

bool ca_is_url(const char *s) {
        const char *e;
        size_t n, k;

        assert(s);

        /* Checks whether something appears to be a URL. This is inspired by RFC3986, but a bit more restricted, so
         * that we can clearly distuingish URLs from file system paths, and ssh specifications. For example, the kind
         * of URLs we are interested in must contain '://' as host/path separator.
         *
         * We explicit exclude all strings starting with either "/" or "./" as URL from being detected as URLs, so that
         * this can always be used for explicitly referencing local directories. */

        if (ca_is_definitely_path(s))
                return false;

        if (!strchr(URL_PROTOCOL_FIRST, s[0]))
                return false;

        n = 1 + strspn(s + 1, URL_PROTOCOL_CHARSET);

        e = startswith(s + n, "://");
        if (!e)
                return false;

        k = strspn(e, HOSTNAME_CHARSET "@");
        if (k <= 0)
                return false;

        if (e[k] != '/' && e[k] != 0)
                return false;

        return true;
}

bool ca_is_ssh_path(const char *s) {
        size_t n;

        assert(s);

        if (ca_is_definitely_path(s))
                return false;

        n = strspn(s, HOSTNAME_CHARSET);
        if (n <= 0)
                return false;

        if (s[n] == '@') {
                size_t k;

                k = strspn(s + n + 1, HOSTNAME_CHARSET);
                if (k <= 0)
                        return false;

                if (s[n + 1 + k] != ':')
                        return false;

                n += 1 + k;

        } else if (s[n] != ':')
                return false;

        return true;
}

CaLocatorClass ca_classify_locator(const char *s) {
        if (isempty(s))
                return _CA_LOCATOR_CLASS_INVALID;

        if (ca_is_url(s))
                return CA_LOCATOR_URL;

        if (ca_is_ssh_path(s))
                return CA_LOCATOR_SSH;

        return CA_LOCATOR_PATH;
}

char *ca_strip_file_url(const char *p) {
        const char *e, *f;
        char *t, *result;

        assert(p);

        /* If the input is a file:// URL, turn it into a normal path, in a very defensive way. */

        e = startswith(p, "file://");
        if (!e)
                return strdup(p);

        if (*e == '/')
                goto unescape;

        e = startswith(e, "localhost/");
        if (e) {
                e --;
                goto unescape;
        }

        return strdup(p);

unescape:
        result = new(char, strlen(e) + 1);
        if (!result)
                return NULL;

        for (f = e, t = result; *f; f++) {
                int a, b;

                if (f[0] == '%' &&
                    (a = unhexchar(f[1])) >= 0 &&
                    (b = unhexchar(f[2])) >= 0) {

                        *(t++) = (char) (((uint8_t) a << 4) | (uint8_t) b);
                        f += 2;
                        continue;
                }

                *(t++) = *f;
        }

        *t = 0;

        return result;
}

bool ca_locator_has_suffix(const char *p, const char *suffix) {
        const char *e, *q;

        if (isempty(suffix))
                return true;

        if (isempty(p))
                return false;

        if (ca_is_url(p)) {
                size_t n;

                n = strlen(suffix);

                e = strrchr(p, '?');
                if (!e)
                        e = strrchr(p, ';');
                if (!e)
                        e = strchr(p, 0);

                if ((size_t) (e - p) < n)
                        return false;

                return memcmp(e - n, suffix, n) == 0;
        }

        e = strrchr(p, '/');
        if (e)
                e++;
        else
                e = p;

        q = endswith(e, suffix);

        return q && q != e;
}
