#include "caformat.h"
#include "caformat-util.h"

const char *ca_format_type_name(uint64_t u) {

        switch (u) {

        case CA_FORMAT_HELLO:
                return "hello";

        case CA_FORMAT_ENTRY:
                return "entry";

        case CA_FORMAT_USER:
                return "user";

        case CA_FORMAT_GROUP:
                return "group";

        case CA_FORMAT_SYMLINK:
                return "symlink";

        case CA_FORMAT_DEVICE:
                return "device";

        case CA_FORMAT_PAYLOAD:
                return "payload";

        case CA_FORMAT_GOODBYE:
                return "goodbye";

        case CA_FORMAT_INDEX:
                return "index";

        case CA_FORMAT_TABLE:
                return "table";
        }

        return NULL;
}

static const struct {
        const char *name;
        uint64_t feature;
} feature_map[] = {
        { "16bit-uids",       CA_FORMAT_WITH_16BIT_UIDS       },
        { "32bit-uids",       CA_FORMAT_WITH_32BIT_UIDS       },
        { "user-names",       CA_FORMAT_WITH_USER_NAMES       },
        { "sec-time",         CA_FORMAT_WITH_SEC_TIME         },
        { "usec-time",        CA_FORMAT_WITH_USEC_TIME        },
        { "nsec-time",        CA_FORMAT_WITH_NSEC_TIME        },
        { "2sec-time",        CA_FORMAT_WITH_2SEC_TIME        },
        { "read-only",        CA_FORMAT_WITH_READ_ONLY        },
        { "permissions",      CA_FORMAT_WITH_PERMISSIONS      },
        { "symlinks",         CA_FORMAT_WITH_SYMLINKS         },
        { "device-nodes",     CA_FORMAT_WITH_DEVICE_NODES     },
        { "fifos",            CA_FORMAT_WITH_FIFOS            },
        { "sockets",          CA_FORMAT_WITH_SOCKETS          },
        { "best",             CA_FORMAT_WITH_BEST             },
        { "unix",             CA_FORMAT_WITH_UNIX             },
        { "fat",              CA_FORMAT_WITH_FAT              },
};

int ca_feature_flags_parse_one(const char *name, uint64_t *ret) {
        size_t i;

        for (i = 0; i < ELEMENTSOF(feature_map); i++)
                if (streq(feature_map[i].name, name)) {
                        *ret = feature_map[i].feature;
                        return 0;
                }

        return -ENXIO;
}

int ca_feature_flags_format(uint64_t features, char **ret) {
        char *s = NULL;
        size_t i;

        for (i = 0; i < ELEMENTSOF(feature_map); i++) {
                uint64_t f;

                if (features == 0)
                        break;

                f = feature_map[i].feature;

                if ((features & f) != f)
                        continue;

                if (!strextend(&s, s ? " " : "", feature_map[i].name, NULL)) {
                        free(s);
                        return -ENOMEM;
                }

                features &= ~f;
        }

        if (features != 0) {
                free(s);
                return -EINVAL;
        }

        *ret = s;
        return 0;
}

int ca_feature_flags_normalize(uint64_t flags, uint64_t *ret) {
        if (!ret)
                return -EINVAL;

        if ((flags & ~CA_FORMAT_FEATURE_FLAGS_MAX) != 0)
                return -EOPNOTSUPP;

        if (flags & CA_FORMAT_WITH_32BIT_UIDS)
                flags &= ~CA_FORMAT_WITH_16BIT_UIDS;

        if (flags & CA_FORMAT_WITH_NSEC_TIME)
                flags &= ~(CA_FORMAT_WITH_USEC_TIME|CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_2SEC_TIME);
        if (flags & CA_FORMAT_WITH_USEC_TIME)
                flags &= ~(CA_FORMAT_WITH_SEC_TIME|CA_FORMAT_WITH_2SEC_TIME);
        if (flags & CA_FORMAT_WITH_SEC_TIME)
                flags &= ~CA_FORMAT_WITH_2SEC_TIME;

        if (flags & CA_FORMAT_WITH_PERMISSIONS)
                flags &= ~CA_FORMAT_WITH_READ_ONLY;

        *ret = flags;
        return 0;
}

int ca_feature_flags_time_granularity_nsec(uint64_t flags, uint64_t *ret) {
        uint64_t granularity;

        if ((flags & ~CA_FORMAT_FEATURE_FLAGS_MAX) != 0)
                return -EOPNOTSUPP;
        if (!ret)
                return -EINVAL;

        if (flags & CA_FORMAT_WITH_NSEC_TIME)
                granularity = 1;
        else if (flags & CA_FORMAT_WITH_USEC_TIME)
                granularity = 1000;
        else if (flags & CA_FORMAT_WITH_SEC_TIME)
                granularity = 1000000000;
        else if (flags & CA_FORMAT_WITH_2SEC_TIME)
                granularity = 2000000000;
        else
                return -ENODATA;

        *ret = granularity;
        return 0;
}
