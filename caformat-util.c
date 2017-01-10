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
