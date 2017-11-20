#!/bin/sh -eu
# SPDX-License-Identifier: LGPL-2.1+

# output width
if "$1"  --help | grep -v 'default:' | grep -E -q '.{80}.'; then
        echo "$(basename "$1") --help output is too wide:"
        "$1"  --help | awk 'length > 80' | grep -E --color=yes '.{80}'
        exit 1
fi

# no --help output to stdout
if "$1" --help 2>&1 1>/dev/null | grep .; then
        echo "$(basename "$1") --help prints to stderr"
        exit 2
fi

# error output to stderr
if ! "$1" --no-such-parameter 2>&1 1>/dev/null | grep -q .; then
        echo "$(basename "$1") with an unknown parameter does not print to stderr"
        exit 3
fi
