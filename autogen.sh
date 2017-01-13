#!/bin/sh

#  This file is part of systemd-journal-remote.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

set -e

oldpwd=$(pwd)
topdir=$(dirname $0)
cd $topdir

autoreconf --force --install --symlink

libdir() {
        echo $(cd "$1/$(gcc -print-multi-os-directory)"; pwd)
}

cd $oldpwd

if [ "x$1" = "xc" ]; then
        $topdir/configure CFLAGS='-g -O0 -ftrapv' $args
        make clean
else
        echo
        echo "----------------------------------------------------------------"
        echo "Initialized build system. For a common configuration please run:"
        echo "----------------------------------------------------------------"
        echo
        echo "$topdir/configure CFLAGS='-g -O0 -ftrapv' $args"
        echo
fi
