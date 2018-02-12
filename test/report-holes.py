#!/usr/bin/python3
# SPDX-License-Identifier: CC0-1.0

import os
import sys
import errno

def report(fname):
    fd = os.open(fname, os.O_RDONLY)
    len = os.lseek(fd, 0, os.SEEK_END)
    offset = 0
    while offset < len:
        start = os.lseek(fd, offset, os.SEEK_HOLE)
        if start == len:
            break
        try:
            offset = os.lseek(fd, start, os.SEEK_DATA)
        except OSError as e:
            if e.errno == errno.ENXIO:
                offset = len
            else:
                raise
        print(f'found hole between 0x{start:08X} and 0x{offset:08X} ({offset - start} bytes)')

if __name__ == '__main__':
    for name in sys.argv[1:]:
        report(name)
