#!/bin/sh -ex

cd "$(dirname "$0")"
if [ "$1" != "clean" ]; then
    test -e thisisafifo || mkfifo thisisafifo
    test -e ablockdevice || mknod ablockdevice b 0 0
    test -e achardevice || mknod achardevice c 0 0
    test -e immutable || ( touch immutable && chattr +i immutable )
    test -e nocow || ( touch nocow && chattr +C nocow )
    test -e acl || ( touch acl && setfacl -nm u:nobody:rw,u:root:rw acl )
    test -e sparse || dd if=/dev/urandom of=sparse count=2 bs=1 seek=9999
    test -e reflink || ( cp --reflink=auto large reflink &&
                             dd if=/dev/urandom of=reflink seek=102400 bs=1 count=1 conv=notrunc )
else
    chattr -i test-files/immutable || :
    rm -f test-files/thisisafifo
    rm -f test-files/ablockdevice
    rm -f test-files/achardevice
    rm -f test-files/immutable
    rm -f test-files/nocow
    rm -f test-files/acl
    rm -f test-files/sparse
fi
