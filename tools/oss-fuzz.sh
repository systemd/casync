#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1+

set -ex

export LC_CTYPE=C.UTF-8

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
clang_version="$($CC --version | sed -nr 's/.*version ([^ ]+?) .*/\1/p' | sed -r 's/-$//')"

SANITIZER=${SANITIZER:-address -fsanitize-address-use-after-scope}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize-coverage=trace-pc-guard,trace-cmp"

clang_lib="/usr/lib64/clang/${clang_version}/lib/linux"
[ -d "$clang_lib" ] || clang_lib="/usr/lib/clang/${clang_version}/lib/linux"

export CFLAGS=${CFLAGS:-$flags}
export CXXFLAGS=${CXXFLAGS:-$flags}
export LDFLAGS=${LDFLAGS:--L${clang_lib}}

export WORK=${WORK:-$(pwd)}
export OUT=${OUT:-$(pwd)/out}
mkdir -p $OUT

build=$WORK/build
rm -rf $build
mkdir -p $build

fuzzflag="oss-fuzz=true"
if [ -z "$FUZZING_ENGINE" ]; then
        fuzzflag="llvm-fuzz=true"
fi

meson $build -D$fuzzflag \
      -Db_lundef=false \
      -Dlibzstd=disabled \
      -Dman=false
ninja -C $build fuzzers

# The seed corpus is a separate flat archive for each fuzzer,
# with a fixed name ${fuzzer}_seed_corpus.zip.
for d in "$(dirname "$0")/../test/fuzz/fuzz-"*/; do
        [ -d "$d" ] || continue
        zip -jqr $OUT/$(basename "$d")_seed_corpus.zip "$d"
done

find $build -maxdepth 1 -type f -executable -name "fuzz-*" -exec mv {} $OUT \;
# cp test/fuzz/*.options $OUT
