#  -*- Mode: makefile; indent-tabs-mode: t -*-

CLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

GCC_COLORS ?= 'ooh, shiny!'
export GCC_COLORS

protocoldir=$(prefix)/lib/casync/protocols

SUBDIRS = .

AM_CFLAGS = \
	-pipe \
	-Wall \
	-Wextra \
	-Wundef \
	-Wformat=2 -Wformat-security -Wformat-nonliteral \
	-Wlogical-op \
	-Wmissing-include-dirs \
	-Wold-style-definition \
	-Wpointer-arith \
	-Winit-self \
	-Wdeclaration-after-statement \
	-Wfloat-equal \
	-Wsuggest-attribute=noreturn \
	-Werror=missing-prototypes \
	-Werror=implicit-function-declaration \
	-Werror=missing-declarations \
	-Werror=return-type \
	-Werror=shadow \
	-Wstrict-prototypes \
	-Wredundant-decls \
	-Wmissing-noreturn \
	-Wshadow \
	-Wendif-labels \
	-Wstrict-aliasing=2 \
	-Wwrite-strings \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers \
	-Wno-unused-result \
	-Wno-format-signedness \
	-Werror=overflow \
	-Wdate-time \
	-Wnested-externs \
	-ffast-math \
	-fno-common \
	-fdiagnostics-show-option \
	-fno-strict-aliasing \
	-fvisibility=hidden \
	-fstack-protector \
	-fstack-protector-strong \
	-fPIE \
	--param=ssp-buffer-size=4 \
	-D_GNU_SOURCE \
	-DCASYNC_PROTOCOL_PATH=\"$(protocoldir)\"

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I $(top_srcdir)/src

tests = \
	test-cachunk \
	test-cachunker \
	test-caencoder \
	test-casync \
	test-cautil \
	test-camakebst \
	test-util

bin_PROGRAMS = \
	casync

protocol_PROGRAMS = \
	casync-http

noinst_PROGRAMS = \
	$(tests) \
	test-caindex \
	test-caformat

TESTS = \
	$(tests) \
	test-script.sh

lib_SOURCES = \
	src/cachunk.c \
	src/cachunk.h \
	src/cachunker.c \
	src/cachunker.h \
	src/cachunkid.c \
	src/cachunkid.h \
	src/cadecoder.c \
	src/cadecoder.h \
	src/caencoder.c \
	src/caencoder.h \
	src/caformat-util.c \
	src/caformat-util.h \
	src/caformat.h \
	src/caindex.c \
	src/caindex.h \
	src/calocation.c \
	src/calocation.h \
	src/camakebst.c \
	src/camakebst.h \
	src/canbd.c \
	src/canbd.h \
	src/caprotocol-util.c \
	src/caprotocol-util.h \
	src/caprotocol.h \
	src/caremote.c \
	src/caremote.h \
	src/caseed.c \
	src/caseed.h \
	src/castore.c \
	src/castore.h \
	src/casync.c \
	src/casync.h \
	src/cautil.c \
	src/cautil.h \
	src/def.h \
	src/fssize.c \
	src/fssize.h \
	src/gcrypt-util.c \
	src/gcrypt-util.h \
	src/parse-util.c \
	src/parse-util.h \
	src/realloc-buffer.c \
	src/realloc-buffer.h \
	src/rm-rf.c \
	src/rm-rf.h \
	src/siphash24.c \
	src/siphash24.h \
	src/util.c \
	src/util.h

## casync

casync_SOURCES = \
	src/casync-tool.c \
	$(lib_SOURCES)

casync_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

casync_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## casync-http

casync_http_SOURCES = \
	src/casync-http.c \
	$(lib_SOURCES)

casync_http_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(LIBCURL_CFLAGS)

casync_http_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(LIBCURL_LIBS) \
	$(ACL_LIBS)

install-exec-hook:
	mkdir -p $(DESTDIR)$(protocoldir)
	ln -s casync-http $(DESTDIR)$(protocoldir)/casync-https
	ln -s casync-http $(DESTDIR)$(protocoldir)/casync-ftp

## test-caencoder

test_caencoder_SOURCES = test/test-caencoder.c $(lib_SOURCES)

test_caencoder_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_caencoder_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-caformat

test_caformat_SOURCES = \
	test/test-caformat.c \
	$(lib_SOURCES)

test_caformat_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_caformat_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-cachunker

test_cachunker_SOURCES = test/test-cachunker.c $(lib_SOURCES)

test_cachunker_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_cachunker_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-casync

test_casync_SOURCES = test/test-casync.c $(lib_SOURCES)

test_casync_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_casync_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-cautil

test_cautil_SOURCES = \
	test/test-cautil.c \
	$(lib_SOURCES)

test_cautil_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_cautil_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-cachunk

test_cachunk_SOURCES = \
	test/test-cachunk.c \
	$(lib_SOURCES)

test_cachunk_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_cachunk_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-caindex

test_caindex_SOURCES = \
	test/test-caindex.c \
	$(lib_SOURCES)

test_caindex_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_caindex_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-camakebst

test_camakebst_SOURCES = \
	test/test-camakebst.c \
	$(lib_SOURCES)

test_camakebst_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_camakebst_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-util

test_util_SOURCES = \
	test/test-util.c \
	$(lib_SOURCES)

test_util_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_util_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(ACL_LIBS)

## test-script.sh

test-script.sh: test/test-script.sh.in
	sed -e "s,@top_srcdir\@,$(abs_top_srcdir)," \
	-e "s,@top_builddir\@,$(abs_top_builddir)," $^ > $@
	chmod +x $@

noinst_SCRIPTS = \
	test-script.sh

EXTRA_DIST = \
	test/test-script.sh.in \
	test/pseudo-ssh \
	test/http-server.py

CLEANFILES = \
        test-script.sh

test-files:
	test -e test-files/thisisafifo || mkfifo test-files/thisisafifo
	test -e test-files/ablockdevice || mknod test-files/ablockdevice b 0 0
	test -e test-files/achardevice || mknod test-files/achardevice c 0 0
	test -e test-files/immutable || ( touch test-files/immutable && chattr +i test-files/immutable )
	test -e test-files/nocow || ( touch test-files/nocow && chattr +C test-files/nocow )
	test -e test-files/acl || ( touch test-files/acl && setfacl -nm u:nobody:rw,u:root:rw test-files/acl)
	test -e test-files/sparse || dd if=/dev/urandom of=test-files/sparse count=2 bs=1 seek=9999

rm-test-files:
	chattr -i test-files/immutable || :
	rm -f test-files/thisisafifo
	rm -f test-files/ablockdevice
	rm -f test-files/achardevice
	rm -f test-files/immutable
	rm -f test-files/nocow
	rm -f test-files/acl
	rm -f test-files/sparse

.PHONY: test-files
