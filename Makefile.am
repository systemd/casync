CLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

GCC_COLORS ?= 'ooh, shiny!'
export GCC_COLORS

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
	-D_GNU_SOURCE

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I $(top_srcdir)/src

tests = \
	test-caencoder \
	test-chunker \
	test-casync

bin_PROGRAMS = casync

noinst_PROGRAMS = $(tests)
TESTS = $(tests)

lib_SOURCES = \
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
	src/caobjectid.c \
	src/caobjectid.h \
	src/caseed.c \
	src/caseed.h \
	src/castore.c \
	src/castore.h \
	src/casync.c \
	src/casync.h \
	src/chunker.c \
	src/chunker.h \
	src/def.h \
	src/gcrypt-util.c \
	src/gcrypt-util.h \
	src/realloc-buffer.c \
	src/realloc-buffer.h \
	src/util.c \
	src/util.h

## casync

casync_SOURCES = src/casync-tool.c $(lib_SOURCES)

casync_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

casync_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS)


## test-caencoder

test_caencoder_SOURCES = test/test-caencoder.c $(lib_SOURCES)

test_caencoder_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_caencoder_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS)


## test-chunker

test_chunker_SOURCES = test/test-chunker.c $(lib_SOURCES)

test_chunker_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_chunker_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS)

## test-casync

test_casync_SOURCES = test/test-casync.c $(lib_SOURCES)

test_casync_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBLZMA_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

test_casync_LDADD = \
	$(LIBLZMA_LIBS) \
	$(LIBGCRYPT_LIBS)

test-files:
	test -e test-files/thisisafifo || mkfifo test-files/thisisafifo
	test -e test-files/ablockdevice || mknod test-files/ablockdevice b 0 0
	test -e test-files/achardevice || mknod test-files/achardevice c 0 0

.PHONY: test-files
