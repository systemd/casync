LIBS=`libgcrypt-config --libs` `pkg-config --libs liblzma`
CFLAGS=-O0 -g -Wall -D_GNU_SOURCE `libgcrypt-config --cflags` `pkg-config --cflags liblzma`

HEADERS= \
	cadecoder.h \
	caencoder.h \
	caformat.h \
	caformat-util.h \
	caindex.h \
	castore.h \
	casync.h \
	chunker.h \
	def.h \
	objectid.h \
	realloc-buffer.h \
	util.h

OBJECTS= \
	cadecoder.o \
	caencoder.o \
	caindex.o \
	caformat-util.o \
	castore.o \
	casync.o \
	chunker.o \
	objectid.o \
	realloc-buffer.o \
	util.o

all: test-chunker test-casync test-caencoder casync

cadecoder.o: $(HEADERS)
caencoder.o: $(HEADERS)
caindex.o: $(HEADERS)
caformat-util.o: $(HEADERS)
castore.o: $(HEADERS)
casync.o: $(HEADERS)
chunker.o: $(HEADERS)
objectid.o: $(HEADERS)
realloc-buffer.o: $(HEADERS)
util.o: $(HEADERS)
casync-tool.o: $(HEADERS)
test-caencoder.o: $(HEADERS)
test-chunker.o: $(HEADERS)
test-casync.o: $(HEADERS)

casync: casync-tool.o $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test-caencoder: test-caencoder.o $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test-chunker: test-chunker.o $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test-casync: test-casync.c  $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test-files:
	test -e test-files/thisisafifo || mkfifo test-files/thisisafifo
	test -e test-files/ablockdevice || mknod test-files/ablockdevice b 0 0
	test -e test-files/achardevice || mknod test-files/achardevice c 0 0

.PHONY: test-files

clean:
	rm -f *.o casync test-chunker test-casync test-caencoder
