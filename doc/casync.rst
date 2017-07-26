:orphan:

casync manual page
==================

Synopsis
--------

| **casync** [*OPTIONS*...] make [*ARCHIVE* | *ARCHIVE_INDEX* | *BLOB_INDEX*] [*PATH*]
| **casync** [*OPTIONS*...] extract [*ARCHIVE* | *ARCHIVE_INDEX* | *BLOB_INDEX*] [*PATH*]
| **casync** [*OPTIONS*...] list [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*]
| **casync** [*OPTIONS*...] mtree [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*]
| **casync** [*OPTIONS*...] stat [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*] [*PATH*]
| **casync** [*OPTIONS*...] digest [*ARCHIVE* | *BLOB* | *ARCHIVE_INDEX* | *BLOB_INDEX* | *DIRECTORY*]
| **casync** [*OPTIONS*...] mount [*ARCHIVE* | *ARCHIVE_INDEX*] *PATH*
| **casync** [*OPTIONS*...] mkdev [*BLOB* | *BLOB_INDEX*] [*NODE*]

Description
-----------

Content-Addressable Data Synchronization Tool

Commands
--------

| **casync** **make** [*ARCHIVE* | *ARCHIVE_INDEX*] [*DIRECTORY*]
| **casync** **make** [*BLOB_INDEX*] *FILE* | *DEVICE*

This will create either a .catar archive or an .caidx index for for the given
*DIRECTORY*, or a .caibx index for the given *FILE* or block *DEVICE*. The type
of output is automatically chosen based on the file extension (this may be
override with ``--what=``). *DIRECTORY* is optional, and the current directory
will be used if not specified.

When a .caidx or .caibx file is created, a .castr storage directory will be
created too, by default located in the same directory, and named
``default.castr`` unless configured otherwise (see ``--store=`` option).

The metadata included in the archive is controlled by the ``--with-*`` and
``--without-*`` options.

|
| **casync** extract [*ARCHIVE* | *ARCHIVE_INDEX*] [*DIRECTORY*]
| **casync** extract *BLOB_INDEX* *FILE* | *DEVICE*

This will extract the contents of a .catar archive or .caidx index
into the specified *DIRECTORY*, or the contents specified by *BLOB_INDEX*
to the specified *FILE* or block *DEVICE*. *DIRECTORY* may be omitted,
and the current directory will be used by default.

The metadata replayed from the archive is controlled by the ``--with-*`` and
``--without-*`` options.

|
| **casync** list [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*]

This will list all the files and directories in the specified .catar
archive or .caidx index, or the directory. The argument is optional,
and the current directory will be used by default.

The output includes the permission mask and file names::

  $ casync list /usr/share/doc/casync
  drwxr-xr-x
  -rw-r--r-- README.md
  -rw-r--r-- TODO

|
| **casync** mtree [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*]

This is similar to **list**, but includes information about each entry in the
key=value format defined by BSD mtree(5):

  $ casync mtree /usr/share/doc/casync
  . type=dir mode=0755 uid=0 gid=0 time=1500343585.721189650
  README.md type=file mode=0644 size=7286 uid=0 gid=0 time=1498175562.000000000 sha256digest=af75eacac1f00abf6adaa7510a2c7fe00a4636daf9ea910d69d96f0a4ae85df4
  TODO type=file mode=0644 size=2395 uid=0 gid=0 time=1498175562.000000000 sha256digest=316f11a03c08ec39f0328ab1f7446bd048507d3fbeafffe7c32fad4942244b7d

|
| **casync** stat [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*] [*PATH*]

This will show detailed information about a file or directory *PATH*, as found
in either *ARCHIVE* or *ARCHIVE_INDEX* or underneath *DIRECTORY*. Both arguments
are optional. The first defaults to the current directory, and the second
the top-level path (``.``).

Example output::

  $ casync stat .
      File: .
      Mode: drwxrwxr-x
  FileAttr: ----------
   FATAttr: ---
    Offset: 0
      Time: 2017-07-17 22:53:30.723304050
      User: zbyszek (1000)
     Group: zbyszek (1000)

|
| **casync** digest [*ARCHIVE* | *BLOB* | *ARCHIVE_INDEX* | *BLOB_INDEX* | *DIRECTORY*]

This will compute and print the checksum of the argument.
The argument is optional and defaults to the current directory::

  $ casync digest
  d1698b0c4c27163284abea5d1e369b92e89dd07cb74378638849800e0406baf7

  $ casync digest .
  d1698b0c4c27163284abea5d1e369b92e89dd07cb74378638849800e0406baf7

|
| **casync** mount [*ARCHIVE* | *ARCHIVE_INDEX*] *PATH*

This will mount the specified .catar archive or .caidx index at the
specified *PATH*, using the FUSE protocol.

|
| **casync** mkdev [*BLOB* | *BLOB_INDEX*] [*NODE*]

This will create a block device *NODE* with the contents specified
by the .caibx *BLOB_INDEX* or just the file or block device *BLOB*,
using the NBD protocol.

Example::

  $ sudo casync -v mkdev README.md
  Attached: /dev/nbd0

  (in another terminal)
  $ sudo head -n1 /dev/nbd0
  # casync — Content Addressable Data Synchronizer

When ``casync mkdev`` is killed, the device is destroyed.

Options
-------

General options:

--help, -h                      Show terse help output
--verbose, -v                   Show terse status information during runtime
--store=PATH                    The primary chunk store to use
--extra-store=<PATH>            Additional chunk store to look for chunks in
--chunk-size=<[MIN:]AVG[:MAX]>  The minimal/average/maximum number of bytes in a chunk
--digest=<DIGEST>               Pick digest algorithm (sha512-256 or sha256)
--compression=<COMPRESSION>     Pick compression algorithm (zstd, xz or gzip)
--seed=<PATH>                   Additional file or directory to use as seed
--rate-limit-bps=<LIMIT>        Maximum bandwidth in bytes/s for remote communication
--exclude-nodump=no             Don't exclude files with chattr(1)'s +d **nodump** flag when creating archive
--exclude-submounts=yes         Exclude submounts when creating archive
--reflink=no                    Don't create reflinks from seeds when extracting
--hardlink=yes                  Create hardlinks from seeds when extracting
--punch-holes=no                Don't create sparse files when extracting
--delete=no                     Don't delete existing files not listed in archive after extraction
--undo-immutable=yes            When removing existing files, undo chattr(1)'s +i 'immutable' flag when extracting
--seed-output=no                Don't implicitly add pre-existing output as seed when extracting
--recursive=no                  List non-recursively
--uid-shift=<yes|SHIFT>         Shift UIDs/GIDs
--uid-range=<RANGE>             Restrict UIDs/GIDs to range

Input/output selector:

--what=archive          Operate on archive file
--what=archive-index    Operate on archive index file
--what=blob             Operate on blob file
--what=blob-index       Operate on blob index file
--what=directory        Operate on directory

Archive feature sets:

--with=best             Store most accurate information
--with=unix             Store UNIX baseline information
--with=fat              Store FAT information
--with=chattr           Store chattr(1) file attributes
--with=fat-attrs        Store FAT file attributes
--with=privileged       Store file data that requires privileges to restore
--with=fuse             Store file data that can exposed again via 'casync mount'

(and similar: ``--without=fat-attrs``, ``--without=privileged``, ...)

Individual archive features:

--with=<16bit-uids>        Store reduced 16bit UID/GID information
--with=<32bit-uids>        Store full 32bit UID/GID information
--with=<user-names>        Store user/group names
--with=<sec-time>          Store timestamps in 1s granularity
--with=<usec-time>         Store timestamps in 1µs granularity
--with=<nsec-time>         Store timestamps in 1ns granularity
--with=<2sec-time>         Store timestamps in 2s granularity
--with=<read-only>         Store per-file read only flag
--with=<permissions>       Store full per-file UNIX permissions
--with=<symlinks>          Store symbolic links
--with=<device-nodes>      Store block and character device nodes
--with=<fifos>             Store named pipe nodes
--with=<sockets>           Store AF_UNIX file system socket nodes
--with=<flag-hidden>       Store FAT hidden file flag
--with=<flag-system>       Store FAT system file flag
--with=<flag-archive>      Store FAT archive file flag
--with=<flag-append>       Store append-only file flag
--with=<flag-noatime>      Store disable access time file flag
--with=<flag-compr>        Store enable compression file flag
--with=<flag-nocow>        Store disable copy-on-write file flag
--with=<flag-nodump>       Store disable dumping file flag
--with=<flag-dirsync>      Store synchronous directory flag
--with=<flag-immutable>    Store immutable file flag
--with=<flag-sync>         Store synchronous file flag
--with=<flag-nocomp>       Store disable compression file flag
--with=<flag-projinherit>  Store project quota inheritance flag
--with=<subvolume>         Store btrfs subvolume information
--with=<subvolume-ro>      Store btrfs subvolume read-only property
--with=<xattrs>            Store extended file attributes
--with=<acl>               Store file access control lists
--with=<selinux>           Store SElinux file labels
--with=<fcaps>             Store file capabilities

(and similar: ``--without=16bit-uids``, ``--without=32bit-uids``, ...)

Archive features
----------------

The various ``--with=`` and ``--without=`` parameters control the precise set
of metadata to store in the archive, or restore when extracting. These flags
only apply if ``casync`` operates on the file system level.
