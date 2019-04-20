.. SPDX-License-Identifier: LGPL-2.1+

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
| **casync** [*OPTIONS*...] gc *BLOB_INDEX* | *ARCHIVE_INDEX* ...

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
overridden with ``--what=``). *DIRECTORY* is optional, and the current directory
will be used if not specified.

When a .caidx or .caibx file is created, a .castr storage directory will be
created too, by default located in the same directory, and named
``default.castr`` unless configured otherwise (see ``--store=`` option).

The metadata included in the archive is controlled by the ``--with-*`` and
``--without-*`` options.

|
| **casync** **extract** [*ARCHIVE* | *ARCHIVE_INDEX*] [*DIRECTORY*]
| **casync** **extract** *BLOB_INDEX* *FILE* | *DEVICE*

This will extract the contents of a .catar archive or .caidx index
into the specified *DIRECTORY*, or the contents specified by *BLOB_INDEX*
to the specified *FILE* or block *DEVICE*. *DIRECTORY* may be omitted,
and the current directory will be used by default.

The metadata replayed from the archive is controlled by the ``--with-*`` and
``--without-*`` options.

|
| **casync** **list** [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*]

This will list all the files and directories in the specified .catar
archive or .caidx index, or the directory. The argument is optional,
and the current directory will be used by default.

The output includes the permission mask and file names::

  $ casync list /usr/share/doc/casync
  drwxr-xr-x
  -rw-r--r-- README.md
  -rw-r--r-- TODO

|
| **casync** **mtree** [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*]

This is similar to **list**, but includes information about each entry in the
key=value format defined by BSD mtree(5)::

  $ casync mtree /usr/share/doc/casync
  . type=dir mode=0755 uid=0 gid=0 time=1500343585.721189650
  README.md type=file mode=0644 size=7286 uid=0 gid=0 time=1498175562.000000000 sha256digest=af75eacac1f00abf6adaa7510a2c7fe00a4636daf9ea910d69d96f0a4ae85df4
  TODO type=file mode=0644 size=2395 uid=0 gid=0 time=1498175562.000000000 sha256digest=316f11a03c08ec39f0328ab1f7446bd048507d3fbeafffe7c32fad4942244b7d

|
| **casync** **stat** [*ARCHIVE* | *ARCHIVE_INDEX* | *DIRECTORY*] [*PATH*]

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
| **casync** **digest** [*ARCHIVE* | *BLOB* | *ARCHIVE_INDEX* | *BLOB_INDEX* | *DIRECTORY*]

This will compute and print the checksum of the argument.
The argument is optional and defaults to the current directory::

  $ casync digest
  d1698b0c4c27163284abea5d1e369b92e89dd07cb74378638849800e0406baf7

  $ casync digest .
  d1698b0c4c27163284abea5d1e369b92e89dd07cb74378638849800e0406baf7

|
| **casync** **mount** [*ARCHIVE* | *ARCHIVE_INDEX*] *PATH*

This will mount the specified .catar archive or .caidx index at the
specified *PATH*, using the FUSE protocol.

|
| **casync** **mkdev** [*BLOB* | *BLOB_INDEX*] [*NODE*]

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

|
| **casync** **gc** *ARCHIVE_INDEX* | *BLOB_INDEX* ...

This will remove all chunks that are not used by one of the specified indices
(one or more blob and archive indices can be given). If ``--store`` is not
given, the default store for the first index will be used.

This command can be used to prune unused chunks from a shared chunk
store.

Options
-------

General options:

--help, -h                      Show terse help output
--version                       Show brief version information
--log-level=<LEVEL>, -l         Set log level (debug, info, err)
--verbose, -v                   Show terse status information during runtime
--dry-run, -n                   Only print what would be removed with **gc**
--store=PATH                    The primary chunk store to use
--extra-store=<PATH>            Additional chunk store to look for chunks in
--chunk-size=<[MIN:]AVG[:MAX]>  The minimal/average/maximum number of bytes in a chunk
--cutmark=CUTMARK               Specify a cutmark
--cutmark-delta-bytes=BYTES     Maximum bytes to shift cut due to cutmark
--digest=<DIGEST>               Pick digest algorithm (sha512-256 or sha256)
--compression=<COMPRESSION>     Pick compression algorithm (zstd, xz or gzip)
--seed=<PATH>                   Additional file or directory to use as seed
--cache=<PATH>                  Directory to use as encoder cache
--cache-auto, -c                Pick encoder cache directory automatically
--rate-limit-bps=<LIMIT>        Maximum bandwidth in bytes/s for remote communication
--exclude-nodump=no             Don't exclude files with chattr(1)'s +d **nodump** flag when creating archive
--exclude-submounts=yes         Exclude submounts when creating archive
--exclude-file=no               Don't respect .caexclude files in the file tree
--reflink=no                    Don't create reflinks from seeds when extracting
--hardlink=yes                  Create hardlinks from seeds when extracting
--punch-holes=no                Don't create sparse files when extracting
--delete=no                     Don't delete existing files not listed in archive after extraction
--undo-immutable=yes            When removing existing files, undo chattr(1)'s +i 'immutable' flag when extracting
--seed-output=no                Don't implicitly add pre-existing output as seed when extracting
--recursive=no                  List non-recursively
--mkdir=no                      Don't automatically create mount directory if it is missing
--uid-shift=<yes|SHIFT>         Shift UIDs/GIDs
--uid-range=<RANGE>             Restrict UIDs/GIDs to range

Input/output selector:

--what=archive          Operate on archive file
--what=archive-index    Operate on archive index file
--what=blob             Operate on blob file
--what=blob-index       Operate on blob index file
--what=directory        Operate on directory
--what=help             Print a list of allowed values (and terminate the program)

Turn on archive feature sets:

--with=best             Store most accurate information
--with=unix             Store UNIX baseline information
--with=fat              Store FAT information
--with=chattr           Store chattr(1) file attributes
--with=fat-attrs        Store FAT file attributes
--with=privileged       Store file data that requires privileges to restore
--with=fuse             Store file data that can exposed again via 'casync mount'

To turn archive features *off*, ``--without=…`` may be used, such as
``--without=fat-attrs``, ``--without=privileged``, etc.
To disable all optional features, ``--without=all`` may be used.
(The positive form ``--with=all`` does not make sense, because some
features are conflicting. To enable the maximum set of information, use
``--with=best``.)

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
--with=<flag-hidden>       Store FAT "hidden" file flag
--with=<flag-system>       Store FAT "system" file flag
--with=<flag-archive>      Store FAT "archive" file flag
--with=<flag-append>       Store "append-only" file flag
--with=<flag-noatime>      Store "disable access time" file flag
--with=<flag-compr>        Store "enable compression" file flag
--with=<flag-nocow>        Store "disable copy-on-write" file flag
--with=<flag-nodump>       Store "disable dumping" file flag
--with=<flag-dirsync>      Store "synchronous" directory flag
--with=<flag-immutable>    Store "immutable" file flag
--with=<flag-sync>         Store "synchronous" file flag
--with=<flag-nocomp>       Store "disable compression" file flag
--with=<flag-projinherit>  Store "project quota inheritance" flag
--with=<subvolume>         Store btrfs subvolume information
--with=<subvolume-ro>      Store btrfs subvolume read-only property
--with=<xattrs>            Store extended file attributes
--with=<acl>               Store file access control lists
--with=<selinux>           Store SElinux file labels
--with=<fcaps>             Store file capabilities
--with=<quota-projid>      Store ext4/XFS quota project ID

(and similar: ``--without=16bit-uids``, ``--without=32bit-uids``, ...)

Archive features
----------------

The various ``--with=`` and ``--without=`` parameters control the precise set
of metadata to store in the archive, or restore when extracting. These flags
only apply if ``casync`` operates on the file system level.

Excluding Files and Directories from Archiving
----------------------------------------------

When generating an archive or index from a file system directory tree, some
files and directories are excluded by default and others may optionally be
excluded:

1. Files and directories of virtual API file systems exposed by the kernel
   (i.e. procfs, sysfs, cgroupfs, devpts … — but not tmpfs/devtmpfs) are
   excluded unconditionally.

2. Depending on whether symlinks, device nodes, fifos and sockets are enabled
   for archiving with ``--with=`` and ``--without=``, file nodes of these types
   are excluded.

3. By default, files and directories with the ``+d`` chattr(1) flag set are
   excluded, however this behaviour may be turned off with
   ``--exclude-nodump=no``.

4. Optionally, files and directories contained in submounts of the specified
   file system tree are excluded, if ``--exclude-submounts=yes`` is specified.

5. By default, any files and directories listed in ``.caexclude`` files in the
   file hierarchy are excluded, however interpretation of these files may be
   turned off with ``--exclude-file=no``. These files operate similar to
   ``git``'s ``.gitignore`` concept: they are read as text file where each line
   is either empty/starts with ``#`` (in which case they have no effect, which
   may be used for commenting), or list a globbing path pattern of
   files/directories to ignore. If a line contains no ``/`` character the line
   applies to the directory the ``.caexclude`` file is located in as well as
   all child directories of it. If it contains at least one ``/`` character it
   is considered stricly relative to the directory the ``.caexclude`` file is
   located in. ``.caexclude`` files may appear in any directory of the file
   system tree that is archived, however they have no effect when placed in
   directories that are marked for exclusion via ``.caexclude`` files placed
   further up in the directory tree. When a line ends in a ``/`` character it
   applies to directories only, and not regular files or other file node
   types. If a line is prefixed with a ``!`` character matching files are
   excluded from the exclusion, i.e. the effect of other matching lines that
   are not prefixed like this is cancelled for matching files. ``!`` lines
   unconditionally take precedence over lines not marked like this. Moreover,
   lines prefixed with ``!`` also cancel the effect of patterns in
   ``.caexclude`` files placed in directories further up the tree.

Cutmarks
--------

``casync`` cuts the stream to serialize into chunks of an average size (as
specified with ``--chunk-size=``), determining cut points using the ``buzhash``
rolling hash function and a modulo test. Frequently, cut points determined that
way are at slightly inconvenient locations: in the midle of objects serialized
in the stream rather then before or after them, thus needlessly exploding
changes to individual objects into more than one chunk. To optimize this
**cutmarks** may be configured. These are byte sequences ``casync`` (up to 8
bytes in length) automatically detects in the data stream and that should be
considered particularly good cutpoints. When cutmarks are defined the chunking
algorithm will slightly move the cut point between two chunks to match a
cutmark if one has recently been seen in the serialization stream.

Cutmarks may be specified with the ``--cutmark=`` option. It takes a cutmark
specification in the format ``VALUE:MASK+OFFSET`` or ``VALUE:MASK-OFFSET``. The
first part, the value indicates the byte sequence to detect in hexadecimal
digits, up to 8 bytes (thus 16 characters) in length. Following the colon a
bitmask (also in hexadecimal) may be specified of the same size. Every 8 byte
sequence at every 1 byte granularity stream position is tested against the
value. If all bits indicated in the mask match a cutmark is found. The third
part of the specification indicates where to place the cutmark specifically
relative to the the end of the 8 byte sequence. Specify ``-8`` to cut
immediately before the cutmark sequence, and ``+0`` right after. The offset
(along with its ``+`` or ``-`` character) may be omitted, in which case the
offset is assumed to be zero, i.e. the cut is done right after the
sequence. The mask (along with its ``:`` character) may also be omitted, in
which case it is assumed to be ``FFFFFFFFFFFFFFFF``, i.e. all
bits on, matching the full specified byte sequence. In order to match shorter
byte sequence (for example to adapt the tool to some specific file format using
shorter object or section markers) simply specificy a shorter mask value and
correct the offset value.

Examples:

  --cutmark=123456789ABCDEF0


This defines a cutmark to be the 8 byte sequence 0x12, 0x34, 0x56, 0x78, 0x9A,
0xBC, 0xDE, 0xF0, and the cut is placed right after the last byte, i.e. after the
0xF0.


  --cutmark=C0FFEE:FFFFFF-5


This defines a cutmark to be the 3 byte sequence 0xC0, 0xFF, 0xEE and the cut is
placed right after the last byte, i.e. after the 0xEE.

  --cutmark=C0DECAFE:FFFFFFFF-8


This defines a cutmark to be the 4 byte sequence 0xC0, 0xDE, 0xCA, 0xFE and the
cut is placed right before the first byte, i.e. before the 0xC0.

When operating on the file system layer (i.e. when creating `.caidx` files),
the implicit cutmark of ``--cutmark=51bb5beabcfa9613+8`` is used, to increase
the chance that cutmarks are placed right before each serialized file.

Multiple cutmarks may be defined on the same operation, simply specify
``--cutmark=`` multiple times. The parameter also takes the specifical values
``yes`` and ``no``. If the latter any implicit cutmarks are turned off, in
particular the implicit cutmark used when generating ``.caidx`` files above.

``casync`` will honour cutmarks only within the immediate vicinity of the cut
point the modulo test suggested. By default this a 16K window before the
calculated cut point. This value may be altered using the
``--cutmark-delta-max=`` setting.

Any configured cutmark (and the selected ``--cutmark-delta-max=`` value) is
also stored in the ``.caidx`` or ``.caibx`` file to ensure that such an index
file contains sufficient data for an extracting client to properly use an
existing file system tree (or block device) as seed while applying the same
chunking logic as the original image.
