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
| **casync** [*OPTIONS*...] mkdev [*BLOB* | *BLOB_INDEX*] [*NODE*]

Description
-----------

Content-Addressable Data Synchronization Tool

Options
-------

General options:

--help, -h                      Show this help
--verbose, -v                   Show terse status information during runtime
--store=PATH                    The primary chunk store to use
--extra-store=PATH              Additional chunk store to look for chunks in
--chunk-size=<[MIN]:AVG:[MAX]>  The minimal/average/maximum number of bytes in a chunk
--seed=PATH                     Additional file or directory to use as seed
--rate-limit-bps=LIMIT          Maximum bandwidth in bytes/s for remote communication
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
--uid-range=RANGE               Restrict UIDs/GIDs to range

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
--with=<xattrs>            Store extended file attributes
--with=<acl>               Store file access control lists
--with=<fcaps>             Store file capabilities

(and similar: ``--without=16bit-uids``, ``--without=32bit-uids``, ...)
