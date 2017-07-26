# casync — Content Addressable Data Synchronizer

What is this?

1. A combination of the rsync algorithm and content-addressable storage

2. An efficient way to store and retrieve multiple related versions of large file systems or directory trees

3. An efficient way to deliver and update OS, VM, IoT and container images over the Internet in an HTTP and CDN friendly way

4. An efficient backup system

See the [Announcement Blog
Story](http://0pointer.net/blog/casync-a-tool-for-distributing-file-system-images.html) for a
comprehensive introduction. The medium length explanation goes something like
this:

Encoding: Let's take a large linear data stream, split it into
variable-sized chunks (the size of each being a function of the
chunk's contents), and store these chunks in individual, compressed
files in some directory, each file named after a strong hash value of
its contents, so that the hash value may be used to as key for
retrieving the full chunk data. Let's call this directory a "chunk
store". At the same time, generate a "chunk index" file that lists
these chunk hash values plus their respective chunk sizes in a simple
linear array. The chunking algorithm is supposed to create variable,
but similarly sized chunks from the data stream, and do so in a way
that the same data results in the same chunks even if placed at
varying offsets. For more information [see this blog
story](https://moinakg.wordpress.com/2013/06/22/high-performance-content-defined-chunking/).

Decoding: Let's take the chunk index file, and reassemble the large
linear data stream by concatenating the uncompressed chunks retrieved
from the chunk store, keyed by the listed chunk hash values.

As an extra twist, we introduce a well-defined, reproducible,
random-access serialization format for directory trees (think: a more
modern `tar`), to permit efficient, stable storage of complete directory
trees in the system, simply by serializing them and then passing them
into the encoding step explained above.

Finally, let's put all this on the network: for each image you want to
deliver, generate a chunk index file and place it on an HTTP
server. Do the same with the chunk store, and share it between the
various index files you intend to deliver.

Why bother with all of this? Streams with similar contents will result
in mostly the same chunk files in the chunk store. This means it is
very efficient to store many related versions of a data stream in the
same chunk store, thus minimizing disk usage. Moreover, when
transferring linear data streams chunks already known on the receiving
side can be made use of, thus minimizing network traffic.

Why is this different from `rsync` or OSTree, or similar tools? Well,
one major difference between `casync` and those tools is that we
remove file boundaries before chunking things up. This means that
small files are lumped together with their siblings and large files
are chopped into pieces, which permits us to recognize similarities in
files and directories beyond file boundaries, and makes sure our chunk
sizes are pretty evenly distributed, without the file boundaries
affecting them.

The "chunking" algorithm is based on a the buzhash rolling hash
function. SHA512/256 is used as strong hash function to generate digests of the
chunks (alternatively: SHA256). zstd is used to compress the individual chunks
(alternatively xz or gzip).

Is this new? Conceptually, not too much. This uses well-known concepts,
implemented in a variety of other projects, and puts them together in a
moderately new, nice way. That's all. The primary influences are rsync and git,
but there are other systems that use similar algorithms, in particular:

- BorgBackup (http://www.borgbackup.org/)
- bup (https://bup.github.io/)
- CAFS (https://github.com/indyjo/cafs)
- dedupfs (https://github.com/xolox/dedupfs)
- LBFS (https://pdos.csail.mit.edu/archive/lbfs/)
- restic (https://restic.github.io/)
- Tahoe-LAFS (https://tahoe-lafs.org/trac/tahoe-lafs)
- tarsnap (https://www.tarsnap.com/)
- Venti (https://en.wikipedia.org/wiki/Venti)
- zsync (http://zsync.moria.org.uk/)

(ordered alphabetically, not in order of relevance)

## File Suffixes

1. .catar → archive containing a directory tree (like "tar")
2. .caidx → index file referring to a directory tree (i.e. a .catar file)
3. .caibx → index file referring to a blob (i.e. any other file)
4. .castr → chunk store directory (where we store chunks under their hashes)
5. .cacnk → a compressed chunk in a chunk store (i.e. one of the files stored below a .castr directory)

## Operations on directory trees

```
# casync list /home/lennart
# casync digest /home/lennart
# casync mtree /home/lennart (BSD mtree(5) compatible manifest)
```

## Operations on archives

```
# casync make /home/lennart.catar /home/lennart
# casync extract /home/lennart.catar /home/lennart
# casync list /home/lennart.catar
# casync digest /home/lennart.catar
# casync mtree /home/lennart.catar
# casync mount /home/lennart.catar /home/lennart
# casync verify /home/lennart.catar /home/lennart  (NOT IMPLEMENTED YET)
# casync diff /home/lennart.catar /home/lennart (NOT IMPLEMENTED YET)
```

## Operations on archive index files

```
# casync make --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart
# casync extract --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart
# casync list --store=/var/lib/backup.castr /home/lennart.caidx
# casync digest --store=/var/lib/backup.castr /home/lennart.caidx
# casync mtree -pool=/var/lib/backup.castr /home/lennart.caidx
# casync mount --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart
# casync verify --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart (NOT IMPLEMENTED YET)
# casync diff --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart (NOT IMPLEMENTED YET)
```

## Operations on blob index files

```
# casync digest --store=/var/lib/backup.castr fedora25.caibx
# casync mkdev --store=/var/lib/backup.castr fedora25.caibx
# casync verify --store=/var/lib/backup.castr fedora25.caibx /home/lennart/Fedora25.raw (NOT IMPLEMENTED YET)
```

## Operations involving ssh remoting

```
# casync make foobar:/srv/backup/lennart.caidx /home/lennart
# casync extract foobar:/srv/backup/lennart.caidx /home/lennart2
# casync list foobar:/srv/backup/lennart.caidx
# casync digest foobar:/srv/backup/lennart.caidx
# casync mtree foobar:/srv/backup/lennart.caidx
# casync mount foobar:/srv/backup/lennart.caidx /home/lennart
```

## Operations involving the web

```
# casync extract http://www.foobar.com/lennart.caidx /home/lennart
# casync list http://www.foobar.com/lennart.caidx
# casync digest http://www.foobar.com/lennart.caidx
# casync mtree http://www.foobar.com/lennart.caidx
# casync extract --seed=/home/lennart http://www.foobar.com/lennart.caidx /home/lennart2
# casync mount --seed=/home/lennart http://www.foobar.com/lennart.caidx /home/lennart2
```

## Maintenance

```
# casync gc /var/lib/backup.castr /home/lennart.caidx /home/foobar.caidx ... (NOT IMPLEMENTED YET)
# casync make /home/lennart.catab /home/lennart (NOT IMPLEMENTED)
```

## Building casync

casync uses the [Meson](http://mesonbuild.com/) build system. To build casync,
install Meson (at least 0.40), as well as the necessary build dependencies
(gcc, liblzma, libcurl, libacl, and optionally libfuse). Then run:

```
# meson build && ninja -C build && sudo ninja -C build install
```
