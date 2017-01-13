# casync — Content Addressable Data Synchronizer

*WORK IN PROGRESS*

What is this?

1. A combination of the rsync algorithm and content-addressable storage

2. An efficient way to store and retrieve multiple related versions of large file systems or directory trees

3. An efficient way to deliver and update OS and container images over the Internet

4. An efficient backup system

The longer explanation goes something like this:

Encoding: Let's take a large linear data stream, split it into
variable-sized chunks (the size being a function of the chunk
contents), and store these chunk in individual, compressed files,
named after a strong hash value of their contents. Let's call this
directory an "object store". Then, generate an "index" file that lists
these hash values plust the chunk size.

Decoding: Let's take the "index" file, and reassemble the large linear
data stream by concatenating the uncompressed chunks from the "object
store".

As an extra twist, we introduce a well-defined, reproducible
serialization format for directory trees (i.e. a more modern "tar"),
to permit efficient, stable storage of complete directory trees in the
system.

Why bother with all of this? Streams with similar contents will result
in mostly the same object files in the object store. This means, it is
very efficient to store many related versions of a data stream in the
same object store, thus minimizing disk usage. Moreover, when
transferring linear data streams chunks already existing on the
receiving side can be made use of, thus minimizing network traffic.

The "chunking" algorithm is based on a the Adler32 rolling hash
function (similar to how the rsync algorithm does it). Otherwise,
SHA256 is used as strong hash function to generate digests of the
chunk objects.

Is this new? Conceptually, not too much. This uses well-known
concepts, implemented in a variety of other projects, and puts them
together in a moderately new, nice way. That's all. The primary
influences are rsync and git, but there are other systems that use
similar algorithms, in particular:

- CAFS (https://github.com/indyjo/cafs)
- LBFS (https://pdos.csail.mit.edu/archive/lbfs/)
- Tahoe-LAFS (https://tahoe-lafs.org/trac/tahoe-lafs)
- Venti (https://en.wikipedia.org/wiki/Venti)
- bup (https://bup.github.io/)
- dedupfs (https://github.com/xolox/dedupfs)
- zsync (http://zsync.moria.org.uk/)

(ordered alphabetically, not in order of relevance)

## File Suffixes

1. .catar → archive containing a directory tree (like "tar")
2. .caidx → index file referring to a directory tree (i.e. a .catar object)
3. .caibx → index file referring to a blob (i.e. any other object)
4. .castr → hash object store directory (where we store objects under their hashes)

## Operations on directory trees

# casync digest /home/lennart

## Operations on archives

```
# casync make /home/lennart.catar /home/lennart
# casync extract /home/lennart.catar /home/lennart
# casync list /home/lennart.catar
# casync digest /home/lennart.catar
# casync manifest /home/lennart.catar (NOT IMPLEMENTED YET)
# casync verify /home/lennart.catar /home/lennart  (NOT IMPLEMENTED YET)
# casync diff /home/lennart.catar /home/lennart (NOT IMPLEMENTED YET)
# casync mount /home/lennart.catar /home/lennart (NOT IMPLEMENTED YET)
```

## Operations on archive index files

```
# casync make --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart
# casync extract --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart
# casync put --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart.catar (NOT IMPLEMENTED YET)
# casync get --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart.catar (NOT IMPLEMENTED YET)
# casync list --store=/var/lib/backup.castr /home/lennart.caidx
# casync digest --store=/var/lib/backup.castr /home/lennart.caidx
# casync manifest -pool=/var/lib/backup.castr /home/lennart.caidx (NOT IMPLEMENTED YET)
# casync verify --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart (NOT IMPLEMENTED YET)
# casync diff --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart (NOT IMPLEMENTED YET)
# casync mount --store=/var/lib/backup.castr /home/lennart.caidx /home/lennart (NOT IMPLEMENTED YET)
```

## Operations on blob index files

```
# casync put --store=/var/lib/backup.castr fedora25.caibx /home/lennart/Fedora25.raw (NOT IMPLEMENTED YET)
# casync get --store=/var/lib/backup.castr fedora25.caibx /home/lennart/Fedora25.raw (NOT IMPLEMENTED YET)
# casync digest --store=/var/lib/backup.castr fedora25.caibx
# casync verify --store=/var/lib/backup.castr fedora25.caibx /home/lennart/Fedora25.raw (NOT IMPLEMENTED YET)
# casync mkdev --store=/var/lib/backup.castr fedora25.caibx (NOT IMPLEMENTED YET)
```

## Operations involving the web

```
# casync extract http://www.foobar.com/lennart.caidx /home/lennart (NOT IMPLEMENTED YET)
# casync extract --seed=/home/lennart http://www.foobar.com/lennart.caidx /home/lennart2 (NOT IMPLEMENTED YET)
# casync mount --seed=/home/lennart --cache=/var/tmp/lennart/cache http://www.foobar.com/lennart.caidx /home/lennart2 (NOT IMPLEMENTED YET)
```

```
# casync clone /home/lennart /home/lennart2 (NOT IMPLEMENTED YET)
```
