#include "fssize.h"
#include "util.h"

#define _ANDROID_BOOTIMG_MAGIC_1 0x52444e41
#define _ANDROID_BOOTIMG_MAGIC_2 0x2144494f

int read_file_system_size(int fd, uint64_t *ret) {

        union {
                struct {
                        le32_t magic;
                        le32_t inodes;
                        le32_t mkfs_time;
                        le32_t block_size;
                        le32_t fragments;
                        le16_t compression;
                        le16_t block_log;
                        le16_t flags;
                        le16_t no_ids;
                        le16_t s_major;
                        le16_t s_minor;
                        le64_t root_inode;
                        le64_t bytes_used;

                        /* ignore the rest */
                } _packed_ squashfs;

                struct {
                        le32_t magic;
                        le32_t magic2;

                        le32_t kernel_size;
                        le32_t kernel_addr;

                        le32_t initrd_size;
                        le32_t initrd_addr;

                        le32_t second_size;
                        le32_t second_addr;

                        le32_t tags_addr;
                        le32_t page_size;

                        le32_t dtb_size;

                        /* ignore the rest */
                } _packed_ android_bootimg;
        } superblock;

        ssize_t n;

        assert(fd >= 0);
        assert(ret);

        n = pread(fd, &superblock, sizeof(superblock), 0);
        if (n < 0)
                return -errno;
        if (n != sizeof(superblock))
                return 0; /* don't know such short superblocks */

        if (le32toh(superblock.squashfs.magic == SQUASHFS_MAGIC)) {
                *ret = ALIGN_TO(le64toh(superblock.squashfs.bytes_used), UINT64_C(4096));
                return 1;
        }

        if (le32toh(superblock.android_bootimg.magic) == _ANDROID_BOOTIMG_MAGIC_1 &&
            le32toh(superblock.android_bootimg.magic2) == _ANDROID_BOOTIMG_MAGIC_2) {
                uint32_t pagesize;

                pagesize = le32toh(superblock.android_bootimg.page_size);
                if (__builtin_popcount(pagesize) != 1)
                        return -EBADMSG;

                *ret = ALIGN_TO(608, pagesize) /* header size */ +
                        ALIGN_TO(le32toh(superblock.android_bootimg.kernel_size), pagesize) +
                        ALIGN_TO(le32toh(superblock.android_bootimg.initrd_size), pagesize) +
                        ALIGN_TO(le32toh(superblock.android_bootimg.second_size), pagesize) +
                        ALIGN_TO(le32toh(superblock.android_bootimg.dtb_size), pagesize);

                return 1;
        }

        return 0;
}
