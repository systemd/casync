/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fssize.h"
#include "util.h"

#define FAT_SIGNATURE UINT16_C(0xaa55)

#define _ANDROID_BOOTIMG_MAGIC_1 UINT32_C(0x52444e41)
#define _ANDROID_BOOTIMG_MAGIC_2 UINT32_C(0x2144494f)

int read_file_system_size(int fd, uint64_t *ret) {

        /* The squashfs and Android bootimg super block starts at offset 1024 */
        union {
                struct {
                        uint8_t ignored[3];
                        uint8_t system_id[8];
                        le16_t sector_size;
                        uint8_t sec_per_cluster;
                        le16_t reserved;
                        uint8_t fats;
                        le16_t dir_entries;
                        le16_t sectors;
                        uint8_t media;
                        le16_t fat_length;
                        le16_t secs_track;
                        le16_t heads;
                        le32_t hidden;
                        le32_t total_sect;

                        /* skip the boot code in the middle */
                        uint8_t _skip[474];

                        uint16_t signature;

                        /* ignore the rest */
                } _packed_ fat;

                struct {
                        le32_t s_magic;
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

                struct {
                        /* The ext2, ext3, ext4 superblock starts at offset 1024 */
                        uint8_t _skip[1024];

                        le32_t s_inodes_count;
                        le32_t s_blocks_count;
                        le32_t s_r_blocks_count;
                        le32_t s_free_blocks_count;
                        le32_t s_free_inodes_count;
                        le32_t s_first_data_block;
                        le32_t s_log_block_size;
                        le32_t s_log_frag_size;
                        le32_t s_blocks_per_group;
                        le32_t s_frags_per_group;
                        le32_t s_inodes_per_group;
                        le32_t s_mtime;
                        le32_t s_wtime;
                        le16_t s_mnt_count;
                        le16_t s_max_mnt_count;
                        le16_t s_magic;

                        /* ignore the rest */
                } _packed_ ext234;

        } superblock;

        ssize_t n;

        assert(fd >= 0);
        assert(ret);

        n = pread(fd, &superblock, sizeof(superblock), 0);
        if (n < 0)
                return -errno;
        if (n != sizeof(superblock))
                return 0; /* don't know such short file systems */

        if (le32toh(superblock.squashfs.s_magic == SQUASHFS_MAGIC)) {
                *ret = ALIGN_TO(le64toh(superblock.squashfs.bytes_used), UINT64_C(4096));
                return 1;
        }

        if (le32toh(superblock.android_bootimg.magic) == _ANDROID_BOOTIMG_MAGIC_1 &&
            le32toh(superblock.android_bootimg.magic2) == _ANDROID_BOOTIMG_MAGIC_2) {
                uint32_t pagesize;

                pagesize = le32toh(superblock.android_bootimg.page_size);
                if (IS_POWER_OF_TWO(pagesize)) {

                        *ret = (uint64_t) ALIGN_TO(608, pagesize) /* header size */ +
                                (uint64_t) ALIGN_TO(le32toh(superblock.android_bootimg.kernel_size), pagesize) +
                                (uint64_t) ALIGN_TO(le32toh(superblock.android_bootimg.initrd_size), pagesize) +
                                (uint64_t) ALIGN_TO(le32toh(superblock.android_bootimg.second_size), pagesize) +
                                (uint64_t) ALIGN_TO(le32toh(superblock.android_bootimg.dtb_size), pagesize);

                        return 1;
                }
        }

        if (le16toh(superblock.fat.signature) == FAT_SIGNATURE) {
                uint16_t sector_size;

                sector_size = le16toh(superblock.fat.sector_size);
                if (IS_POWER_OF_TWO(sector_size)) {
                        uint64_t l;

                        l = (uint64_t) le16toh(superblock.fat.sectors) * le16toh(superblock.fat.sector_size);
                        if (l == 0)
                                l = (uint64_t) le32toh(superblock.fat.total_sect) * le16toh(superblock.fat.sector_size);

                        if (l > 0) {
                                *ret = l;
                                return 1;
                        }
                }
        }

        if (le16toh(superblock.ext234.s_magic) == EXT2_SUPER_MAGIC) {
                uint64_t shift;

                shift = 10 + le32toh(superblock.ext234.s_log_block_size);
                if (shift < 64) {
                        *ret = (uint64_t) le32toh(superblock.ext234.s_blocks_count) * (UINT64_C(1) << shift);
                        return 1;
                }
        }

        return 0;
}
