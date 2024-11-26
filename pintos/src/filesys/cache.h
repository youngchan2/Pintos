#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <list.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/inode.h"

struct lock cache_lock;

struct buffer_head
{
    bool dirty;
    bool access;
    block_sector_t sector;
    struct inode *inode;
    void *data;
    struct list_elem cache_elem;
};

void cache_init(void);
struct buffer_head *find_bce(block_sector_t idx);
void cache_read(void *buffer, off_t bytes_read, int sector_ofs, block_sector_t sector_idx, int chunk_size);
void cache_write(const void *buffer, off_t bytes_written, int sector_ofs, block_sector_t sector_idx, int chunk_size, int sector_left);
struct list_elem *find_cache_pointer(void);
void flush_victim(void);
void cache_shutdown(void);
void insert_bce(struct buffer_head *bh);
void delete_bce(struct buffer_head *bh);

#endif /* filesys/cache.h */