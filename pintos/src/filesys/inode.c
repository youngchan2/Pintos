#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCK_ENTRIES 123
#define INDIRECT_BLOCK_ENTRIES 128
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  // block_sector_t start; /* First data sector. */
  off_t length; /* File size in bytes. */
  uint32_t is_dir;
  unsigned magic; /* Magic number. */
  block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];
  block_sector_t indirect_block_sec;
  block_sector_t double_indirect_block_sec;
  // uint32_t unused[125];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
  struct lock inode_lock;
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector(const struct inode_disk *inode_disk, off_t pos)
{
  ASSERT(inode_disk != NULL);
  // if (pos < inode->data.length)
  //   return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  // else
  //   return -1;

  block_sector_t sector = -1;
  if (pos < inode_disk->length)
  {
    off_t sec_index = pos / BLOCK_SECTOR_SIZE;

    if (sec_index < DIRECT_BLOCK_ENTRIES)
    {
      sector = inode_disk->direct_map_table[sec_index];
    }
    else if (sec_index < DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES)
    {
      sec_index -= DIRECT_BLOCK_ENTRIES;
      block_sector_t indirect_idx = inode_disk->indirect_block_sec;
      if (indirect_idx != (block_sector_t)-1)
      {
        block_sector_t *indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
        cache_read(indirect_block, 0, 0, indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
        sector = indirect_block[sec_index];
        free(indirect_block);
      }
      else
      {
        sector = -1;
      }
    }
    else if (sec_index < DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES)
    {
      sec_index -= (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES);
      block_sector_t lev1 = sec_index / INDIRECT_BLOCK_ENTRIES;
      block_sector_t lev2 = sec_index % INDIRECT_BLOCK_ENTRIES;

      block_sector_t double_indirect_idx = inode_disk->double_indirect_block_sec;
      if (double_indirect_idx != (block_sector_t)-1)
      {
        block_sector_t *double_indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
        cache_read(double_indirect_block, 0, 0, double_indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);

        block_sector_t indirect_idx = double_indirect_block[lev1];
        if (indirect_idx != (block_sector_t)-1)
        {
          block_sector_t *indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
          cache_read(indirect_block, 0, 0, indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);

          sector = indirect_block[lev2];
          free(double_indirect_block);
          free(indirect_block);
        }
        else
        {
          free(double_indirect_block);
          sector = -1;
        }
      }
      else
      {
        sector = -1;
      }
    }
    else
    {
      sector = -1;
    }
  }
  return sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void)
{
  list_init(&open_inodes);
}

static bool block_sector_allocate(struct inode_disk *inode_disk, block_sector_t idx, off_t pos)
{
  off_t sec_index = pos / BLOCK_SECTOR_SIZE;

  if (sec_index < DIRECT_BLOCK_ENTRIES)
  {
    inode_disk->direct_map_table[sec_index] = idx;
    return true;
  }
  else if (sec_index < DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES)
  {
    sec_index -= DIRECT_BLOCK_ENTRIES;
    block_sector_t *indirect_idx = &inode_disk->indirect_block_sec;
    block_sector_t *indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);

    if (*indirect_idx == (block_sector_t)-1)
    {
      if (free_map_allocate(1, indirect_idx))
      {
        memset(indirect_block, -1, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
      }
      else
      {
        free(indirect_block);
        return false;
      }
    }
    else
    {
      cache_read(indirect_block, 0, 0, *indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
    }

    if (indirect_block[sec_index] == (block_sector_t)-1)
    {
      indirect_block[sec_index] = idx;
    }
    cache_write(indirect_block, 0, 0, *indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES, BLOCK_SECTOR_SIZE);
    free(indirect_block);
    return true;
  }
  else if (sec_index < DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES)
  {
    sec_index -= (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES);
    block_sector_t lev1 = sec_index / INDIRECT_BLOCK_ENTRIES;
    block_sector_t lev2 = sec_index % INDIRECT_BLOCK_ENTRIES;

    block_sector_t *double_indirect_idx = &inode_disk->double_indirect_block_sec;
    block_sector_t *double_indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);

    if (*double_indirect_idx == (block_sector_t)-1)
    {
      if (free_map_allocate(1, double_indirect_idx))
      {
        memset(double_indirect_block, -1, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
      }
      else
      {
        free(double_indirect_block);
        return false;
      }
    }
    else
    {
      cache_read(double_indirect_block, 0, 0, *double_indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
    }

    block_sector_t *indirect_idx = &double_indirect_block[lev1];
    block_sector_t *indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);

    if (*indirect_idx == (block_sector_t)-1)
    {
      if (free_map_allocate(1, indirect_idx))
      {
        memset(indirect_block, -1, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
      }
      else
      {
        free(indirect_block);
        return false;
      }
    }
    else
    {
      cache_read(indirect_block, 0, 0, *indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
    }

    if (indirect_block[lev2] == (block_sector_t)-1)
    {
      indirect_block[lev2] = idx;
    }

    cache_write(double_indirect_block, 0, 0, *double_indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES, BLOCK_SECTOR_SIZE);
    cache_write(indirect_block, 0, 0, *indirect_idx, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES, BLOCK_SECTOR_SIZE);
    free(double_indirect_block);
    free(indirect_block);
    return true;
  }
  else
  {
    return false;
  }

  return true;
}

static bool inode_increase(struct inode_disk *inode_disk, off_t start, off_t end)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  block_sector_t sector;

  inode_disk->length = end;

  /*grow-root-lg*/
  start = start / BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE;
  end--;
  end = end / BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE;

  off_t i = start;
  while (i <= end)
  {
    sector = byte_to_sector(inode_disk, i);
    if (sector == (block_sector_t)-1)
    {
      if (free_map_allocate(1, &sector))
      {
        if (block_sector_allocate(inode_disk, sector, i))
          cache_write(zeros, 0, 0, sector, BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE);
        else
        {
          return false;
        }
      }
      else
      {
        return false;
      }
    }

    i += BLOCK_SECTOR_SIZE;
  }

  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, uint32_t is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL)
  {
    // size_t sectors = bytes_to_sectors(length);
    // disk_inode->length = length;
    // disk_inode->magic = INODE_MAGIC;
    // if (free_map_allocate(sectors, &disk_inode->start))
    // {
    //   block_write(fs_device, sector, disk_inode);
    //   if (sectors > 0)
    //   {
    //     static char zeros[BLOCK_SECTOR_SIZE];
    //     size_t i;

    //     for (i = 0; i < sectors; i++)
    //       block_write(fs_device, disk_inode->start + i, zeros);
    //   }
    //   success = true;
    // }
    // free(disk_inode);

    // static char zeros[BLOCK_SECTOR_SIZE];
    memset(disk_inode, -1, sizeof(struct inode_disk));
    // disk_inode->length = length;
    // disk_inode->is_dir = is_dir;
    // disk_inode->magic = INODE_MAGIC;
    // off_t i = 0;
    // while (i < length)
    // {
    //   block_sector_t sectors = byte_to_sector(disk_inode, i);
    //   if (sectors == (block_sector_t)-1)
    //   {
    //     if (free_map_allocate(1, &sectors))
    //     {
    //       if (block_sector_allocate(disk_inode, sectors, i))
    //       {
    //         cache_write(zeros, 0, 0, sectors, BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE);
    //       }
    //       else
    //       {
    //         free(disk_inode);
    //         return false;
    //       }
    //     }
    //     else
    //     {
    //       free(disk_inode);
    //       return false;
    //     }
    //   }
    //   i += BLOCK_SECTOR_SIZE;
    // }
    if (inode_increase(disk_inode, 0, length))
    {
      disk_inode->is_dir = is_dir;
      disk_inode->magic = INODE_MAGIC;
      cache_write(disk_inode, 0, 0, sector, BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE);
      free(disk_inode);
      success = true;
    }
    else
    {
      free(disk_inode);
    }
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
       e = list_next(e))
  {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector)
    {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);
  // block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber(const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode)
{
  size_t i;

  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
  {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed)
    {
      // free_map_release(inode->sector, 1);
      // free_map_release(inode->data.start,
      //                  bytes_to_sectors(inode->data.length));
      struct inode_disk inode_disk;
      cache_read(&inode_disk, 0, 0, inode->sector, sizeof(struct inode_disk));

      /*Direct*/
      for (i = 0; i < DIRECT_BLOCK_ENTRIES; i++)
      {
        if (inode_disk.direct_map_table[i] != (block_sector_t)-1)
          free_map_release(inode_disk.direct_map_table[i], 1);
      }
      /*Indirect*/
      if (inode_disk.indirect_block_sec == (block_sector_t)-1)
      {
        free(inode);
        return;
      }
      else
      {
        block_sector_t *indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
        cache_read(indirect_block, 0, 0, inode_disk.indirect_block_sec, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);

        for (i = 0; i < INDIRECT_BLOCK_ENTRIES; i++)
        {
          if (indirect_block[i] != (block_sector_t)-1)
          {
            free_map_release(indirect_block[i], 1);
          }
        }
        free_map_release(inode_disk.indirect_block_sec, 1);
      }
      /*Double Indirect*/
      if (inode_disk.double_indirect_block_sec == (block_sector_t)-1)
      {
        free(inode);
        return;
      }
      else
      {
        block_sector_t *double_indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
        cache_read(double_indirect_block, 0, 0, inode_disk.double_indirect_block_sec, sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);

        for (i = 0; i < INDIRECT_BLOCK_ENTRIES; i++)
        {
          if (double_indirect_block[i] != (block_sector_t)-1)
          {
            block_sector_t *indirect_block = (block_sector_t *)malloc(sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
            cache_read(indirect_block, 0, 0, double_indirect_block[i], sizeof(block_sector_t) * INDIRECT_BLOCK_ENTRIES);
            size_t j;
            for (j = 0; j < INDIRECT_BLOCK_ENTRIES; j++)
            {
              if (indirect_block[j] != (block_sector_t)-1)
              {
                free_map_release(indirect_block[j], 1);
              }
            }
            free_map_release(double_indirect_block[i], 1);
          }
        }
        free_map_release(inode_disk.double_indirect_block_sec, 1);
      }
      free_map_release(inode->sector, 1);
    }
    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode *inode)
{
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  // uint8_t *bounce = NULL;

  lock_acquire(&inode->inode_lock);
  struct inode_disk inode_disk;
  cache_read(&inode_disk, 0, 0, inode->sector, sizeof(struct inode_disk));
  while (size > 0)
  {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(&inode_disk, offset);
    // lock_release(&inode->inode_lock);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_disk.length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
    {
      // lock_acquire(&inode->inode_lock);
      break;
    }

    // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
    // {
    //   /* Read full sector directly into caller's buffer. */
    //   block_read(fs_device, sector_idx, buffer + bytes_read);
    // }
    // else
    // {
    //   /* Read sector into bounce buffer, then partially copy
    //      into caller's buffer. */
    //   if (bounce == NULL)
    //   {
    //     bounce = malloc(BLOCK_SECTOR_SIZE);
    //     if (bounce == NULL)
    //       break;
    //   }
    //   block_read(fs_device, sector_idx, bounce);
    //   memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    // }
    cache_read(buffer, bytes_read, sector_ofs, sector_idx, chunk_size);
    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
    // lock_acquire(&inode->inode_lock);
  }
  // free(bounce);
  lock_release(&inode->inode_lock);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
                     off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  // uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  lock_acquire(&inode->inode_lock);
  struct inode_disk inode_disk;
  cache_read(&inode_disk, 0, 0, inode->sector, sizeof(struct inode_disk));

  /*grow-root-lg: offset이 계속 쌓여서 length가 되면 문제 발생*/
  if (inode_disk.length < size + offset)
  {
    inode_increase(&inode_disk, inode_disk.length, size + offset);
    cache_write(&inode_disk, 0, 0, inode->sector, BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE);
  }

  while (size > 0)
  {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(&inode_disk, offset);
    // lock_release(&inode->inode_lock);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_disk.length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
    {
      // lock_acquire(&inode->inode_lock);
      break;
    }

    // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
    // {
    //   /* Write full sector directly to disk. */
    //   block_write(fs_device, sector_idx, buffer + bytes_written);
    // }
    // else
    // {
    //   /* We need a bounce buffer. */
    //   if (bounce == NULL)
    //   {
    //     bounce = malloc(BLOCK_SECTOR_SIZE);
    //     if (bounce == NULL)
    //       break;
    //   }

    //   /* If the sector contains data before or after the chunk
    //      we're writing, then we need to read in the sector
    //      first.  Otherwise we start with a sector of all zeros. */
    //   if (sector_ofs > 0 || chunk_size < sector_left)
    //     block_read(fs_device, sector_idx, bounce);
    //   else
    //     memset(bounce, 0, BLOCK_SECTOR_SIZE);
    //   memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
    //   block_write(fs_device, sector_idx, bounce);
    // }
    cache_write(buffer, bytes_written, sector_ofs, sector_idx, chunk_size, sector_left);
    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
    // lock_acquire(&inode->inode_lock);
  }
  // free(bounce);
  lock_release(&inode->inode_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode)
{
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode)
{
  struct inode_disk inode_disk;
  cache_read(&inode_disk, 0, 0, inode->sector, sizeof(struct inode_disk));
  return inode_disk.length;
}

bool inode_is_dir(struct inode *inode)
{
  struct inode_disk inode_disk;
  cache_read(&inode_disk, 0, 0, inode->sector, sizeof(struct inode_disk));

  return inode_disk.is_dir;
}