#include "filesys/inode.h"
#include <bitmap.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_CNT 123
#define INDIRECT_CNT 1
#define DBL_INDIRECT_CNT 1
#define SECTOR_CNT (DIRECT_CNT + INDIRECT_CNT + DBL_INDIRECT_CNT)

#define PTRS_PER_SECTOR ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))
#define INODE_SPAN ((DIRECT_CNT                                              \
                     + PTRS_PER_SECTOR * INDIRECT_CNT                        \
                     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT) \
                    * BLOCK_SECTOR_SIZE)
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t sectors[125];        /* Sectors. */
    off_t length;                       /* File size in bytes. */
    bool directory;
    unsigned magic;                     /* Magic number. */
    uint32_t unused[125];               /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}


/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
}

/* Initializes an inode of the given TYPE, writes the new inode
   to sector SECTOR on the file system device, and returns the
   inode thus created.  Returns a null pointer if unsuccessful,
   in which case SECTOR is released in the free map. */  
struct inode *
inode_create (block_sector_t sector, bool directory) 
{
  struct inode_disk *disk_inode;
  struct inode *inode;

  struct cache_entry *cache=cache_lock(sector, 1);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  memset (cache->data, 0, BLOCK_SECTOR_SIZE);
  cache->correct = true;
  cache->dirty = true;
  disk_inode = (struct inode_disk*)cache->data;
  disk_inode->directory = directory;
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;
  cache_unlock (cache);

  inode = inode_open (sector);
  if (inode==NULL)
  {
    free_map_release(sector);
  }
  return inode;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  lock_acquire (&open_inodes_lock);

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode->open_cnt++;
          lock_release(&open_inodes_lock);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL){
    lock_release(&open_inodes_lock);
    return NULL;
  }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->lock);
  lock_init (&inode->deny_write);
  cond_init (&inode->no_writers);
  lock_release (&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    {
      lock_acquire (&open_inodes_lock);
      inode->open_cnt++;
      lock_release (&open_inodes_lock);
    }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  lock_acquire (&open_inodes_lock);
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
      lock_release (&open_inodes_lock);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct cache_entry* cache=cache_lock(inode->sector,1);
          struct inode_disk* disk=cache_read(cache);
          for (int i = 0; i < 125; ++i)
          {
            if (disk->sectors[i])
            {
              if (i<123)
              {
                inode_deallocate(disk->sectors[i],0);
              }else if (i==123)
              {
                inode_deallocate(disk->sectors[i],1);
              }else{
                inode_deallocate(disk->sectors[i],2);
              }
            }
          }
          cache_unlock(cache);
          inode_deallocate(inode->sector,0);
        }
      free (inode); 
    }
  else{
    lock_release (&open_inodes_lock);
  }
}

void inode_deallocate(block_sector_t sector, int level) {
  if (level > 0) 
  {
    struct cache_entry *c=cache_lock(sector,1);
    block_sector_t *block=cache_read(c);
    for (int i = 0; i < (off_t)(BLOCK_SECTOR_SIZE/sizeof(block_sector_t)); ++i){
      if (block[i])
      {
        inode_deallocate(sector,level-1);
      }
    }
    cache_unlock(c);
  }

  lock_acquire (&search_lock);
  for (int i = 0; i < 64; ++i){
    struct cache_entry *b = &cache[i];
    lock_acquire (&b->lock);
    if (b->sector == sector) {
      lock_release (&search_lock);
      if (b->readers == 0 && b->read_waiters == 0 && b->writers == 0 && b->write_waiters == 0){
        b->sector = (block_sector_t)-1; 
      }
      lock_release (&b->lock);
      break;
    }
    lock_release (&b->lock);
  }
  lock_release (&search_lock);
  free_map_release (sector);
}


/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}


/* Translates SECTOR_IDX into a sequence of block indexes in
   OFFSETS and sets *OFFSET_CNT to the number of offsets. */
static void
calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt)
{
  /* Handle direct blocks. */
  if (sector_idx < DIRECT_CNT) 
    {
      offsets[0] = sector_idx;
      *offset_cnt = 1;
      return;
    }
  sector_idx -= DIRECT_CNT;

  /* Handle indirect blocks. */
  if (sector_idx < PTRS_PER_SECTOR * INDIRECT_CNT)
    {
      offsets[0] = DIRECT_CNT + sector_idx / PTRS_PER_SECTOR;
      offsets[1] = sector_idx % PTRS_PER_SECTOR;
      *offset_cnt = 2;
      return;
    }
  sector_idx -= PTRS_PER_SECTOR * INDIRECT_CNT;

  /* Handle doubly indirect blocks. */
  if (sector_idx < DBL_INDIRECT_CNT * PTRS_PER_SECTOR * PTRS_PER_SECTOR)
    {
      offsets[0] = (DIRECT_CNT + INDIRECT_CNT
                    + sector_idx / (PTRS_PER_SECTOR * PTRS_PER_SECTOR));
      offsets[1] = sector_idx / PTRS_PER_SECTOR;
      offsets[2] = sector_idx % PTRS_PER_SECTOR;
      *offset_cnt = 3;
      return;
    }
  NOT_REACHED ();
}

/* Retrieves the data block for the given byte OFFSET in INODE,
   setting *DATA_BLOCK to the block.
   Returns true if successful, false on failure.
   If ALLOCATE is false, then missing blocks will be successful
   with *DATA_BLOCk set to a null pointer.
   If ALLOCATE is true, then missing blocks will be allocated.
   The block returned will be locked, normally non-exclusively,
   but a newly allocated block will have an exclusive lock. */
static bool
get_data_block (struct inode *inode, off_t offset, bool allocate,
                struct cache_entry **data_block) 
{
  block_sector_t this_level_sector;
  size_t offsets[3];
  size_t offset_cnt;
  size_t level;

  ASSERT (offset >= 0);

  calculate_indices (offset / BLOCK_SECTOR_SIZE, offsets, &offset_cnt);
  level = 0;
  this_level_sector = inode->sector;
  for (;;) 
    {
      struct cache_entry *this_level_block;
      uint32_t *this_level_data;

      struct cache_entry *next_level_block;

      /* Check whether the block for the next level is allocated. */
      this_level_block = cache_lock (this_level_sector, 0);
      this_level_data = cache_read (this_level_block);
      if (this_level_data[offsets[level]] != 0)
        {
          /* Yes, it's allocated.  Advance to next level. */
          this_level_sector = this_level_data[offsets[level]];

          if (++level == offset_cnt) 
            {
              /* We hit the data block.
                 Do read-ahead. */
              if ((level == 0 && offsets[level] + 1 < DIRECT_CNT)
                  || (level > 0 && offsets[level] + 1 < PTRS_PER_SECTOR)) 
                {
                  uint32_t next_sector = this_level_data[offsets[level] + 1];
                  if (next_sector
                      && next_sector < block_size (fs_device))
                    cache_readahead (next_sector); 
                }
              cache_unlock (this_level_block);

              /* Return block. */
              *data_block = cache_lock (this_level_sector, 0);
              return true;
            }
          cache_unlock (this_level_block);
          continue;
        }
      cache_unlock (this_level_block);

      /* No block is allocated.  Nothing is locked.
         If we're not allocating new blocks, then this is
         "success" (with all-zero data). */
      if (!allocate) 
        {
          *data_block = NULL;
          return true;
        }

      /* We need to allocate a new block.
         Grab an exclusive lock on this level's block so we can
         insert the new block. */
      this_level_block = cache_lock (this_level_sector, 1);
      this_level_data = cache_read (this_level_block);

      /* Since we released this level's block, someone else might
         have allocated the block in the meantime.  Recheck. */
      if (this_level_data[offsets[level]] != 0)
        {
          cache_unlock (this_level_block);
          continue;
        }

      /* Allocate the new block. */
      if (!free_map_allocate (&this_level_data[offsets[level]]))
        {
          cache_unlock (this_level_block);
          *data_block = NULL;
          return false;
        }
        this_level_block->dirty=true;

      /* Lock and clear the new block. */
      next_level_block = cache_lock (this_level_data[offsets[level]],1);
      memset (next_level_block->data, 0, BLOCK_SECTOR_SIZE);
      next_level_block->correct = true;
      next_level_block->dirty = true;

      /* Release this level's block.  No one else can access the
         new block yet, because we have an exclusive lock on it. */
      cache_unlock (this_level_block);

      /* If this is the final level, then return the new block. */
      if (level == offset_cnt - 1) 
        {
          *data_block = next_level_block;
          return true;
        }

      /* Otherwise, release the new block and go around again to
         follow the new pointer. */
      cache_unlock (next_level_block);
    }
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) 
    {
      /* Sector to read, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      struct cache_entry *block;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0 || !get_data_block (inode, offset, false, &block))
        break;

      if (block == NULL) 
        memset (buffer + bytes_read, 0, chunk_size);
      else 
        {
          const uint8_t *sector_data = cache_read (block);
          memcpy (buffer + bytes_read, sector_data + sector_ofs, chunk_size);
          cache_unlock (block);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Extends INODE to be at least LENGTH bytes long. */
static void
extend_file (struct inode *inode, off_t length) 
{
  if (length > inode_length (inode)) 
    {
      struct cache_entry *inode_block = cache_lock (inode->sector, 1);
      struct inode_disk *disk_inode = cache_read (inode_block);
      if (length > disk_inode->length) 
        {
          disk_inode->length = length;
          inode_block->dirty=true;
        }
      cache_unlock (inode_block);
    }
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  /* Don't write if writes are denied. */
  lock_acquire (&inode->deny_write_lock);
  if (inode->deny_write_cnt) 
    {
      lock_release (&inode->deny_write_lock);
      return 0;
    }
  inode->writer_cnt++;
  lock_release (&inode->deny_write_lock);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      struct cache_entry *block;
      uint8_t *sector_data;

      /* Bytes to max inode size, bytes left in sector, lesser of the two. */
      off_t inode_left = INODE_SPAN - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;

      if (chunk_size <= 0 || !get_data_block (inode, offset, true, &block))
        break;

      sector_data = cache_read (block);
      memcpy (sector_data + sector_ofs, buffer + bytes_written, chunk_size);
      block->dirty=true;
      cache_unlock (block);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  extend_file (inode, offset);

  lock_acquire (&inode->deny_write_lock);
  if (--inode->writer_cnt == 0)
    cond_signal (&inode->no_writers_cond, &inode->deny_write_lock);
  lock_release (&inode->deny_write_lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  lock_acquire(&inode->deny_write);
  while(inode->writer_cnt>0){
    cond_wait(&inode->no_writers,&inode->deny_write);
  }
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->deny_write);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  lock_acquire(&inode->deny_write);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->deny_write);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct cache_entry* inode_block=cache_lock(inode->sector,0);
  struct inode_disk* disk=cache_read(inode_block);
  cache_unlock(inode_block);
  return disk->length;
}

bool is_directory (const struct inode * inode){
  struct cache_entry* inode_block=cache_lock(inode->sector,0);
  struct inode_disk* disk_inode=cache_read(inode_block);
  bool ret=disk_inode->directory;
  cache_unlock (inode_block);
  return ret;
}

struct inode * file_create(block_sector_t sector, off_t length) {
  struct inode* inode=inode_create(sector,false);
  if (inode!=NULL && length>0 && inode_write_at(inode,"",1,length-1)!=1)
    {
      inode_remove(inode); 
      inode_close(inode);
      inode=NULL;
    }
  return inode;
}

int inode_open_cnt (const struct inode * inode) 
{
  int open_cnt;
  lock_acquire (&open_inodes_lock);
  open_cnt = inode->open_cnt;
  lock_release (&open_inodes_lock);
  return open_cnt;
}
