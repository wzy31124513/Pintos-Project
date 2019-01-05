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

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t sectors[125];         /* First data sector. */
    bool directory;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
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
  struct inode* inode;
  struct cache_entry* cache=cache_lock(sector);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);


  memset(cache->data,0,BLOCK_SECTOR_SIZE);
  cache->correct=true;
  disk_inode=(struct inode_disk*)cache->data;
  disk_inode->directory=directory;
  disk_inode->length=0;
  disk_inode->magic=INODE_MAGIC;
  cache->dirty=true;
  cache_unlock(cache);
  inode=inode_open(sector);
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

  lock_init(&inode->lock);
  lock_init(&inode->deny_write);
  cond_init(&inode->no_writers);
  lock_release(&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    {
      lock_acquire(&open_inodes_lock);
      inode->open_cnt++;
      lock_release(&open_inodes_lock);
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
          struct cache_entry* cache=cache_lock(inode->sector);
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
    }else{
      lock_release (&open_inodes_lock);
    }
}

void inode_deallocate (block_sector_t sector, int level) {
  if (level>0)
  {
    struct cache_entry* c=cache_lock(sector);
    block_sector_t* block=cache_read(c);
    for (int i = 0; i < ((off_t)(BLOCK_SECTOR_SIZE / sizeof (block_sector_t))); ++i)
    {
      if(block[i])
      {
        inode_deallocate(sector,level-1);
      }
    }
    cache_unlock(c);
  }
  lock_acquire(&search_lock);
  for (int i = 0; i < 64; ++i){
    struct cache_entry *b = &cache[i];
    lock_acquire (&b->lock);
    if (b->sector == sector) {
      lock_release (&search_lock);
      if (b->readers == 0 && b->read_waiters == 0 && b->writers == 0 && b->write_waiters == 0){
        b->sector = (block_sector_t)-1; 
      }
      lock_release (&b->lock);
      free_map_release (sector);
      return;
    }
    lock_release (&b->lock);
  }
  lock_release (&search_lock);
  free_map_release(sector);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

static bool
get_data_block (struct inode *inode, off_t offset, bool allocate,struct cache_entry **data_block) {
  size_t offsets[3];
  size_t offset_cnt=0;
  off_t sector_idx=offset/BLOCK_SECTOR_SIZE;
  if (sector_idx<123) 
  {
    offsets[0]=sector_idx;
    offset_cnt=1;
  }else{
    sector_idx-=123;
    if (sector_idx<((off_t)(BLOCK_SECTOR_SIZE / sizeof (block_sector_t))))
    {
      offsets[0]=123 + sector_idx/((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)));
      offsets[1]=sector_idx%((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)));
      offset_cnt=2;
    }else{
      sector_idx-=((off_t)(BLOCK_SECTOR_SIZE / sizeof (block_sector_t)));
      if (sector_idx<((off_t)(BLOCK_SECTOR_SIZE/sizeof(block_sector_t)))*((off_t)(BLOCK_SECTOR_SIZE/sizeof(block_sector_t))))
      {
        offsets[0]=(124+sector_idx/(((off_t)(BLOCK_SECTOR_SIZE/sizeof(block_sector_t)))*((off_t)(BLOCK_SECTOR_SIZE/sizeof(block_sector_t)))));
        offsets[1]=sector_idx/((off_t)(BLOCK_SECTOR_SIZE/sizeof(block_sector_t)));
        offsets[2]=sector_idx%((off_t)(BLOCK_SECTOR_SIZE/sizeof(block_sector_t)));
        offset_cnt=3;
      }
    }
  }
  size_t level=0;
  block_sector_t sector=inode->sector;
  while(1){
    struct cache_entry *c=cache_alloc(sector);
    uint32_t *data=cache_read(c);
    data = cache_read (c);
    if(data[offsets[level]]!=0)
    {
      sector = data[offsets[level]];
      level++;
      if (level==offset_cnt) 
      {
        if ((level==0 && offsets[level]+1<123) || (level>0 && offsets[level]+1 < ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t))))) 
        {
          uint32_t next_sector=data[offsets[level]+1];
          if (next_sector && next_sector < block_size(fs_device)){
            struct readahead_block *block = malloc (sizeof(struct readahead_block));
            block->sector = next_sector;
            lock_acquire (&readahead_lock);
            list_push_back (&readahead_list,&block->elem);
            cond_signal (&readahead_list_nonempty, &readahead_lock);
            lock_release (&readahead_lock);
          }
        }
        cache_unlock (c);
        *data_block=cache_alloc(sector);
        return true;
      }
      cache_unlock (c);
      continue;
    }
    cache_unlock (c);
    if (!allocate) 
    {
      *data_block=NULL;
      return true;
    }
    c=cache_lock(sector);
    data=cache_read(c);
    if (data[offsets[level]] != 0)
    {
      cache_unlock (c);
      continue;
    }
    if (!free_map_allocate (&data[offsets[level]]))
    {
      cache_unlock (c);
      *data_block = NULL;
      return false;
    }
    c->dirty=true;
    struct cache_entry *next_cache=cache_lock(data[offsets[level]]);
    memset(next_cache->data,0,BLOCK_SECTOR_SIZE);
    next_cache->correct = true;
    next_cache->dirty = true;
    cache_unlock (c);
    if (level == offset_cnt - 1) 
    {
      *data_block = next_cache;
      return true;
    }
    cache_unlock (next_cache);
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
      struct cache_entry *c;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      bool ok=get_data_block(inode,offset,false,&c);
      if (chunk_size <= 0 || !ok)
        break;

      if (c == NULL){
        memset(buffer + bytes_read, 0, chunk_size);
      } 
      else {
        const uint8_t* data=cache_read(c);
        memcpy(buffer + bytes_read, data + sector_ofs, chunk_size);
        cache_unlock(c);
      }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
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

  lock_acquire(&inode->deny_write);
  if (inode->deny_write_cnt)
  {
    lock_release(&inode->deny_write);
    return 0;
  }
  inode->writer_cnt++;
  lock_release(&inode->deny_write);
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      struct cache_entry *block;

      /* Bytes to max inode size, bytes left in sector, lesser of the two. */
      off_t inode_left = ((123+((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))+((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))*((off_t)(BLOCK_SECTOR_SIZE / sizeof (block_sector_t))))* BLOCK_SECTOR_SIZE) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      bool ok=get_data_block(inode,offset,true,&block);
      if (chunk_size <= 0 || !ok)
        break;

      uint8_t* data=cache_read(block);
      memcpy(data+sector_ofs,buffer+bytes_written,chunk_size);
      block->dirty=true;
      cache_unlock(block);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  if (offset>inode_length(inode)) 
  {
    struct cache_entry* inode_block=cache_lock(inode->sector);
    struct inode_disk* disk_inode=cache_read(inode_block);
    if(offset>disk_inode->length) 
    {
      disk_inode->length=offset;
      inode_block->dirty=true;
    }
    cache_unlock (inode_block);
  }


  lock_acquire (&inode->deny_write);
  inode->writer_cnt-=1;
  if (inode->writer_cnt==0){
    cond_signal (&inode->no_writers, &inode->deny_write);
  }
  lock_release (&inode->deny_write);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  lock_acquire (&inode->deny_write);
  while (inode->writer_cnt>0){
    cond_wait (&inode->no_writers, &inode->deny_write);
  }
  ASSERT (inode->deny_write_cnt < inode->open_cnt);
  inode->deny_write_cnt++;
  lock_release (&inode->deny_write);
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
  struct cache_entry *inode_block=cache_alloc(inode->sector);
  struct inode_disk *disk=cache_read(inode_block);
  cache_unlock (inode_block);
  return disk->length;
}

bool is_directory (const struct inode * inode){
  struct cache_entry *cache=cache_alloc(inode->sector);
  struct inode_disk *disk=cache_read(cache);
  bool ret=disk->directory;
  cache_unlock(cache);
  return ret;
}

struct inode * file_create (block_sector_t sector, off_t length) {
  struct inode *inode = inode_create(sector, 0);
  if (inode != NULL && length>0 && inode_write_at(inode,"",1,length-1)!=1)
  {
    inode_remove (inode); 
    inode_close (inode);
    inode = NULL;
  }
  return inode;
}
