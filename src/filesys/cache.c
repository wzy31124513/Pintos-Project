#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <string.h>

static void flushed (void *aux);
static void readahead (void *aux);
static size_t m=0;

void cache_init (void) {
  lock_init(&search_lock);
  for (int i = 0; i < 64; ++i)
  {
    struct cache_entry* c=&cache[i];
    lock_init(&c->lock);
    lock_init(&c->data_lock);
    c->dirty=false;
    c->correct=false;
    cond_init(&c->no_writers);
    cond_init(&c->no_readers);
    c->readers=0;
    c->writers=0;
    c->read_waiters=0;
    c->write_waiters=0;
    c->sector=(block_sector_t)-1;
  }
  thread_create("writebehind",0,flushed,NULL);
  lock_init(&readahead_lock);
  list_init(&readahead_list);
  cond_init(&readahead_list_nonempty);
  thread_create ("readahead",0,readahead,NULL);
}


void cache_flush (void) {
  for (int i = 0; i < 64; ++i)
  {
    struct cache_entry* c=&cache[i];
    lock_acquire(&c->lock);
    block_sector_t sector=c->sector;
    lock_release(&c->lock);
    if (sector!=(block_sector_t)-1)
    {
      c=cache_lock(sector,1);
      if (c->correct&&c->dirty)
      {
        block_write(fs_device,c->sector,c->data);
        c->dirty=false;
      }
      cache_unlock(c);
    }
  }
}


struct cache_entry * cache_lock (block_sector_t sector,bool exclusive){
 try_again:
  lock_acquire (&search_lock);
  for (int i = 0; i < 64; i++){
    struct cache_entry *b = &cache[i];
    lock_acquire (&b->lock);
    if (b->sector != sector) 
    {
      lock_release (&b->lock);
      continue;
    }
    lock_release (&search_lock);
    if (!exclusive) 
      {
        b->read_waiters++;
        if (b->writers || b->write_waiters)
          do {
            cond_wait (&b->no_writers, &b->lock);
          } while (b->writers);
        b->readers++;
        b->read_waiters--;
      }else {
        b->write_waiters++;
        if (b->readers || b->read_waiters || b->writers)
          do {
            cond_wait (&b->no_readers, &b->lock);
          } while (b->readers || b->writers);
        b->writers++;
        b->write_waiters--;
      }
    lock_release (&b->lock);
     return b;
  }
  for (int i = 0; i < 64; i++){
    struct cache_entry *b = &cache[i];
    lock_acquire (&b->lock);
    if (b->sector == (block_sector_t)-1) {
      lock_release (&b->lock);
      b->sector = sector;
      b->correct = false;
      if (!exclusive){
        b->readers = 1;
      }else{
        b->writers = 1;
      }
      lock_release (&search_lock);
      return b;
    }
    lock_release (&b->lock); 
  }

  for (int i = 0; i < 64; i++){
    struct cache_entry *b = &cache[m%64];
    m++;
    lock_acquire (&b->lock);
    if (b->readers || b->writers || b->read_waiters || b->write_waiters) {
      lock_release (&b->lock);
      continue;
    }
    b->writers = 1;
    lock_release (&b->lock);
    lock_release (&search_lock);
    if (b->correct && b->dirty) {
      block_write (fs_device, b->sector, b->data);
      b->dirty = false;
    }
    lock_acquire (&b->lock);
    b->writers = 0;
    if (!b->read_waiters && !b->write_waiters) {
      b->sector = (block_sector_t)-1; 
    }else{
      if (b->read_waiters){
        cond_broadcast (&b->no_writers, &b->lock);
      }else{
        cond_signal (&b->no_readers, &b->lock);
      }
    }
    lock_release (&b->lock);
    goto try_again;
  }
  lock_release (&search_lock);
  timer_msleep (1000);
  goto try_again;
}


void* cache_read(struct cache_entry* c){
  lock_acquire(&c->data_lock);
  if (!c->correct)
  {
    block_read(fs_device,c->sector,c->data);
    c->correct=true;
    c->dirty=false;
  }
  lock_release(&c->data_lock);
  return c->data;
}


void * cache_zero (struct cache_entry *b) {
  memset (b->data, 0, BLOCK_SECTOR_SIZE);
  b->correct = true;
  b->dirty = true;
  return b->data;
}


void cache_dirty (struct cache_entry *b) 
{
  b->dirty = true;
}


void cache_unlock (struct cache_entry *b){
  lock_acquire (&b->lock);
  if (b->readers) {
    if (--b->readers == 0){
      cond_signal (&b->no_readers, &b->lock);
    }
  }else{
      b->writers--;
      if (b->read_waiters){
        cond_broadcast (&b->no_writers, &b->lock);
      }else{
        cond_signal (&b->no_readers, &b->lock);
      }
  }
  lock_release (&b->lock);
}


void cache_free (block_sector_t sector) {
  int i;
  lock_acquire (&search_lock);
  for (i = 0; i < 64; i++){
    struct cache_entry *b = &cache[i];
    lock_acquire (&b->lock);
    if (b->sector == sector) {
      lock_release (&search_lock);
      if (b->readers == 0 && b->read_waiters == 0 && b->writers == 0 && b->write_waiters == 0){
        b->sector = (block_sector_t)-1; 
      }
      lock_release (&b->lock);
      return;
    }
    lock_release (&b->lock);
  }
  lock_release (&search_lock);
}

static void flushed (void *aux UNUSED) {
  for (;;) 
    {
      timer_msleep (30 * 1000);
      cache_flush ();
    }
}



void cache_readahead (block_sector_t sector) {
  struct readahead_block *block = malloc (sizeof *block);
  if (block == NULL){
    return;
  }
  block->sector = sector;
  lock_acquire (&readahead_lock);
  list_push_back (&readahead_list, &block->elem);
  cond_signal (&readahead_list_nonempty, &readahead_lock);
  lock_release (&readahead_lock);
}

static void readahead (void *aux UNUSED) 
{
  while(1){
    struct readahead_block* r;
    lock_acquire(&readahead_lock);
    while(list_empty(&readahead_list)){
      cond_wait(&readahead_list_nonempty,&readahead_lock);
    }
    r=list_entry(list_pop_front(&readahead_list),struct readahead_block,elem);
    lock_release (&readahead_lock);
    struct cache_entry* c=cache_lock(r->sector, 0);
    cache_read(c);
    cache_unlock(c);
    free (r);
  }
}
