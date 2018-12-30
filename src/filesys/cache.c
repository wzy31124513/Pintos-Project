#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <string.h>

static void cache_writebehind (void *aux);
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
  thread_create("writebehind",0,cache_writebehind,NULL);
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
      c=cache_lock(sector);
      if (c->correct&&c->dirty)
      {
        block_write(fs_device,c->sector,c->data);
        c->dirty=false;
      }
      cache_unlock(c);
    }
  }
}

static void cache_writebehind (void *aux UNUSED) {
  while(1){
    timer_msleep (30 * 1000);
    cache_flush ();
  }
}

static void readahead (void *aux UNUSED){
  while(1){
    struct readahead_block* r;
    lock_acquire(&readahead_lock);
    while(list_empty(&readahead_list)){
      cond_wait(&readahead_list_nonempty,&readahead_lock);
    }
    r=list_entry(list_pop_front(&readahead_list),struct readahead_block,elem);
    lock_release (&readahead_lock);
    struct cache_entry* c=cache_alloc(r->sector);
    cache_read(c);
    cache_unlock(c);
    free (r);
  }
}

void cache_readahead (block_sector_t sector) {
  struct readahead_block *block = malloc (sizeof(struct readahead_block));
  block->sector = sector;
  lock_acquire (&readahead_lock);
  list_push_back (&readahead_list,&block->elem);
  cond_signal (&readahead_list_nonempty, &readahead_lock);
  lock_release (&readahead_lock);
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

struct cache_entry * cache_lock(block_sector_t sector){
  bool a=false;
  while(1){
    lock_acquire (&search_lock);
    for (int i = 0; i < 192; i++){
      if (i<64)
      {
        struct cache_entry *b = &cache[i];
        lock_acquire (&b->lock);
        if (b->sector != sector) 
        {
          lock_release (&b->lock);
          continue;
        }
        lock_release (&search_lock);
        b->write_waiters++;
        if (b->readers || b->read_waiters || b->writers)
          do {
            cond_wait (&b->no_readers, &b->lock);
          } while (b->readers || b->writers);
        b->writers++;
        b->write_waiters--;
        lock_release (&b->lock);
        return b;
      }else if (i<128){
        struct cache_entry *b = &cache[i%64];
        lock_acquire (&b->lock);
        if (b->sector == (block_sector_t)-1) {
          lock_release (&b->lock);
          b->sector = sector;
          b->correct = false;
          b->writers = 1;
          lock_release (&search_lock);
          return b;
        }
        lock_release (&b->lock); 
      }else{
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
        a=true;
        break;
      }
    }
    if (a==true)
    {
      a=false;
      continue;
    }
    lock_release (&search_lock);
    timer_msleep (1000);
  }
}

struct cache_entry * cache_alloc(block_sector_t sector){
  bool a=false;
  while(1){
    lock_acquire (&search_lock);
    for (int i = 0; i < 192; i++){
      if (i<64)
      {
        struct cache_entry *b = &cache[i];
        lock_acquire (&b->lock);
        if (b->sector != sector) 
        {
          lock_release (&b->lock);
          continue;
        }
        lock_release (&search_lock);
        b->read_waiters++;
        if (b->writers || b->write_waiters)
          do {
            cond_wait (&b->no_writers, &b->lock);
          } while (b->writers);
        b->readers++;
        b->read_waiters--;
        lock_release (&b->lock);
        return b;
      }else if (i<128){
        struct cache_entry *b = &cache[i%64];
        lock_acquire (&b->lock);
        if (b->sector == (block_sector_t)-1) {
          lock_release (&b->lock);
          b->sector = sector;
          b->correct = false;
          b->readers = 1;
          lock_release (&search_lock);
          return b;
        }
        lock_release (&b->lock); 
      }else{
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
        a=true;
        break;
      }
    }
    if (a==true)
    {
      a=false;
      continue;
    }
    lock_release (&search_lock);
    timer_msleep (1000);
  }
}

void cache_unlock (struct cache_entry *b){
  lock_acquire (&b->lock);
  if (b->readers) {
    b->readers--;
    if(b->readers == 0)
    {
      cond_signal(&b->no_readers,&b->lock);
    }
  }else{
    b->writers=0;
    if (b->read_waiters)
    {
      cond_broadcast (&b->no_writers,&b->lock);
    }else{
      cond_signal(&b->no_readers,&b->lock);
    }
  }
  lock_release (&b->lock);
}


