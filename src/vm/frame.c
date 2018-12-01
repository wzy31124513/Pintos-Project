#include "vm/frame.h"
#include <stdio.h>
#include "vm/page.h"
#include "devices/timer.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct frame *frames;
static size_t count;
static struct lock frame_lock;
static size_t mark;

void frame_init(void){
  lock_init (&frame_lock);
  void *addr;
  frames=malloc(init_ram_pages*sizeof(struct frame));
  while((addr=palloc_get_page(PAL_USER))!=NULL){
    struct frame *f = &frames[count++];
    f->addr = addr;
    f->page = NULL;
    lock_init (&f->lock);
  }
}

static struct frame* try_frame_alloc (struct page *page){
  size_t i;
  lock_acquire(&frame_lock);
  for (i = 0; i < count; ++i)
    {
      struct frame* f=&frames[i];
      if (!lock_try_acquire(&f->lock)){
        continue;
      }
      if (f->page==NULL){
        f->page = page;
        lock_release(&frame_lock);
        return f;
      } 
      lock_release (&f->lock);
    }
  for (i = 0; i<count*2;++i) 
  {
    struct frame* f=&frames[mark];
    if (++mark>=count){
      mark=0;
    }
    if (!lock_try_acquire(&f->lock)){
      continue;
    }
    if (f->page==NULL) 
      {
        f->page=page;
        lock_release(&frame_lock);
        return f;
      } 
    if(recently_used(f->page)) 
    {
      lock_release (&f->lock);
      continue;
    }
    lock_release (&frame_lock);
    if(!page_evict(f->page)){
      lock_release(&f->lock);
      return NULL;
    }
    f->page=page;
    return f;
  }
  lock_release (&frame_lock);
  return NULL;
}

struct frame* frame_alloc(struct page* page){
  size_t i;
  for (i = 0; i < 3; ++i) 
  {
    struct frame* f =try_frame_alloc(page);
    if (f != NULL) 
      {
        return f; 
      }
    timer_msleep (1000);
  }
  return NULL;
}

void frame_lock(struct page* p){
  struct frame *f = p->frame;
  if(f!=NULL){
    lock_acquire(&f->lock);
    if(f!=p->frame){
      lock_release (&f->lock);
    } 
  }
}

void frame_free(struct frame* f)
{          
  f->page = NULL;
  lock_release (&f->lock);
}
