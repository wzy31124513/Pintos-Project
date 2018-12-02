#include "vm/page.h"
#include <stdio.h>
#include <string.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

void init_page(struct hash* h){
  hash_init(h, page_hash_func, less, NULL);
}
unsigned page_hash_func (const struct hash_elem *e, void *aux UNUSED){
  return ((uint32_t)hash_entry(e,struct page,elem)->addr) >> 12;
}
bool less (const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED){
  return (uint32_t)hash_entry(a,struct page,elem)->addr < (uint32_t)hash_entry(b,struct page,elem)->addr;
}

struct page * page_alloc(void* addr, bool read_only){
  struct page* p =malloc(sizeof(struct page));
  if (p != NULL){
    p->addr=pg_round_down(addr);
    p->read_only=read_only;
    p->mmap=!read_only;
    p->frame=NULL;
    p->swap=(block_sector_t)-1;
    p->file=NULL;
    p->offset=0;
    p->rw_bytes=0;
    p->t=thread_current();
    if(hash_insert(thread_current()->pages,&p->elem)!=NULL){
      free (p);
      p=NULL;
    }
  }
  return p;
}

static struct page * find_page(const void* addr){
  if (addr<PHYS_BASE)
  {
    struct page page;
    struct hash_elem* e;
    page.addr=(void*)pg_round_down(addr);
    e=hash_find(thread_current()->pages,&page.elem);
    if (e)
    {
      return hash_entry(e,struct page,elem);
    }else if (PHYS_BASE-addr<=(1024*1024)){
      if (addr>=thread_current()->esp-32)
      {
        return page_alloc((void*)addr,false);
      }
    }
  }
  return NULL;
}


bool load_page(struct page* p){
  p->frame=frame_alloc(p);
  if(p->frame==NULL){
    return false;
  }
  if (p->swap!=(block_sector_t)-1)
  {
    swap_in(p);
  }else if(p->file!=NULL){
    int rw_bytes=file_read_at(p->file,p->frame->addr,p->rw_bytes,p->offset);
    int zero_bytes=PGSIZE-rw_bytes;
    memset(p->frame->addr+rw_bytes,0,zero_bytes);
  }else{
    memset(p->frame->addr,0,PGSIZE);
  }
  return true;
}


bool load_fault(void* addr){
  if (thread_current()->pages==NULL)
  {
    return false;
  }
  struct page *p=find_page(addr);
  if (!p)
  {
    return false;
  }
  frame_lock (p);
  if (p->frame==NULL)
  {
    if (!load_page(p))
    {
      return false;
    }
  }
  bool ret=pagedir_set_page(thread_current()->pagedir,p->addr,p->frame->addr,!p->read_only);
  lock_release(&p->frame->lock);
  return ret;
}


bool page_evict(struct page* p){
  pagedir_clear_page(p->t->pagedir,p->addr);
  bool ret;
  bool dirty=pagedir_is_dirty(p->t->pagedir,p->addr);
  if (!dirty)
  {
    ret=true;
  }
  if (p->file)
  {
    if (dirty)
    {
      if (p->mmap)
      {
        ret=swap_out(p);
      }else{
        ret=file_write_at(p->file,p->frame->addr,p->rw_bytes,p->offset);
      }
    } 
  }else{
    ret=swap_out(p);
  }
  if (ret)
  {
    p->frame=NULL;
  }
  return ret;
}


bool recently_used(struct page* p){
  bool recently_used=pagedir_is_accessed(p->t->pagedir,p->addr);
  if (recently_used)
  {
    pagedir_set_accessed(p->t->pagedir,p->addr,false);
  }
  return recently_used;
}

void page_deallocate(void *addr){
  struct page* p=find_page(addr);
  frame_lock(p);
  if (p->frame)
  {
    struct frame *f = p->frame;
    if (p->file && !p->mmap){
      page_evict(p);
    }
    frame_free(f);
  }
  hash_delete(thread_current()->pages,&p->elem);
  free(p);
}

bool page_lock(const void* addr, bool writable){
  struct page* p=find_page(addr);
  if (p==NULL || (p->read_only && writable)){
    return false;
  }
  frame_lock (p);
  if (p->frame==NULL){
    return (load_page(p) && pagedir_set_page(thread_current()->pagedir,p->addr,p->frame->addr,!p->read_only));
  }
  else{
    return true;
  }
}

void page_unlock(const void *addr){
  struct page *p = find_page(addr);
  frame_unlock (p->frame);
}

void page_exit (void){
  struct hash* h=thread_current()->pages;
  if (h!=NULL)
  {
    hash_destroy(h,page_destructor);
  }
}

void page_destructor(struct hash_elem* e,void* aux UNUSED){
  struct page *p=hash_entry(e,struct page,elem);
  frame_lock (p);
  if (p->frame){
    frame_free(p->frame);
  }
  free (p);
}