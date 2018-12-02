#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "threads/synch.h"


struct page {
  void* addr;
  struct frame* frame;
  struct thread* t;
  bool read_only;
  struct file* file;
  int offset;
  int rw_bytes;
  block_sector_t swap;
  bool mmap;
  struct hash_elem elem;  
};

void init_page(struct hash* h);
struct page* page_alloc(void* addr, bool writable);
bool load_fault(void* addr);
bool load_page(struct page* p);
bool recently_used(struct page* p);
bool page_lock(const void* addr,bool writable);
void page_unlock(const void* addr);
void page_exit (void);
void page_deallocate (void *vaddr);
bool page_evict(struct page* p);
void page_destructor(struct hash_elem* e,void* aux);
hash_hash_func page_hash_func;
hash_less_func less;

#endif
