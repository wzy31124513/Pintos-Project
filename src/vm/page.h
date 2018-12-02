#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"


struct page 
{
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
unsigned page_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool less (const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED);
void page_destructor(struct hash_elem* e,void* aux UNUSED);

#endif
