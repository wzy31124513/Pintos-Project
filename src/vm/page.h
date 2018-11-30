#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "threads/thread.h"
#include "frame.h"
#include "swap.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "devices/block.h"
struct page
{
	void* addr;
	struct frame* f;
	struct thread* t;
	bool writable;
	struct file* file;
	int offset;
	int rw_bytes;
	int swap;
	bool mmap;
	struct hash_elem elem;	
};


void init_page(struct hash* h);
struct page* page_alloc(void* addr, bool writable);
struct page* find_page(void* addr);
void page_free(struct page* p);
bool load_fault(void* addr);
bool load_page(struct page* p);
bool page_evict(struct page* p);
bool recently_used(struct page* p);
bool page_lock(void* addr,bool writable);
void page_unlock(void* addr);
unsigned page_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool hash_less_func (const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED);
#endif