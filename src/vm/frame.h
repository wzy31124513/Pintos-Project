#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "thread/thread.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

struct frame{
	struct page* page;
	void* addr;
	struct thread* t;
	struct list_elem elem;
	struct lock lock;

}

void* frame_init(void);
void* alloc_frame(struct page*,enum palloc_flags flags);
void* free_frame(struct frame* f);
#endif