#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "threads/thread.h"
struct frame{
	struct page* page;
	void* addr;
	struct thread* t;
	struct list_elem elem;
	struct lock lock;
};

void frame_init(void);
void* alloc_frame(struct page*);
void free_frame(struct frame* f);
#endif