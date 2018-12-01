#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
static struct list frames;
static struct lock frame_lock;


void* frame_init(void){
	lock_init(&frame_lock);
	list_init(&frames);
]	void* addr=palloc_get_page(PAL_USER);
	while(addr){
		struct frame* f=malloc(sizeof(struct frame));
		f->addr=addr;
		f->page=NULL;
		f->t=thread_current();
		lock_init (&f->lock);
	}
}

void* alloc_frame(struct page* page){
	struct list_elem* e;
	lock_acquire(&frame_lock);
	for (e = list_begin(&frames); e!=list_tail(&frames); e=list_next(e))
	{
		struct frame* f=list_entry(e,struct frame,elem);
		if (!lock_try_acquire(&f->lock))
		{
			continue;
		}
		if (f->page==NULL)
		{
			f->page=page;
			lock_release(&frame_lock);
			return f;
		}
	}
	e = list_begin(&frames);
	while(1){
		struct frame* f=list_entry(e,struct frame,elem);
		e=list_next(e);
		if (e==list_tail(&frames))
		{
			e=list_begin(&frames);
		}
		if (!lock_try_acquire(&f->lock))
		{
			continue;
		}
		if (f->page==NULL)
		{
			f->page=page;
			lock_release(&frame_lock);
			return f;
		}
		if (recently_used(f->page))
		{
			lock_release(&f->lock);
			continue;
		}
		if (!page_evict(f->page))
		{
			lock_release(&f->lock);
			lock_release (&frame_lock);
			return NULL;
		}
        lock_release (&frame_lock);
		f->page=page;
		return f;
	}

}

void* free_frame(struct frame* f){
	f->page=NULL;
	lock_release(&f->lock);
}



