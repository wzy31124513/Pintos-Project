#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
static struct frame* frames;
static struct lock frame_lock;
int count;
int mark;

void frame_init(void){
	lock_init(&frame_lock);
	frames=malloc(sizeof(struct frame)*init_ram_pages);
	void* addr;
	while((addr=palloc_get_page(PAL_USER))!=NULL){
		struct frame* f=&frames[count];
		count++;
		f->addr=addr;
		f->page=NULL;
		lock_init (&f->lock);
	}
}

void* alloc_frame(struct page* page){
	lock_acquire(&frame_lock);
	for (int i = 0; i<count; i++)
	{
		struct frame* f=&frames[i];
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
	for(int i=0;i<count*2;i++){
		struct frame* f=&frames[mark];
		mark++;
		if (mark>=count)
		{
			mark=0;
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
		lock_release (&frame_lock);
		if (!page_evict(f->page))
		{
			lock_release(&f->lock);
			return NULL;
		}
		f->page=page;
		return f;
	}
	lock_release (&frame_lock);
	return NULL;
}

void free_frame(struct frame* f){
	f->page=NULL;
	lock_release(&f->lock);
}



