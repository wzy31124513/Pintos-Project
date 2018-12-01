#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "devices/block.h"
#include <string.h>
void init_page(struct hash* h){
	hash_init(h, page_hash_func, less, NULL);
}

unsigned page_hash_func (const struct hash_elem *e, void *aux UNUSED){
	return ((uint32_t)hash_entry(e,struct page,elem)->addr) >> 12;
}

bool less (const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED){
	return (uint32_t)hash_entry(a,struct page,elem)->addr < (uint32_t)hash_entry(b,struct page,elem)->addr;
}

struct page * page_alloc(void* addr, bool writable){
	struct page* p =malloc(sizeof(struct page));
	p->addr=addr;
	p->writable=writable;
	p->f=NULL;
	p->t=thread_current();
	p->file=NULL;
	p->offset=0;
	p->rw_bytes=0;
	p->swap=-1;
	p->mmap=writable;
	if (hash_insert(thread_current()->pages,&p->elem)!=NULL)
	{
		free(p);
		p=NULL;
	}
	return p;
}
struct page * find_page(void* addr){
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
				return page_alloc(addr,true);
			}
		}
	}
	return NULL;
}

void page_free(struct page* p){
	if (p->f!=NULL)
	{
		lock_acquire(&p->f->lock);
		if (p->file && !p->mmap)
		{
			page_evict(p);
		}
		p->f->page=NULL;
		lock_release(&p->f->lock);
	}
	hash_delete(thread_current()->pages,&p->elem);
	free(p);
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
	if (p->f==NULL)
	{
		if (!load_page(p))
		{
			return false;
		}
	}
	lock_try_acquire(&p->f->lock);
	bool ret=pagedir_set_page(thread_current()->pagedir,p->addr,p->f->addr,p->writable);
	lock_release(&p->f->lock);
	return ret;
}


bool load_page(struct page* p){
	p->f=alloc_frame(p);
	if (p->f==NULL)
	{
		return false;
	}
	if (p->swap!=-1)
	{
		swap_in(p);
	}else if(p->file!=NULL){
		int rw_bytes=file_read_at(p->file,p->f->addr,p->rw_bytes,p->offset);
		int zero_bytes=PGSIZE-rw_bytes;
		memset(p->f->addr+rw_bytes,0,zero_bytes);

	}else{
		memset(p->f->addr,0,PGSIZE);
	}
	return true;
}

bool page_evict(struct page* p){
	pagedir_clear_page(p->t->pagedir,p->addr);
	if (p->file)
	{
		if (pagedir_is_dirty(p->t->pagedir,p->addr))
		{
			if (p->mmap)
			{
				bool ret=swap_out(p);
				if (ret)
				{
					p->f=NULL;
				}
				return ret;
			}else{
				if(file_write_at(p->file,p->f->addr,p->rw_bytes,p->offset)==p->rw_bytes){
					p->f=NULL;
					return true;
				}
				return false;
			}
		}else{
			p->f=NULL;
			return true;
		}
	}else{
		bool ret=swap_out(p);
		if (ret)
		{
			p->f=NULL;
		}
		return ret;
	}
	return false;
}

bool recently_used(struct page* p){
	bool recently_used=pagedir_is_accessed(p->t->pagedir,p->addr);
	if (recently_used)
	{
		pagedir_set_accessed(p->t->pagedir,p->addr,false);
	}
	return recently_used;
}

bool page_lock(void* addr,bool writable){
	struct page* p=find_page(addr);
	if (!p || (!p->writable && !writable))
	{
		return false;
	}
	if (p->f)
	{
		lock_acquire(&p->f->lock);
		return true;
	}else{
		return load_page(p)&&pagedir_set_page(thread_current()->pagedir,p->addr,p->f->addr,p->writable);
	}

}

void page_unlock(void* addr){
	struct page* p=find_page(addr);
	if (p->f)
	{
		lock_release(&p->f->lock);
	}
}