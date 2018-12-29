#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"

void cache_init(void){
	lock_init(&search_lock);
	for (int i = 0; i < 64; ++i)
	{
		struct cache_entry* c=&cache[i];
		lock_init(&c->lock);
		lock_init(&c->data_lock);
		c->dirty=false;
		c->correct=false;
		cond_init(&c->no_writers);
		cond_init(&c->no_readers);
		c->readers=0;
		c->writers=0;
		c->read_waiters=0;
		c->write_waiters=0;
		c->sector=(block_sector_t)-1;
	}
	thread_create("writebehind",0,cache_writebehind,NULL);
	lock_init(&readahead_lock);
	list_init(&readahead_list);
	cond_init(&readahead_list_nonempty);
	thread_create ("readahead",0,cache_readahead,NULL);
}


void cache_flush(void){
	for (int i = 0; i < 64; ++i)
	{
		struct cache_entry* c=&cache[i];
		lock_acquire(&c->lock);
		block_sector_t sector=c->sector;
		lock_release(&c->lock);
		if (sector!=(block_sector_t)-1)
		{
			c=cache_lock(sector);
			if (c->correct&&c->dirty)
			{
				block_write(fs_device,c->sector,c->data);
				c->dirty=false;
			}
			cache_unlock(c);
		}
	}
}


static void cache_writebehind(void* aux UNUSED){
	while(1){
		timer_msleep(1000);
		cache_flush();
	}
} 

static void cache_readahead(void* aux UNUSED){
	while(1){
		struct readahead_entry* r=malloc(sizeof(struct readahead));
		lock_acquire(&readahead_lock);
		while(list_empty(&readahead_list)){
			cond_wait(&readahead_list_nonempty,&readahead_lock);
		}
		r=list_entry(list_pop_front(&readahead_list),struct readahead_entry,elem);
		lock_release(&readahead_lock);
		struct cache_entry* c;
		c=cache_alloc(sector);
		cache_read(c);
		cache_unlock(c);
		free(r);
	}
}

void* cache_read(struct* cache_entry c){
	lock_acquire(&c->data_lock);
	if (!c->correct)
	{
		block_read(fs_device,c->sector,c->data);
		c->correct=true;
		c->dirty=false;
	}
	lock_release(&c->data_lock);
	return c->data;
}

struct cache_entry * cache_alloc(block_sector_t sector)
{
	struct cache_entry* c;
	while(1){
		lock_acquire(&search_lock)
		for (int i = 0; i < 192; ++i)
		{
			if (i<64)
			{
				c=&cache[i];
				lock_acquire(&c->lock);
				if (c->sector!=sector)
				{
					lock_release(&c->lock);
					continue;
				}
				lock_release(&search_lock);
				c->read_waiters++;
				if (c->writers||c->write_waiters)
				{
					cond_wait(&c->no_writers,&c->lock);
					while(c->writers){
						cond_wait(&c->no_writers,&c->lock);
					}
				}
				c->readers++;
				c->read_waiters--;
				lock_release(&c->lock);
				return c;
			}else if (i>=64 && i<128)
			{
				c=&cache[i-64];
				lock_acquire(&c->lock);
				if (c->sector==(block_sector_t)-1)
				{
					lock_release(&c->lock);
					c->sector=sector;
					c->correct=false;
					c->readers=1;
					lock_release(&search_lock);
					return c;
				}
				lock_release(&c->lock);
			}else{
				c=&cache[mark];
				mark++;
				mark=mark%64;
				lock_acquire(&c->lock);
				if (c->readers||c->writers||c->read_waiters||c->write_waiters)
				{
					lock_release(&c->lock);
					continue;
				}
				lock_release(&search_lock);
				c->writers=1;
				if (c->correct&c->dirty)
				{
					block_write(fs_device,c->sector,c->data);
					c->dirty=false;
				}
				c->writers=0;
				if (!c->read_waiters&&!c->write_waiters)
				{
					c->sector=(block_sector_t)-1;
				}else{
					if (c->read_waiters)
					{
						cond_broadcast(&c->no_writers,&c->lock);
					}else{
						cond_signal(&c->no_writers,&c->lock);
					}
				}
				lock_release(&c->lock);
				lock_release(&search_lock);
				break;
			}
		}
		timer_msleep(1000);
	}
}

void cache_unlock(struct cache_block *c){
	lock_acquire(&c->lock);
	if (c->readers)
	{
		c->readers--;
		if (c->readers==0)
		{
			cond_signal(&c->no_readers,&c->lock);
		}
	}else{
		c->writers=0;
		if (c->read_waiters)
		{
			cond_broadcast(&c->no_writers,&c->lock);
		}else{
			cond_signal(&c->no_readers,&c->ock);
		}
	}
	lock_release(&c->lock);
}

struct cache_entry * cache_lock(block_sector_t sector)
{
	struct cache_entry* c;
	while(1){
		lock_acquire(&search_lock)
		for (int i = 0; i < 192; ++i)
		{
			if (i<64)
			{
				c=&cache[i];
				lock_acquire(&c->lock);
				if (c->sector!=sector)
				{
					lock_release(&c->lock);
					continue;
				}
				lock_release(&search_lock);
				c->write_waiters++;
				if (c->readers||c->read_waiters||c->writers)
				{
					cond_wait(&c->no_readers,&c->lock);
					while(c->readers||c->writers){
						cond_wait(&c->no_readers,&c->lock);
					}
				}
				c->writers++;
				c->write_waiters--;
				lock_release(&c->lock);
				return c;
			}else if (i>=64 && i<128)
			{
				c=&cache[i-64];
				lock_acquire(&c->lock);
				if (c->sector==(block_sector_t)-1)
				{
					lock_release(&c->lock);
					c->sector=sector;
					c->correct=false;
					c->writers=1;
					lock_release(&search_lock);
					return c;
				}
				lock_release(&c->lock);
			}else{
				c=&cache[mark];
				mark++;
				mark=mark%64;
				lock_acquire(&c->lock);
				if (c->readers||c->writers||c->read_waiters||c->write_waiters)
				{
					lock_release(&c->lock);
					continue;
				}
				lock_release(&search_lock);
				c->writers=1;
				if (c->correct&c->dirty)
				{
					block_write(fs_device,c->sector,c->data);
					c->dirty=false;
				}
				c->writers=0;
				if (!c->read_waiters&&!c->write_waiters)
				{
					c->sector=(block_sector_t)-1;
				}else{
					if (c->read_waiters)
					{
						cond_broadcast(&c->no_writers,&c->lock);
					}else{
						cond_signal(&c->no_writers,&c->lock);
					}
				}
				lock_release(&c->lock);
				lock_release(&search_lock);
				break;
			}
		}
		timer_msleep(1000);
	}
}

