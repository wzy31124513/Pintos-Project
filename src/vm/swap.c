#include "vm/swap.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <bitmap.h>
#include "devices/block.h"

struct lock swap_lock;
struct bitmap* swap_map;
struct block* swap_block;

void swap_init(void){
	swap_block=block_get_role(BLOCK_SWAP);
	if (swap_block==NULL)
	{
		swap_map=bitmap_create(0);
		return;
	}
	swap_map=bitmap_create(block_size(swap_block)/(PGSIZE/BLOCK_SECTOR_SIZE));
	if (swap_map==NULL)
	{
		return;
	}
	lock_init(&swap_lock);
}

void swap_in(struct page* p){
	if (!swap_block || !swap_map)
	{
		return;
	}
	lock_acquire(&swap_lock);
	for (int i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; ++i)
	{
		block_read(swap_block,p->swap+i,p->f->addr+BLOCK_SECTOR_SIZE*i);
	}
	bitmap_reset(swap_map,p->swap/(PGSIZE/BLOCK_SECTOR_SIZE));
	p->swap=-1;
	lock_release(&swap_lock);
}


bool swap_out(struct page* p){
	lock_acquire(&swap_lock);
	size_t free_index=bitmap_scan_and_flip(swap_map,0,1,false);
	if (free_index==BITMAP_ERROR)
	{
		lock_release(&swap_lock);
		return false;
	}
	p->swap=free_index*(PGSIZE/BLOCK_SECTOR_SIZE);
	for (int i = 0; i < (PGSIZE/BLOCK_SECTOR_SIZE); ++i)
	{
		block_write(swap_block,free_index*(PGSIZE/BLOCK_SECTOR_SIZE)+i,p->f->addr+i*BLOCK_SECTOR_SIZE);
	}
	p->mmap=false;
	p->file=NULL;
	p->offset=0;
	p->rw_bytes=0;
	lock_release(&swap_lock);
	return true;
}