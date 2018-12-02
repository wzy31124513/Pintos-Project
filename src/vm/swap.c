#include "vm/swap.h"
#include <bitmap.h>
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

struct lock swap_lock;
struct bitmap* swap_map;
struct block* swap_block;
#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)


void swap_init(void){
  swap_block=block_get_role(BLOCK_SWAP);
  if (swap_block==NULL){
    swap_map=bitmap_create (0);
    return;
  }
  swap_map=bitmap_create(block_size(swap_block)/PAGE_SECTORS);
  if (swap_map == NULL){
    return ;
  }
  lock_init(&swap_lock);
}

void swap_in(struct page* p){
  size_t i;
  for (i = 0; i < PAGE_SECTORS; i++){
    block_read (swap_block,p->swap+i,p->frame->addr + i*BLOCK_SECTOR_SIZE);
  }
  bitmap_reset(swap_map,p->swap/PAGE_SECTORS);
  p->swap=(block_sector_t)-1;
}

bool swap_out(struct page* p)
{
  size_t slot;
  size_t i;

  lock_acquire (&swap_lock);
  slot=bitmap_scan_and_flip(swap_map,0,1,false);
  lock_release (&swap_lock);
  if (slot==BITMAP_ERROR){
    return false;
  }
  p->swap = slot*PAGE_SECTORS;
  for (i = 0; i<PAGE_SECTORS;i++)
  {
    block_write (swap_block,p->swap+i,(uint8_t *)p->frame->addr + i*BLOCK_SECTOR_SIZE);
  }
  p->mmap = false;
  p->file = NULL;
  p->offset = 0;
  p->rw_bytes = 0;
  return true;
}
