#ifndef VM_SWAP_H
#define VM_SWAP_H


#include "vm/frame.h"
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <bitmap.h>
#include "devices/block.h"

struct lock swap_lock;
struct bitmap* swap_map;
struct block* swap_block;



void swap_init(void);
void swap_in(struct page* p);
bool swap_out(struct page* p);

#endif