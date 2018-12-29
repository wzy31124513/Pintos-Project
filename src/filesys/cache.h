#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"
#include <list.h>

struct cache_entry{
	struct lock lock;
	struct lock data_lock;
	block_sector_t sector;
	bool dirty;
	bool correct;
	char data[BLOCK_SECTOR_SIZE];
	struct condition no_writers;
	struct condition no_readers;
	int readers;
	int writers;
	int read_waiters;
	int write_waiters;
};

struct readahead_block{
	block_sector_t sector;
	struct list_elem elem;
};


struct cache_entry cache[64];
struct lock search_lock;
static struct lock readahead_lock;
static struct condition readahead_list_nonempty;
static struct list readahead_list;
static size_t mark;

void cache_init(void);
void* cache_read(struct cache_entry* c);
static void cache_writebehind(void* aux UNUSED);
static void cache_readahead(void* aux UNUSED);
struct cache_entry* cache_alloc(block_sector_t sector);
void cache_unlock(struct cache_entry *c);
struct cache_entry * cache_lock(block_sector_t sector);
void cache_flush(void);

#endif