#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct exec_table{
	const char* file_name;
	struct semaphore load;
	struct child_proc* child_proc;
	struct dir *wd; 
	bool loaded;
};
#endif /* userprog/process.h */
