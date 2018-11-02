#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"


static void syscall_handler (struct intr_frame *);

struct fds
{
    int fd;
    struct file *f;
    struct list_elem elem;
    struct thread* t;
};

struct fds* getfile(int fd);
bool is_valid_vaddr(const void* esp);
void halt (void);
void exit (int status);
int exec (const char *cmd_line);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);



bool is_valid_vaddr(const void* esp){
	if(esp!=NULL && is_user_vaddr(esp) && pagedir_get_page(thread_current()->pagedir,esp)!=NULL){
		return 1;
	}
	return 0;
}

void halt (void){
	shutdown_power_off();
}

void exit (int status){
	thread_current()->exitcode=status;
	thread_exit();
}

int exec (const char *cmd_line){
	thread_current()->child_load=0;
	int ret=process_execute(cmd_line);
	lock_acquire(&thread_current()->wait_for_child);
	while(thread_current()->child_load==0){
		cond_wait(&thread_current()->wait_cond, &thread_current()->wait_for_child);
	}
	if (thread_current()->child_load==-1)
	{
		ret=-1;
	}
	lock_release(&thread_current()->wait_for_child);
	return ret;
}

int wait (int pid){
	return process_wait(pid);
}
bool create (const char *file, unsigned initial_size){
	if (!is_valid_vaddr(file))
	{
		return false;
		exit(-1);
	}else{
		lock_acquire(&file_lock);
		return filesys_create(file,initial_size);
		lock_release(&file_lock);
	}
}
bool remove (const char *file){
	if (!is_valid_vaddr(file))
	{
		return false;
		exit(-1);
	}else{
		lock_acquire(&file_lock);
		return filesys_remove(file);
		lock_release(&file_lock);
	}
}
int open (const char *file){
	struct fds* fd;
	if (!is_valid_vaddr(file))
	{
		return -1;
		exit(-1);
	}
	fd=calloc(1,sizeof(struct fds));
	lock_acquire (&file_lock); 
	fd->f=filesys_open(file);
	if (fd->f==NULL)
	{
		fd->fd=-1;
	}else{
		fd_num++;
		fd->fd=fd_num;
		list_push_back(&file_list,&fd->elem);
	}
	lock_release (&file_lock);
	return fd->fd;
}

int filesize (int fd){
	lock_acquire (&file_lock); 
	struct fds* fds=getfile(fd);
	if (fds!=NULL)
	{
		return file_length(fds->f);
	}else{
		return -1;
	}
	lock_release (&file_lock);
}

int read (int fd, void *buffer, unsigned size){
	if (fd==0)
	{
		for (unsigned i = 0; i < size; i++)
		{
			(char)buffer[i]=input_getc();
		}
		return size;

	}
	lock_acquire (&file_lock); 
	struct fds* fds=getfile(fd);
	if (fds==NULL)
	{
		return -1;
	}else{
		return file_read(fds->f,buffer,size);
	}
	lock_release (&file_lock);
}

int write (int fd, const void *buffer, unsigned size){
	lock_acquire (&file_lock); 
	if (fd==1)
	{
		putbuf(buffer,size);
		return size;
	}else{
		struct fds* fds=getfile(fd);
		if (fds==NULL)
		{
			return 0;
		}else{
			return file_write(fds->f,buffer,size);
		}
	}
	lock_release (&file_lock);
}

void seek (int fd, unsigned position){
	lock_acquire (&file_lock); 
	struct fds* fds=getfile(fd);
	file_seek(fds->f,position);
	lock_release (&file_lock);
}

unsigned tell (int fd){
	lock_acquire(&file_lock);
	struct fds* fds=getfile(fd);
	if (fds!=NULL)
	{
		return file_tell(fds->f);
	}else{
		return 1;
	}
	lock_release(&file_lock);
}

void close (int fd){
	lock_acquire(&file_lock);
	struct fds* fds=getfile(fd);
	if (fds!=NULL)
	{
		struct list_elem* e;
		for (e=list_begin(&file_list);e!=list_tail(&file_list);e=list_next(e))
		{
			if (list_entry(e,struct fds,elem)->fd==fd)
			{
				file_close(list_entry(e,struct fds,elem)->f);
				list_remove(e);
				free(list_entry(e,struct fds,elem)->f);
				lock_release(&file_lock);
				return;
			}
		}
	}
	lock_release(&file_lock);
}




void
syscall_init (void) 
{
  fd_num=1;
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int *esp=f->esp;
	if (!is_valid_vaddr(esp) || !is_valid_vaddr(esp+1) || !is_valid_vaddr(esp+2) || !is_valid_vaddr(esp+3))
	{
		exit(-1);
		return;
	}
	if (*esp==SYS_HALT)
	{
		halt();
	}else if (*esp==SYS_HALT)
	{
		f->eax=wait(*(esp+1));
	}else if (*esp==SYS_EXIT)
	{
		exit(*(esp+1));
	}else if (*esp==SYS_EXEC)
	{
		f->eax=exec((char*)*(esp+1));
	}else if (*esp==SYS_WAIT)
	{
		f->eax=wait(*(esp+1));
	}else if (*esp==SYS_CREATE)
	{
		f->eax=create((char*)*(esp+1),*(esp+2));
	}else if (*esp==SYS_REMOVE)
	{
		f->eax=remove((char*)*(esp+1));
	}else if (*esp==SYS_FILESIZE)
	{
		f->eax=filesize(*(esp+1));
	}else if (*esp==SYS_READ)
	{
		f->eax=read(*(esp+1),(void*)*(esp+2),*(esp+3));
	}else if (*esp==SYS_WRITE)
	{
		f->eax=write(*(esp+1),(void*)*(esp+2),*(esp+3));
	}else if (*esp==SYS_SEEK)
	{
		seek(*(esp+1),*(esp+2));
	}else if (*esp==SYS_TELL)
	{
		f->eax=tell(*(esp+1));
	}else if (*esp==SYS_CLOSE)
	{
		close(*(esp+1));
	}
}

struct fds* getfile(int fd){
	struct list_elem *e;
	for(e=list_begin(&file_list);e!=list_end(&file_list);e=list_next(e)){
		if (list_entry(e,struct fds, elem)->fd==fd)
		{
			return (struct fds*)list_entry(e,struct fds, elem)->fd;
		}
	}
	return NULL;
}