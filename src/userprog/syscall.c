#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"
static void syscall_handler (struct intr_frame *);

struct fds* getfile(int fd);
void* is_valid_vaddr(const void* esp);
void halt (void);
void exit (int status);
int exec (const char *cmd_line);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, char *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);




void* is_valid_vaddr(const void* esp){
	if(esp==NULL || !is_user_vaddr(esp)){
		exit(-1);
		return 0;
	}
	if (pagedir_get_page(thread_current()->pagedir,esp)==NULL)
	{
		exit(-1);
		return 0;
	}
	return pagedir_get_page(thread_current()->pagedir,esp);
}

void halt (void){
	shutdown_power_off();
}

void exit (int status){
	thread_current()->exitcode=status;
	printf ("%s: exit(%d)\n",thread_current()->name, thread_current()->exitcode);
	struct list_elem* e;
	for (e=list_begin(&thread_current()->parent->children);e!=list_tail(&thread_current()->parent->children); e=list_next(e))
	{
		if (list_entry(e,struct child_proc,elem)->id==thread_current()->tid)
		{
			list_entry(e,struct child_proc,elem)->ret=status;
			list_entry(e,struct child_proc,elem)->waited=false;
		}
	}


	if (thread_current()->parent->wait==thread_current()->tid)
	{
		sema_up(&thread_current()->parent->wait_for_child);
	}


	thread_exit();
}

int exec (const char *cmd_line){
	lock_acquire(&file_lock);
	char* fn_copy=calloc(1,strlen(cmd_line)+1);
	strlcpy(fn_copy,cmd_line,strlen(cmd_line)+1);
	char* p;
	fn_copy=strtok_r(fn_copy," ",&p);
	int ret;
	if (filesys_open(fn_copy)==NULL)
	{
		ret=-1;
		lock_release(&file_lock);
	}else{
		file_close(filesys_open(fn_copy));
		lock_release(&file_lock);
		ret=process_execute(cmd_line);
	}
	return ret;
}

int wait (int pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
	bool ret;
	lock_acquire(&file_lock);
	ret= filesys_create(file,initial_size);
	lock_release(&file_lock);
	return ret;
}

bool remove (const char *file){
	bool ret;
	lock_acquire(&file_lock);
	ret = filesys_remove(file);
	lock_release(&file_lock);
	return ret;
}

int open (const char *file){
	lock_acquire (&file_lock);
	struct fds* fd=calloc(1,sizeof(struct fds)); 
	fd->f=filesys_open(file);
	if (fd->f==NULL)
	{
		fd->fd=-1;
	}else{
		thread_current()->fd_num=thread_current()->fd_num+1;
		fd->fd=thread_current()->fd_num;
		list_push_back(&thread_current()->file_list,&fd->elem);
	}
	lock_release (&file_lock);
	return fd->fd;
}

int filesize (int fd){
	lock_acquire (&file_lock); 
	int ret;
	struct fds* fds=getfile(fd);
	if (fds!=NULL)
	{
		ret = file_length(fds->f);
	}else{
		ret = -1;
	}
	lock_release (&file_lock);
	return ret;
}

int read (int fd, char *buffer, unsigned size){
	if (fd==0)
	{
		for (unsigned i = 0; i < size; i++)
		{
			buffer[i]=input_getc();
		}
		return size;

	}
	lock_acquire (&file_lock); 
	int ret;
	struct fds* fds=getfile(fd);
	if (fds==NULL)
	{
		ret = -1;
	}else{
		ret = file_read(fds->f,buffer,size);
	}
	lock_release (&file_lock);
	return ret;
}

int write (int fd, const void *buffer, unsigned size){
	int ret;

	if (fd==0)
	{
		ret= -1;
	}
	else if (fd==1)
	{
		putbuf(buffer,size);
		ret= size;
	}else{
		lock_acquire(&file_lock);
		struct fds* fds=getfile(fd);
		if (fds==NULL)
		{
			ret= -1;
		}else{
			ret= file_write(fds->f,buffer,size);
		}
		lock_release(&file_lock);

	}
	return ret;
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
	struct list_elem* e;
	for (e=list_begin(&thread_current()->file_list);e!=list_tail(&thread_current()->file_list);e=list_next(e))
	{
		if (list_entry(e,struct fds,elem)->fd==fd)
		{
			list_remove(e);
			file_close(list_entry(e,struct fds,elem)->f);
			free(list_entry(e,struct fds,elem));
			break;
		}
	}
	lock_release(&file_lock);
}




void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int *esp=f->esp;
	is_valid_vaddr(esp);
	is_valid_vaddr(esp+1);
	is_valid_vaddr(esp+2);
	is_valid_vaddr(esp+3);
	if (*esp==SYS_HALT)
	{
		halt();
	}else if (*esp==SYS_EXIT)
	{
		is_valid_vaddr(esp+1);
		exit(*(esp+1));
	}else if (*esp==SYS_EXEC)
	{
		is_valid_vaddr(esp+1);
		is_valid_vaddr((void*)*(esp+1));
		f->eax=exec((char*)*(esp+1));
	}else if (*esp==SYS_WAIT)
	{
		is_valid_vaddr(esp+1);
		f->eax=wait((int)*(esp+1));
	}else if (*esp==SYS_CREATE)
	{
		is_valid_vaddr(esp+5);
		is_valid_vaddr((void*)*(esp+4));
		f->eax=create((char*)*(esp+4),*(esp+5));
	}else if (*esp==SYS_REMOVE)
	{
		is_valid_vaddr(esp+1);
		is_valid_vaddr((void*)*(esp+1));
		f->eax=remove((char*)*(esp+1));
	}else if (*esp==SYS_OPEN){
		is_valid_vaddr(esp+1);
		is_valid_vaddr((void*)*(esp+1));
		f->eax=open((char *)*(esp+1));
	}
	else if (*esp==SYS_FILESIZE)
	{
		is_valid_vaddr(esp+1);
		f->eax=filesize((int)*(esp+1));
	}else if (*esp==SYS_READ)
	{
		is_valid_vaddr(esp+7);
		is_valid_vaddr((void*)*(esp+6));
		f->eax=read(*(esp+5),(void*)*(esp+6),*(esp+7));
	}else if (*esp==SYS_WRITE)
	{
		is_valid_vaddr(esp+7);
		is_valid_vaddr(*(esp+6));
		f->eax=write(*(esp+5),*(esp+6),*(esp+7));
	}else if (*esp==SYS_SEEK)
	{
		is_valid_vaddr(esp+5);
		seek(*(esp+4),*(esp+5));
	}else if (*esp==SYS_TELL)
	{
		is_valid_vaddr(esp+1);
		f->eax=tell(*(esp+1));
	}else if (*esp==SYS_CLOSE)
	{
		is_valid_vaddr(esp+1);
		close(*(esp+1));
	}
}

struct fds* getfile(int fd){
	struct list_elem *e;
	struct fds* fds;
	for(e=list_begin(&thread_current()->file_list);e!=list_end(&thread_current()->file_list);e=list_next(e))
	{	
		fds=list_entry(e,struct fds, elem);
		if (fds->fd==fd)
		{
			return fds;
		}
	}
	return NULL;
}