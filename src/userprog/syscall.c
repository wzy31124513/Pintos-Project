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
#include "filesys/directory.h"

static void syscall_handler (struct intr_frame *);

struct fds* getfile(int fd);
void* is_valid_vaddr(const void* esp);
void halt (void);
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
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);




void* is_valid_vaddr(const void* esp){
	if(!is_user_vaddr(esp)){
		exit1(-1);
		return 0;
	}
	if (pagedir_get_page(thread_current()->pagedir,esp)==NULL)
	{
		exit1(-1);
		return 0;
	}
	return pagedir_get_page(thread_current()->pagedir,esp);
}

void halt (void){
	shutdown_power_off();
}

void exit1 (int status){
	struct thread *cur = thread_current();
	struct list_elem* e;
	struct list_elem *next;
  	for (e=list_begin(&cur->file_list);e!=list_end(&cur->file_list);e=next)
  	{
  	  struct fds *fd=list_entry(e,struct fds,elem);
  	  next=list_next(e);
  	  lock_acquire(&file_lock);
  	  file_close(fd->f);
  	  dir_close(fd->dir);
  	  lock_release(&file_lock);
  	  free (fd);
  	}
  	dir_close(cur->directory);
  	cur->exitcode=status;
  	thread_exit ();
}

int exec (const char *cmd_line){
	int ret=process_execute(cmd_line);
	return ret;
}

int wait (int pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
	bool ret;
	lock_acquire(&file_lock);
	ret= filesys_create(file,initial_size,false);
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
	struct inode* inode=filesys_open(file);
	if (inode==NULL)
	{
		fd->fd=-1;
	}else{
		if (is_directory(inode)==true)
		{
			fd->dir=dir_open(inode);
		}else{
			fd->f=file_open(inode);
		}
		if (fd->f!=NULL || fd->dir!=NULL)
		{
			thread_current()->fd_num=thread_current()->fd_num+1;
			fd->fd=thread_current()->fd_num;
			list_push_back(&thread_current()->file_list,&fd->elem);
		}else{
			free(fd);
			inode_close(inode);
		}
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
		if (fds->f==NULL)
		{
			exit1(-1);
		}
		ret = file_length(fds->f);
	}else{
		ret = -1;
	}
	lock_release (&file_lock);
	return ret;
}

int read (int fd, char *buffer, unsigned size){

	int ret=size;
	char* check=(char*)buffer;
	for (unsigned i = 0; i < size; ++i)
	{
		if (!is_user_vaddr(check) || check==NULL)
		{
			exit1(-1);
		}
		if (pagedir_get_page(thread_current()->pagedir,check)==NULL)
		{
			exit1(-1);
		}
		check=check+1;
	}

	lock_acquire (&file_lock); 
	if (fd==0)
	{
		for (unsigned i = 0; i < size; i++)
		{
			buffer[i]=input_getc();
		}
	}else{
		struct fds* fds=getfile(fd);
		//is_valid_vaddr(fds->f);
		if (fds==NULL)
		{
			ret = -1;
		}else{
			if (fds->f==NULL)
			{
				exit1(-1);
			}
			ret = file_read(fds->f,buffer,size);
		}
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
		struct fds* fds=getfile(fd);
		//is_valid_vaddr(fds->f);
		if (fds==NULL)
		{
			ret= -1;
		}else{
			if (fds->f==NULL)
			{
				exit1(-1);
			}
			lock_acquire(&file_lock);
			ret= file_write(fds->f,buffer,size);
			lock_release(&file_lock);

		}
	}
	return ret;
}

void seek (int fd, unsigned position){
	lock_acquire (&file_lock); 
	struct fds* fds=getfile(fd);
	if (fds->f==NULL)
	{
		exit1(-1);
	}
	file_seek(fds->f,position);
	lock_release (&file_lock);
}

unsigned tell (int fd){
	lock_acquire(&file_lock);
	struct fds* fds=getfile(fd);
	unsigned ret;
	if (fds!=NULL)
	{
		if (fds->f==NULL)
		{
			exit1(-1);
		}
		ret = file_tell(fds->f);
	}else{
		ret = 1;
	}
	lock_release(&file_lock);
	return ret;
}

void close (int fd){
	struct list_elem* e;
	struct fds* f;
	lock_acquire(&file_lock);
	for (e=list_begin(&thread_current()->file_list);e!=list_tail(&thread_current()->file_list);e=list_next(e))
	{
		f=list_entry(e,struct fds,elem);
		if (f->fd==fd)
		{
			file_close(f->f);
			dir_close(f->dir);
			list_remove(e);
			free(f);
			break;
		}
	}
	lock_release(&file_lock);
}

bool chdir (const char *dir){
	struct dir* d=dir_open(filesys_open(dir));
	if (d!=NULL)
	{
		dir_close(thread_current()->directory);
		thread_current()->directory=d;
		return true;
	}
	return false;
}
bool mkdir (const char *dir){
	return filesys_create(dir,0,true);
}

bool readdir (int fd, char *name){
	struct fds* fds=getfile(fd);
	if (fds->dir==NULL)
	{
		exit1(-1);
	}
	return dir_readdir(fds->dir,name);

}

bool isdir (int fd){
	return getfile(fd)->dir!=NULL;
}
int inumber (int fd){
	struct fds* fds=getfild(fd);
	if (isdir(fd))
	{
		if (fds->dir==NULL)
		{
			exit1(-1);
		}
		struct inode* inode=dir_get_inode(fds->dir);
		return inode_get_inumber(inode);
	}else{
		if (fds->f==NULL)
		{
			exit1(-1);
		}
		struct inode* inode=file_get_inode(fds->f);
		return inode_get_inumber(inode);
	}
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

	if (*esp==SYS_HALT)
	{
		halt();
	}else if (*esp==SYS_EXIT)
	{
		is_valid_vaddr(esp+1);
		exit1(*(esp+1));
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
		is_valid_vaddr((void*)*(esp+6));
		f->eax=write(*(esp+5),(void*)*(esp+6),*(esp+7));
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
	}else if (*esp==SYS_CHDIR)
	{
		is_valid_vaddr(esp+1);
		chdir((const char *)*(esp+1));
	}else if (*esp==SYS_MKDIR)
	{
		is_valid_vaddr(esp+1);
		mkdir((const char *)*(esp+1));
	}else if (*esp==SYS_READDIR)
	{
		is_valid_vaddr(esp+5);
		readdir(*(esp+4),(char *)*(esp+5));
	}else if (*esp==SYS_ISDIR)
	{
		is_valid_vaddr(esp+1);
		isdir(*(esp+1));
	}else if (*esp==SYS_INUMBER)
	{
		is_valid_vaddr(esp+1);
		inumber(*(esp+1));
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