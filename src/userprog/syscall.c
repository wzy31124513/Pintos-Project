#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
static void syscall_handler (struct intr_frame *);

struct fds
{
    int fd;
    struct file *f;
    struct list_elem elem;
    struct thread* t;
};

struct fds* getfile(int fd);

bool is_valid_vaddr(const void* esp){
	if(esp!=NULL && is_user_vaddr(esp) && pagedir_get_page(thread_current(),esp)!=NULL){
		return 1;
	}
	return 0;
}

void halt (void){
	shutdown_power_off();
}

void exit (int status){
	thread_current()->exitcode=status;
	if (status!=-1)
	{
		f->eax=0;
	}
	thread_exit();
}

void exec (const char *cmd_line){
	thread_current()->child_load=0;
	int ret=process_execute(cmd_line);
	lock_acquire(thread_current()->wait_for_child);
	while(thread_current()->child_load==0){
		cond_wait(thread_current()->wait_cond, thread_current()->wait_for_child);
	}
	if (thread_current()->child_load==-1)
	{
		ret=-1;
	}
	lock_release(thread_current()->wait_for_child);
	f->eax=ret;
}

void wait (pid_t pid){
	f->eax=process_wait(pid);
}
void create (const char *file, unsigned initial_size){
	if (!is_valid_vaddr(file))
	{
		f->eax=false;
		exit(-1);
	}else{
		lock_acquire(&file_lock);
		f->eax=filesys_create(file,initial_size);
		lock_release(&file_lock);
	}
}
void remove (const char *file){
	if (!is_valid_vaddr(file))
	{
		f->eax=false;
		exit(-1);
	}else{
		lock_acquire(&file_lock);
		f->eax=filesys_remove(file);
		lock_release(&file_lock);
	}
}
void open (const char *file){
	struct fds* fd;
	if (!is_valid_vaddr(file))
	{
		f->eax=-1;
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
	f->eax=fd->fd;
}

void filesize (int fd){
	lock_acquire (&file_lock); 
	struct fds* fds=getfile(fd);
	if (fds!=NULL)
	{
		f->eax=file_length(fds->f);
	}else{
		f->eax=-1;
	}
	lock_release (&file_lock);
}

void read (int fd, void *buffer, unsigned size){
	if (fd==0)
	{
		for (int i = 0; i < size; i++)
		{
			buffer[i]=input_getc();
		}
		f->eax=size;

	}else{
		lock_acquire (&file_lock); 
		struct fds* fds=getfile(fd);
		if (fds==NULL)
		{
			f->eax=-1;
		}else{
			f->eax=file_read(fn->f,buffer,size);
		}
		lock_release (&file_lock);
	}
}

void write (int fd, const void *buffer, unsigned size){
	lock_acquire (&file_lock); 
	if (fd==1)
	{
		putbuf(buffer,size);
		f->eax=size;
	}else{
		struct fds* fds=getfile(fd);
		if (fds==NULL)
		{
			f->eax=0;
		}else{
			f->eax=file_write(fds->f,buffer,size);
		}
	}
	lock_release (&file_lock);
}

void seek (int fd, unsigned position){
	lock_acquire (&file_lock); 
	struct *fds fds=getfile(fd);
	file_seek(fds->f,position);
	lock_release (&file_lock);
}

void tell (int fd){
	lock_acquire(&file_lock);
	struct fds* fds=getfile(fd);
	if (fds!=NULL)
	{
		f->eax=file_tell(fds->f);
	}else{
		f->eax=1;
	}
	lock_release(&file_lock);
}

void close (int fd){
	lock_acquire(&file_lock);
	struct fds* fds-getfile(fd);
	if (fds!=NULL)
	{
		struct list_elem* e;
		for (e=list_begin(&file_list);e!=list_tail(&file_list);e=list_next(e))
		{
			if (list_entry(e,struct fds,elem)->fd==fd)
			{
				file_close(list_entry(e,struct fds,elem)->f);
				list_remove(e);
				free(list_entry(e,struct fds,elem)->f)
				f->eax=0;
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
		wait(*(esp+1));
	}else if (*esp==SYS_EXIT)
	{
		exit(*(esp+1));
	}else if (*esp==SYS_EXEC)
	{
		exec((char*)*(esp+1));
	}else if (*esp==SYS_WAIT)
	{
		wait(*(esp+1));
	}else if (*esp==SYS_CREATE)
	{
		create((char*)*(esp+1),*(esp+2));
	}else if (*esp==SYS_REMOVE)
	{
		remove((char*)*(esp+1));
	}else if (*esp==SYS_FILESIZE)
	{
		filesize(*(esp+1));
	}else if (*esp==SYS_READ)
	{
		read(*(esp+1),(void*)*(esp+2),*(esp+3));
	}else if (*esp==SYS_WRITE)
	{
		write(*(esp+1),(void*)*(esp+2),*(esp+3));
	}else if (*esp==SYS_SEEK)
	{
		seek(*(esp+1),*(esp+2));
	}else if (*esp==SYS_TELL)
	{
		tell(*(esp+1));
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
			return list_entry(e,struct fds, elem)->fd;
		}
	}
	return NULL;
}