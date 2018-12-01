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
#include "vm/page.h"
#include "vm/frame.h"

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
int mmap (int fd, void *addr);
void munmap (int mapping);
struct mapping* getmap(int id);
char* strcpy_to_kernel(const char* str);
static void argcpy(void* cp,void* addr1,size_t size);

void* is_valid_vaddr(const void* esp){
	if(!is_user_vaddr(esp)){
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
	
	struct list_elem* e;
	for (e=list_begin(&thread_current()->parent->children);e!=list_tail(&thread_current()->parent->children); e=list_next(e))
	{
		if (list_entry(e,struct child_proc,elem)->id==thread_current()->tid)
		{
			list_entry(e,struct child_proc,elem)->ret=status;
			list_entry(e,struct child_proc,elem)->waited=false;
		}
	}

	for (e = list_begin(&thread_current()->mapping); e!=list_tail(&thread_current()->mapping); e=list_next(e))
	{
		munmap(list_entry(e,struct mapping,elem)->id);
	}
    thread_current()->exitcode=status;


	if (thread_current()->parent->wait==thread_current()->tid)
	{
		sema_up(&thread_current()->parent->wait_for_child);
	}
	thread_exit();
}

int exec (const char *cmd_line){
	int ret;
	char* fn_copy=strcpy_to_kernel(cmd_line);
	ret=process_execute(fn_copy);
	palloc_free_page(fn_copy);
	return ret;
}

int wait (int pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
	bool ret;
	char* fn_copy=strcpy_to_kernel(file);
	lock_acquire(&file_lock);
	ret= filesys_create(fn_copy,initial_size);
	lock_release(&file_lock);
	palloc_free_page(fn_copy);
	return ret;
}

bool remove (const char *file){
	bool ret;
	char* fn_copy=strcpy_to_kernel(file);
	lock_acquire(&file_lock);
	ret = filesys_remove(fn_copy);
	lock_release(&file_lock);
	palloc_free_page(fn_copy);
	return ret;
}

int open (const char *file){
	char* fn_copy=strcpy_to_kernel(file);
	lock_acquire (&file_lock);
	struct fds* fd=calloc(1,sizeof(struct fds)); 
	fd->f=filesys_open(file);
	if (fd->f==NULL)
	{
		fd->fd=-1;
	}else{
		thread_current()->fd_num++;
		fd->fd=thread_current()->fd_num;
		list_push_back(&thread_current()->file_list,&fd->elem);
	}
	lock_release (&file_lock);
	palloc_free_page(fn_copy);
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

	int read=0;
	struct fds* f=getfile(fd);
	uint8_t* b=buffer;
	while(size>0){
		size_t page_left=PGSIZE-pg_ofs(b);
		int32_t ret;
		size_t read_size;
		if (size<page_left)
		{
			read_size=size;
		}else{
			read_size=page_left;
		}
		if (fd!=0)
		{
			if (!page_lock(b,true))
			{
				exit(-1);
			}
			lock_acquire(&file_lock);
			ret=file_read(f->f,b,read_size);
			lock_release(&file_lock);
			page_unlock(b);
		}else{
			for (int i = 0; i < read_size; ++i)
			{
				char c=input_getc();
				if (!page_lock(b,true))
				{
					exit(-1);
				}
				b[i]=c;
				page_unlock(b);
			}
			read=read_size;
		}
		if (ret<0)
		{
			if (read==0)
			{
				read==-1
			}
			break;
		}
		read+=ret;
		if (ret!=read_size)
		{
			break;
		}
		b+=ret;
		size-=ret;
	}
	return read;
}

int write (int fd, const void *buffer, unsigned size){
	uint8_t b=buffer;
	struct fds* f;
	int write=0;
	if (fd!=1)
	{
		f=getfile(fd);
	}
	while(size>0){
		size_t page_left=PGSIZE-pg_ofs(b);
		size_t write_size;
		int32_t ret;
		if (size<page_left)
		{
			write_size=size;
		}else{
			write_size=page_left;
		}
		if (!page_lock(b,false))
		{
			exit(-1);		
		}
		lock_acquire(&file_lock);
		if (fd==1)
		{
			putbuf((char*)b,write_size);
			ret=write_size;
		}else{
			ret=file_write(f->f,b,write_size);
		}
		lock_release(&file_lock);
		page_unlock(b);
		if (ret<0)
		{
			if (write==0)
			{
				write=-1;
			}
			break;
		}
		write+=ret;
		if (ret!=write_size)
		{
			break;
		}
		b+=ret;
		size-=ret;
	}
	return write;
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
	unsigned ret;
	if (fds!=NULL)
	{
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
			list_remove(e);
			free(f);
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
	typedef int function (int,int,int);
	struct syscall{
		size_t arg_num;
		function* func;
	};
    static const struct syscall syscall_table[] =
    {
      {0,(function*)halt},
      {1,(function*)exit},
      {1,(function*)exec},
      {1,(function*)wait},
      {2,(function*)create},
      {1,(function*)remove},
      {1,(function*)open},
      {1,(function*)filesize},
      {3,(function*)read},
      {3,(function*)write},
      {2,(function*)seek},
      {1,(function*)tell},
      {1,(function*)close},
      {2,(function*)mmap},
      {1,(function*)munmap},
    };
    const struct syscall* syscall;
    unsigned int func;
    int args[3];
    argcpy(&func,f->esp,sizeof(func));
    if (func>=(sizeof(syscall_table)/sizeof(*syscall_table)))
    {
    	exit(-1);
    }
    memset(args,0,sizeof(args));
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*syscall->arg_num);
    f->eax=syscall->func(args[0],args[1],args[2]);
}

struct mapping* getmap(int id){
	struct list_elem* e;
	for (e=list_begin(&thread_current()->mapping); e != list_tail(&thread_current()->mapping) ; e=list_next(e))
	{
		struct mapping* m=list_entry(e,struct mapping, elem);
		if (m->id==id)
		{
			return m;
		}
	}
	exit(-1);
}



void munmap (int mapping){
	struct mapping* m=getmap(mapping);
	list_remove(&m->elem);
	for (int i = 0; i < m->num; ++i)
	{
		if (pagedir_is_dirty(thread_current()->pagedir,(m->addr+PGSIZE*i)))
		{
			lock_acquire(&file_lock);
			file_write_at(m->file,(const void*)(m->addr+PGSIZE*i),(PGSIZE*(m->num)),PGSIZE*i);
			lock_release(&file_lock);
		}
	}
	for (int i = 0; i < m->num; ++i)
	{
		struct page* p=find_page(m->addr+PGSIZE * i);
		if (p->f!=NULL)
		{
			lock_acquire(&p->f->lock);
			if (p->file && !p->mmap)
			{
				page_evict(p);
			}
			free_frame(p->f);
		}
		hash_delete(thread_current()->pages,&p->elem);
		free(p);
	}
}


int mmap (int fd, void *addr){
	struct fds* f=getfile(fd);
	struct mapping* m = malloc(sizeof(struct mapping));
	if (m==NULL || addr==NULL || pg_ofs(addr)!=0)
	{
		return -1;
	}

	m->id=thread_current()->fd_num++;
	lock_acquire(&file_lock);
	m->file=file_reopen(f->f);
	if (m->file==NULL)
	{
		free(m);
		return -1;
	}
	m->addr=addr;
	m->num=0;
	list_push_front(&thread_current()->mapping,&m->elem);
	int length=file_length(m->file);
	lock_release(&file_lock);
	int offset=0;
	while(length>0){
		struct page* p=page_alloc(addr+offset,true);
		if (p==NULL)
		{
			munmap(m->id);
			return -1;
		}
		p->mmap=false;
		p->file=m->file;
		p->offset=offset;
		if (length>PGSIZE)
		{
			p->rw_bytes=PGSIZE;
		}else{
			p->rw_bytes=length;
		}
		offset+=p->rw_bytes;
		length-=p->rw_bytes;
		m->num++;

	}
	return m->id;
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

char* strcpy_to_kernel(const char* str){
	char* cp;
	int length=0;
	char* addr;
	cp=palloc_get_page(0);
	if (cp==NULL)
	{
		exit(-1);
	}
	while(1){
		addr=pg_round_down(str);
		if (!page_lock(addr,false))
		{
			page_unlock(addr);
			return NULL;
		}
		while(str<addr+PGSIZE){
			cp[length]=*str;
			length++;
			if (*str=='\0')
			{
				page_unlock(addr);
				return cp;
			}else if (length>=PGSIZE)
			{
				goto error;
			}
			str++;
		}
		page_unlock(addr);
	}
	error:
	  	palloc_free_page(cp);
		exit(-1);
	return NULL;
}

static void argcpy(void* cp,void* addr1,size_t size){
	uint8_t* dst=cp;
	const uint8_t* addr=addr1;
	while(size>0){
		size_t s=PGSIZE-pg_ofs(addr);
		if (s>size)
		{
			s=size;
		}
		if (!page_lock(addr,false))
		{
			exit(-1);
		}
		memcpy(dst,addr,s);
		page_unlock(addr);
		dst+=s;
		addr+=s;
		size-=s;
	}
}