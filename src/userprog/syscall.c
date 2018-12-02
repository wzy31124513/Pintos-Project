#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
struct fds
{
    struct file *file;
    int fd;
    struct list_elem elem;
};

struct mapping
{
  int id;
  struct file* file;
  uint8_t * addr;
  int num;
  struct list_elem elem;
};

static int halt (void);
static int exit1 (int status);
static int exec (const char *cmd_line);
static int wait (int pid);
static int create (const char *file, unsigned initial_size);
static int remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd,  void *buffer, unsigned size);
static int seek (int fd, unsigned position);
static int tell (int fd);
static int close (int fd);
static int mmap (int fd, void *addr);
static int munmap (int mapping);
static void syscall_handler (struct intr_frame *);
static void argcpy(void* cp,const void* addr1,size_t size);
static char * strcpy_to_kernel (const char *us);
static struct fds* getfile(int fd);
static struct mapping* getmap (int fd);
void exit2 (void);

static int halt(void)
{
  shutdown_power_off ();
}

static int exit1(int status)
{
  thread_current()->exitcode=status;
  thread_exit ();
}

void
exit2 (void)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct list_elem *next;
  for (e=list_begin(&cur->file_list);e!=list_end(&cur->file_list);e=next)
  {
    struct fds *fd=list_entry(e,struct fds,elem);
    next=list_next(e);
    lock_acquire(&file_lock);
    file_close(fd->file);
    lock_release(&file_lock);
    free (fd);
  }
  for (e =list_begin(&thread_current()->mapping);e!=list_end(&thread_current()->mapping);e=next)
  {
    next=list_next(e);
    struct mapping *m=list_entry(e,struct mapping,elem);
    munmap(m->id);
  }
}

static int exec(const char* cmd_line)
{
  int ret;
  char* fn_copy=strcpy_to_kernel(cmd_line);
  lock_acquire(&file_lock);
  ret=process_execute(fn_copy);
  lock_release(&file_lock);
  palloc_free_page (fn_copy);
  return ret;
}

static int wait(int pid)
{
  return process_wait(pid);
}

static int create(const char *file, unsigned initial_size)
{
  bool ret;
  char* fn_copy=strcpy_to_kernel(file);
  lock_acquire(&file_lock);
  ret=filesys_create(fn_copy,initial_size);
  lock_release(&file_lock);
  palloc_free_page (fn_copy);
  return ret;
}

static int remove(const char* file)
{
  char* fn_copy=strcpy_to_kernel(file);
  bool ret;
  lock_acquire(&file_lock);
  ret=filesys_remove(fn_copy);
  lock_release(&file_lock);
  palloc_free_page (fn_copy);
  return ret;
}

static int open(const char* file)
{
  char* fn_copy=strcpy_to_kernel(file);
  struct fds* f;
  int fd=-1;
  f=malloc(sizeof(struct fds));
  if(f!=NULL)
  {
    lock_acquire(&file_lock);
    f->file=filesys_open(fn_copy);
      if(f->file!=NULL)
      {
        fd=f->fd=thread_current()->fd_num++;
        list_push_front(&thread_current()->file_list,&f->elem);
      }
      else{
        free(f);
      }
      lock_release (&file_lock);
  }
  palloc_free_page (fn_copy);
  return fd;
}

static int filesize(int fd)
{
  struct fds* f=getfile(fd);
  int ret;
  lock_acquire (&file_lock);
  ret=file_length(f->file);
  lock_release (&file_lock);
  return ret;
}

static int read (int fd, void *buffer, unsigned size)
{
  int read=0;
  struct fds* f=getfile(fd);
  uint8_t* b=(uint8_t*)buffer;
  while(size>0){
    size_t page_left=PGSIZE-pg_ofs(b);
    int32_t ret=0;
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
        thread_exit();
      }
      lock_acquire(&file_lock);
      ret=file_read(f->file,b,read_size);
      lock_release(&file_lock);
      page_unlock(b);
    }else{
      for (size_t i = 0; i < read_size; ++i)
      {
        char c=input_getc();
        if (!page_lock(b,true))
        {
          thread_exit();
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
        read=-1;
      }
      break;
    }
    read+=ret;
    if (ret!=(int32_t)read_size)
    {
      break;
    }
    b+=ret;
    size-=ret;
  }
  return read;
}

static int write (int fd,  void *buffer, unsigned size){
  uint8_t* b=(uint8_t*)buffer;
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
      thread_exit();   
    }
    lock_acquire(&file_lock);
    if (fd==1)
    {
      putbuf((char*)b,write_size);
      ret=write_size;
    }else{
      ret=file_write(f->file,b,write_size);
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
    if (ret!=(int32_t)write_size)
    {
      break;
    }
    b+=ret;
    size-=ret;
  }
  return write;
}

static int seek (int fd, unsigned position){
  lock_acquire (&file_lock); 
  struct fds* fds=getfile(fd);
  file_seek(fds->file,position);
  lock_release (&file_lock);
  return 0;
}

static int tell (int fd)
{
  lock_acquire(&file_lock);
  struct fds* fds=getfile(fd);
  unsigned ret;
  if (fds!=NULL)
  {
    ret = file_tell(fds->file);
  }else{
    ret = 1;
  }
  lock_release(&file_lock);
  return ret;
}

static int close(int fd)
{
  struct fds* f=getfile(fd);
  lock_acquire(&file_lock);
  file_close(f->file);
  lock_release(&file_lock);
  list_remove(&f->elem);
  free(f);
  return 0;
}

static int mmap (int fd, void *addr)
{
  struct fds* f=getfile(fd);
  struct mapping* m=malloc(sizeof(struct mapping));
  size_t offset;
  off_t length;
  if (m==NULL || addr==NULL || pg_ofs(addr)!=0){
    return -1;
  }
  m->id=thread_current()->fd_num++;
  lock_acquire(&file_lock);
  m->file=file_reopen(f->file);
  lock_release(&file_lock);
  if(m->file==NULL)
  {
    free (m);
    return -1;
  }
  m->addr=addr;
  m->num=0;
  list_push_front(&thread_current()->mapping,&m->elem);

  offset=0;
  lock_acquire(&file_lock);
  length=file_length(m->file);
  lock_release(&file_lock);
  while(length>0){
    struct page* p=page_alloc((uint8_t*)addr+offset,false);
    if(p==NULL){
      munmap(m->id);
      return -1;
    }
    p->mmap=false;
    p->file=m->file;
    p->offset=offset;
    if (length>=PGSIZE)
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

static int munmap (int mapping)
{
  struct mapping *m = getmap(mapping);
  list_remove(&m->elem);
  for(int i=0;i<m->num;i++)
  {
    if(pagedir_is_dirty(thread_current()->pagedir,((const void *)(m->addr+PGSIZE * i))))
    {
      lock_acquire (&file_lock);
      file_write_at(m->file,(const void *)(m->addr+PGSIZE * i),PGSIZE*(m->num),PGSIZE*i);
      lock_release (&file_lock);
    }
  }
  for(int i=0;i<m->num;i++)
  {
    page_deallocate((void *)(m->addr+PGSIZE * i));
  }
  return 0;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  const struct syscall *sc;
  unsigned func;
  int args[3];
  argcpy(&func,f->esp,sizeof(func));
  if(func>=15){
    thread_exit();
  }
  memset(args,0,sizeof(args));
  if (func==SYS_HALT)
  {
    f->eax=halt();
  }else if (func==SYS_EXIT)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=exit1(args[0]);
  }else if (func==SYS_EXEC)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=exec(args[0]);
  }else if (func==SYS_WAIT)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=wait(args[0]);
  }else if (func==SYS_CREATE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=create(args[0],args[1]);
  }else if (func==SYS_REMOVE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=remove(args[0]);
  }else if (func==SYS_OPEN){
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=open(args[0]);
  }
  else if (func==SYS_FILESIZE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=filesize(args[0]);
  }else if (func==SYS_READ)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*3);
    f->eax=read(args[0],args[1],args[2]);
  }else if (func==SYS_WRITE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*3);
    f->eax=write(args[0],args[1],args[2]);
  }else if (func==SYS_SEEK)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=seek(args[0],args[1]);
  }else if (func==SYS_TELL)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=tell(args[0]);
  }else if (func==SYS_CLOSE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=close(args[0]);
  }else if (func==SYS_MMAP)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=mmap(args[0],args[1]);
  }else if (func==SYS_MUNMAP)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=munmap(args[0]);
  }
}

static void argcpy(void* cp,const void* addr1,size_t size){
  uint8_t *dst=cp;
  const uint8_t *addr=addr1;
  while(size>0){
    size_t s=PGSIZE-pg_ofs(addr);
    if(s>size){
      s=size;
    }
    if(!page_lock(addr,false)){
      thread_exit();
    }
    memcpy(dst,addr,s);
    page_unlock(addr);
    dst+=s;
    addr+=s;
    size-=s;
  }
}

static char * strcpy_to_kernel (const char *str)
{
  char* cp;
  char* addr;
  size_t length;
  cp=palloc_get_page(0);
  if(cp==NULL){
    thread_exit ();
  }
  length=0;
  while(1){
    addr=pg_round_down (str);
    if(!page_lock(addr,false)){
      palloc_free_page (cp);
      thread_exit ();
      return NULL;
    }
    while(str<addr+PGSIZE){
      cp[length++]=*str;
      if (*str=='\0')
        {
          page_unlock(addr);
          return cp;
        }
        else if (length>=PGSIZE){
          page_unlock(addr);
          return NULL;
        }
      str++;
    }
    page_unlock (addr);
  }
}


static struct fds* getfile(int fd){
  struct list_elem *e;
  struct fds* fds;
  for(e=list_begin(&thread_current()->file_list);e!=list_end(&thread_current()->file_list);e=list_next(e))
  {
    fds=list_entry(e,struct fds,elem);
      if(fds->fd == fd){
        return fds;
      }
  }
  thread_exit ();
}

static struct mapping* getmap (int fd)
{
  struct list_elem *e;
  for (e = list_begin (&thread_current()->mapping); e != list_end (&thread_current()->mapping);e = list_next (e))
  {
    struct mapping* m=list_entry(e,struct mapping,elem);
    if(m->id==fd){
      return m;
    }
  }
  thread_exit ();
}