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
static int exit (int status);
static int exec (const char *cmd_line);
static int wait (int pid);
static int create (const char *file, unsigned initial_size);
static int remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size)
static int write (int fd,  void *buffer, unsigned size);
static int seek (int fd, unsigned position);
static int tell (int fd);
static int close (int fd);
static int mmap (int fd, void *addr);
static int munmap (int mapping);
char* strcpy_to_kernel(const char* str);
static void syscall_handler (struct intr_frame *);
static void argcpy(void* cp,const void* addr1,size_t size);
static struct fds* getfile(int fd);
void exit2 (void);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  typedef int syscall_function (int,int,int);

  struct syscall
    {
      size_t arg_num;
      syscall_function *func;
    };

  static const struct syscall syscall_table[] =
    {
      {0,(syscall_function *)halt},
      {1,(syscall_function *)exit},
      {1,(syscall_function *)exec},
      {1,(syscall_function *)wait},
      {2,(syscall_function *)create},
      {1,(syscall_function *)remove},
      {1,(syscall_function *)open},
      {1,(syscall_function *)filesize},
      {3,(syscall_function *)read},
      {3,(syscall_function *)write},
      {2,(syscall_function *)seek},
      {1,(syscall_function *)tell},
      {1,(syscall_function *)close},
      {2,(syscall_function *)mmap},
      {1,(syscall_function *)munmap},
    };
  unsigned call_nr;
  int args[3];
  argcpy(&call_nr,f->esp,sizeof(call_nr));
  if(call_nr>=sizeof(syscall_table)/sizeof(*syscall_table)){
    thread_exit ();
  }
  const struct syscall* sc=syscall_table+call_nr;
  memset(args,0,sizeof(args));
  argcpy(args,(uint32_t *)f->esp+1,sizeof(*args)*sc->arg_num);
  f->eax=sc->func(args[0],args[1],args[2]);
}


static void argcpy(void* cp,const void* addr1,size_t size){
  uint8_t *dst = cp;
  const uint8_t *addr = addr1;
  while (size > 0){
    size_t chunk_size=PGSIZE-pg_ofs(addr);
    if(chunk_size > size){
      chunk_size = size;
    }
    if (!page_lock (addr, false)){
      thread_exit ();
    }
    memcpy(cp,addr,chunk_size);
    page_unlock (addr);
    dst+=chunk_size;
    addr+=chunk_size;
    size-=chunk_size;
  }
}

char* strcpy_to_kernel(const char* str){
  char *cp;
  char *addr;
  size_t length;
  cp=palloc_get_page (0);
  if (cp == NULL){
    thread_exit ();
  }
  length=0;
  for (;;)
    {
      addr=pg_round_down(str);
      if (!page_lock(addr,false))
        goto lock_error;
      for (; str<addr+PGSIZE;str++){
        cp[length++] = *str;
        if(*str=='\0')
        {
          page_unlock (addr);
          return cp;
        }else if (length>=PGSIZE)
          goto too_long_error;
      }
      page_unlock (addr);
    }

 too_long_error:
  page_unlock (addr);
 lock_error:
  palloc_free_page (cp);
  thread_exit ();
}

static int halt (void)
{
  shutdown_power_off ();
}

static int exit (int status)
{
  thread_current ()->exitcode=status;
  thread_exit ();
}

static int exec(const char *cmd_line)
{
  int ret;
  char* fn_copy=strcpy_to_kernel(cmd_line);
  lock_acquire (&file_lock);
  ret = process_execute (fn_copy);
  lock_release (&file_lock);
  palloc_free_page (fn_copy);
  return ret;
}

static int wait(int pid)
{
  return process_wait(pid);
}

static int create (const char *file, unsigned initial_size)
{
  char *fn_copy=strcpy_to_kernel(file);
  bool ret;
  lock_acquire (&file_lock);
  ret = filesys_create (fn_copy, initial_size);
  lock_release (&file_lock);
  palloc_free_page (fn_copy);
  return ret;
}

static int remove(const char *file)
{
  char *fn_copy=strcpy_to_kernel(file);
  bool ok;
  lock_acquire (&file_lock);
  ok = filesys_remove (fn_copy);
  lock_release (&file_lock);
  palloc_free_page (fn_copy);
  return ok;
}

static int open (const char *file)
{
  char* fn_copy=strcpy_to_kernel(file);
  struct fds* fd;
  int ret = -1;
  fd = malloc (sizeof(struct fds));
  if (fd != NULL){
    lock_acquire(&file_lock);
    fd->file=filesys_open(fn_copy);
    if (fd->file != NULL){
      struct thread *cur = thread_current();
      fd->fd=cur->fd_num++;
      ret=fd->fd;
      list_push_front(&cur->file_list,&fd->elem);
    }
    else{
      free (fd);
    }
    lock_release (&file_lock);
  }
  palloc_free_page(fn_copy);
  return ret;
}


static struct fds* getfile(int fd)
{
  struct list_elem *e;
  for(e=list_begin(&thread_current()->file_list);e!=list_end(&thread_current()->file_list);e=list_next(e)){
    struct fds* f;
    f=list_entry(e,struct fds,elem);
    if (f->fd == fd){
      return f;
    }
  }
  thread_exit ();
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

static int read(int fd,void *buffer, unsigned size)
{
  uint8_t *udst = buffer;
  struct fds *f=getfile(fd);
  int bytes_read = 0;

  while(size>0){
    size_t page_left=PGSIZE-pg_ofs(udst);
    size_t read_size=size < page_left?size:page_left;
    int32_t ret;
    if(fd != STDIN_FILENO){
      if(!page_lock(udst,true)){
        thread_exit ();
      }
      lock_acquire (&file_lock);
      ret=file_read(f->file,udst,read_size);
      lock_release(&file_lock);
      page_unlock(udst);
    }else{
      size_t i;
      for (i = 0; i<read_size; ++i){
        char c = input_getc ();
        if (!page_lock (udst, true)){
          thread_exit ();
        }
        udst[i] = c;
        page_unlock (udst);
      }
          bytes_read = read_size;
    }
    if(ret<0){
      if (bytes_read == 0){
        bytes_read = -1;
      }
      break;
    }
    bytes_read+=ret;
    if(ret != (int32_t)read_size){
      break;
    }
    udst += ret;
    size -= ret;
  }
  return bytes_read;
}

static int write (int fd, const void *buffer, unsigned size){
  uint8_t *usrc=buffer;
  struct fds* f = NULL;
  int bytes_written = 0;
  if (fd != STDOUT_FILENO){
    f=getfile(fd);
  }
  while (size > 0){
    size_t page_left=PGSIZE-pg_ofs(usrc);
    size_t write_size= size < page_left ? size : page_left;
    off_t ret;
    if(!page_lock (usrc, false)){
      thread_exit ();
    }
    lock_acquire (&file_lock);
    if (fd == STDOUT_FILENO){
      putbuf ((char *) usrc,write_size);
      ret=write_size;
    }else{
      ret=file_write (f->file, usrc, write_size);
    }
    lock_release (&file_lock);
    page_unlock (usrc);
    if(ret<0){
      if (bytes_written == 0){
        bytes_written = -1;
      }         
      break;
    }
    bytes_written+=ret;
    if(ret!=(int32_t)write_size){
      break;
    }
    usrc += ret;
    size -= ret;
  }
  return bytes_written;
}

static int seek (int fd, unsigned position){
  struct fds *f=getfile(fd);
  lock_acquire (&file_lock);
  if ((int32_t)position>= 0){
    file_seek(f->file,position);
  }
  lock_release(&file_lock);
  return 0;
}

static int tell(int fd)
{
  struct fds* f=getfile(fd);
  off_t ret;
  lock_acquire (&file_lock);
  ret = file_tell(f->file);
  lock_release (&file_lock);
  return ret;
}

static int close (int fd)
{
  struct fds *f=getfile(fd);
  lock_acquire(&file_lock);
  file_close(f->file);
  lock_release(&file_lock);
  list_remove(&f->elem);
  free(f);
  return 0;
}

static struct mapping *getmap(int id){
  struct list_elem *e;
  for (e=list_begin(&thread_current()->mapping); e != list_tail(&thread_current()->mapping) ; e=list_next(e))    
  {
    struct mapping *m=list_entry(e,struct mapping,elem);
    if (m->id==id){
      return m;
    }
  }
  thread_exit ();
}

static void unmap(struct mapping *m)
{
  list_remove(&m->elem);
  for(int i = 0; i < m->num;++i)
  {
    if (pagedir_is_dirty(thread_current()->pagedir,((const void *)((m->addr)+(PGSIZE * i)))))
    {
      lock_acquire (&file_lock);
      file_write_at(m->file,(const void *)(m->addr+(PGSIZE*i)),(PGSIZE*(m->num)),PGSIZE*i);
      lock_release (&file_lock);
    }
  }
  for(int i = 0; i < m->num; i++)
  {
    page_deallocate((void *)((m->addr)+(PGSIZE * i)));
  }
}
static int mmap (int fd, void *addr)
{
  struct fds *f=getfile(fd);
  struct mapping *m = malloc (sizeof(struct mapping));
  size_t offset;
  off_t length;

  if (m==NULL||addr==NULL||pg_ofs(addr)!=0){
    return -1;
  }
  m->id=thread_current ()->fd_num++;
  lock_acquire(&file_lock);
  m->file =file_reopen(f->file);
  lock_release(&file_lock);
  if (m->file == NULL){
    free(m);
    return -1;
  }
  m->addr=addr;
  m->num=0;
  list_push_front(&thread_current ()->mapping,&m->elem);
  offset = 0;
  lock_acquire(&file_lock);
  length=file_length(m->file);
  lock_release(&file_lock);
  while(length>0){
    struct page *p = page_alloc((uint8_t *) addr + offset,false);
    if (p == NULL)
    {
      unmap (m);
      return -1;
    }
    p->mmap = false;
    p->file=m->file;
    p->offset=offset;
    p->rw_bytes=length >= PGSIZE ? PGSIZE : length;
    offset+=p->rw_bytes;
    length-=p->rw_bytes;
    m->num++;
  }
  return m->id;
}

static int munmap (int mapping)
{
  struct mapping *map = getmap(mapping);
  unmap(map);
  return 0;
}

void exit2 (void)
{
  struct list_elem *e;
  for (e=list_begin(&thread_current()->file_list);e!=list_end(&thread_current()->file_list);e=list_next(e))
  {
    struct fds* fd=list_entry(e,struct fds,elem);
    lock_acquire (&file_lock);
    file_close(fd->file);
    lock_release(&file_lock);
    free(fd);
  }
  for(e=list_begin(&thread_current()->mapping);e!=list_end(&thread_current()->mapping);e=list_next(e))
  {
    struct mapping* m=list_entry(e,struct mapping,elem);
    unmap(m);
  }
}
