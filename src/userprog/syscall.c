#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "filesys/directory.h"
 
void halt (void);
int exec (const char *cmd_line);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd,  void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int mmap (int fd, void *addr);
void munmap (int mapping);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);
 
static void syscall_handler (struct intr_frame *);
static void argcpy(void* cp,const void* addr1,size_t size);
static char * strcpy_to_kernel (const char *us);
static void copy_out (void *udst_, const void *src_, size_t size);
static struct fds * getfile (int fd);
static struct mapping * getmap (int handle);

struct fds{
  int handle;
  struct file *file;
  struct dir *dir;   
  struct list_elem elem;
};

struct mapping{
  int id;
  struct file *file;
  uint8_t *addr;
  size_t num;
  struct list_elem elem;
};

void halt(void){
  shutdown_power_off ();
}
 
void exit1(int status){
  struct thread* cur=thread_current();
  cur->exit_code=status;
  struct list_elem* e;
  struct list_elem* next;
  for (e=list_begin(&cur->fds);e!=list_end(&cur->fds);e=next)
  {
    struct fds *fd=list_entry(e,struct fds,elem);
    next=list_next(e);
    file_close(fd->file);
    dir_close(fd->dir);
    free (fd);
  }
  for (e =list_begin(&thread_current()->mapping);e!=list_end(&thread_current()->mapping);e=next)
  {
    next=list_next(e);
    struct mapping *m=list_entry(e,struct mapping,elem);
    munmap(m->id);
  }
  dir_close(cur->wd);
  thread_exit();
}
 
int exec(const char* cmd_line){
  int ret;
  char* fn_copy=strcpy_to_kernel(cmd_line);
  ret=process_execute(fn_copy);
  palloc_free_page (fn_copy);
  return ret;
}
 
int wait(int pid){
  return process_wait(pid);
}
 
bool create(const char *file, unsigned initial_size){
  bool ret;
  char* fn_copy=strcpy_to_kernel(file);
  ret=filesys_create(fn_copy,initial_size,0);
  palloc_free_page (fn_copy);
  return ret;
}
 
bool remove(const char* file){
  char* fn_copy=strcpy_to_kernel(file);
  bool ret;
  ret=filesys_remove(fn_copy);
  palloc_free_page (fn_copy);
  return ret;
}


int open(const char* file){
  char *kfile = strcpy_to_kernel(file);
  struct fds *fd;
  int handle = -1;
  fd = calloc (1, sizeof *fd);
  if (fd != NULL){
    struct inode *inode = filesys_open (kfile);
    if (inode != NULL){
      if (inode_get_type (inode) == FILE_INODE){
        fd->file = file_open (inode);
      }
      else{
        fd->dir = dir_open (inode);
      }
      if (fd->file != NULL || fd->dir != NULL)
      {
        struct thread *cur = thread_current ();
        handle = fd->handle = cur->next_handle++;
        list_push_front (&cur->fds, &fd->elem);
      }else {
        free (fd);
        inode_close (inode);
      }
    }
  }
  palloc_free_page (kfile);
  return handle;
}

int filesize(int fd){
  struct fds* f=getfile(fd);
  if (f->file==NULL)
  {
    exit1(-1);
  }
  int ret;
  ret=file_length(f->file);
  return ret;
}

int read (int fd, void *buffer, unsigned size){
  int read=0;
  struct fds* f=getfile(fd);
  if (f->file==NULL)
  {
    exit1(-1);
  }
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
        exit1(-1);
      }
      ret=file_read(f->file,b,read_size);
      page_unlock(b);
    }else{
      for (size_t i = 0; i < read_size; ++i)
      {
        char c=input_getc();
        if (!page_lock(b,true))
        {
          exit1(-1);
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
 
int write (int fd,void *buffer, unsigned size){
  uint8_t* b=(uint8_t*)buffer;
  struct fds* f;
  int write=0;
  if (fd!=1)
  {
    f=getfile(fd);
    if (f->file==NULL)
    {
      exit1(-1);
    }
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
      exit1(-1);   
    }
    if (fd==1)
    {
      putbuf((char*)b,write_size);
      ret=write_size;
    }else{
      ret=file_write(f->file,b,write_size);
    }
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
 
void seek (int fd, unsigned position) {
  struct fds* fds=getfile(fd);
  if (fds->file==NULL)
  {
    exit1(-1);
  }
  file_seek(fds->file, position);
}
 
unsigned tell (int fd){
  struct fds* fds=getfile(fd);
  if (fds->file==NULL)
  {
    exit1(-1);
  }
  return file_tell(fds->file);
}
 
void close (int fd) {
  struct fds *f=getfile(fd);
  file_close(f->file);
  dir_close(f->dir);
  list_remove(&f->elem);
  free (f);
}

int mmap (int fd, void *addr){
  struct fds *f=getfile(fd);
  if (f->file==NULL)
  {
    exit1(-1);
  }
  struct mapping *m= malloc (sizeof(struct mapping));
  size_t offset;
  off_t length;
  if (m == NULL|| addr == NULL || pg_ofs (addr) != 0){
    return -1;
  }
  thread_current()->next_handle++;
  m->id=thread_current()->next_handle;
  m->file = file_reopen(f->file);
  if (m->file == NULL) {
    free (m);
    return -1;
  }
  m->addr=addr;
  m->num=0;
  list_push_front(&thread_current()->mappings, &m->elem);
  offset=0;
  length=file_length (m->file);
  while (length > 0){
    struct page *p=page_alloc((uint8_t *)addr+offset,false);
    if (p == NULL){
      munmap (m->id);
      return -1;
    }
    p->mmap = false;
    p->file = m->file;
    p->offset = offset;
    p->rw_bytes = length >= PGSIZE ? PGSIZE : length;
    offset += p->rw_bytes;
    length -= p->rw_bytes;
    m->num++;
  }
  return m->id;
}

void munmap (int mapping){
  struct mapping *m=getmap (mapping);
  list_remove (&m->elem);
  for(int i=0;i<(int)m->num;i++)
  {
    if(pagedir_is_dirty(thread_current()->pagedir,((const void *)(m->addr+PGSIZE * i))))
    {
      file_write_at(m->file,(const void *)(m->addr+PGSIZE * i),PGSIZE*(m->num),PGSIZE*i);
    }
  }
  for(int i=0;i<(int)m->num;i++)
  {
    page_deallocate((void *)(m->addr+PGSIZE * i));
  }
  free (m);
}

bool chdir (const char *dir) {
  char *cp = strcpy_to_kernel(dir);
  bool ret=filesys_chdir(cp);
  palloc_free_page(cp);
  return ret;
}

bool mkdir (const char *dir){
  char *cp = strcpy_to_kernel(dir);
  bool ret = filesys_create (cp, 0, 1);
  palloc_free_page (cp);
  return ret;
}

bool readdir (int fd, char *name){
  struct fds *f=getfile(fd);
  if (f->dir == NULL){
    exit1(-1);
  }
  char cp[15];
  bool ret = dir_readdir(f->dir, cp);
  if (ret){
    copy_out (name,cp,strlen(cp)+1);
  }
  return ret;
}

bool isdir (int fd){
  struct fds *f = getfile(fd);
  return f->dir!=NULL;
}


int inumber (int fd)
{
  if(isdir(fd))
  {
    struct fds *f=getfile(fd);
    if (f->dir==NULL){
      exit1(-1);
    }
    struct inode *inode=dir_get_inode(f->dir);
    return inode_get_inumber(inode);
  }
  struct fds *f=getfile(fd);
  if (f->file==NULL)
  {
    exit1(-1);
  }
  struct inode *inode=file_get_inode (f->file);
  return inode_get_inumber(inode);
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  unsigned func;
  int args[3];
  argcpy(&func,f->esp,sizeof(func));

  memset(args,0,sizeof(args));
  if (func==SYS_HALT)
  {
    halt();
  }else if (func==SYS_EXIT)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    exit1(args[0]);
  }else if (func==SYS_EXEC)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=exec((const char *)args[0]);
  }else if (func==SYS_WAIT)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=wait(args[0]);
  }else if (func==SYS_CREATE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=create((const char *)args[0],(unsigned)args[1]);
  }else if (func==SYS_REMOVE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=remove((const char *)args[0]);
  }else if (func==SYS_OPEN){
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=open((const char *)args[0]);
  }
  else if (func==SYS_FILESIZE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=filesize(args[0]);
  }else if (func==SYS_READ)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*3);
    f->eax=read(args[0],(void*)args[1],args[2]);
  }else if (func==SYS_WRITE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*3);
    f->eax=write(args[0],(void*)args[1],args[2]);
  }else if (func==SYS_SEEK)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    seek(args[0],args[1]);
  }else if (func==SYS_TELL)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=tell(args[0]);
  }else if (func==SYS_CLOSE)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    close(args[0]);
  }else if (func==SYS_MMAP)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=mmap(args[0],(void*)args[1]);
  }else if (func==SYS_MUNMAP)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    munmap(args[0]);
  }else if (func==SYS_CHDIR)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=chdir((const char *)args[0]);
  }else if (func==SYS_MKDIR)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=mkdir((const char *)args[0]);
  }else if (func==SYS_READDIR)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=readdir(args[0],(char*)args[1]);
  }else if (func==SYS_ISDIR)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=isdir(args[0]);
  }else if (func==SYS_INUMBER)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=inumber(args[0]);
  }else{
    exit1(-1);
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
      exit1(-1);
    }
    memcpy(dst,addr,s);
    page_unlock(addr);
    dst+=s;
    addr+=s;
    size-=s;
  }
}
 
static void copy_out (void *udst_, const void *src_, size_t size) {
  uint8_t *udst = udst_;
  const uint8_t *src = src_;
  while (size > 0) {
    size_t chunk_size=PGSIZE-pg_ofs(udst);
    if (chunk_size>size){
      chunk_size = size;
    }
    if (!page_lock (udst, false)){
      exit1(-1);
    }
    memcpy(udst, src, chunk_size);
    page_unlock (udst);
    udst+=chunk_size;
    src+=chunk_size;
    size-=chunk_size;
  }
}
 
static char * strcpy_to_kernel (const char *str){
  char* cp;
  char* addr;
  size_t length;
  cp=palloc_get_page(0);
  if(cp==NULL){
    exit1(-1);
  }
  length=0;
  while(1){
    addr=pg_round_down (str);
    if(!page_lock(addr,false)){
      palloc_free_page (cp);
      exit1(-1);
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

static struct fds * getfile (int fd){
  struct thread *cur=thread_current ();
  struct list_elem *e;
  for (e=list_begin(&cur->fds);e!=list_end(&cur->fds);e=list_next (e)){
    struct fds *f=list_entry(e,struct fds, elem);
    if (f->handle == fd){
      return f;
    }
  }
  exit1(-1);
}


static struct mapping * getmap (int handle) {
  struct thread *cur = thread_current ();
  struct list_elem *e;
  for (e = list_begin (&cur->mappings); e != list_end (&cur->mappings);e=list_next(e)){
      struct mapping *m =list_entry(e,struct mapping, elem);
      if (m->id == handle){
        return m;
      }
    }
  exit1(-1);
}