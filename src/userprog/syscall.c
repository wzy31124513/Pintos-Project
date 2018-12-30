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
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);
 
static void syscall_handler (struct intr_frame *);
static void argcpy(void* cp,const void* addr1,size_t size);
static char * strcpy_to_kernel (const char *us);
static struct fds * getfile (int fd);

struct fds{
  int handle;
  struct file *file;
  struct dir *dir;   
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
  for (e=list_begin(&cur->file_list);e!=list_end(&cur->file_list);e=next)
  {
    struct fds *fd=list_entry(e,struct fds,elem);
    next=list_next(e);
    file_close(fd->file);
    dir_close(fd->dir);
    free (fd);
  }
  dir_close(cur->wd);
  thread_exit();
}
 
int exec(const char* cmd_line){
  int ret;
  ret=process_execute(cmd_line);
  return ret;
}
 
int wait(int pid){
  return process_wait(pid);
}
 
bool create(const char *file, unsigned initial_size){
  bool ret;
  ret=filesys_create(file,initial_size,0);
  return ret;
}
 
bool remove(const char* file){
  bool ret;
  ret=filesys_remove(file);
  return ret;
}


int open(const char* file){
  struct fds *fd;
  int handle = -1;
  fd = calloc (1, sizeof *fd);
  if (fd != NULL){
    struct inode *inode = filesys_open (file);
    if (inode != NULL){
      if (is_directory (inode)==0){
        fd->file = file_open (inode);
      }
      else{
        fd->dir = dir_open (inode);
      }
      if (fd->file != NULL || fd->dir != NULL)
      {
        struct thread *cur = thread_current ();
        handle = fd->handle = cur->fd_num++;
        list_push_front (&cur->file_list, &fd->elem);
      }else {
        free (fd);
        inode_close (inode);
      }
    }
  }
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
      ret=file_read(f->file,b,read_size);
    }else{
      for (size_t i = 0; i < read_size; ++i)
      {
        char c=input_getc();
        b[i]=c;
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
    if (fd==1)
    {
      putbuf((char*)b,write_size);
      ret=write_size;
    }else{
      ret=file_write(f->file,b,write_size);
    }
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


bool chdir (const char *dir) {
  bool ret=false;
  struct dir* d=dir_open(filesys_open(dir));
  if (d!=NULL)
  {
    dir_close(thread_current()->wd);
    thread_current()->wd=d;
    ret=true;
  }
  return ret;
}

bool mkdir (const char *dir){
  bool ret = filesys_create (dir, 0, 1);
  return ret;
}

bool readdir (int fd, char *name){
  struct fds *f=getfile(fd);
  if (f->dir == NULL){
    exit1(-1);
  }
  bool ret = dir_readdir(f->dir, name);
  return ret;
}

bool isdir (int fd){
  struct fds *f = getfile(fd);
  return f->dir!=NULL;
}


int inumber (int fd)
{
  struct fds *f=getfile(fd);
  if (f->dir!=NULL)
  {
    struct inode *inode=dir_get_inode(f->dir);
    return inode_get_inumber(inode);
  }
  if (f->file!=NULL)
  {
    struct inode *inode=file_get_inode (f->file);
    return inode_get_inumber(inode);
  }
  exit1(-1);
  return 0;
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
  argcpy(&func,f->esp,sizeof(func));
  int args[3];
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
    memcpy(dst,addr,s);
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
    memcpy(udst, src, chunk_size);
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
    while(str<addr+PGSIZE){
      cp[length++]=*str;
      if (*str=='\0')
        {
          return cp;
        }
        else if (length>=PGSIZE){
          return NULL;
        }
      str++;
    }
  }
}

static struct fds * getfile (int fd){
  struct thread *cur=thread_current ();
  struct list_elem *e;
  for (e=list_begin(&cur->file_list);e!=list_end(&cur->file_list);e=list_next (e)){
    struct fds *f=list_entry(e,struct fds, elem);
    if (f->handle == fd){
      return f;
    }
  }
  exit1(-1);
  return NULL;
}
