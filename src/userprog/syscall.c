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

void* is_valid_vaddr(const void* esp);
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
static struct fds * getfile (int fd);

void* is_valid_vaddr(const void* esp){
  if(esp==NULL || !is_user_vaddr(esp)){
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
  char* fn_copy=malloc(strlen(cmd_line)+1);
  strlcpy(fn_copy,cmd_line,strlen(cmd_line)+1);
  int ret=process_execute(fn_copy);
  free(fn_copy);
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

  if (fd==0)
  {
    for (unsigned i = 0; i < size; i++)
    {
      buffer[i]=input_getc();
    }
  }else{
    struct fds* fds=getfile(fd);
    if (fds==NULL)
    {
      ret = -1;
    }else{
      ret = file_read(fds->f,buffer,size);
    }
  }
  return ret;
}
 
int write (int fd,void *buffer, unsigned size){
  int ret;
  char* check=(char*)buffer;
  for (unsigned i = 0; i < size+1; ++i)
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
    if (fds==NULL)
    {
      ret= -1;
    }else{
      ret= file_write(fds->f,buffer,size);
    }
  }
  return ret;
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
    f->eax=chdir((const char *)*(esp+1));
  }else if (*esp==SYS_MKDIR)
  {
    is_valid_vaddr(esp+1);
    f->eax=mkdir((const char *)*(esp+1));
  }else if (*esp==SYS_READDIR)
  {
    is_valid_vaddr(esp+5);
    f->eax=readdir(*(esp+4),(char*)*(esp+5));
  }else if (*esp==SYS_ISDIR)
  {
    is_valid_vaddr(esp+1);
    f->eax=isdir(*(esp+1));
  }else if (*esp==SYS_INUMBER)
  {
    is_valid_vaddr(esp+1);
    f->eax=inumber(*(esp+1));
  }else{
    exit1(-1);
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
