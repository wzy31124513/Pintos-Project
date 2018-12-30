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
static struct fds * lookup_file_fd (int fd);
static struct fds * lookup_dir_fd (int fd);
static struct mapping * getmap (int handle);

struct fds
{
  int handle;
  struct file *file;
  struct dir *dir;   
  struct list_elem elem;
};

void halt(void){
  shutdown_power_off ();
}
 
void exit1(int status){
  thread_current ()->exit_code = status;
  thread_exit ();
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
  char* fn_copy=strcpy_to_kernel(file);
  struct fds* f=malloc(sizeof(struct fds));
  int fd=-1;
  if (f!=NULL)
  {
    struct inode *inode=filesys_open(fn_copy);
    if (inode != NULL){
      if (inode_get_type(inode)== 0){
        f->file=file_open(inode);
      }else{
        f->dir=dir_open(inode);
      }
      if (f->file!= NULL||f->dir!=NULL){
        thread_current()->next_handle++;
        fd=thread_current()->next_handle;
        f->handle=fd;
        list_push_front (&thread_current()->fds,&f->elem);
      }else{
        free (f);
        inode_close (inode);
      }
    }
  }
  palloc_free_page (fn_copy);
  return fd;
}

/*
int open(const char* file){
  char *kfile = strcpy_to_kernel (file);
  struct fds *fd;
  int handle = -1;
 
  fd = calloc (1, sizeof *fd);
  if (fd != NULL)
    {
      struct inode *inode = filesys_open (kfile);
      if (inode != NULL)
        {
          if (inode_get_type (inode) == FILE_INODE)
            fd->file = file_open (inode);
          else
            fd->dir = dir_open (inode);
          if (fd->file != NULL || fd->dir != NULL)
            {
              struct thread *cur = thread_current ();
              handle = fd->handle = cur->next_handle++;
              list_push_front (&cur->fds, &fd->elem);
            }
          else 
            {
              free (fd);
              inode_close (inode);
            }
        }
    }
  palloc_free_page (kfile);
  return handle;
}
*/


int filesize(int fd)
{
  struct fds* f=lookup_file_fd(fd);
  int ret;
  ret=file_length(f->file);
  return ret;
}

 
int read (int handle, void *udst_, unsigned size) 
{
  uint8_t *udst = udst_;
  struct fds *fd;
  int bytes_read = 0;

  /* Look up file descriptor. */
  if (handle != STDIN_FILENO)
    fd = lookup_file_fd (handle);

  while (size > 0) 
    {
      /* How much to read into this page? */
      size_t page_left = PGSIZE - pg_ofs (udst);
      size_t read_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Check that touching this page is okay. */
      if (!page_lock (udst, true)) 
        thread_exit ();

      /* Read from file into page. */
      if (handle != STDIN_FILENO) 
        {
          retval = file_read (fd->file, udst, read_amt);
          if (retval < 0)
            {
              if (bytes_read == 0)
                bytes_read = -1; 
              break;
            }
          bytes_read += retval; 
        }
      else 
        {
          size_t i;
          
          for (i = 0; i < read_amt; i++) 
            udst[i] = input_getc ();
          bytes_read = read_amt;
        }

      /* Release page. */
      page_unlock (udst);

      /* If it was a short read we're done. */
      if (retval != (off_t) read_amt)
        break;

      /* Advance. */
      udst += retval;
      size -= retval;
    }
   
  return bytes_read;
}
 
int write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct fds *fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_file_fd (handle);

  while (size > 0) 
    {
      /* How much bytes to write to this page? */
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Check that we can touch this user page. */
      if (!page_lock (usrc, false)) 
        thread_exit ();

      /* Do the write. */
      if (handle == STDOUT_FILENO)
        {
          putbuf ((char *) usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);

      /* Release user page. */
      page_unlock (usrc);

      /* Handle return value. */
      if (retval < 0) 
        {
          if (bytes_written == 0)
            bytes_written = -1;
          break;
        }
      bytes_written += retval;

      /* If it was a short write we're done. */
      if (retval != (off_t) write_amt)
        break;

      /* Advance. */
      usrc += retval;
      size -= retval;
    }
 
  return bytes_written;
}
 
void seek (int handle, unsigned position) 
{
  if ((off_t) position >= 0)
    file_seek (lookup_file_fd (handle)->file, position);
}
 
unsigned tell (int handle) 
{
  return file_tell (lookup_file_fd (handle)->file);
}
 

void close (int handle) 
{
  struct fds *fd = getfile (handle);
  file_close (fd->file);
  dir_close (fd->dir);
  list_remove (&fd->elem);
  free (fd);
}

struct mapping
  {
    struct list_elem elem;
    int id;
    struct file *file;
    uint8_t *base;
    size_t page_cnt;
  };


int mmap (int fd, void *addr)
{
  struct fds *f=lookup_file_fd (fd);
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
  m->base=addr;
  m->page_cnt=0;
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
    m->page_cnt++;
  }
  return m->id;
}

void munmap (int mapping){
  struct mapping *m=getmap (mapping);
  list_remove (&m->elem);
  for(int i=0;i<m->page_cnt;i++)
  {
    if(pagedir_is_dirty(thread_current()->pagedir,((const void *)(m->base+PGSIZE * i))))
    {
      file_write_at(m->file,(const void *)(m->base+PGSIZE * i),PGSIZE*(m->page_cnt),PGSIZE*i);
    }
  }
  for(int i=0;i<(int)m->page_cnt;i++)
  {
    page_deallocate((void *)(m->base+PGSIZE * i));
  }
  free (m);
}

bool chdir (const char *dir) {
  bool ok = false;
  char *kdir = strcpy_to_kernel(dir);
  ok = filesys_chdir(kdir);
  palloc_free_page(kdir);

  return ok;
}


bool mkdir (const char *udir){
  char *kdir = strcpy_to_kernel (udir);
  bool ok = filesys_create (kdir, 0, 1);
  palloc_free_page (kdir);
  return ok;
}

bool readdir (int handle, char *uname){
  struct fds *fd = lookup_dir_fd (handle);
  char name[NAME_MAX + 1];
  bool ok = dir_readdir (fd->dir, name);
  if (ok)
    copy_out (uname, name, strlen (name) + 1);
  return ok;
}

bool isdir (int handle)
{
  struct fds *fd = getfile (handle);
  return fd->dir != NULL;
}


int inumber (int handle)
{
  if(isdir(handle))
  {
    struct fds *dir_descriptor = lookup_dir_fd(handle);
    struct inode *inode = dir_get_inode(dir_descriptor->dir);
    return inode_get_inumber(inode);
  }
  struct fds *fd = lookup_file_fd (handle);
  struct inode *inode = file_get_inode (fd->file);
  return inode_get_inumber (inode);
}

void
syscall_exit (void) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e, *next;
   
  for (e = list_begin (&cur->fds); e != list_end (&cur->fds); e = next)
    {
      struct fds *fd = list_entry (e, struct fds, elem);
      next = list_next (e);
      file_close (fd->file);
      dir_close (fd->dir);
      free (fd);
    }
   
  for (e = list_begin (&cur->mappings); e != list_end (&cur->mappings);
       e = next)
    {
      struct mapping *m = list_entry (e, struct mapping, elem);
      next = list_next (e);
      munmap (m->id);
    }

  dir_close (cur->wd);
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
    f->eax=chdir(args[0]);
  }else if (func==SYS_MKDIR)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=mkdir((const char *)args[0]);
  }else if (func==SYS_READDIR)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=readdir(args[0],args[1]);
  }else if (func==SYS_ISDIR)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
   f->eax=isdir(args[0]);
  }else if (func==SYS_INUMBER)
  {
    argcpy(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=inumber(args[0]);
  }else{
    thread_exit();
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
 
static void copy_out (void *udst_, const void *src_, size_t size) {
  uint8_t *udst = udst_;
  const uint8_t *src = src_;
  while (size > 0) 
    {
      size_t chunk_size = PGSIZE - pg_ofs (udst);
      if (chunk_size > size)
        chunk_size = size;
      
      if (!page_lock (udst, false))
        thread_exit ();
      memcpy (udst, src, chunk_size);
      page_unlock (udst);

      udst += chunk_size;
      src += chunk_size;
      size -= chunk_size;
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
      thread_exit();
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
  thread_exit ();
}

static struct fds * lookup_file_fd (int fd) { 
  struct fds *f = getfile (fd);
  if (f->file == NULL){
    thread_exit ();
  }
  return f;
}

static struct fds * lookup_dir_fd (int fd) {
  struct fds *f = getfile (fd);
  if (f->dir == NULL){
    thread_exit ();
  }
  return f;
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
  thread_exit ();
}