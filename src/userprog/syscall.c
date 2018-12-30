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
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
 
static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
static int sys_mmap (int handle, void *addr);
static int sys_munmap (int mapping);
static int sys_chdir (const char *udir);
static int sys_mkdir (const char *udir);
static int sys_readdir (int handle, char *name);
static int sys_isdir (int handle);
static int sys_inumber (int handle);
 
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);
 
 
/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  while (size > 0) 
    {
      size_t chunk_size = PGSIZE - pg_ofs (usrc);
      if (chunk_size > size)
        chunk_size = size;

      memcpy (dst, usrc, chunk_size);

      dst += chunk_size;
      usrc += chunk_size;
      size -= chunk_size;
    }
}
 
/* Copies SIZE bytes from kernel address SRC to user address
   UDST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_out (void *udst_, const void *src_, size_t size) 
{
  uint8_t *udst = udst_;
  const uint8_t *src = src_;

  while (size > 0) 
    {
      size_t chunk_size = PGSIZE - pg_ofs (udst);
      if (chunk_size > size)
        chunk_size = size;
      
      memcpy (udst, src, chunk_size);


      udst += chunk_size;
      src += chunk_size;
      size -= chunk_size;
    }
}

 
/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 
/* Exit system call. */
static int
sys_exit (int exit_code) 
{
  thread_current ()->exit_code = exit_code;
  thread_exit ();
  NOT_REACHED ();
}
 
/* Exec system call. */
static int
sys_exec (const char *ufile) 
{
  tid_t tid;
 
  tid = process_execute (ufile);
 
 
  return tid;
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
  return process_wait (child);
}
 
/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size) 
{

  bool ok = filesys_create (ufile, initial_size, FILE_INODE);

 
  return ok;
}
 
/* Remove system call. */
static int
sys_remove (const char *ufile) 
{

  bool ok = filesys_remove (ufile);

 
  return ok;
}

/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
  {
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    struct dir *dir;            /* Directory. */
    int handle;                 /* File handle. */
  };
 
/* Open system call. */
static int
sys_open (const char *ufile) 
{
  struct file_descriptor *fd;
  int handle = -1;
 
  fd = calloc (1, sizeof *fd);
  if (fd != NULL)
    {
      struct inode *inode = filesys_open (ufile);
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
  
  return handle;
}
 

static struct file_descriptor *
lookup_fd (int handle) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
   
  for (e = list_begin (&cur->fds); e != list_end (&cur->fds);
       e = list_next (e))
    {
      struct file_descriptor *fd;
      fd = list_entry (e, struct file_descriptor, elem);
      if (fd->handle == handle)
        return fd;
    }
 
  thread_exit ();
}
 

static struct file_descriptor *
lookup_file_fd (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd->file == NULL)
    thread_exit ();
  return fd;
}
 

static struct file_descriptor *
lookup_dir_fd (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd->dir == NULL)
    thread_exit ();
  return fd;
}

/* Filesize system call. */
static int
sys_filesize (int handle) 
{
  struct file_descriptor *fd = lookup_file_fd (handle);
  int size;
 
  size = file_length (fd->file);
 
  return size;
}
 
/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size) 
{
  uint8_t *udst = udst_;
  struct file_descriptor *fd;
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



      /* If it was a short read we're done. */
      if (retval != (off_t) read_amt)
        break;

      /* Advance. */
      udst += retval;
      size -= retval;
    }
   
  return bytes_read;
}
 
/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
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

      /* Do the write. */
      if (handle == STDOUT_FILENO)
        {
          putbuf ((char *) usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);


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
 
/* Seek system call. */
static int
sys_seek (int handle, unsigned position) 
{
  if ((off_t) position >= 0)
    file_seek (lookup_file_fd (handle)->file, position);
  return 0;
}
 
/* Tell system call. */
static int
sys_tell (int handle) 
{
  return file_tell (lookup_file_fd (handle)->file);
}
 
/* Close system call. */
static int
sys_close (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  file_close (fd->file);
  dir_close (fd->dir);
  list_remove (&fd->elem);
  free (fd);
  return 0;
}



/* Chdir system call. */
static int
sys_chdir (const char *udir) 
{
  bool ok = false;

  // ADD CODE HERE
  ok = filesys_chdir(udir);


  return ok;
}

static int
sys_mkdir (const char *udir)
{

  bool ok = filesys_create (udir, 0, DIR_INODE);

 
  return ok;
}

static int
sys_readdir (int handle, char *uname)
{
  struct file_descriptor *fd = lookup_dir_fd (handle);

  bool ok = dir_readdir (fd->dir, uname);

  return ok;
}

static int
sys_isdir (int handle)
{
  struct file_descriptor *fd = lookup_fd (handle);
  return fd->dir != NULL;
}

/* Inumber system call. */
static int
sys_inumber (int handle)
{
  // ADD AND MODIFY CODE HERE - call dir_get_inode() for directories
  if(sys_isdir(handle))
  {
    struct file_descriptor *dir_descriptor = lookup_dir_fd(handle);
    struct inode *inode = dir_get_inode(dir_descriptor->dir);
    return inode_get_inumber(inode);
  }

  struct file_descriptor *fd = lookup_fd (handle);
  struct inode *inode = file_get_inode (fd->file);
  return inode_get_inumber (inode);
}
 
/* On thread exit, close all open files and unmap all mappings. */
void
syscall_exit (void) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e, *next;
   
  for (e = list_begin (&cur->fds); e != list_end (&cur->fds); e = next)
    {
      struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
      next = list_next (e);
      file_close (fd->file);
      dir_close (fd->dir);
      free (fd);
    }


  dir_close (cur->wd);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  unsigned func;
  int args[3];
  copy_in(&func,f->esp,sizeof(func));
  memset(args,0,sizeof(args));
  if (func==SYS_HALT)
  {
    sys_halt();
  }else if (func==SYS_EXIT)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    sys_exit(args[0]);
  }else if (func==SYS_EXEC)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_exec((const char *)args[0]);
  }else if (func==SYS_WAIT)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_wait(args[0]);
  }else if (func==SYS_CREATE)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=sys_create((const char *)args[0],(unsigned)args[1]);
  }else if (func==SYS_REMOVE)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_remove((const char *)args[0]);
  }else if (func==SYS_OPEN){
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_open((const char *)args[0]);
  }
  else if (func==SYS_FILESIZE)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_filesize(args[0]);
  }else if (func==SYS_READ)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args)*3);
    f->eax=sys_read(args[0],(void*)args[1],args[2]);
  }else if (func==SYS_WRITE)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args)*3);
    f->eax=sys_write(args[0],(void*)args[1],args[2]);
  }else if (func==SYS_SEEK)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    sys_seek(args[0],args[1]);
  }else if (func==SYS_TELL)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_tell(args[0]);
  }else if (func==SYS_CLOSE)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    sys_close(args[0]);
  }else if (func==SYS_CHDIR)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_chdir(args[0]);
  }else if (func==SYS_MKDIR)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_mkdir((const char *)args[0]);
  }else if (func==SYS_READDIR)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args)*2);
    f->eax=sys_readdir(args[0],args[1]);
  }else if (func==SYS_ISDIR)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
   f->eax= sys_isdir(args[0]);
  }else if (func==SYS_INUMBER)
  {
    copy_in(args,(uint32_t*)f->esp+1,sizeof(*args));
    f->eax=sys_inumber(args[0]);
  }else{
    sys_exit(-1);
  }
}
