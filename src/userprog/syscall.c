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
static void copy_in (void *, const void *, size_t);
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


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  typedef int syscall_function (int, int, int);

  struct syscall
    {
      size_t arg_cnt;           /* Number of arguments. */
      syscall_function *func;   /* Implementation. */
    };

  /* Table of system calls. */
  static const struct syscall syscall_table[] =
    {
      {0, (syscall_function *)halt},
      {1, (syscall_function *)exit1},
      {1, (syscall_function *)exec},
      {1, (syscall_function *)wait},
      {2, (syscall_function *)create},
      {1, (syscall_function *)remove},
      {1, (syscall_function *)open},
      {1, (syscall_function *)filesize},
      {3, (syscall_function *)read},
      {3, (syscall_function *)write},
      {2, (syscall_function *)seek},
      {1, (syscall_function *)tell},
      {1, (syscall_function *)close},
      {2, (syscall_function *)mmap},
      {1, (syscall_function *)munmap},
    };

  const struct syscall *sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in (&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
    thread_exit ();
  sc = syscall_table + call_nr;

  /* Get the system call arguments. */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,
     and set the return value. */
  f->eax = sc->func (args[0], args[1], args[2]);
}

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

      if (!page_lock (usrc, false))
        thread_exit ();
      memcpy (dst, usrc, chunk_size);
      page_unlock (usrc);

      dst += chunk_size;
      usrc += chunk_size;
      size -= chunk_size;
    }
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us)
{
  char *ks;
  char *upage;
  size_t length;

  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();

  length = 0;
  for (;;)
    {
      upage = pg_round_down (us);
      if (!page_lock (upage, false))
        goto lock_error;

      for (; us < upage + PGSIZE; us++)
        {
          ks[length++] = *us;
          if (*us == '\0')
            {
              page_unlock (upage);
              return ks;
            }
          else if (length >= PGSIZE)
            goto too_long_error;
        }

      page_unlock (upage);
    }

 too_long_error:
  page_unlock (upage);
 lock_error:
  palloc_free_page (ks);
  thread_exit ();
}



static int
remove (const char *ufile)
{
  char *kfile = copy_in_string (ufile);
  bool ok;

  lock_acquire (&file_lock);
  ok = filesys_remove (kfile);
  lock_release (&file_lock);

  palloc_free_page (kfile);

  return ok;
}

struct file_descriptor
  {
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
  };

static int
open (const char *ufile)
{
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;

  fd = malloc (sizeof *fd);
  if (fd != NULL)
    {
      lock_acquire (&file_lock);
      fd->file = filesys_open (kfile);
      if (fd->file != NULL)
        {
          struct thread *cur = thread_current ();
          handle = fd->handle = cur->fd_num++;
          list_push_front (&cur->file_list, &fd->elem);
        }
      else
        free (fd);
      lock_release (&file_lock);
    }

  palloc_free_page (kfile);
  return handle;
}

static struct file_descriptor *
lookup_fd (int handle)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->file_list); e != list_end (&cur->file_list);
       e = list_next (e))
    {
      struct file_descriptor *fd;
      fd = list_entry (e, struct file_descriptor, elem);
      if (fd->handle == handle)
        return fd;
    }

  thread_exit ();
}

static int
filesize (int handle)
{
  struct file_descriptor *fd = lookup_fd (handle);
  int size;

  lock_acquire (&file_lock);
  size = file_length (fd->file);
  lock_release (&file_lock);

  return size;
}

static int
read (int handle, void *udst_, unsigned size)
{
  uint8_t *udst = udst_;
  struct file_descriptor *fd;
  int bytes_read = 0;

  fd = lookup_fd (handle);
  while (size > 0)
    {
      /* How much to read into this page? */
      size_t page_left = PGSIZE - pg_ofs (udst);
      size_t read_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Read from file into page. */
      if (handle != STDIN_FILENO)
        {
          if (!page_lock (udst, true))
            thread_exit ();
          lock_acquire (&file_lock);
          retval = file_read (fd->file, udst, read_amt);
          lock_release (&file_lock);
          page_unlock (udst);
        }
      else
        {
          size_t i;

          for (i = 0; i < read_amt; i++)
            {
              char c = input_getc ();
              if (!page_lock (udst, true))
                thread_exit ();
              udst[i] = c;
              page_unlock (udst);
            }
          bytes_read = read_amt;
        }

      /* Check success. */
      if (retval < 0)
        {
          if (bytes_read == 0)
            bytes_read = -1;
          break;
        }
      bytes_read += retval;
      if (retval != (off_t) read_amt)
        {
          /* Short read, so we're done. */
          break;
        }

      /* Advance. */
      udst += retval;
      size -= retval;
    }

  return bytes_read;
}

static int
write (int handle, void *usrc_, unsigned size)
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_fd (handle);

  while (size > 0)
    {
      /* How much bytes to write to this page? */
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Write from page into file. */
      if (!page_lock (usrc, false))
        thread_exit ();
      lock_acquire (&file_lock);
      if (handle == STDOUT_FILENO)
        {
          putbuf ((char *) usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);
      lock_release (&file_lock);
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

static int
seek (int handle, unsigned position)
{
  struct file_descriptor *fd = lookup_fd (handle);

  lock_acquire (&file_lock);
  if ((off_t) position >= 0)
    file_seek (fd->file, position);
  lock_release (&file_lock);

  return 0;
}

static int
tell (int handle)
{
  struct file_descriptor *fd = lookup_fd (handle);
  unsigned position;

  lock_acquire (&file_lock);
  position = file_tell (fd->file);
  lock_release (&file_lock);

  return position;
}

static int
close (int handle)
{
  struct file_descriptor *fd = lookup_fd (handle);
  lock_acquire (&file_lock);
  file_close (fd->file);
  lock_release (&file_lock);
  list_remove (&fd->elem);
  free (fd);
  return 0;
}

struct mapping
  {
    struct list_elem elem;
    int handle;
    struct file *file;      
    uint8_t *base;    
    size_t page_cnt;
  };


static struct mapping *
lookup_mapping (int handle)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->mapping); e != list_end (&cur->mapping);
       e = list_next (e))
    {
      struct mapping *m = list_entry (e, struct mapping, elem);
      if (m->handle == handle)
        return m;
    }

  thread_exit ();
}


static void
unmap (struct mapping *m)
{
  /* Remove this mapping from the list of mapping for this process. */
  list_remove(&m->elem);

  /* For each page in the memory mapped file... */
  for(int i = 0; i < m->page_cnt; i++)
  {
    /* ...determine whether or not the page is dirty (modified). If so, write that page back out to disk. */
    if (pagedir_is_dirty(thread_current()->pagedir, ((const void *) ((m->base) + (PGSIZE * i)))))
    {
      lock_acquire (&file_lock);
      file_write_at(m->file, (const void *) (m->base + (PGSIZE * i)), (PGSIZE*(m->page_cnt)), (PGSIZE * i));
      lock_release (&file_lock);
    }
  }

  /* Finally, deallocate all memory mapped pages (free up the process memory). */
  for(int i = 0; i < m->page_cnt; i++)
  {
    page_deallocate((void *) ((m->base) + (PGSIZE * i)));
  }
}

static int
mmap (int handle, void *addr)
{
  struct file_descriptor *fd = lookup_fd (handle);
  struct mapping *m = malloc (sizeof *m);
  size_t offset;
  off_t length;

  if (m == NULL || addr == NULL || pg_ofs (addr) != 0)
    return -1;

  m->handle = thread_current ()->fd_num++;
  lock_acquire (&file_lock);
  m->file = file_reopen (fd->file);
  lock_release (&file_lock);
  if (m->file == NULL)
    {
      free (m);
      return -1;
    }
  m->base = addr;
  m->page_cnt = 0;
  list_push_front (&thread_current ()->mapping, &m->elem);

  offset = 0;
  lock_acquire (&file_lock);
  length = file_length (m->file);
  lock_release (&file_lock);
  while (length > 0)
    {
      struct page *p = page_alloc ((uint8_t *) addr + offset, false);
      if (p == NULL)
        {
          unmap (m);
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

  return m->handle;
}

static int
munmap (int mapping)
{
  struct mapping *map = lookup_mapping(mapping);
  unmap(map);
  return 0;
}
void
exit2 (void)
{
  struct thread *cur = thread_current ();
  struct list_elem *e, *next;

  for (e = list_begin (&cur->file_list); e != list_end (&cur->file_list); e = next)
    {
      struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
      next = list_next (e);
      lock_acquire (&file_lock);
      file_close (fd->file);
      lock_release (&file_lock);
      free (fd);
    }

  for (e = list_begin (&cur->mapping); e != list_end (&cur->mapping);
       e = next)
    {
      struct mapping *m = list_entry (e, struct mapping, elem);
      next = list_next (e);
      unmap (m);
    }
}
