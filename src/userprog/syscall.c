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
static void copy_in (void *, const void *, size_t);
static char * copy_in_string (const char *us);
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
  char* fn_copy=copy_in_string(cmd_line);
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
  char* fn_copy=copy_in_string(file);
  lock_acquire(&file_lock);
  ret=filesys_create(fn_copy,initial_size);
  lock_release(&file_lock);
  palloc_free_page (fn_copy);
  return ret;
}

static int remove(const char* file)
{
  char* fn_copy=copy_in_string(file);
  bool ret;
  lock_acquire(&file_lock);
  ret=filesys_remove(fn_copy);
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

static int open(const char* file)
{
  char* fn_copy=copy_in_string(file);
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


static int read (int fd, char *buffer, unsigned size)
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


static int write (int fd, const void *buffer, unsigned size){
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

static struct mapping *
lookup_mapping (int handle)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->mapping); e != list_end (&cur->mapping);
       e = list_next (e))
    {
      struct mapping *m = list_entry (e, struct mapping, elem);
      if (m->id == id)
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
  for(int i = 0; i < m->num; i++)
  {
    /* ...determine whether or not the page is dirty (modified). If so, write that page back out to disk. */
    if (pagedir_is_dirty(thread_current()->pagedir, ((const void *) ((m->addr) + (PGSIZE * i)))))
    {
      lock_acquire (&file_lock);
      file_write_at(m->file, (const void *) (m->addr + (PGSIZE * i)), (PGSIZE*(m->num)), (PGSIZE * i));
      lock_release (&file_lock);
    }
  }

  /* Finally, deallocate all memory mapped pages (free up the process memory). */
  for(int i = 0; i < m->page_cnt; i++)
  {
    page_deallocate((void *) ((m->addr) + (PGSIZE * i)));
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

  m->id = thread_current ()->fd_num++;
  lock_acquire (&file_lock);
  m->file = file_reopen (fd->file);
  lock_release (&file_lock);
  if (m->file == NULL)
    {
      free (m);
      return -1;
    }
  m->addr = addr;
  m->num = 0;
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
      m->num++;
    }

  return m->id;
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


static char * copy_in_string (const char *us)
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
