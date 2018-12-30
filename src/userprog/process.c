#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmd_line, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char* name=malloc(strlen(file_name)+1);
  char *p;
  tid_t tid;
  struct exec_table exec;
  exec.file_name = file_name;
  sema_init (&exec.load,0);

  struct dir *wd = thread_current ()->wd;
  exec.wd = wd != NULL ? dir_reopen (wd) : dir_open_root ();
  if (exec.wd == NULL)
    return TID_ERROR;


  /* Create a new thread to execute FILE_NAME. */
  strlcpy (name,file_name,strlen(file_name)+1);
  strtok_r (name," ",&p);
  tid = thread_create (name, PRI_DEFAULT, start_process,&exec);
  if (tid != TID_ERROR)
  {
      sema_down(&exec.load);
      if (exec.success){
        list_push_back(&thread_current()->children,&exec.child_proc->elem);
      }else {
          tid = TID_ERROR;
        }
  }else{
    dir_close(exec.wd);
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *exec_table)
{
  struct intr_frame if_;
  bool success;

  thread_current ()->wd = exec->wd;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (exec->file_name, &if_.eip, &if_.esp);

  if(success){
    exec->child_proc=malloc(sizeof(struct child_proc));
    thread_current()->child_proc=exec->child_proc;
    if(exec->child_proc==NULL){
      success=false;
    }
  }
  if(success) 
  {
    lock_init(&exec->child_proc->lock);
    exec->child_proc->status=2;
    exec->child_proc->id=thread_current()->tid;
    sema_init (&exec->child_proc->exit,0);
  }
  exec->success = success;
  sema_up(&exec->load);
  if (!success) {
    thread_exit ();
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct list_elem *e;
  for (e = list_begin(&thread_current()->children); e != list_tail(&thread_current()->children); e=list_next(e))
  {
    struct child_proc* c=list_entry(e,struct child_proc,elem);
    if (c->id == child_tid) 
      {
        list_remove(e);
        sema_down(&c->exit);
        int ret = c->ret;
        lock_acquire(&c->lock);
        int temp=--c->status;
        lock_release(&c->lock);
        if (temp==0)
        {
          free(c);
        }
        return ret;
      }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  struct list_elem *e, *next;
  uint32_t *pd;

  printf ("%s: exit(%d)\n", cur->name, cur->exit_code);
  if (cur->child_proc != NULL) {
    struct child_proc *c = cur->child_proc;
    c->ret = cur->exitcode;
    sema_up (&c->exit);
    lock_acquire(&c->lock);
    int temp=--c->status;
    lock_release(&c->lock);
    if (temp==0)
    {
      free(c);
    }
  }
  for (e = list_begin(&thread_current()->children); e != list_tail(&thread_current()->children); e=next){
    struct child_proc *c = list_entry (e, struct child_proc, elem);
    next = list_remove (e);
    lock_acquire (&c->lock);
    int temp=--c->status;
    lock_release (&c->lock);
    if (temp==0)
    {
      free(c);
    }
  }

  struct hash* h=thread_current()->pages;
  if (h!=NULL)
  {
    hash_destroy(h,page_destructor);
  }
  
  file_close (cur->self);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (const char *cmd_line, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  char* name=malloc(strlen(file_name)+1);
  char *p;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  t->pages = malloc (sizeof *t->pages);
  if (t->pages == NULL)
    goto done;
  init_page(t->pages);

  strlcpy (name,file_name,strlen(file_name)+1);
  strtok_r (name," ",&p);
  /* Open executable file. */
  file=filesys_open(name);
  t->self=file;
  free(name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, (char*)file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  file_deny_write (file);

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      struct page *p = page_alloc (upage, !writable);
      if (p == NULL)
        return false;
      if (page_read_bytes > 0) 
        {
          p->file = file;
          p->offset = ofs;
          p->rw_bytes = page_read_bytes;
        }
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

static void * push (uint8_t *kpage, size_t *ofs, const void *buf, size_t size); 
static bool getargs(uint8_t* kpage, uint8_t* upage, const char* cmd_line, void** esp);
static void reverse (int argc, char **argv);

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void** esp,char* file_name)
{
  struct page *page=page_alloc(((uint8_t *)PHYS_BASE)-PGSIZE,false);
  if (page!=NULL) 
    {
      page->frame=frame_alloc(page);
      if (page->frame!=NULL)
      {
        bool ok;
        page->read_only = false;
        page->mmap = false;
        ok = getargs (page->frame->addr, page->addr, file_name, esp);
        frame_unlock (page->frame);
        return ok;
      }
    }
  return false;
}

static bool getargs(uint8_t* kpage, uint8_t* upage, const char* cmd_line, void** esp){
  size_t ofs = PGSIZE;
  char *const null = NULL;
  char *copy;
  char *karg,*p;
  int argc;
  char **argv;
  copy=push(kpage,&ofs,cmd_line,strlen(cmd_line)+1);
  if (copy==NULL){
    return false;
  }
  if (push(kpage,&ofs,&null,sizeof(null))==NULL){
    return false;
  }
  argc=0;
  for(karg=strtok_r(copy," ",&p);karg!=NULL;karg=strtok_r(NULL," ",&p))
  {
    void *uarg=upage+(karg-(char*)kpage);
    if(push(kpage,&ofs,&uarg,sizeof(uarg))==NULL){
      return false;
    }
    argc++;
  }
  argv=(char**)(upage+ofs);
  reverse(argc,(char**)(kpage + ofs));
  if(push(kpage,&ofs,&argv,sizeof(argv))==NULL || push(kpage,&ofs,&argc,sizeof(argc))==NULL|| push(kpage,&ofs,&null,sizeof(null))==NULL){
    return false;
  }
  *esp=upage+ofs;
  return true;
}

static void reverse (int argc, char **argv){
  while(argc>1){
    char *temp=argv[0];
    argv[0]=argv[argc-1];
    argv[argc-1]=temp;
    argc-=2;
    argv++;
  }
}

static void *push(uint8_t *kpage, size_t *ofs, const void *buf, size_t size){
  size_t padsize=ROUND_UP(size,sizeof(uint32_t));
  if(*ofs<padsize){
    return NULL;
  }
  *ofs-=padsize;
  memcpy(kpage+*ofs+padsize-size,buf,size);
  return kpage+*ofs+padsize-size;
}