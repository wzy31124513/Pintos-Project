#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>
void syscall_init (void);
static void syscall_handler (struct intr_frame *);

struct fds* getfile(int fd);
void* is_valid_vaddr(const void* esp);
void halt (void);
void exit (int status);
int exec (const char *cmd_line);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, char *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

struct fds
{
    int fd;
    struct file *f;
    struct list_elem elem;
};

#endif /* userprog/syscall.h */
