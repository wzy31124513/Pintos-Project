#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>
void syscall_init (void);

struct fds
{
    int fd;
    struct file *f;
    struct list_elem elem;
};
void exit (int status);
#endif /* userprog/syscall.h */
