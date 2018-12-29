#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>
void syscall_init (void);

struct fds
{
    int fd;
    struct file *f;
    struct dir* dir;
    struct list_elem elem;
};
void exit1 (int status);
#endif /* userprog/syscall.h */
