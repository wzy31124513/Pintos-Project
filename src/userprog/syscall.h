#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct fds{
    int fd;
    struct file *file;
    struct dir *dir;
    struct list_elem elem;
};


void syscall_init (void);
void syscall_exit (void);
void exit1(int status);
#endif /* userprog/syscall.h */
