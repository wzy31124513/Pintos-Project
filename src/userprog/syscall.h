#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

static int fd_num;
struct list file_list;
#endif /* userprog/syscall.h */
