#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void syscall_exit (void);
static int exit1(int status);
#endif /* userprog/syscall.h */
