#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdlib.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "syscall.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct c_process_arguments{
    struct semaphore load_wait;
    char* fn_copy;
    struct cp_link* cp_l;
};

#endif /* userprog/process.h */
