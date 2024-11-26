#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define STDOUT_FILENO 1
#define STDIN_FILENO 0
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "process.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "list.h"
#include "threads/init.h"
#include "devices/input.h"

typedef int pid_t;

void syscall_init (void);

void halt(void);

bool create(const char *file, unsigned initial_size);

int open(const char *file);

void close(int fd);

int read(int fd, void *buffer, unsigned size);

int write (int fd, const void *buffer, unsigned size);

void exit(int status);

pid_t exec(const char *cmd_line);

int wait(pid_t pid);

void seek(int fd, unsigned position);

unsigned tell(int fd);

int file_size(int fd);

bool remove(const char * file_name);

bool valid_inter_pointer(void *f, int num_args);

bool valid_string_pointer(const char *f);

#endif /* userprog/syscall.h */
