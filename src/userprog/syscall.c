#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>


static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  if(!valid_inter_pointer(f->esp,1)) exit(-1);
  int SYSNUM = *(int *)(f->esp);
  switch (SYSNUM)
  {
  case SYS_HALT:;
    halt();
    break;
  case SYS_EXIT:;
    if (!valid_inter_pointer(f->esp, 1))
      return exit(-1);
    exit(*(int *)(f->esp + 4));
    break;
  case SYS_CREATE:;
    if (!valid_inter_pointer(f->esp, 2))
      return exit(-1);
    bool succeded = create(*(char **)(f->esp + 4), *(unsigned int *)(f->esp + 8));
    f->eax = succeded;
    break;
  case SYS_OPEN:;
    if (!valid_inter_pointer(f->esp, 1))
      return exit(-1);
    f->eax = open(*(char **)(f->esp + 4));
    break;
  case SYS_CLOSE:;
    if (!valid_inter_pointer(f->esp, 1))
      return exit(-1);
    close(*(int *)(f->esp + 4));
    break;
  case SYS_READ:;
    if (!valid_inter_pointer(f->esp, 3))
      return exit(-1);
    f->eax = read(*(int *)(f->esp + 4), *(void **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_WRITE:;
    if (!valid_inter_pointer(f->esp, 3))
      return exit(-1);
    f->eax = write(*(int *)(f->esp + 4), *(void **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_EXEC:;
    if (!valid_inter_pointer(f->esp, 1))
      return exit(-1);
    f->eax = exec(*(char **)(f->esp + 4));
    break;
  case SYS_WAIT:;
    if (!valid_inter_pointer(f->esp, 1))
      return exit(-1);
    f->eax = wait(*(pid_t *)(f->esp + 4));
    break;
  case SYS_SEEK:;
    if(!valid_inter_pointer(f->esp, 2))
      return exit(-1);
    seek(*(int *)(f->esp + 4), *(unsigned *)(f->esp + 8));
    break;
  case SYS_TELL:;
    if(!valid_inter_pointer(f->esp, 1))
      return exit(-1);
    f->eax = tell(*(int *)(f->esp + 4));
    break;
  
  default:;
    break;
  }
}

void halt(void)
{
  power_off();
}

bool create(const char *file, unsigned initial_size)
{
  if (!valid_string_pointer(file))
  {
     exit(-1);
  }
  if(file == NULL)  return -1;
  return filesys_create(file, initial_size);
}

int open(const char *file)
{
  if (!valid_string_pointer(file))
    exit(-1);
  struct file *openedFile = filesys_open(file);
  if (openedFile != NULL)
  {
    int index = 2;
    struct thread *currentThread = thread_current();
    while ((currentThread->fd_list[index]) != NULL)
    {
      index++;
    }
    currentThread->fd_list[index] = openedFile;
    return index;
  }
  else
  {
    return -1;
  }
}

void close(int fd)
{
  if(fd > 129 || fd < 0) exit(-1);
  /*if(thread_current()->fd_list[fd] == NULL){
   return;
  }*/
  file_close(thread_current()->fd_list[fd]);
  thread_current()->fd_list[fd] = NULL;
}

int read(int fd, void *buffer, unsigned size)
{
  if(!valid_string_pointer(buffer)) exit(-1);
  if(fd > 129 || fd < 0) exit(-1);
  /*if (fd == 0)
  {
    unsigned charCounter = 0;
    char sbuf[size];
    while (charCounter < size)
    {
      //sbuf[charCounter] = (char)input_getc();
      //charCounter++;
      *(uint8_t*)buffer = input_getc();
      charCounter++;
      buffer++;

    }
    //buffer = sbuf;
    return size;
  }
  if (thread_current()->fd_list[fd] == NULL)
  {
    return -1;
  }
  
  file_deny_write(thread_current()->fd_list[fd]);
  int bytes_read = file_read(thread_current()->fd_list[fd], buffer, size);
  file_allow_write(thread_current()->fd_list[fd]);
  return bytes_read;*/
  
}

int write(int fd, const void *buffer, unsigned size)
{
  if(!valid_string_pointer((char*)buffer)) {
    exit(-1);
  }
  else if(fd > 129 || fd < 0) 
  {
    exit(-1);
  }
  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }

  if (thread_current()->fd_list[fd] == NULL)
  {
    return -1;
  }

  return file_write(thread_current()->fd_list[fd], buffer, (off_t)size);
}

void exit(int status)
{
  thread_current()->cp_l->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  if (!valid_string_pointer(cmd_line))
  {
    return -1;
  }
  return process_execute(cmd_line);
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

void seek(int fd, unsigned position)
{
    file_seek(thread_current()->fd_list[fd], position);
}

unsigned tell(int fd)
{
  if(thread_current()->fd_list[fd] != NULL){
    return file_tell(thread_current()->fd_list[fd]);
  }
  else{
    return -1;
  }
}

int file_size(int fd)
{
  return (int)file_length(thread_current()->fd_list[fd]);
}

bool remove(const char * file_name)
{
  if(!valid_string_pointer(file_name)) exit(-1);
  return filesys_remove(file_name);
}

bool valid_inter_pointer(void *f, int num_args)
{
  if (f == NULL)
  {
    return false;
  }
  for (int i = 1; i <= num_args; i++)
  {
    if (!is_user_vaddr(f + (i * 4)) || pagedir_get_page(thread_current()->pagedir, f + (i * 4)) == NULL)
      return false;
  }
  return true;
}

bool valid_string_pointer(const char *sp)
{
  if (sp == NULL)
    return false;
  
  int i = 0;
  while (true)
  {
    if (!is_user_vaddr(&(sp[i])) || pagedir_get_page(thread_current()->pagedir, sp + i) == NULL)
      return false;
    else if (sp[i] == '\0')
      return true;
    i++;
  }
}