#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "lib/user/syscall.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "devices/input.h"

#include "userprog/pagedir.h"
#include "userprog/exception.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/fsutil.h"
#include "threads/malloc.h"

#define WORD sizeof(uint32_t)

static void syscall_handler (struct intr_frame *);
void halt(void);
void exit (int status);
pid_t exec (const char *file);
int wait (pid_t pid);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
int fibonacci(int n);
int sum_of_four_int(int a, int b, int c, int d);
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = f->esp;
  is_user_vaddr(esp);

  /* top of stack is system call number */
  uint32_t syscall_number = *(uint32_t *)esp;

  switch(syscall_number){
    case SYS_HALT:{
      halt();
      break;
    }
    case SYS_EXIT:{
      if(!is_user_vaddr(esp + WORD)){
        exit(-1);
      }
      else{
        exit((int)*(uint32_t *)(esp+WORD));
      }
      break;
    }
    case SYS_EXEC:{
      if(!is_user_vaddr(esp+WORD)){
        exit(-1);
      }
      else{
        f->eax = exec((const char *)*(uint32_t *)(esp+WORD));
      }
      break;
    }
    case SYS_WAIT:{
      if(!is_user_vaddr(esp+WORD)){
        exit(-1);
      }
      else{
        f->eax = wait((pid_t) *(uint32_t *)(esp+WORD));
      }
      break;
    }
    case SYS_READ:{
      if(!(is_user_vaddr(esp+WORD) && is_user_vaddr(esp+2*WORD) && is_user_vaddr(esp+3*WORD))){
        exit(-1);
      }
      else{
        f->eax = read((int )*(uint32_t *)(esp+WORD), (void *)*(uint32_t *)(esp+2*WORD), (unsigned)*(uint32_t *)(esp+3*WORD));
      }
      break;
    }
    case SYS_WRITE:{
      if(!(is_user_vaddr(esp+WORD) && is_user_vaddr(esp+2*WORD) && is_user_vaddr(esp+3*WORD))){
        exit(-1);
      }
      else{
        f->eax = write((int )*(uint32_t *)(esp+WORD), (void *)*(uint32_t *)(esp+2*WORD), (unsigned)*(uint32_t *)(esp+3*WORD));
      }
      break;
    }
    /* Additional System Calls */
    case SYS_FIB:{
      if(!is_user_vaddr(esp+WORD)){
        exit(-1);
      }
      else{
        f->eax = fibonacci((int )*(uint32_t *)(esp+WORD));
      }
      break;
    }
    case SYS_SMF:{
      if(!(is_user_vaddr(esp+WORD) && is_user_vaddr(esp+2*WORD) && is_user_vaddr(esp+3*WORD) && is_user_vaddr(esp+4*WORD))){
        exit(-1);
      }
      else{
        f->eax = sum_of_four_int((int )*(uint32_t *)(esp+WORD), (int )*(uint32_t *)(esp+2*WORD), (int )*(uint32_t *)(esp+3*WORD), (int )*(uint32_t *)(esp+4*WORD));
      }
      break;
    }
  }
}
void
halt(void)
{
  shutdown_power_off();
}
void
exit (int status)
{
  struct thread *t = thread_current();
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

pid_t
exec (const char *file)
{
  pid_t ret;
  struct thread *parent = thread_current();

  ret = process_execute(file);

  if(ret != TID_ERROR){
    /* receive signal that child's load is finished. */
    sema_down(&parent->load_wait_signal);

    /* If load failed, */
    if(!parent->child_load_success){
      ret = TID_ERROR;
      /* This makes parent not wait this child. */
    }

   /* To reuse for other child */
    parent->child_load_success = false;
  }
  return ret;
}

int
wait (pid_t pid)
{
  int status;
  status = process_wait(pid);
  return status;
}
int
read (int fd, void *buffer, unsigned size)
{
  int i=0;

  uint8_t *buf = (uint8_t *)buffer;
  if(!fd){
    while(i < (int)size){
      buf[i] = input_getc();
      if(buf[i] == '\0'){
        break;
      }
      i++;
    }
    return i;
  }
  else{
    return -1;
  }
}
int
write (int fd, const void *buffer, unsigned size)
{

  if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size))
    exit (-1);

  if(fd == 1){
    putbuf(buffer,size);
    return size;
  }
  else{
    exit(-1);
  }
  return -1;
}
int
fibonacci(int n)
{ //   1 2 3 4 5 6 7  8  9  10 
  //   1 1 2 3 5 8 13 21 34 55
  int fibo_prev = 0;
  int fibo_cur = 1;
  int fibo_next;
  int i;

  if(n == 0){
    return 0;
  }
  else if(n == 1){
    return 1;
  }
  else if( n < 0 ){
    exit(-1);
  }

  for(i = 2; i <= n ; i++ ){
    fibo_next = fibo_prev + fibo_cur;
    fibo_prev = fibo_cur;
    fibo_cur = fibo_next;
  }
  return fibo_cur;
}
int
sum_of_four_int(int a, int b, int c, int d)
{
  return (a+b+c+d);
}