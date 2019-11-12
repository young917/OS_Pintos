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

static struct lock syscall_lock;
void halt(void);
void exit (int status);
pid_t exec (const char *file);
int wait (pid_t pid);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
int fibonacci(int n);
int sum_of_four_int(int a, int b, int c, int d);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
struct file *fd2fp(int fd);
bool is_vaddr(const void *addr);
static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
	lock_init(&syscall_lock);
	
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
      			if(!is_vaddr(esp + WORD)){
					exit(-1);
				}
				else{
					exit((int)*(uint32_t *)(esp+WORD));
      			}
      			break;
    		}
			case SYS_EXEC:{
    		      if(!is_vaddr(esp+WORD)){
    		        exit(-1);
    		      }
    		      else{
    		        f->eax = exec((const char *)*(uint32_t *)(esp+WORD));
    		      }
    		      break;
			}
			case SYS_WAIT:{
				if(!is_vaddr(esp+WORD)){
					exit(-1);
				}
				else{
					f->eax = wait((pid_t) *(uint32_t *)(esp+WORD));
				}
				break;
			}
			case SYS_READ:{
				if(!(is_vaddr(esp+WORD) && is_vaddr(esp+2*WORD) && is_vaddr(esp+3*WORD))){
					exit(-1);
				}
				else{
					f->eax = read((int )*(uint32_t *)(esp+WORD), (void *)*(uint32_t *)(esp+2*WORD), (unsigned)*(uint32_t *)(esp+3*WORD));
				}
				break;
			}
			case SYS_WRITE:{
				if(!(is_vaddr(esp+WORD) && is_vaddr(esp+2*WORD) && is_vaddr(esp+3*WORD))){
					exit(-1);
				}
				else{
					f->eax = write((int )*(uint32_t *)(esp+WORD), (void *)*(uint32_t *)(esp+2*WORD), (unsigned)*(uint32_t *)(esp+3*WORD));
				}
				break;
			}
			/* Additional System Calls */
			case SYS_FIB:{
				if(!is_vaddr(esp+WORD)){
					exit(-1);
				}
				else{
					f->eax = fibonacci((int )*(uint32_t *)(esp+WORD));
				}
				break;
			}
			case SYS_SMF:{
				if(!(is_vaddr(esp+WORD) && is_vaddr(esp+2*WORD) && is_vaddr(esp+3*WORD) && is_vaddr(esp+4*WORD))){
					exit(-1);
				}
				else{
					f->eax = sum_of_four_int((int )*(uint32_t *)(esp+WORD), (int )*(uint32_t *)(esp+2*WORD), (int )*(uint32_t *)(esp+3*WORD), (int )*(uint32_t *)(esp+4*WORD));
				}
				break;
			}
			
			/* project 2 */
			case SYS_CREATE:{
				if(!(is_vaddr(esp+WORD) && is_vaddr(esp+2*WORD))){
					exit(-1);
				}
				else{
					f->eax = create((const char *)*(uint32_t *)(esp+WORD), (unsigned)*(uint32_t *)(esp+2*WORD));
					}
				break;
			}
			case SYS_REMOVE:{
				if(!is_vaddr(esp+WORD)){
					exit(-1);
				}
				else{
					f->eax = remove((const char *)*(uint32_t *)(esp+WORD));
				}
				break;
			}
			case SYS_OPEN:{
				if(!is_vaddr(esp+WORD)){
					exit(-1);
				}
				else{
					f->eax = open((const char *)*(uint32_t *)(esp+WORD));
				}
				break;
			}
			case SYS_FILESIZE:{
				if(!is_vaddr(esp+WORD)){
					exit(-1);
				}
				else{
					f->eax = filesize((int)*(uint32_t *)(esp+WORD));
					}
				break;
			}
			case SYS_SEEK:{
				if(!(is_vaddr(esp+WORD) && is_vaddr(esp+2*WORD))){
					exit(-1);
				}
				else{
					seek((int)*(uint32_t *)(esp+WORD), (unsigned)*(uint32_t *)(esp+2*WORD));
				}
				break;
			}
			case SYS_TELL:{
				if(!is_vaddr(esp+WORD)){
					exit(-1);
				}
				else{
					f->eax = tell((int)*(uint32_t *)(esp+WORD));
				}
				break;
			}
			case SYS_CLOSE:{
				if(!is_vaddr(esp+WORD)){
					exit(-1);
				}
				else{
					close((int)*(uint32_t *)(esp+WORD));
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
  struct file *fp;
  int readn = -1;

  if (!is_vaddr(buffer) || !is_vaddr(buffer + size)){
	  exit (-1);
  }
 
  if(fd == 0){
    while(i < (int)size){
      buf[i] = input_getc();
      if(buf[i] == '\0'){
        break;
      }
      i++;
    }
    return i;
  }
  else if(fd > 1){
	  fp = fd2fp(fd);
	  if(fp == NULL){
		  return -1;
	  }
	  else{
		  lock_acquire(&syscall_lock);
		  readn = file_read(fp, buffer, size);
		  lock_release(&syscall_lock);
		  return readn;
	  }
  }
  return -1;
}

int
write (int fd, const void *buffer, unsigned size)
{
	int writen;
	struct file *fp;

	if (!is_vaddr(buffer) || !is_vaddr(buffer + size)){
		exit (-1);
	}
	
	if(fd == 1){
    	putbuf(buffer,size);
    	return size;
  	}
  	else if( fd > 1){
		fp = fd2fp(fd);
    	lock_acquire(&syscall_lock);
		writen = file_write(fp, buffer, size);
		lock_release(&syscall_lock);
		return writen;
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

/* project2 */
bool
create(const char *file, unsigned initial_size)
{
	bool success = false;

	if(!is_vaddr(file)){
		exit(-1);
	}
	else{
		success = filesys_create(file, initial_size);
	}
	return success;
}
bool
remove(const char *file)
{
	bool success = false;
	if(!is_vaddr(file)){
		exit(-1);
	}
	else{
		lock_acquire(&syscall_lock);
		success = filesys_remove(file);
		lock_release(&syscall_lock);
	}
	return success;
}

int
open(const char *file)
{
	struct thread *t = thread_current();
	struct file_info *fi;
	struct file *fp;

	if(!is_vaddr(file)){
		exit(-1);
	}
	else{
		fp = filesys_open(file);
		if(fp == NULL){
			return -1;
		}
		fi = (struct file_info *)malloc(sizeof(struct file_info));
		if(fi == NULL){
			exit(-1);
		}
		else{
			fi->fp = fp;
			fi->fd = t->fdn++;
			list_push_back(&t->files, &fi->file_elem);
			return fi->fd;
		}
	}
	return -1;
}

int
filesize(int fd)
{
	struct file *fp;
	fp = fd2fp(fd);
	return file_length(fp);
}

void
seek(int fd, unsigned position)
{
	struct file *fp;

	fp = fd2fp(fd);
	if(fp == NULL){
		return -1;
	}
	else{
		file_seek(fp, position);
	}
}

unsigned
tell(int fd)
{
	struct file *fp;
	unsigned pos;

	fp = fd2fp(fd);
	if(fp == NULL){
		return -1;
	}
	else{
		pos = file_tell(fp);
		return pos;
	}
}

void
close(int fd)
{
	struct thread *t = thread_current();
	struct list_elem *e;
	struct file_info *fentry = NULL;

	for( e = list_begin(&t->files) ; e != list_end(&t->files) ; e = list_next(e) ){
		fentry = list_entry( e, struct file_info, file_elem);
		if(fentry->fd == fd){
			break;
		}
	}
	if(fentry != NULL){
		file_close(fentry->fp);
		list_remove(e);
		free(fentry);
	}
}

struct file*
fd2fp(int fd)
{
	struct thread *t = thread_current();
	struct list_elem *e;
	struct file_info *fentry = NULL;

	for( e = list_begin(&t->files) ; e != list_end(&t->files) ; e = list_next(e) ){
		fentry = list_entry( e, struct file_info, file_elem);
		if(fentry->fd == fd){
			break;
		}
	}
	if(fentry == NULL){
		return NULL;
	}
	else{
		return fentry->fp;
	}
}
bool
is_vaddr(const void *addr){
	if(addr && is_user_vaddr(addr) && pagedir_get_page(thread_current()->pagedir, addr)){
		return true;
	}
	else{
		return false;
	}
}
