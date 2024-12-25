#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/timer.h"

static void syscall_handler (struct intr_frame *);

void syscall_halt(struct intr_frame *f)
{
}
void syscall_exit(struct intr_frame *f)
{
  int exit_code = *(int *)(f->esp + 4);
  thread_current()->exit_code = exit_code;
  thread_exit();
}

void syscall_exec(struct intr_frame *f)
{
}

void syscall_wait(struct intr_frame *f)
{
  int pid = *(int *)(f->esp + 4);
  f->eax = process_wait(pid);
}

void syscall_create(struct intr_frame *f)
{
}
void syscall_remove(struct intr_frame *f)
{  
}
void syscall_open(struct intr_frame *f)
{
}
void syscall_filesize(struct intr_frame *f)
{
}
void syscall_read(struct intr_frame *f)
{
}
void syscall_write(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + 4);
  char *buf = *(char **)(f->esp + 8);
  int size = *(int *)(f->esp + 12);
  if (fd == 0) error_exit();

  if (fd == 1)
  {
    putbuf(buf, size);
    f->eax = size;
  }
}
void syscall_seek(struct intr_frame * f)
{
}
void syscall_tell(struct intr_frame * f)
{
}
void syscall_close(struct intr_frame *f)
{
}

int (*func[20])(struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  func[SYS_HALT] = syscall_halt;
  func[SYS_EXIT] = syscall_exit;
  func[SYS_EXEC] = syscall_exec;
  func[SYS_WAIT] = syscall_wait;
  func[SYS_CREATE] = syscall_create;
  func[SYS_REMOVE] = syscall_remove;
  func[SYS_OPEN] = syscall_open;
  func[SYS_FILESIZE] = syscall_filesize;
  func[SYS_READ] = syscall_read;
  func[SYS_WRITE] = syscall_write;
  func[SYS_SEEK] = syscall_seek;
  func[SYS_TELL] = syscall_tell;
  func[SYS_CLOSE] = syscall_close;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int number = *(int *)(f->esp);
  (func[number])(f);
}