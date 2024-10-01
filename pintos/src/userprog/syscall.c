#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <sys/types.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // printf ("system call!\n");
  uint32_t syscall_num = f->eax;

  switch (syscall_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    exit();
    break;
  case SYS_EXEC:
    exec();
    break;
  case SYS_WAIT:
    wait();
    break;
  case SYS_CREATE:
    create();
    break;
  case SYS_REMOVE:
    remove();
    break;
  case SYS_OPEN:
    open();
    break;
  case SYS_FILESIZE:
    filesize();
    break;
  case SYS_READ:
    read();
    break;
  case SYS_WRITE:
    write();
    break;
  case SYS_SEEK:
    seek();
    break;
  case SYS_TELL:
    tell();
    break;
  case SYS_CLOSE:
    close();
    break;
  }
  thread_exit();
}

void halt()
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", t->name, status);

  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  pid_t pid;
  pid = process_execute(cmd_line);
  return pid;
}

int wait(pid_t pid)
{
  return process_wait((tid_t)pid);
}

bool create(const char *file, unsigned initial_size)
{
}

bool remove(const char *file)
{
}

int open(const char *file)
{
}

int filesize(int fd)
{
}

int read(int fd, void *buffer, unsigned size)
{
}

int write(int fd, const void *buffer, unsigned size)
{
}

void seek(int fd, unsigned position)
{
}

unsigned tell(int fd)
{
}

void close(int fd)
{
}