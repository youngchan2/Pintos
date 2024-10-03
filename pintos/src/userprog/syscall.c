#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <sys/types.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame *);
static struct lock filesys_lock;

static void check_valid_ptr(const void *ptr)
{
  if (!(is_user_vaddr(ptr) && ptr > (void *)0x08048000))
  {
    exit(-1);
  }
  if (!pagedir_get_page(thread_current()->pagedir, ptr))
  {
    exit(-1);
  }
}

void syscall_init(void)
{
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // printf ("system call!\n");
  uint32_t *p = f->esp;
  check_valid_ptr((void *)p);
  uint32_t syscall_num = *p;

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
  lock_acquire(&filesys_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return result;
}

bool remove(const char *file)
{
  lock_acquire(&filesys_lock);
  bool result = filesys_remove(file);
  lock_release(&filesys_lock);

  return result;
}

int open(const char *file)
{
  lock_acquire(&filesys_lock);
  struct file *open_file = filesys_open(file);

  // 2024-10-02 이어서
  struct thread *cur_thread = thread_current();
  int fd;
  if (open_file != NULL)
  {
    for (fd = 2; fd < FDT_SIZE; fd++)
    {
      if (cur_thread->fdt[fd] == NULL)
        break;
    }
    if (fd == FDT_SIZE)
    {
      fd = -1;
    }
    else
    {
      cur_thread->fdt[fd] = open_file;
    }
  }
  else
  {
    fd = -1;
  }
  lock_release(&filesys_lock);

  return fd;
}

int filesize(int fd)
{
  struct thread *cur_thread = thread_current();
  struct file *open_file = cur_thread->fdt[fd];

  if (fd < 2 || fd > FDT_SIZE || open_file == NULL)
  {
    exit(-1);
  }
  lock_acquire(&filesys_lock);
  int l = file_length(open_file);
  lock_release(&filesys_lock);

  return l;
}

int read(int fd, void *buffer, unsigned size)
{
  if (fd < 0 || fd >= FDT_SIZE)
  {
    exit(-1);
  }

  struct thread *cur_thread = thread_current();
  lock_acquire(&filesys_lock);
  if (fd == 0)
  {
    // 2024-10-04 이어서
  }
  else if (fd > 2)
  {
    struct file *open_file = cur_thread->fdt(fd);
    int actual_read = 0;
    if (open_file == NULL)
    {
      lock_release(&filesys_lock);
      exit(-1);
    }
    actual_read = file_read(open_file, buffer, size);
    lock_release(&filesys_lock);

    return actual_read;
  }
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