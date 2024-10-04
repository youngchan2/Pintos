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

static void allocate_argument(int *argv, void *esp, int num)
{
  void *tmp = esp;
  for (int i = 0; i < num; i++)
  {
    tmp += 4;
    check_valid_ptr(tmp);
    argv[i] = *(int *)tmp;
  }
  return;
}

static void check_valid_ptr(void *ptr)
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
  int argv[3];

  switch (syscall_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    allocate_argument(argv, p, 1);
    exit((int)argv[0]);
    break;
  case SYS_EXEC:
    allocate_argument(argv, p, 1);
    (f->eax) = exec((const char *)argv[0]);
    break;
  case SYS_WAIT:
    allocate_argument(argv, p, 1);
    (f->eax) = wait((pid_t)argv[0]);
    break;
  case SYS_CREATE:
    allocate_argument(argv, p, 2);
    (f->eax) = create((const char *)argv[0], (unsigned)argv[1]);
    break;
  case SYS_REMOVE:
    allocate_argument(argv, p, 1);
    (f->eax) = remove((const char *)argv[0]);
    break;
  case SYS_OPEN:
    allocate_argument(argv, p, 1);
    (f->eax) = open((const char *)argv[0]);
    break;
  case SYS_FILESIZE:
    allocate_argument(argv, p, 1);
    (f->eax) = filesize((int)argv[0]);
    break;
  case SYS_READ:
    allocate_argument(argv, p, 3);
    (f->eax) = read((int)argv[0], (void *)argv[1], (unsigned)argv[2]);
    break;
  case SYS_WRITE:
    allocate_argument(argv, p, 3);
    (f->eax) = write((int)argv[0], (const void *)argv[1], (unsigned)argv[2]);
    break;
  case SYS_SEEK:
    allocate_argument(argv, p, 2);
    seek((int)argv[0], (unsigned)argv[1]);
    break;
  case SYS_TELL:
    allocate_argument(argv, p, 1);
    (f->eax) = tell((int)argv[0]);
    break;
  case SYS_CLOSE:
    allocate_argument(argv, p, 1);
    close((int)argv[0]);
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
  t->exit_status = status;
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait(pid_t pid)
{
  return process_wait((tid_t)pid);
}

bool create(const char *file, unsigned initial_size)
{
  if (file == NULL)
  {
    exit(-1);
  }

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
  cur_thread->next_fd++;
  lock_release(&filesys_lock);

  return fd;
}

int filesize(int fd)
{
  struct thread *cur_thread = thread_current();
  struct file *open_file = cur_thread->fdt[fd];
  int l;
  if (fd < 2 || fd > FDT_SIZE || open_file == NULL)
  {
    exit(-1);
  }
  lock_acquire(&filesys_lock);
  l = file_length(open_file);
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
  int actual_read;
  lock_acquire(&filesys_lock);
  if (fd == 0)
  {
    // 2024-10-04 이어서
    actual_read = 0;
    while (actual_read < size)
    {
      char c = input_getc();
      ((char *)buffer)[actual_read++] = c;
      if (c == '\0')
        break;
    }
    lock_release(&filesys_lock);
    return actual_read;
  }
  else if (fd > 2)
  {
    struct file *open_file = cur_thread->fdt[fd];
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
  if (fd < 0 || fd >= FDT_SIZE)
  {
    exit(-1);
  }

  struct file *open_file;
  struct thread *cur_thread = thread_current();
  int actual_write = size;
  lock_acquire(&filesys_lock);
  if (fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return actual_write;
  }
  else if (fd > 2)
  {
    open_file = cur_thread->fdt[fd];

    if (open_file == NULL)
    {
      lock_release(&filesys_lock);
      exit(-1);
    }
    actual_write = file_write(open_file, buffer, size);
    lock_release(&filesys_lock);
    return actual_write;
  }
}

void seek(int fd, unsigned position)
{
  if (fd < 3 || fd >= FDT_SIZE)
  {
    exit(-1);
  }
  struct thread *cur_thread = thread_current();
  struct file *open_file = cur_thread->fdt[fd];
  if (open_file == NULL)
  {
    exit(-1);
  }
  lock_acquire(&filesys_lock);
  file_seek(open_file, position);
  lock_release(&filesys_lock);
}

unsigned tell(int fd)
{
  if (fd < 3 || fd >= FDT_SIZE)
  {
    exit(-1);
  }
  struct thread *cur_thread = thread_current();
  struct file *open_file = cur_thread->fdt[fd];
  if (open_file == NULL)
  {
    exit(-1);
  }

  lock_acquire(&filesys_lock);
  unsigned next_pos = (unsigned)file_tell(open_file);
  lock_release(&filesys_lock);

  return next_pos;
}

void close(int fd)
{
  if (fd < 3 || fd >= FDT_SIZE)
  {
    exit(-1);
  }
  struct thread *cur_thread = thread_current();
  lock_acquire(&filesys_lock);
  file_close(cur_thread->fdt[fd]);
  cur_thread->fdt[fd] = NULL;
  lock_release(&filesys_lock);

  return;
}
