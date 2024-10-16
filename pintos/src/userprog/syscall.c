#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
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
#include <string.h>
#include "threads/malloc.h"

static void syscall_handler(struct intr_frame *);

static void check_valid_ptr(void *ptr)
{
  if (!(is_user_vaddr(ptr) && ptr > (void *)0x08048000))
  {
    exit(-1);
  }
}

static void allocate_argument(int *argv, void *esp, int num)
{
  void *tmp = esp;
  int i;

  for (i = 0; i < num; i++)
  {
    tmp += 4;
    check_valid_ptr(tmp);
    argv[i] = *(int *)tmp;
  }
  return;
}

void syscall_init(void)
{
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
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
  case SYS_PIPE:
    allocate_argument(argv, p, 1);
    (f->eax) = pipe((int *)argv[0]);
    break;
  }
}

void halt()
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *cur_thread = thread_current();
  printf("%s: exit(%d)\n", cur_thread->name, status);
  cur_thread->exit_status = status;

  struct list_elem *e;
  for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
  {
    struct fd *fdelem = list_entry(e, struct fd, fd_elem);
    if (fdelem->pipe == NULL)
    {
      if (fdelem->file != NULL)
      {
        cur_thread->fd_list[fdelem->fd] = 0;
        file_close(fdelem->file);
        list_remove(&fdelem->fd_elem);
        // free(fdelem);
        // close(fdelem->fd);
      }
    }
  }
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  pid_t tid = process_execute(cmd_line);
  return tid;
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
  if (file == NULL)
  {
    exit(-1);
  }
  check_valid_ptr((void *)file);
  int re_fd;
  lock_acquire(&filesys_lock);
  struct thread *cur_thread = thread_current();
  struct file *open_file = filesys_open(file);
  if (open_file == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }
  struct fd *fd = (struct fd *)malloc(sizeof(struct fd));

  int i;
  for (i = 3; i < FDT_SIZE; i++)
  {
    if (cur_thread->fd_list[i] == 0)
    {
      fd->fd = i;
      cur_thread->fd_list[i] = 1;
      break;
    }
  }

  if (i == FDT_SIZE)
  {
    free(fd);
    re_fd = -1;
  }
  else
  {
    re_fd = fd->fd;
    fd->file = open_file;
    fd->pipe = NULL;
    if (strcmp(thread_current()->name, file) == 0)
    {
      file_deny_write(open_file);
    }
    list_push_back(&cur_thread->fdt, &fd->fd_elem);
    cur_thread->next_fd = (cur_thread->next_fd + 1) % FDT_SIZE;
  }

  lock_release(&filesys_lock);

  return re_fd;
}

int filesize(int fd)
{
  struct thread *cur_thread = thread_current();
  struct list_elem *e;

  lock_acquire(&filesys_lock);
  int l = 0;
  for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
  {
    struct fd *fdelem = list_entry(e, struct fd, fd_elem);
    if (fdelem->fd == fd)
    {
      if (fd < 2 || fd > FDT_SIZE || fdelem->file == NULL)
      {
        exit(-1);
      }
      if (fdelem->pipe == NULL)
      {
        l = file_length(fdelem->file);
      }
      break;
    }
  }
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
  unsigned actual_read = 0;
  check_valid_ptr(buffer);
  lock_acquire(&filesys_lock);

  bool pipe = false;
  struct list_elem *e;

  for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
  {
    struct fd *fdelem = list_entry(e, struct fd, fd_elem);
    if (fdelem->fd == fd)
    {
      if (fdelem->file_type == FD_PIPE_READ)
      {
        pipe = true;
        break;
      }
      else
      {
        break;
      }
    }
  }

  if (fd == 0 && pipe == false)
  {
    actual_read = 0;
    while (actual_read < size)
    {
      char c = input_getc();
      ((char *)buffer)[actual_read++] = c;
      if (c == '\0')
        break;
    }
  }
  else if (fd == 1)
  {
    lock_release(&filesys_lock);
    return -1;
  }
  else
  {
    struct list_elem *e;
    for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
    {
      struct fd *fdelem = list_entry(e, struct fd, fd_elem);
      if (fdelem->fd == fd)
      {
        if (fdelem->file == NULL)
        {
          lock_release(&filesys_lock);
          exit(-1);
        }
        if (fdelem->pipe == NULL)
        {
          actual_read = file_read(fdelem->file, buffer, size);
          break;
        }
        else // pipe
        {
          if (fdelem->file_type == FD_PIPE_WRITE)
          {
            lock_release(&filesys_lock);
            return -1;
          }
          lock_acquire(&fdelem->pipe->pipe_lock);
          // while (fdelem->pipe->read_pos == fdelem->pipe->write_pos)
          // { // wait
          //   lock_release(&fdelem->pipe->pipe_lock);
          //   // thread_yield();
          //   // printf("---------read---------\n");
          //   // print_all_pids();
          //   // printf("-----------------------\n");
          //   // print_wait_pids();
          //   // thread_unblock(cur_thread->parent);
          //   printf("parent status %d sema %d\n", cur_thread->parent->status, cur_thread->parent->load_sema.value);
          //   print_wait_pids();
          // sema_up(&cur_thread->parent->load_sema);
          //   printf("block block\n");
          //   thread_yield();
          //   printf("status %d \n", cur_thread->status);
          //   // sema_down(&cur_thread->load_sema);
          //   sema_down(&fdelem->pipe->empty_sema);
          //   lock_acquire(&fdelem->pipe->pipe_lock);
          // }
          // printf("read sema %d\n", cur_thread->load_sema);
          // sema_up(&cur_thread->parent->load_sema);
          // sema_down(&cur_thread->load_sema);
          // if (fdelem->pipe->read_pos == fdelem->pipe->write_pos)
          // {
          //   lock_release(&fdelem->pipe->pipe_lock);
          //   thread_yield();
          //   printf("---------read---------\n");
          //   print_all_pids();
          //   printf("-----------------------\n");
          //   lock_acquire(&fdelem->pipe->pipe_lock);
          // }
          // lock_release(&fdelem->pipe->pipe_lock);
          // printf("---------read---------\n");
          // print_all_pids();
          // printf("-----------------------\n");
          // lock_acquire(&fdelem->pipe->pipe_lock);
          actual_read = 0;
          while (fdelem->pipe->read_pos != fdelem->pipe->write_pos && actual_read < size)
          {
            ((char *)buffer)[actual_read++] = fdelem->pipe->buffer[fdelem->pipe->read_pos];
            fdelem->pipe->read_pos = (fdelem->pipe->read_pos + 1) % BUF_SIZE;
          }
          lock_release(&fdelem->pipe->pipe_lock);
          sema_up(&fdelem->pipe->full_sema);
          break;
        }
      }
    }
  }
  lock_release(&filesys_lock);

  return (int)actual_read;
}

int write(int fd, const void *buffer, unsigned size)
{
  if (fd < 0 || fd >= FDT_SIZE)
  {
    exit(-1);
  }
  if (fd == 0)
  {
    return -1;
  }
  int actual_write = 0;
  lock_acquire(&filesys_lock);
  if (fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return actual_write;
  }

  struct thread *cur_thread = thread_current();
  struct list_elem *e;

  for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
  {
    struct fd *fdelem = list_entry(e, struct fd, fd_elem);
    if (fdelem->fd == fd)
    {
      if (fdelem->file == NULL)
      {
        lock_release(&filesys_lock);
        exit(-1);
      }
      if (fdelem->pipe == NULL)
      {
        actual_write = file_write(fdelem->file, buffer, size);
        lock_release(&filesys_lock);
        return actual_write;
      }
      else
      {
        if (fdelem->file_type == FD_PIPE_READ)
        {
          lock_release(&filesys_lock);
          return -1;
        }
        // if (fdelem->pipe->num_readers == 0)
        // {
        //   lock_release(&filesys_lock);
        //   return -1;
        // }

        // if (fdelem->pipe->fd_read == fd)
        // {
        //   lock_release(&filesys_lock);
        //   return -1;
        // }
        // if (fdelem->pipe->fd_cnt != 2)
        // {
        //   lock_release(&filesys_lock);
        //   return -1;
        // }
        lock_acquire(&fdelem->pipe->pipe_lock);

        // while ((fdelem->pipe->write_pos + 1) % BUF_SIZE == fdelem->pipe->read_pos)
        // { // wait
        //   lock_release(&filesys_lock);
        //   // thread_yield();
        //   sema_down(&fdelem->pipe->full_sema);
        //   lock_acquire(&filesys_lock);
        //   // if(fd->pipe->fd_cnt!=2){
        //   //   lock_release(&filesys_lock);
        //   //   return -1;
        //   // }
        // }

        // sema_up(&cur_thread->load_sema);
        actual_write = 0;
        while ((unsigned)actual_write < size)
        {
          // while (fdelem->pipe->write_pos == fdelem->pipe->read_pos)
          // { // wait
          //   lock_release(&filesys_lock);
          //   thread_yield();
          //   lock_acquire(&filesys_lock);
          // }
          // if (fdelem->pipe->fd_write)
          fdelem->pipe->buffer[fdelem->pipe->write_pos] = ((char *)buffer)[actual_write++];
          fdelem->pipe->write_pos = (fdelem->pipe->write_pos + 1) % BUF_SIZE;
        }
        lock_release(&fdelem->pipe->pipe_lock);
        // sema_up(&fdelem->pipe->empty_sema);
        break;
      }
    }
  }
  lock_release(&filesys_lock);
  return actual_write;
}

void seek(int fd, unsigned position)
{
  if (fd < 3 || fd >= FDT_SIZE)
  {
    exit(-1);
  }
  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
  {
    struct fd *fdelem = list_entry(e, struct fd, fd_elem);
    if (fdelem->fd == fd)
    {
      if (fdelem->file == NULL)
      {
        exit(-1);
      }
      lock_acquire(&filesys_lock);
      file_seek(fdelem->file, position);
      lock_release(&filesys_lock);
      break;
    }
  }
}

unsigned tell(int fd)
{
  if (fd < 3 || fd >= FDT_SIZE)
  {
    exit(-1);
  }
  struct thread *cur_thread = thread_current();
  struct list_elem *e;
  unsigned next_pos = 0;
  for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
  {
    struct fd *fdelem = list_entry(e, struct fd, fd_elem);
    if (fdelem->fd == fd)
    {
      if (fdelem->file == NULL)
      {
        exit(-1);
      }
      lock_acquire(&filesys_lock);
      next_pos = (unsigned)file_tell(fdelem->file);
      break;
    }
  }
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
  struct list_elem *e;

  for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e))
  {
    struct fd *fdelem = list_entry(e, struct fd, fd_elem);
    if (fdelem->fd == fd)
    {
      if (fdelem->file == NULL)
      {
        exit(-1);
      }
      else
      {
        lock_acquire(&filesys_lock);
        list_remove(e);

        if (fdelem->pipe == NULL)
        {
          cur_thread->fd_list[fd] = 0;
          file_close(fdelem->file);
          free(fdelem);
          lock_release(&filesys_lock);
          break;
        }
        else
        {
          if (fdelem->file_type == FD_PIPE_WRITE)
          {
            fdelem->pipe->num_writers--;
            fdelem->pipe = NULL;

            if (fdelem->pipe->num_readers == 0)
            {
              free(fdelem->pipe);
            }
            free(fdelem);
            lock_release(&filesys_lock);
            break;
          }
          if (fdelem->file_type == FD_PIPE_READ)
          {
            fdelem->pipe->num_readers--;
            fdelem->pipe = NULL;

            if (fdelem->pipe->num_writers == 0)
            {
              free(fdelem->pipe);
            }
            free(fdelem);
            lock_release(&filesys_lock);
            break;
          }

          // if (fdelem->file_type == FD_PIPE_WRITE)
          // {
          //   fdelem->pipe->num_writers--;
          //   fdelem->pipe = NULL;
          //   break;
          // }
          // if (fdelem->file_type == FD_PIPE_READ)
          // {
          //   {
          //     fdelem->pipe->num_readers--;
          //     fdelem->pipe = NULL;
          //     break;
          //   }
          //   if (fdelem->pipe->fd_read == fd)
          //   {
          //     for (i = list_begin(&cur_thread->fdt); i != list_end(&cur_thread->fdt); i = list_next(i))
          //     {
          //       struct fd *j = list_entry(i, struct fd, fd_elem);
          //       if (j->fd == fdelem->pipe->fd_write)
          //       {
          //         file_close(j->file);
          //         free(fdelem->pipe);
          //         free(j);
          //         break;
          //         // j->pipe->num_readers--;
          //         // break;
          //       }
          //     }
          //   }
          //   if (fdelem->pipe->fd_write == fd)
          //   {
          //     for (i = list_begin(&cur_thread->fdt); i != list_end(&cur_thread->fdt); i = list_next(i))
          //     {
          //       struct fd *j = list_entry(i, struct fd, fd_elem);
          //       if (j->fd == fdelem->pipe->fd_read)
          //       {
          //         file_close(j->file);
          //         free(fdelem->pipe);
          //         free(j);
          //         break;
          //         // j->pipe->num_writers--;
          //         // break;
          //       }
          //     }
          //   }
          // }
          // ****
        }
        file_close(fdelem->file);
        free(fdelem);
        lock_release(&filesys_lock);
        break;
      }
    }
  }
  return;
}

int pipe(int *fds)
{
  struct fd *fd1 = (struct fd *)malloc(sizeof(struct fd));
  struct fd *fd2 = (struct fd *)malloc(sizeof(struct fd));

  struct thread *cur_thread = thread_current();

  struct pipe *pipe_connect = (struct pipe *)malloc(sizeof(struct pipe));
  pipe_connect->read_pos = 0;
  pipe_connect->write_pos = 0;
  pipe_connect->fd_cnt = 2;
  pipe_connect->num_readers = 1;
  pipe_connect->num_writers = 1;
  lock_init(&pipe_connect->pipe_lock);
  sema_init(&pipe_connect->empty_sema, 0);
  sema_init(&pipe_connect->full_sema, 0);
  fd1->file = (struct file *)malloc(sizeof(struct file));
  fd1->fd = cur_thread->next_fd;
  fd1->file_type = FD_PIPE_READ;
  cur_thread->next_fd++;
  fd1->pipe = pipe_connect;

  fd2->file = (struct file *)malloc(sizeof(struct file));
  fd2->fd = cur_thread->next_fd;
  fd2->file_type = FD_PIPE_WRITE;
  cur_thread->next_fd++;
  fd2->pipe = pipe_connect;

  fds[0] = fd1->fd;
  fds[1] = fd2->fd;

  pipe_connect->fd_read = fds[0];
  pipe_connect->fd_write = fds[1];

  list_push_back(&cur_thread->fdt, &fd1->fd_elem);
  list_push_back(&cur_thread->fdt, &fd2->fd_elem);

  return 0;
}