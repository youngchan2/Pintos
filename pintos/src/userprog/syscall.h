#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include <list.h>
#include "threads/synch.h"

#define BUF_SIZE 200

typedef int pid_t;
struct lock filesys_lock;

void syscall_init(void);

void halt(void);
void exit(int status);
pid_t exec(const char *file);
int wait(pid_t);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int pipe(int *fds);
int mmap(int fd, void *addr);
void munmap(int mappid);

enum fd_type
{
    FD_REGULAR,
    FD_STDIN,
    FD_STDOUT,
    FD_STDERR,
    FD_PIPE_READ,
    FD_PIPE_WRITE
};

struct fd
{
    int fd;
    struct file *file;
    struct list_elem fd_elem;
    struct pipe *pipe;
    enum fd_type file_type;
};

struct pipe
{
    char buffer[BUF_SIZE];
    int fd_cnt;
    int num_readers;
    int num_writers;
    int fd_read;
    int fd_write;
    int read_pos;
    int write_pos;
    struct lock pipe_lock;
    struct semaphore empty_sema;
    struct semaphore full_sema;
};
#endif /* userprog/syscall.h */
