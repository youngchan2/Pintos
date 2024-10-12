#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include <stdbool.h>

// enum fd_type
// {
//     FD_REGULAR,
//     FD_STDIN,
//     FD_STDOUT,
//     FD_STDERR,
//     FD_PIPE_READ,
//     FD_PIPE_WRITE
// };

/* An open file. */
struct file
{
    struct inode *inode; /* File's inode. */
    off_t pos;           /* Current position. */
    bool deny_write;     /* Has file_deny_write() been called? */
    // struct pipe *pipe;
    // enum fd_type file_type;
};

struct inode;

/* Opening and closing files. */
struct file *file_open(struct inode *);
struct file *file_reopen(struct file *);
void file_close(struct file *);
struct inode *file_get_inode(struct file *);

/* Reading and writing. */
off_t file_read(struct file *, void *, off_t);
off_t file_read_at(struct file *, void *, off_t size, off_t start);
off_t file_write(struct file *, const void *, off_t);
off_t file_write_at(struct file *, const void *, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write(struct file *);
void file_allow_write(struct file *);

/* File position. */
void file_seek(struct file *, off_t);
off_t file_tell(struct file *);
off_t file_length(struct file *);

#endif /* filesys/file.h */
