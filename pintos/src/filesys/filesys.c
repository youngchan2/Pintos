#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format(void);

/*
  경로 이름 name을 /로 parsing해서 현재 dir에 cur_dir이 있는지 확인
  확인 후 inode로 dir open => dir or file
*/
static struct dir *parse(const char *name, char *last_name)
{
  if (thread_current()->dir == NULL || name == NULL || strlen(name) == 0)
    return NULL;

  struct dir *ret_dir;
  char *tmp, *cur_dir, *next_dir, *save;
  struct inode *inode;

  if (name[0] == '/')
  {
    ret_dir = dir_open_root();
  }
  else
  {
    ret_dir = dir_reopen(thread_current()->dir);
  }

  tmp = malloc(strlen(name) + 1);
  memset(tmp, 0, strlen(name) + 1);

  strlcpy(tmp, name, strlen(name) + 1);
  cur_dir = strtok_r(tmp, "/", &save);
  next_dir = strtok_r(NULL, "/", &save);

  if (cur_dir != NULL && next_dir == NULL)
  {
    /*create-long*/
    if (strlen(cur_dir) > NAME_MAX + 1)
    {
      dir_close(ret_dir);
      return NULL;
    }
  }

  while (cur_dir != NULL && next_dir != NULL)
  {
    if (strlen(cur_dir) > NAME_MAX + 1 || strlen(next_dir) > NAME_MAX + 1)
    {
      dir_close(ret_dir);
      return NULL;
    }
    if (dir_lookup(ret_dir, cur_dir, &inode))
    {
      dir_close(ret_dir);
      ret_dir = dir_open(inode);
    }
    else
    {
      dir_close(ret_dir);
      return NULL;
    }

    strlcpy(cur_dir, next_dir, strlen(next_dir) + 1);
    next_dir = strtok_r(NULL, "/", &save);
  }

  if (cur_dir == NULL)
  {
    strlcpy(last_name, ".", 2);
  }
  else
  {
    strlcpy(last_name, cur_dir, strlen(cur_dir) + 1);
  }
  free(tmp);
  return ret_dir;
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format)
{
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();
  cache_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void)
{
  free_map_close();
  cache_shutdown();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size)
{
  block_sector_t inode_sector = 0;
  // struct dir *dir = dir_open_root();
  char *last_name = malloc(NAME_MAX + 1);
  memset(last_name, 0, NAME_MAX + 1);

  struct dir *dir = parse(name, last_name);
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) && inode_create(inode_sector, initial_size, 0) && dir_add(dir, last_name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);
  free(last_name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
  // struct dir *dir = dir_open_root();
  char *last_name = malloc(NAME_MAX + 1);
  memset(last_name, 0, NAME_MAX + 1);
  struct dir *dir = parse(name, last_name);
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, last_name, &inode);
  dir_close(dir);
  free(last_name);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
  // struct dir *dir = dir_open_root();
  char *last_name = malloc(NAME_MAX + 1);
  memset(last_name, 0, NAME_MAX + 1);
  struct dir *dir = parse(name, last_name);
  bool success = dir != NULL && dir_remove(dir, last_name);
  dir_close(dir);
  free(last_name);

  return success;
}

/* Formats the file system. */
static void
do_format(void)
{
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  struct dir *root = dir_open_root();
  thread_current()->dir = root;
  dir_special_entries(root, root);
  printf("done.\n");
}

bool filesys_chdir(const char *name)
{
  bool success = false;

  char *last_name = calloc(1, NAME_MAX + 1);
  // memset(last_name, 0, NAME_MAX + 1);
  struct dir *dir = parse(name, last_name);
  struct inode *inode = NULL;
  struct dir *chdir;

  if (dir != NULL)
  {
    if (!dir_lookup(dir, last_name, &inode))
    {
      free(last_name);
      return success;
    }

    chdir = dir_open(inode);

    if (thread_current()->dir != NULL)
      dir_close(thread_current()->dir);

    thread_current()->dir = chdir;
    success = true;
  }

  free(last_name);
  return success;
}

bool filesys_mkdir(const char *name)
{
  if (!strcmp(name, ""))
    return false;

  char *last_name = calloc(1, NAME_MAX + 1);
  // memset(last_name, 0, NAME_MAX + 1);
  struct dir *dir = parse(name, last_name);

  block_sector_t inode_sector = 0;
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) && dir_create(inode_sector, 16) && dir_add(dir, last_name, inode_sector));

  if (!success)
    free_map_release(inode_sector, 1);
  else
  {
    struct dir *mkdir;
    struct inode *inode;

    dir_lookup(dir, last_name, &inode);
    mkdir = dir_open(inode);

    dir_special_entries(dir, mkdir);
    dir_close(mkdir);
  }

  free(last_name);
  dir_close(dir);

  return success;
}