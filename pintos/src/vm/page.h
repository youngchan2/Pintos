#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "lib/kernel/hash.h"
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"
#include "threads/palloc.h"

struct bitmap *swap_bitmap;
struct list lru_list;
struct list_elem *clock_pointer;
struct lock lru_lock;
struct lock swap_lock;

struct vm_entry
{
    int type;
    void *vaddr;
    size_t zero_bytes;
    size_t read_bytes;
    size_t offset;
    struct file *file;
    struct hash_elem elem;
    struct list_elem mmap_file_elem;
    uint32_t swap_slot;
    bool writable;
    bool pinned;
};

enum vm_type
{
    VM_BIN,
    VM_FILE,
    VM_ANON
};

struct page
{
    void *paddr;
    struct vm_entry *vme;
    struct thread *cur_thread;
    struct list_elem lru_elem;
};

struct mmap_file
{
    int mapid;
    struct file *file;
    struct list_elem elem;
    struct list vme_list;
};

void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
struct vm_entry *find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
bool load_file(void *kaddr, struct vm_entry *vme);
bool swap_in(struct page *frame);
void write_swap_partition(struct page *frame);
struct list_elem *find_clock_pointer(void);
void page_free(struct page *frame);
struct page *find_victim(void);
void swap_out(struct page *victim);
struct page *page_alloc(enum palloc_flags flags);
#endif