#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "userprog/syscall.h"

void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
struct vm_entry *find_vme(void *vaddr);
void insert_vme(struct hash *vm, struct vm_entry *vme);
void delete_vme(struct hash *vm, struct vm_entry *vme);
bool load_file(void *kaddr, struct vm_entry *vme);
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED);

void vm_init(struct hash *vm)
{
    hash_init(vm, vm_hash_func, vm_less_func, NULL);
}
void vm_destroy(struct hash *vm)
{
    hash_destroy(vm, vm_destroy_func);
}
struct vm_entry *find_vme(void *vaddr)
{
    struct thread *t = thread_current();
    struct vm_entry v;
    struct hash_elem *e;

    v.vaddr = pg_round_down(vaddr);
    e = hash_find(&t->vm, &v.hash_elem);
    if (e == NULL)
        return NULL;
    else
        return hash_entry(e, struct vm_entry, hash_elem);
}
void insert_vme(struct hash *vm, struct vm_entry *vme)
{
    hash_insert(vm, &vme->hash_elem);
}
void delete_vme(struct hash *vm, struct vm_entry *vme)
{
    hash_delete(vm, &vme->hash_elem);
    free(vme);
}

static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    struct vm_entry *tmp = hash_entry(e, struct vm_entry, hash_elem);
    return hash_int((int)tmp->vaddr);
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct vm_entry *tmpa = hash_entry(a, struct vm_entry, hash_elem);
    struct vm_entry *tmpb = hash_entry(b, struct vm_entry, hash_elem);

    return tmpa->vaddr < tmpb->vaddr;
}

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
    struct vm_entry *tmp = hash_entry(e, struct vm_entry, hash_elem);
    free(tmp);
}

bool load_file(void *kaddr, struct vm_entry *vme)
{
    /*lock for syn-read, syn-write*/
    bool filesys_lock_flag = false;
    if (!lock_held_by_current_thread(&filesys_lock))
    {
        lock_acquire(&filesys_lock);
        filesys_lock_flag = true;
    }

    off_t actual_read = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);
    memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);

    if (actual_read != (off_t)vme->read_bytes)
    {
        return false;
    }

    if (filesys_lock_flag)
    {
        lock_release(&filesys_lock);
    }

    return true;
}

bool swap_in(struct page *frame)
{
    lock_acquire(&lru_lock);
    struct block *swap_partition = block_get_role(BLOCK_SWAP);

    if (bitmap_test(swap_bitmap, frame->vme->swap_slot))
    {
        block_sector_t i;
        block_sector_t sector = frame->vme->swap_slot * (PGSIZE / BLOCK_SECTOR_SIZE);
        for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
        {
            block_read(swap_partition, sector + i, BLOCK_SECTOR_SIZE * i + frame->paddr);
        }
        bitmap_reset(swap_bitmap, frame->vme->swap_slot);
        lock_release(&lru_lock);
        return true;
    }
    else
    {
        lock_release(&lru_lock);
        return false;
    }
}

void write_swap_partition(struct page *frame)
{
    struct block *swap_partition = block_get_role(BLOCK_SWAP);
    size_t target_idx = bitmap_scan(swap_bitmap, 0, 1, false);
    block_sector_t i;
    block_sector_t sector = target_idx * (PGSIZE / BLOCK_SECTOR_SIZE);

    for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
    {
        block_write(swap_partition, sector + i, BLOCK_SECTOR_SIZE * i + frame->paddr);
    }
    bitmap_mark(swap_bitmap, target_idx);

    frame->vme->swap_slot = target_idx;
    return;
}

struct list_elem *find_clock_pointer()
{
    if (list_empty(&lru_list))
        return NULL;
    if (clock_pointer == NULL || clock_pointer == list_end(&lru_list))
        return list_begin(&lru_list);
    return list_next(clock_pointer);
}

void page_free(struct page *frame)
{
    bool lru_lock_flag = false;
    if (!lock_held_by_current_thread(&lru_lock))
    {
        lock_acquire(&lru_lock);
        lru_lock_flag = true;
    }

    if (clock_pointer == &frame->lru_elem)
        clock_pointer = list_next(clock_pointer);

    palloc_free_page(frame->paddr);
    pagedir_clear_page(frame->cur_thread->pagedir, pg_round_down(frame->vme->vaddr));
    list_remove(&frame->lru_elem);
    free(frame);

    if (lru_lock_flag)
        lock_release(&lru_lock);
}

struct page *find_victim()
{
    clock_pointer = find_clock_pointer();

    struct page *vicitm;
    vicitm = list_entry(clock_pointer, struct page, lru_elem);

    while (vicitm->vme->pin == true || pagedir_is_accessed(vicitm->cur_thread->pagedir, vicitm->vme->vaddr))
    {
        pagedir_set_accessed(vicitm->cur_thread->pagedir, vicitm->vme->vaddr, false);
        clock_pointer = find_clock_pointer();
        vicitm = list_entry(clock_pointer, struct page, lru_elem);
    }

    return vicitm;
}

void swap_out(struct page *victim)
{
    bool is_dirty = false;
    switch (victim->vme->type)
    {
    case VM_BIN:
        is_dirty = pagedir_is_dirty(victim->cur_thread->pagedir, victim->vme->vaddr);
        if (is_dirty)
        {
            write_swap_partition(victim);
            victim->vme->type = VM_ANON;
        }
        break;
    case VM_FILE:
        is_dirty = pagedir_is_dirty(victim->cur_thread->pagedir, victim->vme->vaddr);
        if (is_dirty)
        {
            file_write_at(victim->vme->file, victim->vme->vaddr, victim->vme->read_bytes, victim->vme->offset);
        }
        break;
    case VM_ANON:
        write_swap_partition(victim);
        break;
    }
    page_free(victim);
}

struct page *page_alloc(enum palloc_flags flags)
{
    struct page *page = (struct page *)malloc(sizeof(struct page));
    lock_acquire(&lru_lock);
    uint8_t *paddr = palloc_get_page(flags);
    while (paddr == NULL)
    {
        struct page *victim = find_victim();
        swap_out(victim);
        paddr = palloc_get_page(flags);
    }
    page->paddr = paddr;
    page->cur_thread = thread_current();
    list_push_back(&lru_list, &page->lru_elem);
    lock_release(&lru_lock);
    return page;
}