#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/vaddr.h"
#include <stdio.h>

void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
struct vm_entry *find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
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

    v.vaddr = pg_round_down(vaddr); // 확인 => #include "threads/vaddr.h" 필요
    // v.vaddr = vaddr;
    e = hash_find(&t->vm, &v.elem);
    if (e == NULL)
        return NULL;

    return hash_entry(e, struct vm_entry, elem);
}
bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
    return hash_insert(vm, &vme->elem) == NULL;
}
bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
    return hash_delete(vm, &vme->elem) == NULL;
}

static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    struct vm_entry *tmp = hash_entry(e, struct vm_entry, elem);
    return hash_int((int)tmp->vaddr);
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct vm_entry *tmpa = hash_entry(a, struct vm_entry, elem);
    struct vm_entry *tmpb = hash_entry(b, struct vm_entry, elem);

    return tmpa->vaddr < tmpb->vaddr;
}

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
    struct vm_entry *tmp = hash_entry(e, struct vm_entry, elem);
    free(tmp);
}

bool load_file(void *kaddr, struct vm_entry *vme)
{
    off_t actual_read = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);
    if (actual_read != (off_t)vme->read_bytes)
    {
        return false;
    }
    memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
    return true;
}