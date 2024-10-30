#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "lib/kernel/hash.h"
#include <stdbool.h>
#include "filesys/file.h"

struct vm_entry
{
    int type;
    void *vaddr;
    size_t zero_bytes;
    size_t read_bytes;
    size_t offset;
    struct file *file;
    struct hash_elem elem;
    bool writable;
};

enum vm_type
{
    VM_BIN,
    VM_FILE,
    VM_ANON
};

void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
struct vm_entry *find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
bool load_file(void *kaddr, struct vm_entry *vme);

#endif