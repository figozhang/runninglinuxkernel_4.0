#include <linux/list.h>
#include <linux/jhash.h>

#include "stp_helper_lock.h"

// When handling mmap()/munmap()/mprotect() syscall tracing to notice
// memory map changes, we need to cache syscall entry parameter values
// for processing at syscall exit.

// __stp_tf_map_lock protects the hash table.
// Documentation/spinlocks.txt suggest we can be a bit more clever
// if we guarantee that in interrupt context we only read, not write
// the datastructures. We should never change the hash table or the
// contents in interrupt context (which should only ever call 
// stap_find_map_map_info for getting stored info). So we might
// want to look into that if this seems a bottleneck.
static STP_DEFINE_RWLOCK(__stp_tf_map_lock);

#define __STP_TF_HASH_BITS 4
#define __STP_TF_TABLE_SIZE (1 << __STP_TF_HASH_BITS)

#ifndef TASK_FINDER_MAP_ENTRY_ITEMS
#define TASK_FINDER_MAP_ENTRY_ITEMS 100
#endif

struct __stp_tf_map_entry {
/* private: */
	struct hlist_node hlist;
	int usage;

/* public: */
	pid_t pid;
	long syscall_no;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;
};

static struct __stp_tf_map_entry
__stp_tf_map_free_list_items[TASK_FINDER_MAP_ENTRY_ITEMS];

static struct hlist_head __stp_tf_map_free_list[1];

static struct hlist_head __stp_tf_map_table[__STP_TF_TABLE_SIZE];

// __stp_tf_map_initialize():  Initialize the free list.  Grabs the
// lock.
static void
__stp_tf_map_initialize(void)
{
	int i;
	struct hlist_head *head = &__stp_tf_map_free_list[0];

	unsigned long flags;
	stp_write_lock_irqsave(&__stp_tf_map_lock, flags);
	for (i = 0; i < TASK_FINDER_MAP_ENTRY_ITEMS; i++) {
		hlist_add_head(&__stp_tf_map_free_list_items[i].hlist, head);
	}
	stp_write_unlock_irqrestore(&__stp_tf_map_lock, flags);
}


// __stp_tf_map_get_free_entry(): Returns an entry from the free list
// or NULL.  The __stp_tf_map_lock must be write locked before calling this
// function.
static struct __stp_tf_map_entry *
__stp_tf_map_get_free_entry(void)
{
	struct hlist_head *head = &__stp_tf_map_free_list[0];
	struct hlist_node *node;
	struct __stp_tf_map_entry *entry = NULL;

	if (hlist_empty(head))
		return NULL;
	stap_hlist_for_each_entry(entry, node, head, hlist) {
		break;
	}
	if (entry != NULL)
		hlist_del(&entry->hlist);
	return entry;
}


// __stp_tf_map_put_free_entry(): Puts an entry back on the free
// list.  The __stp_tf_map_lock must be write locked before calling this
// function.
static void
__stp_tf_map_put_free_entry(struct __stp_tf_map_entry *entry)
{
	struct hlist_head *head = &__stp_tf_map_free_list[0];
	hlist_add_head(&entry->hlist, head);
}


// __stp_tf_map_hash(): Compute the map hash.
static inline u32
__stp_tf_map_hash(struct task_struct *tsk)
{
    return (jhash_1word(tsk->pid, 0) & (__STP_TF_TABLE_SIZE - 1));
}


// Get map_entry if the map is present in the map hash table.
// Returns NULL if not present. Takes a read lock on __stp_tf_map_lock.
static struct __stp_tf_map_entry *
__stp_tf_get_map_entry(struct task_struct *tsk)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_map_entry *entry;

	unsigned long flags;
	stp_read_lock_irqsave(&__stp_tf_map_lock, flags);
	head = &__stp_tf_map_table[__stp_tf_map_hash(tsk)];
	stap_hlist_for_each_entry(entry, node, head, hlist) {
		if (tsk->pid == entry->pid) {
			stp_read_unlock_irqrestore(&__stp_tf_map_lock, flags);
			return entry;
		}
	}
	stp_read_unlock_irqrestore(&__stp_tf_map_lock, flags);
	return NULL;
}


// Add the map info to the map hash table. Takes a write lock on
// __stp_tf_map_lock.
static int
__stp_tf_add_map(struct task_struct *tsk, long syscall_no, unsigned long arg0,
		 unsigned long arg1, unsigned long arg2)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_map_entry *entry;
	unsigned long flags;

	stp_write_lock_irqsave(&__stp_tf_map_lock, flags);
	head = &__stp_tf_map_table[__stp_tf_map_hash(tsk)];
	stap_hlist_for_each_entry(entry, node, head, hlist) {
		// If we find an existing entry, just increment the
		// usage count.
		if (tsk->pid == entry->pid) {
			entry->usage++;
			stp_write_unlock_irqrestore(&__stp_tf_map_lock, flags);
			return 0;
		}
	}

	// Get an element from the free list.
	entry = __stp_tf_map_get_free_entry();
	if (!entry) {
		stp_write_unlock_irqrestore(&__stp_tf_map_lock, flags);
		return -ENOMEM;
	}
	entry->usage = 1;
	entry->pid = tsk->pid;
	entry->syscall_no = syscall_no;
	entry->arg0 = arg0;
	entry->arg1 = arg1;
	entry->arg2 = arg2;
	hlist_add_head(&entry->hlist, head);
	stp_write_unlock_irqrestore(&__stp_tf_map_lock, flags);
	return 0;
}


// Remove the map entry from the map hash table. Takes a write lock on
// __stp_tf_map_lock.
static int
__stp_tf_remove_map_entry(struct __stp_tf_map_entry *entry)
{
	struct hlist_head *head;
	struct hlist_node *node;
	int found = 0;

	if (entry != NULL) {
		unsigned long flags;
		stp_write_lock_irqsave(&__stp_tf_map_lock, flags);

		// Decrement the usage count.
		entry->usage--;

		// If the entry is unused, put it back on the free
		// list.
		if (entry->usage == 0) {
			hlist_del(&entry->hlist);
			__stp_tf_map_put_free_entry(entry);
		}
		stp_write_unlock_irqrestore(&__stp_tf_map_lock, flags);
	}
	return 0;
}
