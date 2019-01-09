#ifndef TASK_FINDER_VMA_C
#define TASK_FINDER_VMA_C

#include <linux/file.h>
#include <linux/list.h>
#include <linux/jhash.h>

#include <linux/fs.h>
#include <linux/dcache.h>

#include "stp_helper_lock.h"

// __stp_tf_vma_lock protects the hash table.
// Documentation/spinlocks.txt suggest we can be a bit more clever
// if we guarantee that in interrupt context we only read, not write
// the datastructures. We should never change the hash table or the
// contents in interrupt context (which should only ever call 
// stap_find_vma_map_info for getting stored vma info). So we might
// want to look into that if this seems a bottleneck.
static STP_DEFINE_RWLOCK(__stp_tf_vma_lock);

#define __STP_TF_HASH_BITS 4
#define __STP_TF_TABLE_SIZE (1 << __STP_TF_HASH_BITS)

#ifndef TASK_FINDER_VMA_ENTRY_PATHLEN
#define TASK_FINDER_VMA_ENTRY_PATHLEN 64
#elif TASK_FINDER_VMA_ENTRY_PATHLEN < 8
#error "gimme a little more TASK_FINDER_VMA_ENTRY_PATHLEN"
#endif


struct __stp_tf_vma_entry {
	struct hlist_node hlist;

	pid_t pid;
	unsigned long vm_start;
	unsigned long vm_end;
        char path[TASK_FINDER_VMA_ENTRY_PATHLEN]; /* mmpath name, if known */

	// User data (possibly stp_module)
	void *user;
};

static struct hlist_head *__stp_tf_vma_map;

// __stp_tf_vma_new_entry(): Returns an newly allocated or NULL.
// Must only be called from user context.
// ... except, with inode-uprobes / task-finder2, it can be called from
// random tracepoints.  So we cannot sleep after all.
static struct __stp_tf_vma_entry *
__stp_tf_vma_new_entry(void)
{
	struct __stp_tf_vma_entry *entry;
	size_t size = sizeof (struct __stp_tf_vma_entry);
#ifdef CONFIG_UTRACE
	entry = (struct __stp_tf_vma_entry *) _stp_kmalloc_gfp(size,
                                                         STP_ALLOC_SLEEP_FLAGS);
#else
	entry = (struct __stp_tf_vma_entry *) _stp_kmalloc_gfp(size,
                                                               STP_ALLOC_FLAGS);
#endif
	return entry;
}

// __stp_tf_vma_release_entry(): Frees an entry.
static void
__stp_tf_vma_release_entry(struct __stp_tf_vma_entry *entry)
{
	_stp_kfree (entry);
}

// stap_initialize_vma_map():  Initialize the free list.  Grabs the
// spinlock.  Should be called before any of the other stap_*_vma_map
// functions.  Since this is run before any other function is called,
// this doesn't need any locking.  Should be called from a user context
// since it can allocate memory.
static int
stap_initialize_vma_map(void)
{
	size_t size = sizeof(struct hlist_head) * __STP_TF_TABLE_SIZE;
	struct hlist_head *map = (struct hlist_head *) _stp_kzalloc_gfp(size,
							STP_ALLOC_SLEEP_FLAGS);
	if (map == NULL)
		return -ENOMEM;

	__stp_tf_vma_map = map;
	return 0;
}

// stap_destroy_vma_map(): Unconditionally destroys vma entries.
// Nothing should be using it anymore. Doesn't lock anything and just
// frees all items.
static void
stap_destroy_vma_map(void)
{
	if (__stp_tf_vma_map != NULL) {
		int i;
		for (i = 0; i < __STP_TF_TABLE_SIZE; i++) {
			struct hlist_head *head = &__stp_tf_vma_map[i];
			struct hlist_node *node;
			struct hlist_node *n;
			struct __stp_tf_vma_entry *entry = NULL;

			if (hlist_empty(head))
				continue;

		        stap_hlist_for_each_entry_safe(entry, node, n, head, hlist) {
				hlist_del(&entry->hlist);
				__stp_tf_vma_release_entry(entry);
			}
		}
		_stp_kfree(__stp_tf_vma_map);
	}
}


// __stp_tf_vma_map_hash(): Compute the vma map hash.
static inline u32
__stp_tf_vma_map_hash(struct task_struct *tsk)
{
    return (jhash_1word(tsk->pid, 0) & (__STP_TF_TABLE_SIZE - 1));
}

// Get vma_entry if the vma is present in the vma map hash table.
// Returns NULL if not present.  The __stp_tf_vma_lock must be read locked
// before calling this function.
static struct __stp_tf_vma_entry *
__stp_tf_get_vma_map_entry_internal(struct task_struct *tsk,
				    unsigned long vm_start)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_vma_entry *entry;

	head = &__stp_tf_vma_map[__stp_tf_vma_map_hash(tsk)];
	stap_hlist_for_each_entry(entry, node, head, hlist) {
		if (tsk->pid == entry->pid
		    && vm_start == entry->vm_start) {
			return entry;
		}
	}
	return NULL;
}

// Get vma_entry if the vma with the given vm_end is present in the vma map
// hash table for the tsk.  Returns NULL if not present.
// The __stp_tf_vma_lock must be read locked before calling this function.
static struct __stp_tf_vma_entry *
__stp_tf_get_vma_map_entry_end_internal(struct task_struct *tsk,
					unsigned long vm_end)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_vma_entry *entry;

	head = &__stp_tf_vma_map[__stp_tf_vma_map_hash(tsk)];
	stap_hlist_for_each_entry(entry, node, head, hlist) {
		if (tsk->pid == entry->pid
		    && vm_end == entry->vm_end) {
			return entry;
		}
	}
	return NULL;
}


// Add the vma info to the vma map hash table.
// Caller is responsible for name lifetime.
// Can allocate memory, so needs to be called
// only from user context.
static int
stap_add_vma_map_info(struct task_struct *tsk,
		      unsigned long vm_start, unsigned long vm_end,
		      const char *path, void *user)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_vma_entry *entry;
	struct __stp_tf_vma_entry *new_entry;
	unsigned long flags;

	// Take a write lock, since we are most likely going to write
	// after reading. But reserve a new entry first outside the lock.
	new_entry = __stp_tf_vma_new_entry();
	stp_write_lock_irqsave(&__stp_tf_vma_lock, flags);
	entry = __stp_tf_get_vma_map_entry_internal(tsk, vm_start);
	if (entry != NULL) {
		stp_write_unlock_irqrestore(&__stp_tf_vma_lock, flags);
		if (new_entry)
			__stp_tf_vma_release_entry(new_entry);
		return -EBUSY;	/* Already there */
	}

	if (!new_entry) {
		stp_write_unlock_irqrestore(&__stp_tf_vma_lock, flags);
		return -ENOMEM;
	}

	// Fill in the info
	entry = new_entry;
	entry->pid = tsk->pid;
	entry->vm_start = vm_start;
	entry->vm_end = vm_end;
        if (strlen(path) >= TASK_FINDER_VMA_ENTRY_PATHLEN-3)
          {
            strncpy (entry->path, "...", TASK_FINDER_VMA_ENTRY_PATHLEN);
            strlcpy (entry->path+3, &path[strlen(path)-TASK_FINDER_VMA_ENTRY_PATHLEN+4],
                     TASK_FINDER_VMA_ENTRY_PATHLEN-3);
          }
        else
          {
            strlcpy (entry->path, path, TASK_FINDER_VMA_ENTRY_PATHLEN);
          }
	entry->user = user;

	head = &__stp_tf_vma_map[__stp_tf_vma_map_hash(tsk)];
	hlist_add_head(&entry->hlist, head);
	stp_write_unlock_irqrestore(&__stp_tf_vma_lock, flags);
	return 0;
}

// Extend the vma info vm_end in the vma map hash table if there is already
// a vma_info which ends precisely where this new one starts for the given
// task. Returns zero on success, -ESRCH if no existing matching entry could
// be found.
static int
stap_extend_vma_map_info(struct task_struct *tsk,
			 unsigned long vm_start, unsigned long vm_end)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_vma_entry *entry;

	unsigned long flags;
	int res = -ESRCH; // Entry not there or doesn't match.

	// Take a write lock, since we are most likely going to write
	// to the entry after reading, if its vm_end matches our vm_start.
	stp_write_lock_irqsave(&__stp_tf_vma_lock, flags);
	entry = __stp_tf_get_vma_map_entry_end_internal(tsk, vm_start);
	if (entry != NULL) {
		entry->vm_end = vm_end;
		res = 0;
	}
	stp_write_unlock_irqrestore(&__stp_tf_vma_lock, flags);
	return res;
}


// Remove the vma entry from the vma hash table.
// Returns -ESRCH if the entry isn't present.
static int
stap_remove_vma_map_info(struct task_struct *tsk, unsigned long vm_start)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_vma_entry *entry;
	int rc = -ESRCH;

	// Take a write lock since we are most likely going to delete
	// after reading.
	unsigned long flags;
	stp_write_lock_irqsave(&__stp_tf_vma_lock, flags);
	entry = __stp_tf_get_vma_map_entry_internal(tsk, vm_start);
	if (entry != NULL) {
		hlist_del(&entry->hlist);
		__stp_tf_vma_release_entry(entry);
                rc = 0;
	}
	stp_write_unlock_irqrestore(&__stp_tf_vma_lock, flags);
	return rc;
}

// Finds vma info if the vma is present in the vma map hash table for
// a given task and address (between vm_start and vm_end).
// Returns -ESRCH if not present.  The __stp_tf_vma_lock must *not* be
// locked before calling this function.
static int
stap_find_vma_map_info(struct task_struct *tsk, unsigned long addr,
		       unsigned long *vm_start, unsigned long *vm_end,
		       const char **path, void **user)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_vma_entry *entry;
	struct __stp_tf_vma_entry *found_entry = NULL;
	int rc = -ESRCH;
	unsigned long flags;

	if (__stp_tf_vma_map == NULL)
		return rc;

	stp_read_lock_irqsave(&__stp_tf_vma_lock, flags);
	head = &__stp_tf_vma_map[__stp_tf_vma_map_hash(tsk)];
	stap_hlist_for_each_entry(entry, node, head, hlist) {
		if (tsk->pid == entry->pid
		    && addr >= entry->vm_start
		    && addr < entry->vm_end) {
			found_entry = entry;
			break;
		}
	}
	if (found_entry != NULL) {
		if (vm_start != NULL)
			*vm_start = found_entry->vm_start;
		if (vm_end != NULL)
			*vm_end = found_entry->vm_end;
		if (path != NULL)
			*path = found_entry->path;
		if (user != NULL)
			*user = found_entry->user;
		rc = 0;
	}
	stp_read_unlock_irqrestore(&__stp_tf_vma_lock, flags);
	return rc;
}

// Finds vma info if the vma is present in the vma map hash table for
// a given task with the given user handle.
// Returns -ESRCH if not present.  The __stp_tf_vma_lock must *not* be
// locked before calling this function.
static int
stap_find_vma_map_info_user(struct task_struct *tsk, void *user,
			    unsigned long *vm_start, unsigned long *vm_end,
			    const char **path)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct __stp_tf_vma_entry *entry;
	struct __stp_tf_vma_entry *found_entry = NULL;
	int rc = -ESRCH;
	unsigned long flags;

	if (__stp_tf_vma_map == NULL)
		return rc;

	stp_read_lock_irqsave(&__stp_tf_vma_lock, flags);
	head = &__stp_tf_vma_map[__stp_tf_vma_map_hash(tsk)];
	stap_hlist_for_each_entry(entry, node, head, hlist) {
		if (tsk->pid == entry->pid
		    && user == entry->user) {
			found_entry = entry;
			break;
		}
	}
	if (found_entry != NULL) {
		if (vm_start != NULL)
			*vm_start = found_entry->vm_start;
		if (vm_end != NULL)
			*vm_end = found_entry->vm_end;
		if (path != NULL)
			*path = found_entry->path;
		rc = 0;
	}
	stp_read_unlock_irqrestore(&__stp_tf_vma_lock, flags);
	return rc;
}

static int
stap_drop_vma_maps(struct task_struct *tsk)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct hlist_node *n;
	struct __stp_tf_vma_entry *entry;

	unsigned long flags;
	stp_write_lock_irqsave(&__stp_tf_vma_lock, flags);
	head = &__stp_tf_vma_map[__stp_tf_vma_map_hash(tsk)];
        stap_hlist_for_each_entry_safe(entry, node, n, head, hlist) {
            if (tsk->pid == entry->pid) {
		    hlist_del(&entry->hlist);
		    __stp_tf_vma_release_entry(entry);
            }
        }
	stp_write_unlock_irqrestore(&__stp_tf_vma_lock, flags);
	return 0;
}

/*
 * stap_find_exe_file - acquire a reference to the mm's executable file
 *
 * Returns NULL if mm has no associated executable file.  User must
 * release file via fput().
 */
static struct file*
stap_find_exe_file(struct mm_struct* mm)
{
	// The following kernel commit changed the way the exported
	// get_mm_exe_file() works. This commit first appears in the
	// 4.1 kernel:
	//
	// commit 90f31d0ea88880f780574f3d0bb1a227c4c66ca3
	// Author: Konstantin Khlebnikov <khlebnikov@yandex-team.ru>
	// Date:   Thu Apr 16 12:47:56 2015 -0700
	// 
	//     mm: rcu-protected get_mm_exe_file()
	//     
	//     This patch removes mm->mmap_sem from mm->exe_file read side.
	//     Also it kills dup_mm_exe_file() and moves exe_file
	//     duplication into dup_mmap() where both mmap_sems are
	//     locked.
	//
	// So, for kernels >= 4.1, we'll use get_mm_exe_file(). For
	// kernels < 4.1 but with get_mm_exe_file() exported, we'll
	// still use our own code. The original get_mm_exe_file() can
	// sleep (since it calls down_read()), so we'll have to roll
	// our own.
#if defined(STAPCONF_DPATH_PATH) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
	return get_mm_exe_file(mm);
#else
	struct file *exe_file = NULL;

	// The down_read() function can sleep, so we'll call
	// down_read_trylock() instead, which can fail.  If it
	// fails, we'll just pretend this task didn't have a
	// exe file.
	if (mm && down_read_trylock(&mm->mmap_sem)) {

		// VM_EXECUTABLE was killed in kernel commit e9714acf,
		// but in kernels that new we can just use
		// mm->exe_file anyway. (PR14712)
#ifdef VM_EXECUTABLE
		struct vm_area_struct *vma;
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
				exe_file = vma->vm_file;
				break;
			}
		}
#else
		exe_file = mm->exe_file;
#endif
		if (exe_file)
			get_file(exe_file);
		up_read(&mm->mmap_sem);
	}
	return exe_file;
#endif
}

#endif /* TASK_FINDER_VMA_C */
