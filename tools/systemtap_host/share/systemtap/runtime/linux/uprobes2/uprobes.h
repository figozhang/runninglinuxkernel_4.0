#ifndef _LINUX_UPROBES_H
#define _LINUX_UPROBES_H
/*
 * Userspace Probes (UProbes)
 * include/linux/uprobes.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) IBM Corporation, 2006
 */
#include <linux/types.h>
#include <linux/list.h>

/* Adapt to struct renaming. */
#ifdef UTRACE_API_VERSION
#define utrace_attached_engine utrace_engine
#endif

/* Version 2 includes unmap_u[ret]probe(). */
#define UPROBES_API_VERSION 2

struct pt_regs;

enum uprobe_type {
	UPTY_UPROBE,
	UPTY_URETPROBE
};

/* This is what the user supplies us. */
struct uprobe {
	/*
	 * The pid of the probed process.  Currently, this can be the
	 * thread ID (task->pid) of any active thread in the process.
	 */
	pid_t pid;

	/* Location of the probepoint */
	unsigned long vaddr;

	/* Handler to run when the probepoint is hit */
	void (*handler)(struct uprobe*, struct pt_regs*);

	/*
	 * This function, if non-NULL, will be called upon completion of
	 * an ASYNCHRONOUS registration (i.e., one initiated by a uprobe
	 * handler).  reg = 1 for register, 0 for unregister.  type
	 * specifies the type of [un]register call (uprobe or uretprobe).
	 */
	void (*registration_callback)(struct uprobe *u, int reg,
			enum uprobe_type type, int result);

	/* Reserved for use by uprobes */
	void *kdata;
};

struct uretprobe_instance;

struct uretprobe {
	struct uprobe u;
	void (*handler)(struct uretprobe_instance*, struct pt_regs*);
};

struct uretprobe_instance {
	struct uretprobe *rp;
	unsigned long ret_addr;
	struct hlist_node hlist;
	unsigned long sp;	// stack pointer value expected on return
	unsigned long reserved1;
};

extern int register_uprobe(struct uprobe *u);
extern void unregister_uprobe(struct uprobe *u);
/* For runtime, assume uprobes support includes uretprobes. */
extern int register_uretprobe(struct uretprobe *rp);
extern void unregister_uretprobe(struct uretprobe *rp);
/* For PRs 9940, 6852... */
extern void unmap_uprobe(struct uprobe *u);
extern void unmap_uretprobe(struct uretprobe *rp);
/*
 * Given a program counter, translate it back to the original address
 * if it is the address of the trampoline. sp is the stack pointer for
 * the frame that corresponds to the address.
 *
 * When not called from a uretprobe hander, pass GET_PC_URETPROBE_NONE.
 */
#define GET_PC_URETPROBE_NONE ((struct uretprobe_instance *)-1L)
extern unsigned long uprobe_get_pc(struct uretprobe_instance *ri,
                                   unsigned long pc,
                                   unsigned long sp);
/*
 * This version will do the mapping for an arbitrary task.
 */
extern unsigned long uprobe_get_pc_task(struct task_struct *task,
					unsigned long pc,
					unsigned long sp);

#ifdef UPROBES_IMPLEMENTATION

#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include <asm/atomic.h>
#include "uprobes_arch.h"

struct task_struct;
struct utrace_attached_engine;
struct pid;

enum uprobe_probept_state {
	UPROBE_INSERTING,	// process quiescing prior to insertion
	UPROBE_BP_SET,		// breakpoint in place
	UPROBE_REMOVING,	// process quiescing prior to removal
	UPROBE_DISABLED		// removal completed
};

enum uprobe_task_state {
	UPTASK_QUIESCENT,
	UPTASK_SLEEPING,	// used when task may not be able to quiesce
	UPTASK_RUNNING,
	UPTASK_BP_HIT,
	UPTASK_TRAMPOLINE_HIT,
	UPTASK_PRE_SSTEP,
	UPTASK_SSTEP,
	UPTASK_POST_SSTEP
};

#define UPROBE_HASH_BITS 5
#define UPROBE_TABLE_SIZE (1 << UPROBE_HASH_BITS)

/* Used when deciding which instruction slot to steal. */
enum uprobe_slot_state {
	SSOL_FREE,
	SSOL_ASSIGNED,
	SSOL_BEING_STOLEN,
	SSOL_RESERVED		// e.g., for uretprobe trampoline
};

/*
 * For a uprobe_process that uses an SSOL area, there's an array of these
 * objects matching the array of instruction slots in the SSOL area.
 */
struct uprobe_ssol_slot {
	/* The slot in the SSOL area that holds the instruction-copy */
	__user uprobe_opcode_t	*insn;

	enum uprobe_slot_state state;

	/* The probepoint that currently owns this slot */
	struct uprobe_probept *owner;

	/*
	 * Read-locked when slot is in use during single-stepping.
	 * Write-locked by stealing task.
	 */
	struct rw_semaphore rwsem;

	/* Used for LRU heuristics.  If this overflows, it's OK. */
	unsigned long last_used;
};

/*
 * The per-process single-stepping out-of-line (SSOL) area
 */
struct uprobe_ssol_area {
	/* Array of instruction slots in the vma we allocate */
	__user uprobe_opcode_t *insn_area;

	int nslots;
	int nfree;

	/* Array of slot objects, one per instruction slot */
	struct uprobe_ssol_slot *slots;

	/* lock held while finding a free slot */
	spinlock_t lock;

	/*
	 * We currently use access_process_vm() to populate instruction
	 * slots.  Calls must be serialized because access_process_vm()
	 * isn't thread-safe.
	 */
	struct mutex populate_mutex;

	/* Next slot to steal */
	int next_slot;

	/* First slot not reserved for trampoline or some such */
	int first_ssol_slot;

	/* Ensures 2 threads don't try to set up the vma simultaneously. */
	struct mutex setup_mutex;

	/* 1 = we've at least tried.  IS_ERR(insn_area) if we failed. */
	int initialized;
};

/*
 * uprobe_process -- not a user-visible struct.
 * A uprobe_process represents a probed process.  A process can have
 * multiple probepoints (each represented by a uprobe_probept) and
 * one or more threads (each represented by a uprobe_task).
 */
struct uprobe_process {
	/*
	 * rwsem is write-locked for any change to the uprobe_process's
	 * graph (including uprobe_tasks, uprobe_probepts, and uprobe_kimgs) --
	 * e.g., due to probe [un]registration or special events like exit.
	 * It's read-locked during the whole time we process a probepoint hit.
	 */
	struct rw_semaphore rwsem;

	/* Table of uprobe_probepts registered for this process */
	/* TODO: Switch to list_head[] per Ingo. */
	struct hlist_head uprobe_table[UPROBE_TABLE_SIZE];
	int nppt;	/* number of probepoints */

	/* List of uprobe_probepts awaiting insertion or removal */
	struct list_head pending_uprobes;

	/* List of uprobe_tasks in this task group */
	struct list_head thread_list;
	int nthreads;
	int n_quiescent_threads;

	/* this goes on the uproc_table */
	struct hlist_node hlist;

	/*
	 * All threads (tasks) in a process share the same uprobe_process.
	 */
	struct pid *tg_leader;
	pid_t tgid;

	/* Threads in UTASK_SLEEPING state wait here to be roused. */
	wait_queue_head_t waitq;

	/*
	 * We won't free the uprobe_process while...
	 * - any register/unregister operations on it are in progress; or
	 * - any uprobe_report_* callbacks are running; or
	 * - uprobe_table[] is not empty; or
	 * - any tasks are UTASK_SLEEPING in the waitq; or
	 * - any uretprobe_instances are outstanding.
	 * refcount reflects this.  We do NOT ref-count tasks (threads),
	 * since once the last thread has exited, the rest is academic.
	 */
	atomic_t refcount;

	/* Return-probed functions return via this trampoline. */
	__user uprobe_opcode_t *uretprobe_trampoline_addr;

	/*
	 * finished = 1 means the process is execing or the last thread
	 * is exiting, and we're cleaning up the uproc.  If the execed
	 * process is probed, a new uproc will be created.
	 */
	int finished;

	/*
	 * Manages slots for instruction-copies to be single-stepped
	 * out of line.
	 */
	struct uprobe_ssol_area ssol_area;

	/*
	 * 1 to single-step out of line; 0 for inline.  This can drop to
	 * 0 if we can't set up the SSOL area, but never goes from 0 to 1.
	 */
	int sstep_out_of_line;
};

/*
 * uprobe_kimg -- not a user-visible struct.
 * Holds implementation-only per-uprobe data.
 * uprobe->kdata points to this.
 */
struct uprobe_kimg {
	struct uprobe *uprobe;
	struct uprobe_probept *ppt;

	/*
	 * -EBUSY while we're waiting for all threads to quiesce so the
	 * associated breakpoint can be inserted or removed.
	 * 0 if the the insert/remove operation has succeeded, or -errno
	 * otherwise.
	 */
	int status;

	/* on ppt's list */
	struct list_head list;
};

/*
 * uprobe_probept -- not a user-visible struct.
 * A probepoint, at which several uprobes can be registered.
 * Guarded by uproc->rwsem.
 */
struct uprobe_probept {
	/* vaddr copied from (first) uprobe */
	unsigned long vaddr;

	/* The uprobe_kimg(s) associated with this uprobe_probept */
	struct list_head uprobe_list;

	enum uprobe_probept_state state;

	/* Saved opcode (which has been replaced with breakpoint) */
	uprobe_opcode_t opcode;

	/*
	 * Saved original instruction.  This may be modified by
	 * architecture-specific code if the original instruction
	 * can't be single-stepped out of line as-is.
	 */
	uprobe_opcode_t insn[MAX_UINSN_BYTES / sizeof(uprobe_opcode_t)];

	struct uprobe_probept_arch_info arch_info;

	/* The parent uprobe_process */
	struct uprobe_process *uproc;

	/*
	 * ppt goes in the uprobe_process->uprobe_table when registered --
	 * even before the breakpoint has been inserted.
	 */
	struct hlist_node ut_node;

	/*
	 * ppt sits in the uprobe_process->pending_uprobes queue while
	 * awaiting insertion or removal of the breakpoint.
	 */
	struct list_head pd_node;

	/* [un]register_uprobe() waits 'til bkpt inserted/removed. */
	wait_queue_head_t waitq;

	/*
	 * Serialize single-stepping inline, so threads don't clobber
	 * each other swapping the breakpoint instruction in and out.
	 * This helps prevent crashing the probed app, but it does NOT
	 * prevent probe misses while the breakpoint is swapped out.
	 */
	struct mutex ssil_mutex;

	/*
	 * We put the instruction-copy here to single-step it.
	 * We don't own it unless slot->owner points back to us.
	 */
	struct uprobe_ssol_slot *slot;

	/*
	 * Hold this while stealing an insn slot to ensure that no
	 * other thread, having also hit this probepoint, simultaneously
	 * steals a slot for it.
	 */
	struct mutex slot_mutex;
};

/*
 * uprobe_utask -- not a user-visible struct.
 * Corresponds to a thread in a probed process.
 * Guarded by uproc->rwsem.
 */
struct uprobe_task {
	/* Lives in the global utask_table */
	struct hlist_node hlist;

	/* Lives on the thread_list for the uprobe_process */
	struct list_head list;

	struct task_struct *tsk;
	struct pid *pid;

	/* The utrace engine for this task */
	struct utrace_attached_engine *engine;

	/* Back pointer to the associated uprobe_process */
	struct uprobe_process *uproc;

	enum uprobe_task_state state;

	/*
	 * quiescing = 1 means this task has been asked to quiesce.
	 * It may not be able to comply immediately if it's hit a bkpt.
	 */
	int quiescing;

	/* Set before running handlers; cleared after single-stepping. */
	struct uprobe_probept *active_probe;

	/* Saved address of copied original instruction */
	long singlestep_addr;

	struct uprobe_task_arch_info arch_info;

	/*
	 * Unexpected error in probepoint handling has left task's
	 * text or stack corrupted.  Kill task ASAP.
	 */
	int doomed;

	/* LIFO -- active instances */
	struct hlist_head uretprobe_instances;

	/* [un]registrations initiated by handlers must be asynchronous. */
	struct list_head deferred_registrations;

	/* Delay handler-destined signals 'til after single-step done. */
	struct list_head delayed_signals;
};

#ifdef CONFIG_UPROBES_SSOL
static struct uprobe_ssol_slot *uprobe_get_insn_slot(struct uprobe_probept*);
static void uprobe_pre_ssout(struct uprobe_task*, struct uprobe_probept*,
			struct pt_regs*);
static void uprobe_post_ssout(struct uprobe_task*, struct uprobe_probept*,
			struct pt_regs*);
#endif
static int uprobe_emulate_insn(struct pt_regs *regs,
						struct uprobe_probept *ppt);

#endif	/* UPROBES_IMPLEMENTATION */

#endif	/* _LINUX_UPROBES_H */
