#include <linux/utrace.h>
#ifndef UTRACE_ACTION_RESUME

/*
 * Assume the kernel is running the 2008 version of utrace.
 * Skip the code in this file and instead use uprobes 2.
 */
#include "../uprobes2/uprobes.c"

#else	/* uprobes 1 (based on original utrace) */

/*
 *  Userspace Probes (UProbes)
 *  kernel/uprobes_core.c
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
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/err.h>
#include <linux/kref.h>
#include <linux/utrace.h>
#define UPROBES_IMPLEMENTATION 1
#include "uprobes.h"
#include <linux/tracehook.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/tracehook.h>
#include <asm/errno.h>
#include <asm/mman.h>

#define SET_ENGINE_FLAGS	1
#define CLEAR_ENGINE_FLAGS	0

#define MAX_SSOL_SLOTS		1024

#ifdef NO_ACCESS_PROCESS_VM_EXPORT
static int __access_process_vm(struct task_struct *tsk, unsigned long addr,
	void *buf, int len, int write);
#define access_process_vm __access_process_vm
#else
extern int access_process_vm(struct task_struct *tsk, unsigned long addr,
	void *buf, int len, int write);
#endif
static int utask_fake_quiesce(struct uprobe_task *utask);
static void uprobe_release_ssol_vma(struct uprobe_process *uproc);

static void uretprobe_handle_entry(struct uprobe *u, struct pt_regs *regs,
	struct uprobe_task *utask);
static void uretprobe_handle_return(struct pt_regs *regs,
	struct uprobe_task *utask);
static void uretprobe_set_trampoline(struct uprobe_process *uproc,
	struct task_struct *tsk);
static void zap_uretprobe_instances(struct uprobe *u,
	struct uprobe_process *uproc);

typedef void (*uprobe_handler_t)(struct uprobe*, struct pt_regs*);
#define URETPROBE_HANDLE_ENTRY ((uprobe_handler_t)-1L)
#define is_uretprobe(u) (u->handler == URETPROBE_HANDLE_ENTRY)
/* Point utask->active_probe at this while running uretprobe handler. */
static struct uprobe_probept uretprobe_trampoline_dummy_probe;

/* Table of currently probed processes, hashed by tgid. */
static struct hlist_head uproc_table[UPROBE_TABLE_SIZE];

/* Protects uproc_table during uprobe (un)registration */
static DEFINE_MUTEX(uproc_mutex);

/* Table of uprobe_tasks, hashed by task_struct pointer. */
static struct hlist_head utask_table[UPROBE_TABLE_SIZE];
static DEFINE_SPINLOCK(utask_table_lock);

#define lock_uproc_table() mutex_lock(&uproc_mutex)
#define unlock_uproc_table() mutex_unlock(&uproc_mutex)

#define lock_utask_table(flags) spin_lock_irqsave(&utask_table_lock, (flags))
#define unlock_utask_table(flags) \
	spin_unlock_irqrestore(&utask_table_lock, (flags))

/* p_uprobe_utrace_ops = &uprobe_utrace_ops.  Fwd refs are a pain w/o this. */
static const struct utrace_engine_ops *p_uprobe_utrace_ops;

struct deferred_registration {
	struct list_head list;
	struct uprobe *uprobe;
	int regflag;	/* 0 - unregister, 1 - register */
	enum uprobe_type type;
};

/*
 * Calling a signal handler cancels single-stepping, so uprobes delays
 * calling the handler, as necessary, until after single-stepping is completed.
 */
struct delayed_signal {
	struct list_head list;
	siginfo_t info;
};

static struct uprobe_task *uprobe_find_utask_locked(struct task_struct *tsk)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct uprobe_task *utask;

	head = &utask_table[hash_ptr(tsk, UPROBE_HASH_BITS)];
	hlist_for_each_entry(utask, node, head, hlist) {
		if (utask->tsk == tsk)
			return utask;
	}
	return NULL;
}

static struct uprobe_task *uprobe_find_utask(struct task_struct *tsk)
{
        struct uprobe_task *utask;
        unsigned long flags;

        lock_utask_table(flags);
        utask = uprobe_find_utask_locked(tsk);
        unlock_utask_table(flags);
        return utask;
}

static void uprobe_hash_utask(struct uprobe_task *utask)
{
	struct hlist_head *head;
	unsigned long flags;

	INIT_HLIST_NODE(&utask->hlist);
	lock_utask_table(flags);
	head = &utask_table[hash_ptr(utask->tsk, UPROBE_HASH_BITS)];
	hlist_add_head(&utask->hlist, head);
	unlock_utask_table(flags);
}

static void uprobe_unhash_utask(struct uprobe_task *utask)
{
	unsigned long flags;

	lock_utask_table(flags);
	hlist_del(&utask->hlist);
	unlock_utask_table(flags);
}

static struct uprobe_process * uprobe_get_process(struct uprobe_process *uproc)
{
	if (atomic_inc_not_zero(&uproc->refcount))
		return uproc;
	return NULL;
}

/*
 * Decrement uproc's refcount in a situation where we "know" it can't
 * reach zero.  It's OK to call this with uproc locked.  Compare with
 * uprobe_put_process().
 */
static inline void uprobe_decref_process(struct uprobe_process *uproc)
{
	if (atomic_dec_and_test(&uproc->refcount))
		BUG();
}

/*
 * Runs with the uproc_mutex held.  Returns with uproc ref-counted and
 * write-locked.
 *
 * Around exec time, briefly, it's possible to have one (finished) uproc
 * for the old image and one for the new image.  We find the latter.
 */
static struct uprobe_process *uprobe_find_process(pid_t tgid)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct uprobe_process *uproc;

	head = &uproc_table[hash_long(tgid, UPROBE_HASH_BITS)];
	hlist_for_each_entry(uproc, node, head, hlist) {
		if (uproc->tgid == tgid && !uproc->finished) {
			uproc = uprobe_get_process(uproc);
			if (uproc)
				down_write(&uproc->rwsem);
			return uproc;
		}
	}
	return NULL;
}

/*
 * In the given uproc's hash table of probepoints, find the one with the
 * specified virtual address.  Runs with uproc->rwsem locked.
 */
static struct uprobe_probept *uprobe_find_probept(struct uprobe_process *uproc,
		unsigned long vaddr)
{
	struct uprobe_probept *ppt;
	struct hlist_node *node;
	struct hlist_head *head = &uproc->uprobe_table[hash_long(vaddr,
		UPROBE_HASH_BITS)];

	hlist_for_each_entry(ppt, node, head, ut_node) {
		if (ppt->vaddr == vaddr && ppt->state != UPROBE_DISABLED)
			return ppt;
	}
	return NULL;
}

/*
 * set_bp: Store a breakpoint instruction at ppt->vaddr.
 * Returns BP_INSN_SIZE on success.
 *
 * NOTE: BREAKPOINT_INSTRUCTION on all archs is the same size as
 * uprobe_opcode_t.
 */
static int set_bp(struct uprobe_probept *ppt, struct task_struct *tsk)
{
	uprobe_opcode_t bp_insn = BREAKPOINT_INSTRUCTION;
	return access_process_vm(tsk, ppt->vaddr, &bp_insn, BP_INSN_SIZE, 1);
}

/*
 * set_orig_insn:  For probepoint ppt, replace the breakpoint instruction
 * with the original opcode.  Returns BP_INSN_SIZE on success.
 */
static int set_orig_insn(struct uprobe_probept *ppt, struct task_struct *tsk)
{
	return access_process_vm(tsk, ppt->vaddr, &ppt->opcode, BP_INSN_SIZE,
		1);
}

static void bkpt_insertion_failed(struct uprobe_probept *ppt, const char *why)
{
	printk(KERN_ERR "Can't place uprobe at pid %d vaddr %#lx: %s\n",
			ppt->uproc->tgid, ppt->vaddr, why);
}

/*
 * Save a copy of the original instruction (so it can be single-stepped
 * out of line), insert the breakpoint instruction, and awake
 * register_uprobe().
 */
static void insert_bkpt(struct uprobe_probept *ppt, struct task_struct *tsk)
{
	struct uprobe_kimg *uk;
	long result = 0;
	int len;

	if (!tsk) {
		/* No surviving tasks associated with ppt->uproc */
		result = -ESRCH;
		goto out;
	}

	/*
	 * If access_process_vm() transfers fewer bytes than the maximum
	 * instruction size, assume that the probed instruction is smaller
	 * than the max and near the end of the last page of instructions.
	 * But there must be room at least for a breakpoint-size instruction.
	 */
	len = access_process_vm(tsk, ppt->vaddr, ppt->insn, MAX_UINSN_BYTES, 0);
	if (len < BP_INSN_SIZE) {
		bkpt_insertion_failed(ppt,
			"error reading original instruction");
		result = -EIO;
		goto out;
	}
	memcpy(&ppt->opcode, ppt->insn, BP_INSN_SIZE);
	if (ppt->opcode == BREAKPOINT_INSTRUCTION) {
		/*
		 * To avoid filling up the log file with complaints
		 * about breakpoints already existing, don't log this
		 * error.
		 */
		//bkpt_insertion_failed(ppt, "bkpt already exists at that addr");
		result = -EEXIST;
		goto out;
	}

	if ((result = arch_validate_probed_insn(ppt, tsk)) < 0) {
		bkpt_insertion_failed(ppt, "instruction type cannot be probed");
		goto out;
	}

	len = set_bp(ppt, tsk);
	if (len < BP_INSN_SIZE) {
		bkpt_insertion_failed(ppt, "failed to insert bkpt instruction");
		result = -EIO;
		goto out;
	}
out:
	ppt->state = (result ? UPROBE_DISABLED : UPROBE_BP_SET);
	list_for_each_entry(uk, &ppt->uprobe_list, list)
		uk->status = result;
	wake_up_all(&ppt->waitq);
}

static void remove_bkpt(struct uprobe_probept *ppt, struct task_struct *tsk)
{
	int len;

	if (tsk) {
		len = set_orig_insn(ppt, tsk);
		if (len < BP_INSN_SIZE) {
			printk(KERN_ERR
				"Error removing uprobe at pid %d vaddr %#lx:"
				" can't restore original instruction\n",
				tsk->tgid, ppt->vaddr);
			/*
			 * This shouldn't happen, since we were previously
			 * able to write the breakpoint at that address.
			 * There's not much we can do besides let the
			 * process die with a SIGTRAP the next time the
			 * breakpoint is hit.
			 */
		}
	}
	/* Wake up unregister_uprobe(). */
	ppt->state = UPROBE_DISABLED;
	wake_up_all(&ppt->waitq);
}

/*
 * Runs with all of uproc's threads quiesced and uproc->rwsem write-locked.
 * As specified, insert or remove the breakpoint instruction for each
 * uprobe_probept on uproc's pending list.
 * tsk = one of the tasks associated with uproc -- NULL if there are
 * no surviving threads.
 * It's OK for uproc->pending_uprobes to be empty here.  It can happen
 * if a register and an unregister are requested (by different probers)
 * simultaneously for the same pid/vaddr.
 * Note that the current task may be a thread in uproc, or it may be
 * a task running [un]register_uprobe() (or both).
 */
static void handle_pending_uprobes(struct uprobe_process *uproc,
	struct task_struct *tsk)
{
	struct uprobe_probept *ppt, *tmp;

	list_for_each_entry_safe(ppt, tmp, &uproc->pending_uprobes, pd_node) {
		switch (ppt->state) {
		case UPROBE_INSERTING:
			insert_bkpt(ppt, tsk);
			break;
		case UPROBE_REMOVING:
			remove_bkpt(ppt, tsk);
			break;
		default:
			BUG();
		}
		list_del(&ppt->pd_node);
	}
}

static void utask_adjust_flags(struct uprobe_task *utask, int set,
	unsigned long flags)
{
	unsigned long newflags, oldflags;

	newflags = oldflags = utask->engine->flags;

	if (set)
		newflags |= flags;
	else
		newflags &= ~flags;

	if (newflags != oldflags)
		utrace_set_flags(utask->tsk, utask->engine, newflags);
}

static inline void clear_utrace_quiesce(struct uprobe_task *utask)
{
	utask_adjust_flags(utask, CLEAR_ENGINE_FLAGS,
			UTRACE_ACTION_QUIESCE | UTRACE_EVENT(QUIESCE));
}

/* Opposite of quiesce_all_threads().  Same locking applies. */
static void rouse_all_threads(struct uprobe_process *uproc)
{
	struct uprobe_task *utask;

	list_for_each_entry(utask, &uproc->thread_list, list) {
		if (utask->quiescing) {
			utask->quiescing = 0;
			if (utask->state == UPTASK_QUIESCENT) {
				utask->state = UPTASK_RUNNING;
				uproc->n_quiescent_threads--;
				clear_utrace_quiesce(utask);
			}
		}
	}
	/* Wake any threads that decided to sleep rather than quiesce. */
	wake_up_all(&uproc->waitq);
}

/*
 * If all of uproc's surviving threads have quiesced, do the necessary
 * breakpoint insertions or removals and then un-quiesce everybody.
 * tsk is a surviving thread, or NULL if there is none.  Runs with
 * uproc->rwsem write-locked.
 */
static void check_uproc_quiesced(struct uprobe_process *uproc,
		struct task_struct *tsk)
{
	if (uproc->n_quiescent_threads >= uproc->nthreads) {
		handle_pending_uprobes(uproc, tsk);
		rouse_all_threads(uproc);
	}
}

/*
 * Quiesce all threads in the specified process -- e.g., prior to
 * breakpoint insertion.  Runs with uproc->rwsem write-locked.
 * Returns the number of threads that haven't died yet.
 */
static int quiesce_all_threads(struct uprobe_process *uproc,
		struct uprobe_task **cur_utask_quiescing)
{
	struct uprobe_task *utask;
	struct task_struct *survivor = NULL;	// any survivor
	int survivors = 0;

	*cur_utask_quiescing = NULL;
	list_for_each_entry(utask, &uproc->thread_list, list) {
		survivor = utask->tsk;
		survivors++;
		if (!utask->quiescing) {
			/*
			 * If utask is currently handling a probepoint, it'll
			 * check utask->quiescing and quiesce when it's done.
			 */
			utask->quiescing = 1;
			if (utask->tsk == current)
				*cur_utask_quiescing = utask;
			else if (utask->state == UPTASK_RUNNING) {
				utask->quiesce_master = current;
				utask_adjust_flags(utask, SET_ENGINE_FLAGS,
					UTRACE_ACTION_QUIESCE
					| UTRACE_EVENT(QUIESCE));
				utask->quiesce_master = NULL;
			}
		}
	}
	/*
	 * If any task was already quiesced (in utrace's opinion) when we
	 * called utask_adjust_flags() on it, uprobe_report_quiesce() was
	 * called, but wasn't in a position to call check_uproc_quiesced().
	 */
	check_uproc_quiesced(uproc, survivor);
	return survivors;
}

static void utask_free_uretprobe_instances(struct uprobe_task *utask)
{
	struct uretprobe_instance *ri;
	struct hlist_node *r1, *r2;

	hlist_for_each_entry_safe(ri, r1, r2, &utask->uretprobe_instances,
			hlist) {
		hlist_del(&ri->hlist);
		kfree(ri);
		uprobe_decref_process(utask->uproc);
	}
}

/* Called with utask->uproc write-locked. */
static void uprobe_free_task(struct uprobe_task *utask)
{
	struct deferred_registration *dr, *d;
	struct delayed_signal *ds, *ds2;

        /*    printk(KERN_INFO "uprobe_free_task %p (tid %ld), caller %pS, ctid %ld\n", utask, utask->tsk->pid, _RET_IP_, current->pid); */

        /*
         * Do this first, since a utask that's still in the utask_table
         * is assumed (e.g., by uprobe_report_exit) to be valid.
         */
	uprobe_unhash_utask(utask);
	list_del(&utask->list);
	list_for_each_entry_safe(dr, d, &utask->deferred_registrations, list) {
		list_del(&dr->list);
		kfree(dr);
	}

	list_for_each_entry_safe(ds, ds2, &utask->delayed_signals, list) {
		list_del(&ds->list);
		kfree(ds);
	}
	utask_free_uretprobe_instances(utask);

	kfree(utask);
}

/* Runs with uproc_mutex held and uproc->rwsem write-locked. */
static void uprobe_free_process(struct uprobe_process *uproc)
{
	struct uprobe_task *utask, *tmp;
	struct uprobe_ssol_area *area = &uproc->ssol_area;

        /* printk(KERN_INFO "uprobe_free_process %p (pid %ld), caller %pS, ctid %ld\n", uproc, uproc->tgid, _RET_IP_, current->pid); */

	if (!uproc->finished)
		uprobe_release_ssol_vma(uproc);
	if (area->slots)
		kfree(area->slots);
	if (!hlist_unhashed(&uproc->hlist))
		hlist_del(&uproc->hlist);
	list_for_each_entry_safe(utask, tmp, &uproc->thread_list, list) {
		/*
		 * utrace_detach() is OK here (required, it seems) even if
		 * utask->tsk == current and we're in a utrace callback.
		 */
		if (utask->engine)
			utrace_detach(utask->tsk, utask->engine);
		uprobe_free_task(utask);
	}
	up_write(&uproc->rwsem);	// So kfree doesn't complain
        /* printk(KERN_INFO "uprobe_free_process zap %p\n", uproc);*/
	kfree(uproc);
}

/*
 * Decrement uproc's ref count.  If it's zero, free uproc and return 1.
 * Else return 0.  If uproc is locked, don't call this; use
 * uprobe_decref_process().
 *
 * If we free uproc, we also decrement the ref-count on the uprobes
 * module, if any.  If somebody is doing "rmmod --wait uprobes", this
 * function could schedule removal of the module.  Therefore, don't call
 * this function and then sleep in uprobes code, unless you know you'll
 * return with the module ref-count > 0.
 */
static int uprobe_put_process(struct uprobe_process *uproc)
{
	int freed = 0;
	if (atomic_dec_and_test(&uproc->refcount)) {
		lock_uproc_table();
		down_write(&uproc->rwsem);
		if (unlikely(atomic_read(&uproc->refcount) != 0)) {
			/*
			 * The works because uproc_mutex is held any
			 * time the ref count can go from 0 to 1 -- e.g.,
			 * register_uprobe() snuck in with a new probe,
                         * or a callback such as uprobe_report_exit()
                         * just started.
			 */
			up_write(&uproc->rwsem);
		} else {
			uprobe_free_process(uproc);
			freed = 1;
		}
		unlock_uproc_table();
	}
	if (freed)
		module_put(THIS_MODULE);
	return freed;
}

static struct uprobe_kimg *uprobe_mk_kimg(struct uprobe *u)
{
	struct uprobe_kimg *uk = (struct uprobe_kimg*)kzalloc(sizeof *uk,
		GFP_USER);
	if (unlikely(!uk))
		return ERR_PTR(-ENOMEM);
	u->kdata = uk;
	uk->uprobe = u;
	uk->ppt = NULL;
	INIT_LIST_HEAD(&uk->list);
	uk->status = -EBUSY;
	return uk;
}

/*
 * Allocate a uprobe_task object for t and add it to uproc's list.
 * Called with t "got" and uproc->rwsem write-locked.  Called in one of
 * the following cases:
 * - before setting the first uprobe in t's process
 * - we're in uprobe_report_clone() and t is the newly added thread
 * Returns:
 * - pointer to new uprobe_task on success
 * - NULL if t dies before we can utrace_attach it
 * - negative errno otherwise
 */
static struct uprobe_task *uprobe_add_task(struct task_struct *t,
		struct uprobe_process *uproc)
{
	struct uprobe_task *utask;
	struct utrace_attached_engine *engine;

	utask = (struct uprobe_task *)kzalloc(sizeof *utask, GFP_USER);
	if (unlikely(utask == NULL))
		return ERR_PTR(-ENOMEM);

	utask->tsk = t;
	utask->state = UPTASK_RUNNING;
	utask->quiescing = 0;
	utask->uproc = uproc;
	utask->active_probe = NULL;
	utask->doomed = 0;
	INIT_HLIST_HEAD(&utask->uretprobe_instances);
	INIT_LIST_HEAD(&utask->deferred_registrations);
	INIT_LIST_HEAD(&utask->delayed_signals);
	INIT_LIST_HEAD(&utask->list);
	list_add_tail(&utask->list, &uproc->thread_list);
	uprobe_hash_utask(utask);

	engine = utrace_attach(t, UTRACE_ATTACH_CREATE, p_uprobe_utrace_ops,
		utask);
	if (IS_ERR(engine)) {
		long err = PTR_ERR(engine);
		printk("uprobes: utrace_attach failed, returned %ld\n", err);
		uprobe_free_task(utask);
		if (err == -ESRCH)
			 return NULL;
		return ERR_PTR(err);
	}
	utask->engine = engine;
	/*
	 * Always watch for traps, clones, execs and exits. Caller must
	 * set any other engine flags.
	 */
	utask_adjust_flags(utask, SET_ENGINE_FLAGS,
			UTRACE_EVENT(SIGNAL) | UTRACE_EVENT(SIGNAL_IGN) |
			UTRACE_EVENT(SIGNAL_CORE) | UTRACE_EVENT(EXEC) |
			UTRACE_EVENT(CLONE) | UTRACE_EVENT(EXIT));
	/*
	 * Note that it's OK if t dies just after utrace_attach, because
	 * with the engine in place, the appropriate report_* callback
	 * should handle it after we release uproc->rwsem.
	 */
	return utask;
}

/* See comment in uprobe_mk_process(). */
static struct task_struct *find_next_thread_to_add(struct uprobe_process *uproc,		struct task_struct *start)
{
	struct task_struct *t;
	struct uprobe_task *utask;

	read_lock(&tasklist_lock);
	t = start;
	do {
		if (unlikely(t->flags & PF_EXITING))
			goto dont_add;
		list_for_each_entry(utask, &uproc->thread_list, list) {
			if (utask->tsk == t)
				/* Already added */
				goto dont_add;
		}
		/* Found thread/task to add. */
		get_task_struct(t);
		read_unlock(&tasklist_lock);
		return t;
dont_add:
		t = next_thread(t);
	} while (t != start);

	read_unlock(&tasklist_lock);
	return NULL;
}

/*
 * Create a per process uproc struct.
 * at_fork: indicates uprobe_mk_process is called from
 * a fork context of a probe process. refer uprobe_fork_uproc
 * for more details.
 *
 * Runs with uproc_mutex held;
 * Returns with uproc->rwsem write-locked when not called
 * from fork context.
 */
static struct uprobe_process *uprobe_mk_process(struct task_struct *p,
						bool at_fork)
{
	struct uprobe_process *uproc;
	struct uprobe_task *utask;
	struct task_struct *add_me;
	int i;
	long err;

	uproc = (struct uprobe_process *)kzalloc(sizeof *uproc, GFP_USER);
	if (unlikely(uproc == NULL))
		return ERR_PTR(-ENOMEM);

	/* Initialize fields */
	atomic_set(&uproc->refcount, 1);
	init_rwsem(&uproc->rwsem);
	if (!at_fork)
		/* not called from fork context. */
		down_write(&uproc->rwsem);
	init_waitqueue_head(&uproc->waitq);
	for (i = 0; i < UPROBE_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&uproc->uprobe_table[i]);
	uproc->nppt = 0;
	INIT_LIST_HEAD(&uproc->pending_uprobes);
	INIT_LIST_HEAD(&uproc->thread_list);
	uproc->nthreads = 0;
	uproc->n_quiescent_threads = 0;
	INIT_HLIST_NODE(&uproc->hlist);
	uproc->tgid = p->tgid;
	uproc->finished = 0;
	uproc->uretprobe_trampoline_addr = NULL;

	uproc->ssol_area.insn_area = NULL;
	uproc->ssol_area.initialized = 0;
	mutex_init(&uproc->ssol_area.setup_mutex);
	/* Initialize rest of area in uprobe_init_ssol(). */
#ifdef CONFIG_UPROBES_SSOL
	uproc->sstep_out_of_line = 1;
#else
	uproc->sstep_out_of_line = 0;
#endif

	/*
	 * Create and populate one utask per thread in this process.  We
	 * can't call uprobe_add_task() while holding tasklist_lock, so we:
	 *	1. Lock task list.
	 *	2. Find the next task, add_me, in this process that's not
	 *	already on uproc's thread_list.  (Start search at previous
	 *	one found.)
	 *	3. Unlock task list.
	 *	4. uprobe_add_task(add_me, uproc)
	 *	Repeat 1-4 'til we have utasks for all tasks.
	 */
	add_me = p;
	while ((add_me = find_next_thread_to_add(uproc, add_me)) != NULL) {
		utask = uprobe_add_task(add_me, uproc);
		put_task_struct(add_me);
		if (IS_ERR(utask)) {
			err = PTR_ERR(utask);
			goto fail;
		}
		if (utask)
			uproc->nthreads++;
	}

	if (uproc->nthreads == 0) {
		/* All threads -- even p -- are dead. */
		err = -ESRCH;
		goto fail;
	}
	return uproc;

fail:
	uprobe_free_process(uproc);
	return ERR_PTR(err);
}

/*
 * Creates a uprobe_probept and connects it to uk and uproc.  Runs with
 * uproc->rwsem write-locked.
 */
static struct uprobe_probept *uprobe_add_probept(struct uprobe_kimg *uk,
	struct uprobe_process *uproc)
{
	struct uprobe_probept *ppt;

	ppt = (struct uprobe_probept *)kzalloc(sizeof *ppt, GFP_USER);
	if (unlikely(ppt == NULL))
		return ERR_PTR(-ENOMEM);
	init_waitqueue_head(&ppt->waitq);
	mutex_init(&ppt->ssil_mutex);
	mutex_init(&ppt->slot_mutex);
	ppt->slot = NULL;

	/* Connect to uk. */
	INIT_LIST_HEAD(&ppt->uprobe_list);
	list_add_tail(&uk->list, &ppt->uprobe_list);
	uk->ppt = ppt;
	uk->status = -EBUSY;
	ppt->vaddr = uk->uprobe->vaddr;

	/* Connect to uproc. */
	ppt->state = UPROBE_INSERTING;
	ppt->uproc = uproc;
	INIT_LIST_HEAD(&ppt->pd_node);
	list_add_tail(&ppt->pd_node, &uproc->pending_uprobes);
	INIT_HLIST_NODE(&ppt->ut_node);
	hlist_add_head(&ppt->ut_node,
		&uproc->uprobe_table[hash_long(ppt->vaddr, UPROBE_HASH_BITS)]);
	uproc->nppt++;
	uprobe_get_process(uproc);
	return ppt;
}

/* ppt is going away.  Free its slot (if it owns one) in the SSOL area. */
static void uprobe_free_slot(struct uprobe_probept *ppt)
{
	struct uprobe_ssol_slot *slot = ppt->slot;
	if (slot) {
		down_write(&slot->rwsem);
		if (slot->owner == ppt) {
			unsigned long flags;
			struct uprobe_ssol_area *area = &ppt->uproc->ssol_area;
			spin_lock_irqsave(&area->lock, flags);
			slot->state = SSOL_FREE;
			slot->owner = NULL;
			area->nfree++;
			spin_unlock_irqrestore(&area->lock, flags);
		}
		up_write(&slot->rwsem);
	}
}

/*
 * Runs with ppt->uproc write-locked.  Frees ppt and decrements the ref count
 * on ppt->uproc (but ref count shouldn't hit 0).
 */
static void uprobe_free_probept(struct uprobe_probept *ppt)
{
	struct uprobe_process *uproc = ppt->uproc;
	uprobe_free_slot(ppt);
	hlist_del(&ppt->ut_node);
	uproc->nppt--;
	kfree(ppt);
	uprobe_decref_process(uproc);
}

static void uprobe_free_kimg(struct uprobe_kimg *uk)
{
	uk->uprobe->kdata = NULL;
	kfree(uk);
}

/*
 * Runs with uprobe_process write-locked.
 * Note that we never free u, because the user owns that.
 */
static void purge_uprobe(struct uprobe_kimg *uk)
{
	struct uprobe_probept *ppt = uk->ppt;
	list_del(&uk->list);
	uprobe_free_kimg(uk);
	if (list_empty(&ppt->uprobe_list))
		uprobe_free_probept(ppt);
}

/* TODO: Avoid code duplication with uprobe_validate_vaddr(). */
static int uprobe_validate_vma(struct task_struct *t, unsigned long vaddr)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	int ret = 0;

	mm = get_task_mm(t);
	if (!mm)
		return -EINVAL;
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, vaddr);
	if (!vma || vaddr < vma->vm_start)
		ret = -ENOENT;
	else if (!(vma->vm_flags & VM_EXEC))
		ret = -EFAULT;
	up_read(&mm->mmap_sem);
	mmput(mm);
	return ret;
}

/* Probed address must be in an executable VM area, outside the SSOL area. */
static int uprobe_validate_vaddr(struct task_struct *p, unsigned long vaddr,
	struct uprobe_process *uproc)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = p->mm;
	if (!mm)
		return -EINVAL;
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, vaddr);
	if (!vma || vaddr < vma->vm_start || !(vma->vm_flags & VM_EXEC)
	    || vma->vm_start == (unsigned long) uproc->ssol_area.insn_area) {
		up_read(&mm->mmap_sem);
		return -EINVAL;
	}
	up_read(&mm->mmap_sem);
	return 0;
}

static struct task_struct *uprobe_get_task(pid_t pid)
{
	struct task_struct *p;
	rcu_read_lock();
	p = find_task_by_pid(pid);
	if (p)
		get_task_struct(p);
	rcu_read_unlock();
	return p;
}

/* Runs with utask->uproc read-locked.  Returns -EINPROGRESS on success. */
static int defer_registration(struct uprobe *u, int regflag,
		struct uprobe_task *utask)
{
	struct deferred_registration *dr =
		kmalloc(sizeof(struct deferred_registration), GFP_USER);
	if (!dr)
		return -ENOMEM;
	dr->type = (is_uretprobe(u) ? UPTY_URETPROBE : UPTY_UPROBE);
	dr->uprobe = u;
	dr->regflag = regflag;
	INIT_LIST_HEAD(&dr->list);
	list_add_tail(&dr->list, &utask->deferred_registrations);
	return -EINPROGRESS;
}

/* See Documentation/uprobes.txt. */
int register_uprobe(struct uprobe *u)
{
	struct task_struct *p;
	struct uprobe_process *uproc;
	struct uprobe_kimg *uk;
	struct uprobe_probept *ppt;
	struct uprobe_task *cur_utask, *cur_utask_quiescing = NULL;
	int survivors, ret = 0, uproc_is_new = 0;
	if (!u || !u->handler)
		return -EINVAL;

	p = uprobe_get_task(u->pid);
	if (!p)
		return -ESRCH;

	cur_utask = uprobe_find_utask(current);
	if (cur_utask && cur_utask->active_probe) {
		/*
		 * Called from handler; cur_utask->uproc is read-locked.
		 * Do this registration later.
		 */
		put_task_struct(p);
		return defer_registration(u, 1, cur_utask);
	}

	/* Get the uprobe_process for this pid, or make a new one. */
	lock_uproc_table();
	uproc = uprobe_find_process(p->tgid);

	if (uproc)
		unlock_uproc_table();
	else {
		/* Creating a new uprobe_process.  Ref-count the module. */
		if (!try_module_get(THIS_MODULE)) {
			/* uprobes.ko is being removed. */
			ret = -ENOSYS;
			unlock_uproc_table();
			goto fail_tsk;
		}
		uproc = uprobe_mk_process(p, 0);
		if (IS_ERR(uproc)) {
			ret = (int) PTR_ERR(uproc);
			unlock_uproc_table();
			module_put(THIS_MODULE);
			goto fail_tsk;
		}
		/* Hold uproc_mutex until we've added uproc to uproc_table. */
		uproc_is_new = 1;
	}

	if (is_uretprobe(u) && IS_ERR(uproc->uretprobe_trampoline_addr)) {
		/* Previously failed to set up trampoline. */
		ret = -ENOMEM;
		goto fail_uproc;
	}

	if ((ret = uprobe_validate_vaddr(p, u->vaddr, uproc)) < 0)
		goto fail_uproc;

	if (u->kdata) {
		/*
		 * Probe is already/still registered.  This is the only
		 * place we return -EBUSY to the user.
		 */
		ret = -EBUSY;
		goto fail_uproc;
	}

	uk = uprobe_mk_kimg(u);
	if (IS_ERR(uk)) {
		ret = (int) PTR_ERR(uk);
		goto fail_uproc;
	}

	/* See if we already have a probepoint at the vaddr. */
	ppt = (uproc_is_new ? NULL : uprobe_find_probept(uproc, u->vaddr));
	if (ppt) {
		/* Breakpoint is already in place, or soon will be. */
		uk->ppt = ppt;
		list_add_tail(&uk->list, &ppt->uprobe_list);
		switch (ppt->state) {
		case UPROBE_INSERTING:
			uk->status = -EBUSY;	// in progress
			if (uproc->tgid == current->tgid) {
				cur_utask_quiescing = cur_utask;
				BUG_ON(!cur_utask_quiescing);
			}
			break;
		case UPROBE_REMOVING:
			/* Wait!  Don't remove that bkpt after all! */
			ppt->state = UPROBE_BP_SET;
			list_del(&ppt->pd_node);  // Remove from pending list.
			wake_up_all(&ppt->waitq); // Wake unregister_uprobe().
			/*FALLTHROUGH*/
		case UPROBE_BP_SET:
			uk->status = 0;
			break;
		default:
			BUG();
		}
		up_write(&uproc->rwsem);
		put_task_struct(p);
		if (uk->status == 0) {
			uprobe_put_process(uproc);
			return 0;
		}
		goto await_bkpt_insertion;
	} else {
		ppt = uprobe_add_probept(uk, uproc);
		if (IS_ERR(ppt)) {
			ret = (int) PTR_ERR(ppt);
			goto fail_uk;
		}
	}

	if (uproc_is_new) {
		hlist_add_head(&uproc->hlist,
			&uproc_table[hash_long(uproc->tgid, UPROBE_HASH_BITS)]);
		unlock_uproc_table();
	}
	put_task_struct(p);
	survivors = quiesce_all_threads(uproc, &cur_utask_quiescing);

	if (survivors == 0) {
		purge_uprobe(uk);
		up_write(&uproc->rwsem);
		uprobe_put_process(uproc);
		return -ESRCH;
	}
	up_write(&uproc->rwsem);

await_bkpt_insertion:
	if (cur_utask_quiescing)
		/* Current task is probing its own process. */
		(void) utask_fake_quiesce(cur_utask_quiescing);
	else
		wait_event(ppt->waitq, ppt->state != UPROBE_INSERTING);
	ret = uk->status;
	if (ret != 0) {
		down_write(&uproc->rwsem);
		purge_uprobe(uk);
		up_write(&uproc->rwsem);
	}
	uprobe_put_process(uproc);
	return ret;

fail_uk:
	uprobe_free_kimg(uk);

fail_uproc:
	if (uproc_is_new) {
		uprobe_free_process(uproc);
		unlock_uproc_table();
		module_put(THIS_MODULE);
	} else {
		up_write(&uproc->rwsem);
		uprobe_put_process(uproc);
	}

fail_tsk:
	put_task_struct(p);
	return ret;
}
EXPORT_SYMBOL_GPL(register_uprobe);

void __unregister_uprobe(struct uprobe *u, bool remove_bkpt)
{
	struct task_struct *p;
	struct uprobe_process *uproc;
	struct uprobe_kimg *uk;
	struct uprobe_probept *ppt;
	struct uprobe_task *cur_utask, *cur_utask_quiescing = NULL;

	if (!u)
		return;
	p = uprobe_get_task(u->pid);
	if (!p)
		return;

	cur_utask = uprobe_find_utask(current);
	if (cur_utask && cur_utask->active_probe) {
		/* Called from handler; uproc is read-locked; do this later */
		put_task_struct(p);
		(void) defer_registration(u, 0, cur_utask);
		return;
	}

	/*
	 * Lock uproc before walking the graph, in case the process we're
	 * probing is exiting.
	 */
	lock_uproc_table();
	uproc = uprobe_find_process(p->tgid);
	unlock_uproc_table();
	put_task_struct(p);
	if (!uproc)
		return;

	uk = (struct uprobe_kimg *)u->kdata;
	if (!uk)
		/*
		 * This probe was never successfully registered, or
		 * has already been unregistered.
		 */
		goto done;
	if (uk->status == -EBUSY)
		/* Looks like register or unregister is already in progress. */
		goto done;
	ppt = uk->ppt;

	list_del(&uk->list);
	uprobe_free_kimg(uk);

	if (is_uretprobe(u))
		zap_uretprobe_instances(u, uproc);

	if (!list_empty(&ppt->uprobe_list))
		goto done;

	/* The last uprobe at ppt's probepoint is being unregistered. */
	if (!remove_bkpt) {
		uprobe_free_probept(ppt);
		goto done;
	}

	/* Queue the breakpoint for removal. */
	ppt->state = UPROBE_REMOVING;
	list_add_tail(&ppt->pd_node, &uproc->pending_uprobes);

	(void) quiesce_all_threads(uproc, &cur_utask_quiescing);
	up_write(&uproc->rwsem);
	if (cur_utask_quiescing)
		/* Current task is probing its own process. */
		(void) utask_fake_quiesce(cur_utask_quiescing);
	else
		wait_event(ppt->waitq, ppt->state != UPROBE_REMOVING);

	if (likely(ppt->state == UPROBE_DISABLED)) {
		down_write(&uproc->rwsem);
		uprobe_free_probept(ppt);
		/* else somebody else's register_uprobe() resurrected ppt. */
		up_write(&uproc->rwsem);
	}
	uprobe_put_process(uproc);
	return;

done:
	up_write(&uproc->rwsem);
	uprobe_put_process(uproc);
}

/* See Documentation/uprobes.txt. */
void unregister_uprobe(struct uprobe *u)
{
	__unregister_uprobe(u, true);
}
EXPORT_SYMBOL_GPL(unregister_uprobe);

void unmap_uprobe(struct uprobe *u)
{
	__unregister_uprobe(u, false);
}
EXPORT_SYMBOL_GPL(unmap_uprobe);

/* Find a surviving thread in uproc.  Runs with uproc->rwsem locked. */
static struct task_struct *find_surviving_thread(struct uprobe_process *uproc)
{
	struct uprobe_task *utask;

	list_for_each_entry(utask, &uproc->thread_list, list)
		return utask->tsk;
	return NULL;
}

/*
 * Run all the deferred_registrations previously queued by the current utask.
 * Runs with no locks or mutexes held.  The current utask's uprobe_process
 * is ref-counted, so they won't disappear as the result of
 * unregister_u*probe() called here.
 */
static void uprobe_run_def_regs(struct list_head *drlist)
{
	struct deferred_registration *dr, *d;

	list_for_each_entry_safe(dr, d, drlist, list) {
		int result = 0;
		struct uprobe *u = dr->uprobe;

		if (dr->type == UPTY_URETPROBE) {
			struct uretprobe *rp =
				container_of(u, struct uretprobe, u);
			if (dr->regflag)
				result = register_uretprobe(rp);
			else
				unregister_uretprobe(rp);
		} else {
			if (dr->regflag)
				result = register_uprobe(u);
			else
				unregister_uprobe(u);
		}
		if (u && u->registration_callback)
			u->registration_callback(u, dr->regflag, dr->type,
					result);
		list_del(&dr->list);
		kfree(dr);
	}
}

/*
 * Functions for allocation of the SSOL area, and the instruction slots
 * therein
 */

/*
 * We leave the SSOL vma in place even after all the probes are gone.
 * We used to remember its address in current->mm->context.uprobes_ssol_area,
 * but adding that field to mm_context broke KAPI compatibility.
 * Instead, when we shut down the uproc for lack of probes, we "tag" the vma
 * for later identification.  This is not particularly robust, but it's
 * no more vulnerable to ptrace or mprotect mischief than any other part
 * of the address space.
 */
#define UPROBES_SSOL_VMA_TAG \
	"This is the SSOL area for uprobes.  Mess with it at your own risk."
#define UPROBES_SSOL_TAGSZ ((int)sizeof(UPROBES_SSOL_VMA_TAG))

/*
 * Searching downward from ceiling address (0 signifies top of memory),
 * find the next vma whose flags indicate it could be an SSOL area.
 * Return its address, or 0 for no match.
 */
static unsigned long find_next_possible_ssol_vma(unsigned long ceiling)
{
	struct mm_struct *mm = current->mm;
	struct rb_node *rb_node;
	struct vm_area_struct *vma;
	unsigned long good_flags = VM_EXEC | VM_DONTEXPAND;
	unsigned long bad_flags = VM_WRITE | VM_GROWSDOWN | VM_GROWSUP;
	unsigned long addr = 0;

	down_read(&mm->mmap_sem);
	for (rb_node=rb_last(&mm->mm_rb); rb_node; rb_node=rb_prev(rb_node)) {
		vma = rb_entry(rb_node, struct vm_area_struct, vm_rb);
		if (ceiling && vma->vm_start >= ceiling)
			continue;
		if ((vma->vm_flags & good_flags) != good_flags)
			continue;
		if ((vma->vm_flags & bad_flags) != 0)
			continue;
		addr = vma->vm_start;
		break;
	}
	up_read(&mm->mmap_sem);
	return addr;
}

static noinline unsigned long find_old_ssol_vma(void)
{
	unsigned long addr;
	unsigned long ceiling = 0;	// top of memory
	char buf[UPROBES_SSOL_TAGSZ];
	while ((addr = find_next_possible_ssol_vma(ceiling)) != 0) {
		ceiling = addr;
		if (copy_from_user(buf, (const void __user*)addr,
						UPROBES_SSOL_TAGSZ))
			continue;
		if (!strcmp(buf, UPROBES_SSOL_VMA_TAG))
			return addr;
	}
	return 0;
}

/*
 * Mmap nbytes bytes for the uprobes SSOL area for the current process.
 * Returns the address of the page, or a negative errno.
 * This approach was suggested by Roland McGrath.
 */
static noinline unsigned long uprobe_setup_ssol_vma(unsigned long nbytes)
{
	unsigned long addr;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	BUG_ON(nbytes & ~PAGE_MASK);
	if ((addr = find_old_ssol_vma()) != 0)
		return addr;

	down_write(&mm->mmap_sem);
	/*
	 * Find the end of the top mapping and skip a page.
	 * If there is no space for PAGE_SIZE above
	 * that, mmap will ignore our address hint.
	 */
	vma = rb_entry(rb_last(&mm->mm_rb), struct vm_area_struct, vm_rb);
	addr = vma->vm_end + PAGE_SIZE;
	addr = do_mmap_pgoff(NULL, addr, nbytes, PROT_EXEC,
					MAP_PRIVATE|MAP_ANONYMOUS, 0);
	if (addr & ~PAGE_MASK) {
		up_write(&mm->mmap_sem);
		printk(KERN_ERR "Uprobes failed to allocate a vma for"
			" pid/tgid %d/%d for single-stepping out of line.\n",
			current->pid, current->tgid);
		return addr;
	}

	vma = find_vma(mm, addr);
	BUG_ON(!vma);
	/*
	 * Don't expand vma on mremap().  Allow vma to be copied on
	 * fork() -- see uprobe_fork_uproc().
	 */
	vma->vm_flags |= VM_DONTEXPAND;

	up_write(&mm->mmap_sem);
	return addr;
}

/**
 * uprobe_init_ssol -- initialize per-process area for single stepping
 * out-of-line.
 * @uproc:	probed process
 * @tsk:	probed task: must be current if @insn_area is %NULL
 * @insn_area:	virtual address of the already-established SSOL vma --
 * see uprobe_fork_uproc().
 *
 * Returns with @uproc->ssol_area.insn_area pointing to the initialized
 * area, or set to a negative errno.
 */
static void uprobe_init_ssol(struct uprobe_process *uproc,
	struct task_struct *tsk, __user uprobe_opcode_t *insn_area)
{
	struct uprobe_ssol_area *area = &uproc->ssol_area;
	struct uprobe_ssol_slot *slot;
	int i;
	char *slot_addr;	// Simplify pointer arithmetic

	/* Trampoline setup will either fail or succeed here. */
	uproc->uretprobe_trampoline_addr = ERR_PTR(-ENOMEM);

	if (insn_area) {
		BUG_ON(IS_ERR(insn_area));
		area->insn_area = insn_area;
	} else {
		BUG_ON(tsk != current);
		area->insn_area =
			(uprobe_opcode_t *) uprobe_setup_ssol_vma(PAGE_SIZE);
		if (IS_ERR(area->insn_area))
			return;
	}

	area->nfree = area->nslots = PAGE_SIZE / MAX_UINSN_BYTES;
	if (area->nslots > MAX_SSOL_SLOTS)
		area->nfree = area->nslots = MAX_SSOL_SLOTS;
	area->slots = (struct uprobe_ssol_slot *)
		kzalloc(sizeof(struct uprobe_ssol_slot) * area->nslots,
								GFP_USER);
	if (!area->slots) {
		area->insn_area = ERR_PTR(-ENOMEM);
		return;
	}
	mutex_init(&area->populate_mutex);
	spin_lock_init(&area->lock);
	area->next_slot = 0;
	slot_addr = (char*) area->insn_area;
	for (i = 0; i < area->nslots; i++) {
		slot = &area->slots[i];
		init_rwsem(&slot->rwsem);
		slot->state = SSOL_FREE;
		slot->owner = NULL;
		slot->last_used = 0;
		slot->insn = (__user uprobe_opcode_t *) slot_addr;
		slot_addr += MAX_UINSN_BYTES;
	}
	uretprobe_set_trampoline(uproc, tsk);
}

/*
 * Verify that the SSOL area has been set up for uproc.  Returns a
 * pointer to the SSOL area, or a negative erro if we couldn't set it up.
 */
static __user uprobe_opcode_t
			*uprobe_verify_ssol(struct uprobe_process *uproc)
{
	struct uprobe_ssol_area *area = &uproc->ssol_area;

	if (unlikely(!area->initialized)) {
		/* First time through for this probed process */
		mutex_lock(&uproc->ssol_area.setup_mutex);
		if (likely(!area->initialized)) {
			/* Nobody snuck in and set things up ahead of us. */
			uprobe_init_ssol(uproc, current, NULL);
			area->initialized = 1;
		}
		mutex_unlock(&uproc->ssol_area.setup_mutex);
	}
	return area->insn_area;
}

/*
 * uproc is going away, but the process lives on.  Tag the SSOL vma so a new
 * uproc can reuse it if more probes are requested.
 */
static void uprobe_release_ssol_vma(struct uprobe_process *uproc)
{
	unsigned long addr;
	struct task_struct *tsk;
	static const char *buf = UPROBES_SSOL_VMA_TAG;
	int nb;

	/* No need to muck with dying image's mm_struct. */
	BUG_ON(uproc->finished);
	addr = (unsigned long) uproc->ssol_area.insn_area;
	if (!addr || IS_ERR_VALUE(addr))
		return;
	tsk = find_surviving_thread(uproc);
	if (!tsk)
		return;
	nb = access_process_vm(tsk, addr, (void*)buf, UPROBES_SSOL_TAGSZ, 1);
	if (nb != UPROBES_SSOL_TAGSZ)
		printk(KERN_ERR "Failed to tag uprobes SSOL vma: "
			"pid/tgid=%d/%d, vaddr=%#lx\n", tsk->pid, tsk->tgid,
			addr);
}

static inline int advance_slot(int slot, struct uprobe_ssol_area *area)
{
	/* Slot 0 is reserved for uretprobe trampoline. */
	slot++;
	if (unlikely(slot >= area->nslots))
		slot = 1;
	return slot;
}

/*
 * Return the slot number of the least-recently-used slot in the
 * neighborhood of area->next_slot.  Limit the number of slots we test
 * to keep it fast.  Nobody dies if this isn't the best choice.
 */
static int uprobe_lru_insn_slot(struct uprobe_ssol_area *area)
{
#define MAX_LRU_TESTS 10
	struct uprobe_ssol_slot *s;
	int lru_slot = -1;
	unsigned long lru_time = ULONG_MAX;
	int nr_lru_tests = 0;
	int slot = area->next_slot;
	do {
		s = &area->slots[slot];
		if (likely(s->state == SSOL_ASSIGNED)) {
			if( lru_time > s->last_used) {
				lru_time = s->last_used;
				lru_slot = slot;
			}
			if (++nr_lru_tests >= MAX_LRU_TESTS)
				break;
		}
		slot = advance_slot(slot, area);
	} while (slot != area->next_slot);

	if (unlikely(lru_slot < 0))
		/* All slots are in the act of being stolen.  Join the melee. */
		return area->next_slot;
	else
		return lru_slot;
}

/*
 * Choose an instruction slot and take it.  Choose a free slot if there is one.
 * Otherwise choose the least-recently-used slot.  Returns with slot
 * read-locked and containing the desired instruction.  Runs with
 * ppt->slot_mutex locked.
 */
static struct uprobe_ssol_slot
		*uprobe_take_insn_slot(struct uprobe_probept *ppt)
{
	struct uprobe_process *uproc = ppt->uproc;
	struct uprobe_ssol_area *area = &uproc->ssol_area;
	struct uprobe_ssol_slot *s;
	int len, slot;
	unsigned long flags;

	spin_lock_irqsave(&area->lock, flags);

	if (area->nfree) {
		for (slot = 0; slot < area->nslots; slot++) {
			if (area->slots[slot].state == SSOL_FREE) {
				area->nfree--;
				goto found_slot;
			}
		}
		/* Shouldn't get here.  Fix nfree and get on with life. */
		area->nfree = 0;
	}
	slot = uprobe_lru_insn_slot(area);

found_slot:
	area->next_slot = advance_slot(slot, area);
	s = &area->slots[slot];
	s->state = SSOL_BEING_STOLEN;

	spin_unlock_irqrestore(&area->lock, flags);

	/* Wait for current users of slot to finish. */
	down_write(&s->rwsem);
	ppt->slot = s;
	s->owner = ppt;
	s->last_used = jiffies;
	s->state = SSOL_ASSIGNED;
	/* Copy the original instruction to the chosen slot. */
	mutex_lock(&area->populate_mutex);
	len = access_process_vm(current, (unsigned long)s->insn,
					 ppt->insn, MAX_UINSN_BYTES, 1);
	mutex_unlock(&area->populate_mutex);
        if (unlikely(len < MAX_UINSN_BYTES)) {
		up_write(&s->rwsem);
		printk(KERN_ERR "Failed to copy instruction at %#lx"
			" to SSOL area (%#lx)\n", ppt->vaddr,
			(unsigned long) area->slots);
		return NULL;
	}
	/* Let other threads single-step in this slot. */
	downgrade_write(&s->rwsem);
	return s;
}

/* ppt doesn't own a slot.  Get one for ppt, and return it read-locked. */
static struct uprobe_ssol_slot
		*uprobe_find_insn_slot(struct uprobe_probept *ppt)
{
	struct uprobe_ssol_slot *slot;

	mutex_lock(&ppt->slot_mutex);
	slot = ppt->slot;
	if (unlikely(slot && slot->owner == ppt)) {
		/* Looks like another thread snuck in and got a slot for us. */
		down_read(&slot->rwsem);
		if (likely(slot->owner == ppt)) {
			slot->last_used = jiffies;
			mutex_unlock(&ppt->slot_mutex);
			return slot;
		}
		/* ... but then somebody stole it. */
		up_read(&slot->rwsem);
	}
	slot = uprobe_take_insn_slot(ppt);
	mutex_unlock(&ppt->slot_mutex);
	return slot;
}

/*
 * Ensure that ppt owns an instruction slot for single-stepping.
 * Returns with the slot read-locked and ppt->slot pointing at it.
 */
static
struct uprobe_ssol_slot *uprobe_get_insn_slot(struct uprobe_probept *ppt)
{
	struct uprobe_ssol_slot *slot;

retry:
	slot = ppt->slot;
	if (unlikely(!slot))
		return uprobe_find_insn_slot(ppt);

	down_read(&slot->rwsem);
	if (unlikely(slot != ppt->slot)) {
		up_read(&slot->rwsem);
		goto retry;
	}
	if (unlikely(slot->owner != ppt)) {
		up_read(&slot->rwsem);
		return uprobe_find_insn_slot(ppt);
	}
	slot->last_used = jiffies;
	return slot;
}

/*
 * utrace engine report callbacks
 */

/*
 * We've been asked to quiesce, but aren't in a position to do so.
 * This could happen in either of the following cases:
 *
 * 1) Our own thread is doing a register or unregister operation --
 * e.g., as called from a u[ret]probe handler or a non-uprobes utrace
 * callback.  We can't wait_event() for ourselves in [un]register_uprobe().
 *
 * 2) We've been asked to quiesce, but we hit a probepoint first.  Now
 * we're in the report_signal callback, having handled the probepoint.
 * We'd like to just set the UTRACE_ACTION_QUIESCE and
 * UTRACE_EVENT(QUIESCE) flags and coast into quiescence.  Unfortunately,
 * it's possible to hit a probepoint again before we quiesce.  When
 * processing the SIGTRAP, utrace would call uprobe_report_quiesce(),
 * which must decline to take any action so as to avoid removing the
 * uprobe just hit.  As a result, we could keep hitting breakpoints
 * and never quiescing.
 *
 * So here we do essentially what we'd prefer to do in uprobe_report_quiesce().
 * If we're the last thread to quiesce, handle_pending_uprobes() and
 * rouse_all_threads().  Otherwise, pretend we're quiescent and sleep until
 * the last quiescent thread handles that stuff and then wakes us.
 *
 * Called and returns with no mutexes held.  Returns 1 if we free utask->uproc,
 * else 0.
 */
static int utask_fake_quiesce(struct uprobe_task *utask)
{
	struct uprobe_process *uproc = utask->uproc;
	enum uprobe_task_state prev_state = utask->state;

	down_write(&uproc->rwsem);

	/* In case we're somehow set to quiesce for real... */
	clear_utrace_quiesce(utask);

	if (uproc->n_quiescent_threads == uproc->nthreads-1) {
		/* We're the last thread to "quiesce." */
		handle_pending_uprobes(uproc, utask->tsk);
		rouse_all_threads(uproc);
		up_write(&uproc->rwsem);
		return 0;
	} else {
		utask->state = UPTASK_SLEEPING;
		uproc->n_quiescent_threads++;
		up_write(&uproc->rwsem);
		/* We ref-count sleepers. */
		uprobe_get_process(uproc);

		wait_event(uproc->waitq, !utask->quiescing);

		down_write(&uproc->rwsem);
		utask->state = prev_state;
		uproc->n_quiescent_threads--;
		up_write(&uproc->rwsem);

		/*
		 * If uproc's last uprobe has been unregistered, and
		 * unregister_uprobe() woke up before we did, it's up
		 * to us to free uproc.
		 */
		return uprobe_put_process(uproc);
	}
}

/* Prepare to single-step ppt's probed instruction inline. */
static inline void uprobe_pre_ssin(struct uprobe_task *utask,
	struct uprobe_probept *ppt, struct pt_regs *regs)
{
	int len;
	arch_reset_ip_for_sstep(regs);
	mutex_lock(&ppt->ssil_mutex);
	len = set_orig_insn(ppt, utask->tsk);
	if (unlikely(len != BP_INSN_SIZE)) {
		printk("Failed to temporarily restore original "
			"instruction for single-stepping: "
			"pid/tgid=%d/%d, vaddr=%#lx\n",
			utask->tsk->pid, utask->tsk->tgid, ppt->vaddr);
		utask->doomed = 1;
	}
}

/* Prepare to continue execution after single-stepping inline. */
static inline void uprobe_post_ssin(struct uprobe_task *utask,
	struct uprobe_probept *ppt)
{

	int len = set_bp(ppt, utask->tsk);
	if (unlikely(len != BP_INSN_SIZE)) {
		printk("Couldn't restore bp: pid/tgid=%d/%d, addr=%#lx\n",
			utask->tsk->pid, utask->tsk->tgid, ppt->vaddr);
		ppt->state = UPROBE_DISABLED;
	}
	mutex_unlock(&ppt->ssil_mutex);
}

/* uprobe_pre_ssout() and uprobe_post_ssout() are architecture-specific. */

/*
 * Delay delivery of the indicated signal until after single-step.
 * Otherwise single-stepping will be cancelled as part of calling
 * the signal handler.
 */
static u32 uprobe_delay_signal(struct uprobe_task *utask, siginfo_t *info)
{
	struct delayed_signal *ds = kmalloc(sizeof(*ds), GFP_USER);
	if (ds) {
		ds->info = *info;
		INIT_LIST_HEAD(&ds->list);
		list_add_tail(&ds->list, &utask->delayed_signals);
	}
	return UTRACE_ACTION_HIDE | UTRACE_SIGNAL_IGN |
			UTRACE_ACTION_SINGLESTEP | UTRACE_ACTION_NEWSTATE;
}

static void uprobe_inject_delayed_signals(struct list_head *delayed_signals)
{
	struct delayed_signal *ds, *tmp;
	list_for_each_entry_safe(ds, tmp, delayed_signals, list) {
		send_sig_info(ds->info.si_signo, &ds->info, current);
		list_del(&ds->list);
		kfree(ds);
	}
}

/*
 * Signal callback:
 *
 * We get called here with:
 *	state = UPTASK_RUNNING => we are here due to a breakpoint hit
 *		- Read-lock the process
 *		- Figure out which probepoint, based on regs->IP
 *		- Set state = UPTASK_BP_HIT
 *		- Reset regs->IP to beginning of the insn, if necessary
 *		- Invoke handler for each uprobe at this probepoint
 *		- Set singlestep in motion (UTRACE_ACTION_SINGLESTEP),
 *			with state = UPTASK_SSTEP
 *
 *	state = UPTASK_SSTEP => here after single-stepping
 *		- Validate we are here per the state machine
 *		- Clean up after single-stepping
 *		- Set state = UPTASK_RUNNING
 *		- Read-unlock the process
 *		- If it's time to quiesce, take appropriate action.
 *		- If the handler(s) we ran called [un]register_uprobe(),
 *			complete those via uprobe_run_def_regs().
 *
 *	state = ANY OTHER STATE
 *		- Not our signal, pass it on (UTRACE_ACTION_RESUME)
 * Note: Intermediate states such as UPTASK_POST_SSTEP help
 * uprobe_report_exit() decide what to unlock if we die.
 */
static u32 uprobe_report_signal(struct utrace_attached_engine *engine,
		struct task_struct *tsk, struct pt_regs *regs, u32 action,
		siginfo_t *info, const struct k_sigaction *orig_ka,
		struct k_sigaction *return_ka)
{
	struct uprobe_task *utask;
	struct uprobe_probept *ppt;
	struct uprobe_process *uproc;
	struct uprobe_kimg *uk;
	u32 ret;
	unsigned long probept;
	int hit_uretprobe_trampoline = 0;
	int registrations_deferred = 0;
	int uproc_freed = 0;
	struct list_head delayed_signals;

	utask = (struct uprobe_task *)rcu_dereference(engine->data);
	BUG_ON(!utask);

	/*
	 * info will be null if we're called with action=UTRACE_SIGNAL_HANDLER,
	 * which means that single-stepping has been disabled so a signal
	 * handler can be called in the probed process.  That should never
	 * happen because we intercept and delay handled signals (action =
	 * UTRACE_ACTION_RESUME) until after we're done single-stepping.
	 */
	BUG_ON(!info);
	if (action == UTRACE_ACTION_RESUME && utask->active_probe &&
					info->si_signo != SSTEP_SIGNAL)
		return uprobe_delay_signal(utask, info);

	if (info->si_signo != BREAKPOINT_SIGNAL &&
					info->si_signo != SSTEP_SIGNAL)
		goto no_interest;

	/*
	 * Set up the SSOL area if it's not already there.  We do this
	 * here because we have to do it before handling the first
	 * probepoint hit, the probed process has to do it, and this may
	 * be the first time our probed process runs uprobes code.
	 *
	 * We need the SSOL area for the uretprobe trampoline even if
	 * this architectures doesn't single-step out of line.
	 */
	uproc = utask->uproc;
#ifdef CONFIG_UPROBES_SSOL
	if (uproc->sstep_out_of_line &&
			unlikely(IS_ERR(uprobe_verify_ssol(uproc))))
		uproc->sstep_out_of_line = 0;
#elif defined(CONFIG_URETPROBES)
	(void) uprobe_verify_ssol(uproc);
#endif

	switch (utask->state) {
	case UPTASK_RUNNING:
		if (info->si_signo != BREAKPOINT_SIGNAL)
			goto no_interest;
		down_read(&uproc->rwsem);
		clear_utrace_quiesce(utask);
		probept = arch_get_probept(regs);

		hit_uretprobe_trampoline = (probept == (unsigned long)
			uproc->uretprobe_trampoline_addr);
		if (hit_uretprobe_trampoline) {
			uretprobe_handle_return(regs, utask);
			goto bkpt_done;
		}

		ppt = uprobe_find_probept(uproc, probept);
		if (!ppt) {
			up_read(&uproc->rwsem);
			goto no_interest;
		}
		utask->active_probe = ppt;
		utask->state = UPTASK_BP_HIT;

		if (likely(ppt->state == UPROBE_BP_SET)) {
			list_for_each_entry(uk, &ppt->uprobe_list, list) {
				struct uprobe *u = uk->uprobe;
				if (is_uretprobe(u))
					uretprobe_handle_entry(u, regs, utask);
				else if (u->handler)
					u->handler(u, regs);
			}
		}

		if (uprobe_emulate_insn(regs, ppt))
			goto bkpt_done;

		utask->state = UPTASK_PRE_SSTEP;
#ifdef CONFIG_UPROBES_SSOL
		if (uproc->sstep_out_of_line)
			uprobe_pre_ssout(utask, ppt, regs);
		else
#endif
			uprobe_pre_ssin(utask, ppt, regs);
		if (unlikely(utask->doomed))
			do_exit(SIGSEGV);
		utask->state = UPTASK_SSTEP;
		/*
		 * No other engines must see this signal, and the
		 * signal shouldn't be passed on either.
		 */
		ret = UTRACE_ACTION_HIDE | UTRACE_SIGNAL_IGN |
			UTRACE_ACTION_SINGLESTEP | UTRACE_ACTION_NEWSTATE;
		break;
	case UPTASK_SSTEP:
		if (info->si_signo != SSTEP_SIGNAL)
			goto no_interest;
		ppt = utask->active_probe;
		BUG_ON(!ppt);
		utask->state = UPTASK_POST_SSTEP;
#ifdef CONFIG_UPROBES_SSOL
		if (uproc->sstep_out_of_line)
			uprobe_post_ssout(utask, ppt, regs);
		else
#endif
			uprobe_post_ssin(utask, ppt);
bkpt_done:
		/* Note: Can come here after running uretprobe handlers */
		if (unlikely(utask->doomed))
			do_exit(SIGSEGV);

		utask->active_probe = NULL;

		if (!list_empty(&utask->deferred_registrations)) {
			/*
			 * Make sure utask doesn't go away before we run
			 * the deferred registrations.  This also keeps
			 * the module from getting unloaded before we're
			 * ready.
			 */
			registrations_deferred = 1;
			uprobe_get_process(uproc);
		}

		/*
		 * Delayed signals are a little different.  We want
		 * them delivered even if all the probes get unregistered
		 * and uproc and utask go away.  So disconnect the list
		 * from utask and make it a local list.
		 */
		INIT_LIST_HEAD(&delayed_signals);
		list_splice_init(&utask->delayed_signals, &delayed_signals);

		ret = UTRACE_ACTION_HIDE | UTRACE_SIGNAL_IGN
			| UTRACE_ACTION_NEWSTATE;
		utask->state = UPTASK_RUNNING;
		if (utask->quiescing) {
			up_read(&uproc->rwsem);
			uproc_freed |= utask_fake_quiesce(utask);
		} else
			up_read(&uproc->rwsem);

		if (hit_uretprobe_trampoline)
			/*
			 * It's possible that the uretprobe_instance
			 * we just recycled was the last reason for
			 * keeping uproc around.
			 */
			uproc_freed |= uprobe_put_process(uproc);

		if (registrations_deferred) {
			uprobe_run_def_regs(&utask->deferred_registrations);
			uproc_freed |= uprobe_put_process(uproc);
		}

		uprobe_inject_delayed_signals(&delayed_signals);

		if (uproc_freed)
			ret |= UTRACE_ACTION_DETACH;
		break;
	default:
		goto no_interest;
	}
	return ret;

no_interest:
	return UTRACE_ACTION_RESUME;
}

/*
 * utask_quiesce_pending_sigtrap: The utask entered the quiesce callback
 * through the signal delivery path, apparently. Check if the associated
 * signal happened due to a uprobe hit.
 *
 * Called with utask->uproc write-locked.  Returns 1 if quiesce was
 * entered with SIGTRAP pending due to a uprobe hit.
 */
static int utask_quiesce_pending_sigtrap(struct uprobe_task *utask)
{
	const struct utrace_regset_view *view;
	const struct utrace_regset *regset;
	struct uprobe_probept *ppt;
	unsigned long insn_ptr;

	view = utrace_native_view(utask->tsk);
	regset = utrace_regset(utask->tsk, utask->engine, view, 0);
	if (unlikely(regset == NULL))
		return -EIO;

	if ((*regset->get)(utask->tsk, regset,
			SLOT_IP(utask->tsk) * regset->size,
			regset->size, &insn_ptr, NULL) != 0)
		return -EIO;

	if (regset->size != sizeof(insn_ptr)) {
		/* Assume 32-bit app and 64-bit kernel. */
		u32 *insn_ptr32 = (u32*) &insn_ptr;
		BUG_ON(regset->size != sizeof(u32));
		insn_ptr = *insn_ptr32;
	}

	ppt = uprobe_find_probept(utask->uproc, ARCH_BP_INST_PTR(insn_ptr));
	return (ppt != NULL);
}

/*
 * Quiesce callback: The associated process has one or more breakpoint
 * insertions or removals pending.  If we're the last thread in this
 * process to quiesce, do the insertion(s) and/or removal(s).
 */
static u32 uprobe_report_quiesce(struct utrace_attached_engine *engine,
		struct task_struct *tsk)
{
	struct uprobe_task *utask;
	struct uprobe_process *uproc;

	rcu_read_lock();
	utask = (struct uprobe_task *)rcu_dereference(engine->data);
	BUG_ON(!utask);
	uproc = uprobe_get_process(utask->uproc);
	rcu_read_unlock();

	if (!uproc)
		return UTRACE_ACTION_DETACH|UTRACE_ACTION_RESUME;

	if (current == utask->quiesce_master) {
		/*
		 * tsk was already quiescent when quiesce_all_threads()
		 * called utrace_set_flags(), which in turned called
		 * here.  uproc is already locked.  Do as little as possible
		 * and get out.
		 */
		utask->state = UPTASK_QUIESCENT;
		uproc->n_quiescent_threads++;
		return UTRACE_ACTION_RESUME;
	}

	BUG_ON(utask->active_probe);

	down_write(&uproc->rwsem);

        /* printk(KERN_INFO "uprobe_report_quiesce2 %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */

	/*
	 * When a thread hits a breakpoint or single-steps, utrace calls
	 * this quiesce callback before our signal callback.  We must
	 * let uprobe_report_signal() handle the uprobe hit and THEN
	 * quiesce, because (a) there's a chance that we're quiescing
	 * in order to remove that very uprobe, and (b) there's a tiny
	 * chance that even though that uprobe isn't marked for removal
	 * now, it may be before all threads manage to quiesce.
	 */
	if (!utask->quiescing || utask_quiesce_pending_sigtrap(utask) == 1) {
		clear_utrace_quiesce(utask);
		goto done;
	}

	utask->state = UPTASK_QUIESCENT;
	uproc->n_quiescent_threads++;
	check_uproc_quiesced(uproc, tsk);
done:
	up_write(&uproc->rwsem);
	uprobe_put_process(uproc);
        /* printk(KERN_INFO "uprobe_report_quiesce3 %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */
	return UTRACE_ACTION_RESUME;
}

/*
 * uproc's process is exiting or exec-ing, so zap all the (now irrelevant)
 * probepoints and uretprobe_instances.  Runs with uproc->rwsem write-locked.
 * Caller must ref-count uproc before calling this function, to ensure that
 * uproc doesn't get freed in the middle of this.
 */
static void uprobe_cleanup_process(struct uprobe_process *uproc)
{
	int i;
	struct uprobe_probept *ppt;
	struct hlist_node *pnode1, *pnode2;
	struct hlist_head *head;
	struct uprobe_kimg *uk, *unode;
	struct uprobe_task *utask;

	uproc->finished = 1;

	for (i = 0; i < UPROBE_TABLE_SIZE; i++) {
		head = &uproc->uprobe_table[i];
		hlist_for_each_entry_safe(ppt, pnode1, pnode2, head, ut_node) {
			if (ppt->state == UPROBE_INSERTING ||
					ppt->state == UPROBE_REMOVING) {
				/*
				 * This task is (exec/exit)ing with
				 * a [un]register_uprobe pending.
				 * [un]register_uprobe will free ppt.
				 */
				ppt->state = UPROBE_DISABLED;
				list_del(&ppt->pd_node);
				list_for_each_entry_safe(uk, unode,
					       &ppt->uprobe_list, list)
					uk->status = -ESRCH;
				wake_up_all(&ppt->waitq);
			} else if (ppt->state == UPROBE_BP_SET) {
				list_for_each_entry_safe(uk, unode,
					       &ppt->uprobe_list, list) {
					list_del(&uk->list);
					uprobe_free_kimg(uk);
				}
				uprobe_free_probept(ppt);
			/* else */
				/*
				 * If ppt is UPROBE_DISABLED, assume that
				 * [un]register_uprobe() has been notified
				 * and will free it soon.
				 */
			}
		}
	}

	/*
	 * Free uretprobe_instances.  This is a nop on exit, since all
	 * the uprobe_tasks are already gone.  We do this here on exec
	 * (as opposed to letting uprobe_free_process() take care of it)
	 * because uprobe_free_process() never gets called if we don't
	 * tick down the ref count here (PR #7082).
	 */
	list_for_each_entry(utask, &uproc->thread_list, list)
		utask_free_uretprobe_instances(utask);
}

/*
 * Exit callback: The associated task/thread is exiting.
 */
static u32 uprobe_report_exit(struct utrace_attached_engine *engine,
		struct task_struct *tsk, long orig_code, long *code)
{
	struct uprobe_task *utask;
	struct uprobe_process *uproc = NULL;
	struct uprobe_probept *ppt;
	int utask_quiescing;

	utask = (struct uprobe_task *)rcu_dereference(engine->data);
	if (utask)
		uproc = uprobe_get_process(utask->uproc);

	if (!utask || !uproc)
		/* uprobe_free_process() has probably clobbered utask->proc. */
		return UTRACE_ACTION_DETACH;

        /* printk(KERN_INFO "uprobe_report_exit %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */

	ppt = utask->active_probe;
	if (ppt) {
		if (utask->state == UPTASK_TRAMPOLINE_HIT)
			printk(KERN_WARNING "Task died during uretprobe return:"
				"  pid/tgid = %d/%d\n", tsk->pid, tsk->tgid);
		else
			printk(KERN_WARNING "Task died at uprobe probepoint:"
				"  pid/tgid = %d/%d, probepoint = %#lx\n",
				tsk->pid, tsk->tgid, ppt->vaddr);
		/* Mutex cleanup depends on where we died and SSOL vs. SSIL. */
		if (uproc->sstep_out_of_line) {
			if (utask->state == UPTASK_SSTEP
					&& ppt->slot && ppt->slot->owner == ppt)
				up_read(&ppt->slot->rwsem);
		} else {
			switch (utask->state) {
			case UPTASK_PRE_SSTEP:
			case UPTASK_SSTEP:
			case UPTASK_POST_SSTEP:
				mutex_unlock(&ppt->ssil_mutex);
				break;
			default:
				break;
			}
		}
		up_read(&uproc->rwsem);
		if (utask->state == UPTASK_TRAMPOLINE_HIT)
			uprobe_decref_process(uproc);
	}

	down_write(&uproc->rwsem);

        /* printk(KERN_INFO "uprobe_report_exit2 %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */

	utask_quiescing = utask->quiescing;
	uprobe_free_task(utask);

	uproc->nthreads--;
	if (uproc->nthreads) {
		if (utask_quiescing)
			/*
			 * In case other threads are waiting for
			 * us to quiesce...
			 */
			check_uproc_quiesced(uproc,
				       find_surviving_thread(uproc));
	} else {
		/*
		 * We were the last remaining thread - clean up the uprobe
		 * remnants a la unregister_uprobe(). We don't have to
		 * remove the breakpoints, though.
		 */
		uprobe_cleanup_process(uproc);
	}
	up_write(&uproc->rwsem);
        /* printk(KERN_INFO "uprobe_report_exit3 %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */

	uprobe_put_process(uproc);

	return UTRACE_ACTION_DETACH;
}

/*
 * Duplicate the FIFO of uretprobe_instances from parent_utask into
 * child_utask.  Zap the uretprobe pointer, since all we care about is
 * vectoring to the proper return address.  Where there are multiple
 * uretprobe_instances for the same function instance, copy only the
 * one that contains the real return address.
 */
static int uprobe_fork_uretprobe_instances(struct uprobe_task *parent_utask,
					struct uprobe_task *child_utask)
{
	struct uprobe_process *parent_uproc = parent_utask->uproc;
	struct uprobe_process *child_uproc = child_utask->uproc;
	__user uprobe_opcode_t *trampoline_addr =
				child_uproc->uretprobe_trampoline_addr;
	struct hlist_node *tmp, *tail;
	struct uretprobe_instance *pri, *cri;

	BUG_ON(trampoline_addr != parent_uproc->uretprobe_trampoline_addr);

	/* Since there's no hlist_add_tail()... */
	tail = NULL;
	hlist_for_each_entry(pri, tmp, &parent_utask->uretprobe_instances,
								hlist) {
		if (pri->ret_addr == (unsigned long) trampoline_addr)
			continue;
		cri = kmalloc(sizeof(*cri), GFP_USER);
		if (!cri)
			return -ENOMEM;
		cri->rp = NULL;
		cri->ret_addr = pri->ret_addr;
		cri->sp = pri->sp;
		INIT_HLIST_NODE(&cri->hlist);
		if (tail)
			hlist_add_after(tail, &cri->hlist);
		else
			hlist_add_head(&cri->hlist,
				&child_utask->uretprobe_instances);
		tail = &cri->hlist;

		/* Ref-count uretprobe_instances. */
		uprobe_get_process(child_uproc);
	}
	BUG_ON(hlist_empty(&child_utask->uretprobe_instances));
	return 0;
}

/*
 * A probed process is forking, and at least one function in the
 * call stack has a uretprobe on it.  Since the child inherits the
 * call stack, it's possible that the child could attempt to return
 * through the uretprobe trampoline.  Create a uprobe_process for
 * the child, initialize its SSOL vma (which has been cloned from
 * the parent), and clone the parent's list of uretprobe_instances.
 *
 * Called with uproc_table locked and parent_uproc->rwsem write-locked.
 *
 * (On architectures where it's easy to keep track of where in the
 * stack the return addresses are stored, we could just poke the real
 * return addresses back into the child's stack.  We use this more
 * general solution.)
 */
static int uprobe_fork_uproc(struct uprobe_process *parent_uproc,
				struct uprobe_task *parent_utask,
				struct task_struct *child_tsk)
{
	int ret = 0;
	struct uprobe_process *child_uproc;
	struct uprobe_task *child_utask;

	BUG_ON(!parent_uproc->uretprobe_trampoline_addr ||
			IS_ERR(parent_uproc->uretprobe_trampoline_addr));

	ret = uprobe_validate_vma(child_tsk,
			(unsigned long) parent_uproc->ssol_area.insn_area);
	if (ret) {
		int ret2;
		printk(KERN_ERR "uprobes: Child %d failed to inherit"
			" parent %d's SSOL vma at %p.  Error = %d\n",
			child_tsk->pid, parent_utask->tsk->pid,
			parent_uproc->ssol_area.insn_area, ret);
		ret2 = uprobe_validate_vma(parent_utask->tsk,
			(unsigned long) parent_uproc->ssol_area.insn_area);
		if (ret2 != 0)
			printk(KERN_ERR "uprobes: Parent %d's SSOL vma"
				" is no longer valid.  Error = %d\n",
				parent_utask->tsk->pid, ret2);
		return ret;
	}

	if (!try_module_get(THIS_MODULE))
		return -ENOSYS;
	child_uproc = uprobe_mk_process(child_tsk, 1);
	if (IS_ERR(child_uproc)) {
		ret = (int) PTR_ERR(child_uproc);
		module_put(THIS_MODULE);
		return ret;
	}

	mutex_lock(&child_uproc->ssol_area.setup_mutex);
	uprobe_init_ssol(child_uproc, child_tsk,
				parent_uproc->ssol_area.insn_area);
	child_uproc->ssol_area.initialized = 1;
	mutex_unlock(&child_uproc->ssol_area.setup_mutex);

	child_utask = uprobe_find_utask(child_tsk);
	BUG_ON(!child_utask);
	ret = uprobe_fork_uretprobe_instances(parent_utask, child_utask);

	hlist_add_head(&child_uproc->hlist,
			&uproc_table[hash_long(child_uproc->tgid,
			UPROBE_HASH_BITS)]);

	uprobe_decref_process(child_uproc);
	return ret;
}

/*
 * Clone callback: The current task has spawned a thread/process.
 *
 * NOTE: For now, we don't pass on uprobes from the parent to the
 * child. We now do the necessary clearing of breakpoints in the
 * child's address space.
 *
 * TODO:
 *	- Provide option for child to inherit uprobes.
 */
static u32 uprobe_report_clone(struct utrace_attached_engine *engine,
		struct task_struct *parent, unsigned long clone_flags,
		struct task_struct *child)
{
	int len;
	struct uprobe_process *uproc;
	struct uprobe_task *ptask, *ctask;

	ptask = (struct uprobe_task *)rcu_dereference(engine->data);
	uproc = ptask->uproc;

        /* printk(KERN_INFO "uprobe_report_clone %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */
	/*
	 * Lock uproc so no new uprobes can be installed 'til all
	 * report_clone activities are completed.  Lock uproc_table
	 * in case we have to run uprobe_fork_uproc().
	 */
	lock_uproc_table();
	down_write(&uproc->rwsem);
	get_task_struct(child);

        /* printk(KERN_INFO "uprobe_report_clone2 %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */

	if (clone_flags & (CLONE_THREAD|CLONE_VM)) {
		/* New thread in the same process (CLONE_THREAD) or
		 * processes sharing the same memory space (CLONE_VM). */
		ctask = uprobe_add_task(child, uproc);
		BUG_ON(!ctask);
		if (IS_ERR(ctask))
			goto done;
		uproc->nthreads++;
		/*
		 * FIXME: Handle the case where uproc is quiescing
		 * (assuming it's possible to clone while quiescing).
		 */
	} else {
		/*
		 * New process spawned by parent.  Remove the probepoints
		 * in the child's text.
		 *
		 * Its not necessary to quiesce the child as we are assured
		 * by utrace that this callback happens *before* the child
		 * gets to run userspace.
		 *
		 * We also hold the uproc->rwsem for the parent - so no
		 * new uprobes will be registered 'til we return.
		 */
		int i;
		struct uprobe_probept *ppt;
		struct hlist_node *node;
		struct hlist_head *head;

		for (i = 0; i < UPROBE_TABLE_SIZE; i++) {
			head = &uproc->uprobe_table[i];
			hlist_for_each_entry(ppt, node, head, ut_node) {
				len = set_orig_insn(ppt, child);
				if (len != BP_INSN_SIZE) {
					/* Ratelimit this? */
					printk(KERN_ERR "Pid %d forked %d;"
						" failed to remove probepoint"
						" at %#lx in child\n",
						parent->pid, child->pid,
						ppt->vaddr);
				}
			}
		}

		if (!hlist_empty(&ptask->uretprobe_instances))
			(void) uprobe_fork_uproc(uproc, ptask, child);
	}

done:
	put_task_struct(child);
	up_write(&uproc->rwsem);
	unlock_uproc_table();
	return UTRACE_ACTION_RESUME;
}

/*
 * Exec callback: The associated process called execve() or friends
 *
 * The new program is about to start running and so there is no
 * possibility of a uprobe from the previous user address space
 * to be hit.
 *
 * NOTE:
 *	Typically, this process would have passed through the clone
 *	callback, where the necessary action *should* have been
 *	taken. However, if we still end up at this callback:
 *		- We don't have to clear the uprobes - memory image
 *		  will be overlaid.
 *		- We have to free up uprobe resources associated with
 *		  this process.
 */
static u32 uprobe_report_exec(struct utrace_attached_engine *engine,
		struct task_struct *tsk, const struct linux_binprm *bprm,
		struct pt_regs *regs)
{
	struct uprobe_process *uproc = NULL;
	struct uprobe_task *utask;
	u32 ret = UTRACE_ACTION_RESUME;

	utask = (struct uprobe_task *)rcu_dereference(engine->data);
	if (utask)
		uproc = uprobe_get_process(utask->uproc);

	if (!utask || !uproc)
		/* uprobe_free_process() has probably clobbered utask->proc. */
		return UTRACE_ACTION_DETACH;

        /* printk(KERN_INFO "uprobe_report_exec %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */

	/*
	 * Only cleanup if we're the last thread.  If we aren't,
	 * uprobe_report_exit() will handle cleanup.
	 *
	 * One instance of this can happen if vfork() was called,
	 * creating 2 tasks that share the same memory space
	 * (CLONE_VFORK|CLONE_VM).  In this case we don't want to
	 * remove the probepoints from the child, since that would
	 * also remove them from the parent.  Instead, just detach
	 * as if this were a simple thread exit.
	 */
	down_write(&uproc->rwsem);
	if (uproc->nthreads == 1) {
		uprobe_cleanup_process(uproc);
		/*
		 * If [un]register_uprobe() is in progress, cancel the
		 * quiesce.  Otherwise, utrace_report_exec() might
		 * call uprobe_report_exec() while the
		 * [un]register_uprobe thread is freeing the uproc.
		 */
		clear_utrace_quiesce(utask);
        } else {
                uprobe_free_task(utask);
                uproc->nthreads--;
                ret = UTRACE_ACTION_DETACH;
	}
	up_write(&uproc->rwsem);
        /* printk(KERN_INFO "uprobe_report_exec2 %p %ld=%ld\n", uproc, uproc->tgid, current->pid); */

	/* If any [un]register_uprobe is pending, it'll clean up. */
	if (uprobe_put_process(uproc))
		ret = UTRACE_ACTION_DETACH;

        /* printk(KERN_INFO "uprobe_report_exec4 %p %ld=%ld ret=%lu\n", uproc, uproc->tgid, current->pid, (unsigned long)ret); */

	return ret;
}

static const struct utrace_engine_ops uprobe_utrace_ops =
{
	.report_quiesce = uprobe_report_quiesce,
	.report_signal = uprobe_report_signal,
	.report_exit = uprobe_report_exit,
	.report_clone = uprobe_report_clone,
	.report_exec = uprobe_report_exec
};

static int __init init_uprobes(void)
{
	int i;

	for (i = 0; i < UPROBE_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(&uproc_table[i]);
		INIT_HLIST_HEAD(&utask_table[i]);
	}

	p_uprobe_utrace_ops = &uprobe_utrace_ops;
	return 0;
}

static void __exit exit_uprobes(void)
{
}

module_init(init_uprobes);
module_exit(exit_uprobes);

#ifdef CONFIG_URETPROBES

/* Returns true if ri_sp lies outside the stack (beyond cursp). */
static inline bool compare_stack_ptrs(unsigned long cursp,
		unsigned long ri_sp)
{
#ifdef CONFIG_STACK_GROWSUP
	if (cursp < ri_sp)
		return true;
#else
	if (cursp > ri_sp)
		return true;
#endif
	return false;
}

/*
 * A longjmp may cause one or more uretprobed functions to terminate without
 * returning.  Those functions' uretprobe_instances need to be recycled.
 * We detect this when any uretprobed function is subsequently called
 * or returns.  A bypassed uretprobe_instance's stack_ptr is beyond the
 * current stack.
 */
static inline void uretprobe_bypass_instances(unsigned long cursp,
                struct uprobe_task *utask)
{
	struct hlist_node *r1, *r2;
	struct uretprobe_instance *ri;
	struct hlist_head *head = &utask->uretprobe_instances;

	hlist_for_each_entry_safe(ri, r1, r2, head, hlist) {
		if (compare_stack_ptrs(cursp, ri->sp)) {
			hlist_del(&ri->hlist);
			kfree(ri);
			uprobe_decref_process(utask->uproc);
		} else
			return;
	}
}

/* Called when the entry-point probe u is hit. */
static void uretprobe_handle_entry(struct uprobe *u, struct pt_regs *regs,
	struct uprobe_task *utask)
{
	struct uretprobe_instance *ri;
	unsigned long trampoline_addr;

	if (IS_ERR(utask->uproc->uretprobe_trampoline_addr))
		return;
	trampoline_addr = (unsigned long)
		utask->uproc->uretprobe_trampoline_addr;
	ri = (struct uretprobe_instance *)
		kmalloc(sizeof(struct uretprobe_instance), GFP_USER);
	if (!ri)
		return;
	ri->ret_addr = arch_hijack_uret_addr(trampoline_addr, regs, utask);
	if (likely(ri->ret_addr)) {
		ri->sp = arch_predict_sp_at_ret(regs, utask->tsk);
		uretprobe_bypass_instances(ri->sp, utask);
		ri->rp = container_of(u, struct uretprobe, u);
		INIT_HLIST_NODE(&ri->hlist);
		hlist_add_head(&ri->hlist, &utask->uretprobe_instances);
		/* We ref-count outstanding uretprobe_instances. */
		uprobe_get_process(utask->uproc);
	} else
		kfree(ri);
}

/*
 * For each uretprobe_instance pushed onto the LIFO for the function
 * instance that's now returning, call the handler, free the ri, and
 * decrement the uproc's ref count.  Caller ref-counts uproc, so we
 * should never hit zero in this function.
 *
 * Returns the original return address.
 *
 * TODO: Handle longjmp out of uretprobed function.
 */
static unsigned long uretprobe_run_handlers(struct uprobe_task *utask,
		struct pt_regs *regs, unsigned long trampoline_addr)
{
	unsigned long ret_addr, cur_sp;
	struct hlist_head *head = &utask->uretprobe_instances;
	struct uretprobe_instance *ri;
	struct hlist_node *r1, *r2;

	cur_sp = arch_get_cur_sp(regs);
	uretprobe_bypass_instances(cur_sp, utask);
	hlist_for_each_entry_safe(ri, r1, r2, head, hlist) {
		if (ri->rp && ri->rp->handler)
			ri->rp->handler(ri, regs);
		ret_addr = ri->ret_addr;
		hlist_del(&ri->hlist);
		kfree(ri);
		uprobe_decref_process(utask->uproc);
		if (ret_addr != trampoline_addr)
			/*
			 * This is the first ri (chronologically) pushed for
			 * this particular instance of the probed function.
			 */
			return ret_addr;
	}
	printk(KERN_ERR "No uretprobe instance with original return address!"
		" pid/tgid=%d/%d", utask->tsk->pid, utask->tsk->tgid);
	utask->doomed = 1;
	return 0;
}

/* Called when the uretprobe trampoline is hit. */
static void uretprobe_handle_return(struct pt_regs *regs,
	struct uprobe_task *utask)
{
	unsigned long orig_ret_addr;
	/* Delay recycling of uproc until end of uprobe_report_signal() */
	uprobe_get_process(utask->uproc);
	utask->state = UPTASK_TRAMPOLINE_HIT;
	utask->active_probe = &uretprobe_trampoline_dummy_probe;
	orig_ret_addr = uretprobe_run_handlers(utask, regs,
		(unsigned long) utask->uproc->uretprobe_trampoline_addr);
	arch_restore_uret_addr(orig_ret_addr, regs);
}

int register_uretprobe(struct uretprobe *rp)
{
	if (!rp || !rp->handler)
		return -EINVAL;
	rp->u.handler = URETPROBE_HANDLE_ENTRY;
	return register_uprobe(&rp->u);
}
EXPORT_SYMBOL_GPL(register_uretprobe);

/*
 * The uretprobe containing u is being unregistered.  Its uretprobe_instances
 * have to hang around 'til their associated instances return (but we can't
 * run rp's handler).  Zap ri->rp for each one to indicate unregistration.
 *
 * Runs with uproc write-locked.
 */
static void zap_uretprobe_instances(struct uprobe *u,
		struct uprobe_process *uproc)
{
	struct uprobe_task *utask;
	struct uretprobe *rp = container_of(u, struct uretprobe, u);

	if (!uproc)
		return;

	list_for_each_entry(utask, &uproc->thread_list, list) {
		struct hlist_node *r;
		struct uretprobe_instance *ri;

		hlist_for_each_entry(ri, r, &utask->uretprobe_instances, hlist)
			if (ri->rp == rp)
				ri->rp = NULL;
	}
}

void unregister_uretprobe(struct uretprobe *rp)
{
	if (!rp)
		return;
	unregister_uprobe(&rp->u);
}
EXPORT_SYMBOL_GPL(unregister_uretprobe);

void unmap_uretprobe(struct uretprobe *rp)
{
	if (!rp)
		return;
	unmap_uprobe(&rp->u);
}
EXPORT_SYMBOL_GPL(unmap_uretprobe);

/*
 * uproc->ssol_area has been successfully set up.  Establish the
 * uretprobe trampoline in slot 0.
 */
static void uretprobe_set_trampoline(struct uprobe_process *uproc,
					struct task_struct *tsk)
{
	uprobe_opcode_t bp_insn = BREAKPOINT_INSTRUCTION;
	struct uprobe_ssol_area *area = &uproc->ssol_area;
	struct uprobe_ssol_slot *slot = &area->slots[0];

	if (access_process_vm(tsk, (unsigned long) slot->insn,
			&bp_insn, BP_INSN_SIZE, 1) == BP_INSN_SIZE) {
		uproc->uretprobe_trampoline_addr = slot->insn;
		slot->state = SSOL_RESERVED;
		area->next_slot = 1;
		area->nfree--;
	} else {
		printk(KERN_ERR "uretprobes disabled for pid %d:"
			" cannot set uretprobe trampoline at %p\n",
			uproc->tgid, slot->insn);
	}
}

static inline unsigned long lookup_uretprobe(struct hlist_node *r,
					     struct uprobe_process *uproc,
					     unsigned long pc,
					     unsigned long sp)
{
	struct uretprobe_instance *ret_inst;
	unsigned long trampoline_addr;

	if (IS_ERR(uproc->uretprobe_trampoline_addr))
	  return pc;
	trampoline_addr = (unsigned long)uproc->uretprobe_trampoline_addr;
	if (pc != trampoline_addr)
		return pc;
	hlist_for_each_entry_from(ret_inst, r, hlist) {
		if (ret_inst->ret_addr == trampoline_addr)
			continue;
		/* First handler with a stack pointer lower than the
		   address (or equal) must be the one. */
		if (ret_inst->sp == sp || compare_stack_ptrs(ret_inst->sp, sp))
			return ret_inst->ret_addr;
	}
	printk(KERN_ERR "Original return address for trampoline not found at "
	       "0x%lx pid/tgid=%d/%d\n", sp, current->pid, current->tgid);
	return 0;

}

unsigned long uprobe_get_pc(struct uretprobe_instance *ri, unsigned long pc,
			unsigned long sp)
{
	struct uretprobe *rp;
	struct uprobe_kimg *uk;
	struct uprobe_task *utask;
	struct uprobe_process *uproc;
	struct hlist_node *r;

	if (ri == GET_PC_URETPROBE_NONE) {
		utask = uprobe_find_utask(current);
		if (!utask)
			return 0;
		uproc = utask->uproc;
		r = utask->uretprobe_instances.first;
	} else {
		rp = ri->rp;
		uk = (struct uprobe_kimg *)rp->u.kdata;
		if (!uk)
			return 0;
		uproc = uk->ppt->uproc;
		r = &ri->hlist;
	}
	return lookup_uretprobe(r, uproc, pc, sp);
}

EXPORT_SYMBOL_GPL(uprobe_get_pc);

unsigned long uprobe_get_pc_task(struct task_struct *task, unsigned long pc,
				 unsigned long sp)
{
	struct uprobe_task *utask;
	struct uprobe_process *uproc;
	unsigned long result;

	utask = uprobe_find_utask(task);
	if (!utask) {
		return pc;
	} else if (current == task && utask->active_probe) {
		/* everything's locked. */
		return uprobe_get_pc(GET_PC_URETPROBE_NONE, pc, sp);
	}
	uproc = utask->uproc;
	down_read(&uproc->rwsem);
	result = lookup_uretprobe(utask->uretprobe_instances.first, uproc, pc,
				  sp);
	up_read(&uproc->rwsem);
	return result;
}

EXPORT_SYMBOL_GPL(uprobe_get_pc_task);

#else	/* ! CONFIG_URETPROBES */

static void uretprobe_handle_entry(struct uprobe *u, struct pt_regs *regs,
	struct uprobe_task *utask)
{
}
static void uretprobe_handle_return(struct pt_regs *regs,
	struct uprobe_task *utask)
{
}
static void uretprobe_set_trampoline(struct uprobe_process *uproc,
					struct task_struct *tsk)
{
}
static void zap_uretprobe_instances(struct uprobe *u,
	struct uprobe_process *uproc)
{
}
#endif /* CONFIG_URETPROBES */

#ifdef NO_ACCESS_PROCESS_VM_EXPORT
/*
 * Some kernel versions export everything that uprobes.ko needs except
 * access_process_vm, so we copied and pasted it here.  Fortunately,
 * everything it calls is exported.
 */
#include <linux/pagemap.h>
#include <asm/cacheflush.h>
static int __access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct page *page;
	void *old_buf = buf;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transfered */
	while (len) {
		int bytes, ret, offset;
		void *maddr;

		ret = get_user_pages(tsk, mm, addr, 1,
				write, 1, &page, &vma);
		if (ret <= 0)
			break;

		bytes = len;
		offset = addr & (PAGE_SIZE-1);
		if (bytes > PAGE_SIZE-offset)
			bytes = PAGE_SIZE-offset;

		maddr = kmap(page);
		if (write) {
			copy_to_user_page(vma, page, addr,
					  maddr + offset, buf, bytes);
			set_page_dirty_lock(page);
		} else {
			copy_from_user_page(vma, page, addr,
					    buf, maddr + offset, bytes);
		}
		kunmap(page);
		page_cache_release(page);
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);
	mmput(mm);

	return buf - old_buf;
}
#endif
#include "uprobes_arch.c"
MODULE_LICENSE("GPL");

#endif	/* uprobes 1 (based on original utrace) */
