/*
 * utrace infrastructure interface for debugging user processes
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * Heavily based on the original utrace code by Roland McGrath.
 */

#ifndef _STP_UTRACE_C
#define _STP_UTRACE_C

#if (!defined(STAPCONF_UTRACE_VIA_TRACEPOINTS))
#error "STAPCONF_UTRACE_VIA_TRACEPOINTS must be defined."
#endif

#include "stp_utrace.h"
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/slab.h>
#include <trace/events/sched.h>
#include <trace/events/syscalls.h>
#include "stp_task_work.c"
#include "linux/stp_tracepoint.h"

#include "stp_helper_lock.h"

/*
 * Per-thread structure private to utrace implementation.
 * If task_struct.utrace_flags is nonzero, task_struct.utrace
 * has always been allocated first.  Once allocated, it is
 * never freed until free_task().
 *
 * The common event reporting loops are done by the task making the
 * report without ever taking any locks.  To facilitate this, the two
 * lists @attached and @attaching work together for smooth asynchronous
 * attaching with low overhead.  Modifying either list requires @lock.
 * The @attaching list can be modified any time while holding @lock.
 * New engines being attached always go on this list.
 *
 * The @attached list is what the task itself uses for its reporting
 * loops.  When the task itself is not quiescent, it can use the
 * @attached list without taking any lock.  Nobody may modify the list
 * when the task is not quiescent.  When it is quiescent, that means
 * that it won't run again without taking @lock itself before using
 * the list.
 *
 * At each place where we know the task is quiescent (or it's current),
 * while holding @lock, we call splice_attaching(), below.  This moves
 * the @attaching list members on to the end of the @attached list.
 * Since this happens at the start of any reporting pass, any new
 * engines attached asynchronously go on the stable @attached list
 * in time to have their callbacks seen.
 */
struct utrace {
	stp_spinlock_t lock;
	struct list_head attached, attaching;

	struct utrace_engine *reporting;

	enum utrace_resume_action resume:UTRACE_RESUME_BITS;
	unsigned int vfork_stop:1; /* need utrace_stop() before vfork wait */
	unsigned int death:1;	/* in utrace_report_death() now */
	unsigned int reap:1;	/* release_task() has run */
	unsigned int pending_attach:1; /* need splice_attaching() */
	unsigned int task_work_added:1; /* called task_work_add() on 'work' */
	unsigned int report_work_added:1; /* called task_work_add()
					   * on 'report_work' */

	unsigned long utrace_flags;

	struct hlist_node hlist;       /* task_utrace_table linkage */
	struct task_struct *task;

	struct task_work work;
	struct task_work report_work;
};

#define TASK_UTRACE_HASH_BITS 5
#define TASK_UTRACE_TABLE_SIZE (1 << TASK_UTRACE_HASH_BITS)

static struct hlist_head task_utrace_table[TASK_UTRACE_TABLE_SIZE];
//DEFINE_MUTEX(task_utrace_mutex);      /* Protects task_utrace_table */
static STP_DEFINE_SPINLOCK(task_utrace_lock); /* Protects task_utrace_table */

static struct kmem_cache *utrace_cachep;
static struct kmem_cache *utrace_engine_cachep;
static const struct utrace_engine_ops utrace_detached_ops; /* forward decl */

static void utrace_report_clone(void *cb_data __attribute__ ((unused)),
				struct task_struct *task,
				struct task_struct *child);
static void utrace_report_death(void *cb_data __attribute__ ((unused)),
				struct task_struct *task);
static void utrace_report_syscall_entry(void *cb_data __attribute__ ((unused)),
					struct pt_regs *regs, long id);
static void utrace_report_syscall_exit(void *cb_data __attribute__ ((unused)),
				       struct pt_regs *regs, long ret);

static void utrace_report_exec(void *cb_data __attribute__ ((unused)),
			       struct task_struct *task,
			       pid_t old_pid __attribute__((unused)),
			       struct linux_binprm *bprm __attribute__ ((unused)));

#define __UTRACE_UNREGISTERED	0
#define __UTRACE_REGISTERED	1
static atomic_t utrace_state = ATOMIC_INIT(__UTRACE_UNREGISTERED);

// If wake_up_state() is exported, use it.
#if defined(STAPCONF_WAKE_UP_STATE_EXPORTED)
#define stp_wake_up_state wake_up_state
// Otherwise, try to use try_to_wake_up(). The wake_up_state()
// function is just a wrapper around try_to_wake_up().
#elif defined(STAPCONF_TRY_TO_WAKE_UP_EXPORTED)
static inline int stp_wake_up_state(struct task_struct *p, unsigned int state)
{
	return try_to_wake_up(p, state, 0);
}
// Otherwise, we'll have to look up wake_up_state() with kallsyms.
#else
typedef typeof(&wake_up_state) wake_up_state_fn;
#define stp_wake_up_state (* (wake_up_state_fn)kallsyms_wake_up_state)
#endif

#if !defined(STAPCONF_SIGNAL_WAKE_UP_STATE_EXPORTED)
// Sigh. On kernel's without signal_wake_up_state(), there is no
// declaration to use in 'typeof(&signal_wake_up_state)'. So, we'll
// provide one here.
void signal_wake_up_state(struct task_struct *t, unsigned int state);

// First typedef from the original decl, then #define as typecasted call.
typedef typeof(&signal_wake_up_state) signal_wake_up_state_fn;
#define signal_wake_up_state (* (signal_wake_up_state_fn)kallsyms_signal_wake_up_state)
#endif

#if !defined(STAPCONF_SIGNAL_WAKE_UP_EXPORTED)
// First typedef from the original decl, then #define as typecasted call.
typedef typeof(&signal_wake_up) signal_wake_up_fn;
#define signal_wake_up (* (signal_wake_up_fn)kallsyms_signal_wake_up)
#endif

#if !defined(STAPCONF___LOCK_TASK_SIGHAND_EXPORTED)
// First typedef from the original decl, then #define as typecasted call.
typedef typeof(&__lock_task_sighand) __lock_task_sighand_fn;
#define __lock_task_sighand (* (__lock_task_sighand_fn)kallsyms___lock_task_sighand)

/*
 * __lock_task_sighand() is called from the inline function
 * 'lock_task_sighand'. Since the real inline function won't know
 * anything about our '#define' above, we have to have our own version
 * of the inline function.  Sigh.
 */
static inline struct sighand_struct *
stp_lock_task_sighand(struct task_struct *tsk, unsigned long *flags)
{
	struct sighand_struct *ret;

	ret = __lock_task_sighand(tsk, flags);
	(void)__cond_lock(&tsk->sighand->siglock, ret);
	return ret;
}
#else
#define stp_lock_task_sighand lock_task_sighand
#endif


/*
 * Our internal version of signal_wake_up()/signal_wake_up_state()
 * that handles the functions existing and being exported.
 */
static inline void
stp_signal_wake_up(struct task_struct *t, bool resume)
{
#if defined(STAPCONF_SIGNAL_WAKE_UP_STATE_EXPORTED)
    signal_wake_up_state(t, resume ? TASK_WAKEKILL : 0);
#elif defined(STAPCONF_SIGNAL_WAKE_UP_EXPORTED)
    signal_wake_up(t, resume);
#else
    if (kallsyms_signal_wake_up_state) {
	signal_wake_up_state(t, resume ? TASK_WAKEKILL : 0);
    }
    else if (kallsyms_signal_wake_up) {
	signal_wake_up(t, resume);
    }
#endif
}


static int utrace_init(void)
{
	int i;
	int rc = -1;
        static char kmem_cache1_name[50];
        static char kmem_cache2_name[50];

	if (unlikely(stp_task_work_init() != 0))
		goto error;

	/* initialize the list heads */
	for (i = 0; i < TASK_UTRACE_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(&task_utrace_table[i]);
	}

#if !defined(STAPCONF_TRY_TO_WAKE_UP_EXPORTED) \
    && !defined(STAPCONF_WAKE_UP_STATE_EXPORTED)
	kallsyms_wake_up_state = (void *)kallsyms_lookup_name("wake_up_state");
        if (kallsyms_wake_up_state == NULL) {
		_stp_error("Can't resolve wake_up_state!");
		goto error;
        }
#endif
#if !defined(STAPCONF_SIGNAL_WAKE_UP_STATE_EXPORTED)
	/* The signal_wake_up_state() function (which replaces
	 * signal_wake_up() in newer kernels) isn't exported. Look up
	 * that function address. */
        kallsyms_signal_wake_up_state = (void *)kallsyms_lookup_name("signal_wake_up_state");
#endif
#if !defined(STAPCONF_SIGNAL_WAKE_UP_EXPORTED)
	/* The signal_wake_up() function isn't exported. Look up that
	 * function address. */
        kallsyms_signal_wake_up = (void *)kallsyms_lookup_name("signal_wake_up");
#endif
#if (!defined(STAPCONF_SIGNAL_WAKE_UP_STATE_EXPORTED) \
     && !defined(STAPCONF_SIGNAL_WAKE_UP_EXPORTED))
        if (kallsyms_signal_wake_up_state == NULL
	    && kallsyms_signal_wake_up == NULL) {
		_stp_error("Can't resolve signal_wake_up_state or signal_wake_up!");
		goto error;
        }
#endif
#if !defined(STAPCONF___LOCK_TASK_SIGHAND_EXPORTED)
	/* The __lock_task_sighand() function isn't exported. Look up
	 * that function address. */
        kallsyms___lock_task_sighand = (void *)kallsyms_lookup_name("__lock_task_sighand");
        if (kallsyms___lock_task_sighand == NULL) {
		_stp_error("Can't resolve __lock_task_sighand!");
		goto error;
        }
#endif

        /* PR14781: avoid kmem_cache naming collisions (detected by CONFIG_DEBUG_VM)
           by plopping a non-conflicting token - in this case the address of a 
           locally relevant variable - into the names. */
        snprintf(kmem_cache1_name, sizeof(kmem_cache1_name),
                 "utrace_%lx", (unsigned long) (& utrace_cachep));
	utrace_cachep = kmem_cache_create(kmem_cache1_name, 
                                          sizeof(struct utrace),
                                          0, 0, NULL);
	if (unlikely(!utrace_cachep))
		goto error;

        snprintf(kmem_cache2_name, sizeof(kmem_cache2_name),
                 "utrace_engine_%lx", (unsigned long) (& utrace_engine_cachep));
	utrace_engine_cachep = kmem_cache_create(kmem_cache2_name, 
                                                 sizeof(struct utrace_engine),
                                                 0, 0, NULL);
	if (unlikely(!utrace_engine_cachep))
		goto error;

	rc = STP_TRACE_REGISTER(sched_process_fork, utrace_report_clone);
	if (unlikely(rc != 0)) {
		_stp_error("register_trace_sched_process_fork failed: %d", rc);
		goto error;
	}
	rc = STP_TRACE_REGISTER(sched_process_exit, utrace_report_death);
	if (unlikely(rc != 0)) {
		_stp_error("register_trace_sched_process_exit failed: %d", rc);
		goto error2;
	}
	rc = STP_TRACE_REGISTER(sys_enter, utrace_report_syscall_entry);
	if (unlikely(rc != 0)) {
		_stp_error("register_trace_sys_enter failed: %d", rc);
		goto error3;
	}
	rc = STP_TRACE_REGISTER(sys_exit, utrace_report_syscall_exit);
	if (unlikely(rc != 0)) {
		_stp_error("register_trace_sys_exit failed: %d", rc);
		goto error4;
	}

	rc = STP_TRACE_REGISTER(sched_process_exec, utrace_report_exec);
	if (unlikely(rc != 0)) {
		_stp_error("register_sched_process_exec failed: %d", rc);
		goto error5;
	}

	atomic_set(&utrace_state, __UTRACE_REGISTERED);
	return 0;

error5:
	STP_TRACE_UNREGISTER(sys_exit, utrace_report_syscall_exit);
error4:
	STP_TRACE_UNREGISTER(sys_enter, utrace_report_syscall_entry);
error3:
	STP_TRACE_UNREGISTER(sched_process_exit, utrace_report_death);
error2:
	STP_TRACE_UNREGISTER(sched_process_fork, utrace_report_clone);
	tracepoint_synchronize_unregister();
error:
	if (utrace_cachep) {
		kmem_cache_destroy(utrace_cachep);
		utrace_cachep = NULL;
	}
	if (utrace_engine_cachep) {
		kmem_cache_destroy(utrace_engine_cachep);
		utrace_engine_cachep = NULL;
	}
	return rc;
}

static int utrace_exit(void)
{
#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - entry\n", __FUNCTION__, __LINE__);
#endif
	utrace_shutdown();
	stp_task_work_exit();

	/* After utrace_shutdown() and stp_task_work_exit() (and the
	 * code in stap_stop_task_finder()), we're *sure* there are no
	 * tracepoint probes or task work items running or scheduled
	 * to be run. So, now would be a great time to actually free
	 * everything. */

	if (utrace_cachep) {
		kmem_cache_destroy(utrace_cachep);
		utrace_cachep = NULL;
	}
	if (utrace_engine_cachep) {
		kmem_cache_destroy(utrace_engine_cachep);
		utrace_engine_cachep = NULL;
	}

#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - exit\n", __FUNCTION__, __LINE__);
#endif
	return 0;
}

/*
 * stp_task_notify_resume() is our version of
 * set_notify_resume(). When called, the task_work infrastructure will
 * cause utrace_resume() to get called.
 */
static void
stp_task_notify_resume(struct task_struct *target, struct utrace *utrace)
{
	if (! utrace->task_work_added) {
		int rc = stp_task_work_add(target, &utrace->work);
		if (rc == 0) {
			utrace->task_work_added = 1;
		}
		/* stp_task_work_add() returns -ESRCH if the task has
		 * already passed exit_task_work(). Just ignore this
		 * error. */
		else if (rc != -ESRCH) {
			printk(KERN_ERR "%s:%d - task_work_add() returned %d\n",
			       __FUNCTION__, __LINE__, rc);
		}
	}
}

static void utrace_resume(struct task_work *work);
static void utrace_report_work(struct task_work *work);

/*
 * Clean up everything associated with @task.utrace.
 *
 * This routine must be called under the task_utrace_lock.
 */
static void utrace_cleanup(struct utrace *utrace)
{
	struct utrace_engine *engine, *next;

	lockdep_assert_held(&task_utrace_lock);

	/* Free engines associated with the struct utrace, starting
	 * with the 'attached' list then doing the 'attaching' list. */
	stp_spin_lock(&utrace->lock);
	list_for_each_entry_safe(engine, next, &utrace->attached, entry) {
#ifdef STP_TF_DEBUG
	    printk(KERN_ERR "%s:%d - removing engine\n",
		   __FUNCTION__, __LINE__);
#endif
	    list_del_init(&engine->entry);
	    /* FIXME: hmm, should this be utrace_engine_put()? */
	    kmem_cache_free(utrace_engine_cachep, engine);
	}
	list_for_each_entry_safe(engine, next, &utrace->attaching, entry) {
	    list_del(&engine->entry);
	    kmem_cache_free(utrace_engine_cachep, engine);
	}

	if (utrace->task_work_added) {
#ifdef STP_TF_DEBUG
		if (stp_task_work_cancel(utrace->task, &utrace_resume) == NULL)
			printk(KERN_ERR "%s:%d - task_work_cancel() failed? task %p, %d, %s\n",
			       __FUNCTION__, __LINE__, utrace->task,
			       utrace->task->tgid,
			       (utrace->task->comm ? utrace->task->comm
				: "UNKNOWN"));
#else
		stp_task_work_cancel(utrace->task, &utrace_resume);
#endif
		utrace->task_work_added = 0;
	}
	if (utrace->report_work_added) {
#ifdef STP_TF_DEBUG
		if (stp_task_work_cancel(utrace->task, &utrace_report_work) == NULL)
			printk(KERN_ERR "%s:%d - task_work_cancel() failed? task %p, %d, %s\n",
			       __FUNCTION__, __LINE__, utrace->task,
			       utrace->task->tgid,
			       (utrace->task->comm ? utrace->task->comm
				: "UNKNOWN"));
#else
		stp_task_work_cancel(utrace->task, &utrace_report_work);
#endif
		utrace->report_work_added = 0;
	}
	stp_spin_unlock(&utrace->lock);

	/* Free the struct utrace itself. */
	kmem_cache_free(utrace_cachep, utrace);
#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d exit\n", __FUNCTION__, __LINE__);
#endif
}

static void utrace_shutdown(void)
{
	int i;
	struct utrace *utrace;
	struct hlist_head *head;
	struct hlist_node *node, *node2;

	if (atomic_read(&utrace_state) != __UTRACE_REGISTERED)
		return;
	atomic_set(&utrace_state, __UTRACE_UNREGISTERED);

#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d entry\n", __FUNCTION__, __LINE__);
#endif
	/* Unregister all the tracepoint probes. */
	STP_TRACE_UNREGISTER(sched_process_exec, utrace_report_exec);
	STP_TRACE_UNREGISTER(sched_process_fork, utrace_report_clone);
	STP_TRACE_UNREGISTER(sched_process_exit, utrace_report_death);
	STP_TRACE_UNREGISTER(sys_enter, utrace_report_syscall_entry);
	STP_TRACE_UNREGISTER(sys_exit, utrace_report_syscall_exit);

	/* When tracepoint_synchronize_unregister() returns, all
	 * currently executing tracepoint probes will be finished. */
	tracepoint_synchronize_unregister();

	/* (We'd like to wait here until all currrently executing
	 * task_work items are finished (by calling
	 * stp_task_work_exit()), but that gets stuck.)
	 *
	 * After the code above we're *sure* there are no tracepoint
	 * probes running (or scheduled to be run). There could be
	 * currently running task_work items.  Go ahead and cleanup
	 * everything.  Currently running items should be OK, since
	 * utrace_cleanup() just puts the memory back into the utrace
	 * kmem caches. */
#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - freeing task-specific\n", __FUNCTION__, __LINE__);
#endif
	stp_spin_lock(&task_utrace_lock);
	for (i = 0; i < TASK_UTRACE_TABLE_SIZE; i++) {
		head = &task_utrace_table[i];
		stap_hlist_for_each_entry_safe(utrace, node, node2, head,
					       hlist) {
			hlist_del(&utrace->hlist);
			utrace_cleanup(utrace);
		}
	}
	stp_spin_unlock(&task_utrace_lock);
#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - done\n", __FUNCTION__, __LINE__);
#endif
}

/*
 * This routine must be called under the task_utrace_lock.
 */
static struct utrace *__task_utrace_struct(struct task_struct *task)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct utrace *utrace;

	lockdep_assert_held(&task_utrace_lock);
	head = &task_utrace_table[hash_ptr(task, TASK_UTRACE_HASH_BITS)];
	stap_hlist_for_each_entry(utrace, node, head, hlist) {
		if (utrace->task == task)
			return utrace;
	}
	return NULL;
}

/*
 * Set up @task.utrace for the first time.  We can have races
 * between two utrace_attach_task() calls here.  The task_lock()
 * governs installing the new pointer.  If another one got in first,
 * we just punt the new one we allocated.
 *
 * This returns false only in case of a memory allocation failure.
 */
static bool utrace_task_alloc(struct task_struct *task)
{
	struct utrace *utrace = kmem_cache_zalloc(utrace_cachep,
						  STP_ALLOC_FLAGS);
	struct utrace *u;

	if (unlikely(!utrace))
		return false;
	stp_spin_lock_init(&utrace->lock);
	INIT_LIST_HEAD(&utrace->attached);
	INIT_LIST_HEAD(&utrace->attaching);
	utrace->resume = UTRACE_RESUME;
	utrace->task = task;
	stp_init_task_work(&utrace->work, &utrace_resume);
	stp_init_task_work(&utrace->report_work, &utrace_report_work);

	stp_spin_lock(&task_utrace_lock);
	u = __task_utrace_struct(task);
	if (u == NULL) {
		hlist_add_head(&utrace->hlist,
			       &task_utrace_table[hash_ptr(task, TASK_UTRACE_HASH_BITS)]);
	}
	else {
		kmem_cache_free(utrace_cachep, utrace);
	}
	stp_spin_unlock(&task_utrace_lock);

	return true;
}

/*
 * Correctly free a @utrace structure.
 *
 * Originally, this function was called via tracehook_free_task() from
 * free_task() when @task is being deallocated. But free_task() has no
 * tracepoint we can easily hook.
 */
static void utrace_free(struct utrace *utrace)
{
	if (unlikely(!utrace))
		return;

	/* Remove this utrace from the mapping list of tasks to
	 * struct utrace. */
	stp_spin_lock(&task_utrace_lock);
	hlist_del(&utrace->hlist);
	stp_spin_unlock(&task_utrace_lock);

	/* Free the utrace struct. */
	stp_spin_lock(&utrace->lock);
#ifdef STP_TF_DEBUG
	if (unlikely(utrace->reporting)
	    || unlikely(!list_empty(&utrace->attached))
	    || unlikely(!list_empty(&utrace->attaching)))
		printk(KERN_ERR "%s:%d - reporting? %p, attached empty %d, attaching empty %d\n",
		       __FUNCTION__, __LINE__, utrace->reporting,
		       list_empty(&utrace->attached),
		       list_empty(&utrace->attaching));
#endif

	if (utrace->task_work_added) {
		if (stp_task_work_cancel(utrace->task, &utrace_resume) == NULL)
			printk(KERN_ERR "%s:%d - task_work_cancel() failed? task %p, %d, %s\n",
			       __FUNCTION__, __LINE__, utrace->task,
			       utrace->task->tgid,
			       (utrace->task->comm ? utrace->task->comm
				: "UNKNOWN"));
		utrace->task_work_added = 0;
	}
	if (utrace->report_work_added) {
		if (stp_task_work_cancel(utrace->task, &utrace_report_work) == NULL)
			printk(KERN_ERR "%s:%d - task_work_cancel() failed? task %p, %d, %s\n",
			       __FUNCTION__, __LINE__, utrace->task,
			       utrace->task->tgid,
			       (utrace->task->comm ? utrace->task->comm
				: "UNKNOWN"));
		utrace->report_work_added = 0;
	}
	stp_spin_unlock(&utrace->lock);

	kmem_cache_free(utrace_cachep, utrace);
}

static struct utrace *task_utrace_struct(struct task_struct *task)
{
	struct utrace *utrace;

	stp_spin_lock(&task_utrace_lock);
	utrace = __task_utrace_struct(task);
	stp_spin_unlock(&task_utrace_lock);
	return utrace;
}

/*
 * This is called when the task is safely quiescent, i.e. it won't consult
 * utrace->attached without the lock.  Move any engines attached
 * asynchronously from @utrace->attaching onto the @utrace->attached list.
 */
static void splice_attaching(struct utrace *utrace)
{
	lockdep_assert_held(&utrace->lock);
	list_splice_tail_init(&utrace->attaching, &utrace->attached);
	utrace->pending_attach = 0;
}

/*
 * This is the exported function used by the utrace_engine_put() inline.
 */
static void __utrace_engine_release(struct kref *kref)
{
	struct utrace_engine *engine = container_of(kref, struct utrace_engine,
						    kref);
	BUG_ON(!list_empty(&engine->entry));
	if (engine->release)
		(*engine->release)(engine->data);
	kmem_cache_free(utrace_engine_cachep, engine);
}

static bool engine_matches(struct utrace_engine *engine, int flags,
			   const struct utrace_engine_ops *ops, void *data)
{
	if ((flags & UTRACE_ATTACH_MATCH_OPS) && engine->ops != ops)
		return false;
	if ((flags & UTRACE_ATTACH_MATCH_DATA) && engine->data != data)
		return false;
	return engine->ops && engine->ops != &utrace_detached_ops;
}

static struct utrace_engine *find_matching_engine(
	struct utrace *utrace, int flags,
	const struct utrace_engine_ops *ops, void *data)
{
	struct utrace_engine *engine;
	list_for_each_entry(engine, &utrace->attached, entry)
		if (engine_matches(engine, flags, ops, data))
			return engine;
	list_for_each_entry(engine, &utrace->attaching, entry)
		if (engine_matches(engine, flags, ops, data))
			return engine;
	return NULL;
}

/*
 * Enqueue @engine, or maybe don't if UTRACE_ATTACH_EXCLUSIVE.
 */
static int utrace_add_engine(struct task_struct *target,
			     struct utrace *utrace,
			     struct utrace_engine *engine,
			     int flags,
			     const struct utrace_engine_ops *ops,
			     void *data)
{
	int ret;

	stp_spin_lock(&utrace->lock);

	ret = -EEXIST;
	if ((flags & UTRACE_ATTACH_EXCLUSIVE) &&
	     unlikely(find_matching_engine(utrace, flags, ops, data)))
		goto unlock;

	/*
	 * In case we had no engines before, make sure that
	 * utrace_flags is not zero. Since we did unlock+lock
	 * at least once after utrace_task_alloc() installed
	 * ->utrace, we have the necessary barrier which pairs
	 * with rmb() in task_utrace_struct().
	 */
	ret = -ESRCH;
	/* FIXME: Hmm, no reap in the brave new world... */
	if (!utrace->utrace_flags) {
		utrace->utrace_flags = UTRACE_EVENT(REAP);
		/*
		 * If we race with tracehook_prepare_release_task()
		 * make sure that either it sees utrace_flags != 0
		 * or we see exit_state == EXIT_DEAD.
		 */
		smp_mb();
		if (unlikely(target->exit_state == EXIT_DEAD)) {
			utrace->utrace_flags = 0;
			goto unlock;
		}
	}

	/*
	 * Put the new engine on the pending ->attaching list.
	 * Make sure it gets onto the ->attached list by the next
	 * time it's examined.  Setting ->pending_attach ensures
	 * that start_report() takes the lock and splices the lists
	 * before the next new reporting pass.
	 *
	 * When target == current, it would be safe just to call
	 * splice_attaching() right here.  But if we're inside a
	 * callback, that would mean the new engine also gets
	 * notified about the event that precipitated its own
	 * creation.  This is not what the user wants.
	 */
	list_add_tail(&engine->entry, &utrace->attaching);
	utrace->pending_attach = 1;
	utrace_engine_get(engine);
	ret = 0;
unlock:
	stp_spin_unlock(&utrace->lock);

	return ret;
}

/**
 * utrace_attach_task - attach new engine, or look up an attached engine
 * @target:	thread to attach to
 * @flags:	flag bits combined with OR, see below
 * @ops:	callback table for new engine
 * @data:	engine private data pointer
 *
 * The caller must ensure that the @target thread does not get freed,
 * i.e. hold a ref or be its parent.  It is always safe to call this
 * on @current, or on the @child pointer in a @report_clone callback.
 *
 * UTRACE_ATTACH_CREATE:
 * Create a new engine.  If %UTRACE_ATTACH_CREATE is not specified, you
 * only look up an existing engine already attached to the thread.
 *
 * *** FIXME: needed??? ***
 * UTRACE_ATTACH_EXCLUSIVE:
 * Attempting to attach a second (matching) engine fails with -%EEXIST.
 *
 * UTRACE_ATTACH_MATCH_OPS: Only consider engines matching @ops.
 * UTRACE_ATTACH_MATCH_DATA: Only consider engines matching @data.
 *
 * *** FIXME: need exclusive processing??? ***
 * Calls with neither %UTRACE_ATTACH_MATCH_OPS nor %UTRACE_ATTACH_MATCH_DATA
 * match the first among any engines attached to @target.  That means that
 * %UTRACE_ATTACH_EXCLUSIVE in such a call fails with -%EEXIST if there
 * are any engines on @target at all.
 */
static struct utrace_engine *utrace_attach_task(
	struct task_struct *target, int flags,
	const struct utrace_engine_ops *ops, void *data)
{
	struct utrace *utrace = task_utrace_struct(target);
	struct utrace_engine *engine;
	int ret;

#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - target %p, utrace %p\n", __FUNCTION__, __LINE__,
	       target, utrace);
#endif

	if (!(flags & UTRACE_ATTACH_CREATE)) {
		if (unlikely(!utrace))
			return ERR_PTR(-ENOENT);
		stp_spin_lock(&utrace->lock);
		engine = find_matching_engine(utrace, flags, ops, data);
		if (engine)
			utrace_engine_get(engine);
		stp_spin_unlock(&utrace->lock);
		return engine ?: ERR_PTR(-ENOENT);
	}

	if (unlikely(!ops) || unlikely(ops == &utrace_detached_ops))
		return ERR_PTR(-EINVAL);

	if (unlikely(target->flags & PF_KTHREAD))
		/*
		 * Silly kernel, utrace is for users!
		 */
		return ERR_PTR(-EPERM);

	if (!utrace) {
		if (unlikely(!utrace_task_alloc(target)))
			return ERR_PTR(-ENOMEM);
		utrace = task_utrace_struct(target);
	}

	engine = kmem_cache_alloc(utrace_engine_cachep, STP_ALLOC_FLAGS);
	if (unlikely(!engine))
		return ERR_PTR(-ENOMEM);

	/*
	 * Initialize the new engine structure.  It starts out with one ref
	 * to return.  utrace_add_engine() adds another for being attached.
	 */
	kref_init(&engine->kref);
	engine->flags = 0;
	engine->ops = ops;
	engine->data = data;
	engine->release = ops->release;

	ret = utrace_add_engine(target, utrace, engine, flags, ops, data);

	if (unlikely(ret)) {
		kmem_cache_free(utrace_engine_cachep, engine);
		engine = ERR_PTR(ret);
	}


	return engine;
}

/*
 * When an engine is detached, the target thread may still see it and
 * make callbacks until it quiesces.  We install a special ops vector
 * with these two callbacks.  When the target thread quiesces, it can
 * safely free the engine itself.  For any event we will always get
 * the report_quiesce() callback first, so we only need this one
 * pointer to be set.  The only exception is report_reap(), so we
 * supply that callback too.
 */
static u32 utrace_detached_quiesce(u32 action, struct utrace_engine *engine,
				   unsigned long event)
{
	return UTRACE_DETACH;
}

static void utrace_detached_reap(struct utrace_engine *engine,
				 struct task_struct *task)
{
}

static const struct utrace_engine_ops utrace_detached_ops = {
	.report_quiesce = &utrace_detached_quiesce,
	.report_reap = &utrace_detached_reap
};

/*
 * The caller has to hold a ref on the engine.  If the attached flag is
 * true (all but utrace_barrier() calls), the engine is supposed to be
 * attached.  If the attached flag is false (utrace_barrier() only),
 * then return -ERESTARTSYS for an engine marked for detach but not yet
 * fully detached.  The task pointer can be invalid if the engine is
 * detached.
 *
 * Get the utrace lock for the target task.
 * Returns the struct if locked, or ERR_PTR(-errno).
 *
 * This has to be robust against races with:
 *	utrace_control(target, UTRACE_DETACH) calls
 *	UTRACE_DETACH after reports
 *	utrace_report_death
 *	utrace_release_task
 */
static struct utrace *get_utrace_lock(struct task_struct *target,
				      struct utrace_engine *engine,
				      bool attached)
	__acquires(utrace->lock)
{
	struct utrace *utrace;

	rcu_read_lock();

	/*
	 * If this engine was already detached, bail out before we look at
	 * the task_struct pointer at all.  If it's detached after this
	 * check, then RCU is still keeping this task_struct pointer valid.
	 *
	 * The ops pointer is NULL when the engine is fully detached.
	 * It's &utrace_detached_ops when it's marked detached but still
	 * on the list.  In the latter case, utrace_barrier() still works,
	 * since the target might be in the middle of an old callback.
	 */
	if (unlikely(!engine->ops)) {
		rcu_read_unlock();
		return ERR_PTR(-ESRCH);
	}

	if (unlikely(engine->ops == &utrace_detached_ops)) {
		rcu_read_unlock();
		return attached ? ERR_PTR(-ESRCH) : ERR_PTR(-ERESTARTSYS);
	}

	utrace = task_utrace_struct(target);
	stp_spin_lock(&utrace->lock);
	if (unlikely(utrace->reap) || unlikely(!engine->ops) ||
	    unlikely(engine->ops == &utrace_detached_ops)) {
		/*
		 * By the time we got the utrace lock,
		 * it had been reaped or detached already.
		 */
		stp_spin_unlock(&utrace->lock);
		utrace = ERR_PTR(-ESRCH);
		if (!attached && engine->ops == &utrace_detached_ops)
			utrace = ERR_PTR(-ERESTARTSYS);
	}
	rcu_read_unlock();

	return utrace;
}

/*
 * Now that we don't hold any locks, run through any
 * detached engines and free their references.  Each
 * engine had one implicit ref while it was attached.
 */
static void put_detached_list(struct list_head *list)
{
	struct utrace_engine *engine, *next;
	list_for_each_entry_safe(engine, next, list, entry) {
		list_del_init(&engine->entry);
		utrace_engine_put(engine);
	}
}

/*
 * We use an extra bit in utrace_engine.flags past the event bits,
 * to record whether the engine is keeping the target thread stopped.
 *
 * This bit is set in task_struct.utrace_flags whenever it is set in any
 * engine's flags.  Only utrace_reset() resets it in utrace_flags.
 */
#define ENGINE_STOP		(1UL << _UTRACE_NEVENTS)

static void mark_engine_wants_stop(struct utrace *utrace,
				   struct utrace_engine *engine)
{
	engine->flags |= ENGINE_STOP;
	utrace->utrace_flags |= ENGINE_STOP;
}

static void clear_engine_wants_stop(struct utrace_engine *engine)
{
	engine->flags &= ~ENGINE_STOP;
}

static bool engine_wants_stop(struct utrace_engine *engine)
{
	return (engine->flags & ENGINE_STOP) != 0;
}

/**
 * utrace_set_events - choose which event reports a tracing engine gets
 * @target:		thread to affect
 * @engine:		attached engine to affect
 * @events:		new event mask
 *
 * This changes the set of events for which @engine wants callbacks made.
 *
 * This fails with -%EALREADY and does nothing if you try to clear
 * %UTRACE_EVENT(%DEATH) when the @report_death callback may already have
 * begun, or if you try to newly set %UTRACE_EVENT(%DEATH) or
 * %UTRACE_EVENT(%QUIESCE) when @target is already dead or dying.
 *
 * This fails with -%ESRCH if you try to clear %UTRACE_EVENT(%REAP) when
 * the @report_reap callback may already have begun, or when @target has
 * already been detached, including forcible detach on reaping.
 *
 * If @target was stopped before the call, then after a successful call,
 * no event callbacks not requested in @events will be made; if
 * %UTRACE_EVENT(%QUIESCE) is included in @events, then a
 * @report_quiesce callback will be made when @target resumes.
 *
 * If @target was not stopped and @events excludes some bits that were
 * set before, this can return -%EINPROGRESS to indicate that @target
 * may have been making some callback to @engine.  When this returns
 * zero, you can be sure that no event callbacks you've disabled in
 * @events can be made.  If @events only sets new bits that were not set
 * before on @engine, then -%EINPROGRESS will never be returned.
 *
 * To synchronize after an -%EINPROGRESS return, see utrace_barrier().
 *
 * When @target is @current, -%EINPROGRESS is not returned.  But note
 * that a newly-created engine will not receive any callbacks related to
 * an event notification already in progress.  This call enables @events
 * callbacks to be made as soon as @engine becomes eligible for any
 * callbacks, see utrace_attach_task().
 *
 * These rules provide for coherent synchronization based on %UTRACE_STOP,
 * even when %SIGKILL is breaking its normal simple rules.
 */
static int utrace_set_events(struct task_struct *target,
			     struct utrace_engine *engine,
			     unsigned long events)
{
	struct utrace *utrace;
	unsigned long old_flags, old_utrace_flags;
	int ret = -EALREADY;

	/*
	 * We just ignore the internal bit, so callers can use
	 * engine->flags to seed bitwise ops for our argument.
	 */
	events &= ~ENGINE_STOP;

	utrace = get_utrace_lock(target, engine, true);
	if (unlikely(IS_ERR(utrace)))
		return PTR_ERR(utrace);

	old_utrace_flags = utrace->utrace_flags;
	old_flags = engine->flags & ~ENGINE_STOP;

	/*
	 * If utrace_report_death() is already progress now,
	 * it's too late to clear the death event bits.
	 */
	if (target->exit_state &&
	    (((events & ~old_flags) & _UTRACE_DEATH_EVENTS) ||
	     (utrace->death &&
	      ((old_flags & ~events) & _UTRACE_DEATH_EVENTS)) ||
	     (utrace->reap && ((old_flags & ~events) & UTRACE_EVENT(REAP)))))
		goto unlock;

	/*
	 * When setting these flags, it's essential that we really
	 * synchronize with exit_notify().  They cannot be set after
	 * exit_notify() takes the tasklist_lock.  By holding the read
	 * lock here while setting the flags, we ensure that the calls
	 * to tracehook_notify_death() and tracehook_report_death() will
	 * see the new flags.  This ensures that utrace_release_task()
	 * knows positively that utrace_report_death() will be called or
	 * that it won't.
	 */
	if ((events & ~old_flags) & _UTRACE_DEATH_EVENTS) {
		/* FIXME: we can't get the tasklist_lock (since it
		 * isn't exported).  Plus, there is no more tracehook
		 * in exit_notify().  So, we'll ignore this for now
		 * and just assume that the lock on utrace is
		 * enough.  */
		//read_lock(&tasklist_lock);
		if (unlikely(target->exit_state)) {
			//read_unlock(&tasklist_lock);
			goto unlock;
		}
		utrace->utrace_flags |= events;
		//read_unlock(&tasklist_lock);
	}

	engine->flags = events | (engine->flags & ENGINE_STOP);
	utrace->utrace_flags |= events;

	ret = 0;
	if ((old_flags & ~events) && target != current &&
	    !task_is_stopped_or_traced(target) && !target->exit_state) {
		/*
		 * This barrier ensures that our engine->flags changes
		 * have hit before we examine utrace->reporting,
		 * pairing with the barrier in start_callback().  If
		 * @target has not yet hit finish_callback() to clear
		 * utrace->reporting, we might be in the middle of a
		 * callback to @engine.
		 */
		smp_mb();
		if (utrace->reporting == engine)
			ret = -EINPROGRESS;
	}
unlock:
	stp_spin_unlock(&utrace->lock);

	return ret;
}

/*
 * Asynchronously mark an engine as being detached.
 *
 * This must work while the target thread races with us doing
 * start_callback(), defined below.  It uses smp_rmb() between checking
 * @engine->flags and using @engine->ops.  Here we change @engine->ops
 * first, then use smp_wmb() before changing @engine->flags.  This ensures
 * it can check the old flags before using the old ops, or check the old
 * flags before using the new ops, or check the new flags before using the
 * new ops, but can never check the new flags before using the old ops.
 * Hence, utrace_detached_ops might be used with any old flags in place.
 * It has report_quiesce() and report_reap() callbacks to handle all cases.
 */
static void mark_engine_detached(struct utrace_engine *engine)
{
	engine->ops = &utrace_detached_ops;
	smp_wmb();
	engine->flags = UTRACE_EVENT(QUIESCE);
}

/*
 * Get @target to stop and return true if it is already stopped now.
 * If we return false, it will make some event callback soonish.
 * Called with @utrace locked.
 */
static bool utrace_do_stop(struct task_struct *target, struct utrace *utrace)
{
	if (task_is_stopped(target)) {
		/*
		 * Stopped is considered quiescent; when it wakes up, it will
		 * go through utrace_finish_stop() before doing anything else.
		 */
		spin_lock_irq(&target->sighand->siglock);
		if (likely(task_is_stopped(target)))
			__set_task_state(target, TASK_TRACED);
		spin_unlock_irq(&target->sighand->siglock);
	} else if (utrace->resume > UTRACE_REPORT) {
		utrace->resume = UTRACE_REPORT;
		stp_task_notify_resume(target, utrace);
	}

	return task_is_traced(target);
}

/*
 * If the target is not dead it should not be in tracing
 * stop any more.  Wake it unless it's in job control stop.
 */
static void utrace_wakeup(struct task_struct *target, struct utrace *utrace)
{
	lockdep_assert_held(&utrace->lock);
	spin_lock_irq(&target->sighand->siglock);
	if (target->signal->flags & SIGNAL_STOP_STOPPED ||
	    target->signal->group_stop_count)
		target->state = TASK_STOPPED;
	else
		stp_wake_up_state(target, __TASK_TRACED);
	spin_unlock_irq(&target->sighand->siglock);
}

/*
 * This is called when there might be some detached engines on the list or
 * some stale bits in @task->utrace_flags.  Clean them up and recompute the
 * flags.  Returns true if we're now fully detached.
 *
 * Called with @utrace->lock held, returns with it released.
 * After this returns, @utrace might be freed if everything detached.
 */
static bool utrace_reset(struct task_struct *task, struct utrace *utrace)
	__releases(utrace->lock)
{
	struct utrace_engine *engine, *next;
	unsigned long flags = 0;
	LIST_HEAD(detached);

	splice_attaching(utrace);

	/*
	 * Update the set of events of interest from the union
	 * of the interests of the remaining tracing engines.
	 * For any engine marked detached, remove it from the list.
	 * We'll collect them on the detached list.
	 */
	list_for_each_entry_safe(engine, next, &utrace->attached, entry) {
		if (engine->ops == &utrace_detached_ops) {
			engine->ops = NULL;
			list_move(&engine->entry, &detached);
		} else {
			flags |= engine->flags | UTRACE_EVENT(REAP);
		}
	}

	if (task->exit_state) {
		/*
		 * Once it's already dead, we never install any flags
		 * except REAP.  When ->exit_state is set and events
		 * like DEATH are not set, then they never can be set.
		 * This ensures that utrace_release_task() knows
		 * positively that utrace_report_death() can never run.
		 */
		BUG_ON(utrace->death);
		flags &= UTRACE_EVENT(REAP);
	}

	if (!flags) {
		/*
		 * No more engines, cleared out the utrace.
		 */
		utrace->resume = UTRACE_RESUME;
	}

	/*
	 * If no more engines want it stopped, wake it up.
	 */
	if (task_is_traced(task) && !(flags & ENGINE_STOP))
		utrace_wakeup(task, utrace);

	/*
	 * In theory spin_lock() doesn't imply rcu_read_lock().
	 * Once we clear ->utrace_flags this task_struct can go away
	 * because tracehook_prepare_release_task() path does not take
	 * utrace->lock when ->utrace_flags == 0.
	 */
	rcu_read_lock();
	utrace->utrace_flags = flags;
	stp_spin_unlock(&utrace->lock);
	rcu_read_unlock();

	put_detached_list(&detached);

	return !flags;
}

static void utrace_finish_stop(void)
{
	/*
	 * If we were task_is_traced() and then SIGKILL'ed, make
	 * sure we do nothing until the tracer drops utrace->lock.
	 */
	if (unlikely(__fatal_signal_pending(current))) {
		struct utrace *utrace = task_utrace_struct(current);
		stp_spin_unlock_wait(&utrace->lock);
	}
}

/*
 * Perform %UTRACE_STOP, i.e. block in TASK_TRACED until woken up.
 * @task == current, @utrace == current->utrace, which is not locked.
 * Return true if we were woken up by SIGKILL even though some utrace
 * engine may still want us to stay stopped.
 */
static void utrace_stop(struct task_struct *task, struct utrace *utrace,
			enum utrace_resume_action action)
{
relock:
	stp_spin_lock(&utrace->lock);

	if (action < utrace->resume) {
		/*
		 * Ensure a reporting pass when we're resumed.
		 */
		utrace->resume = action;
		stp_task_notify_resume(task, utrace);
		if (action == UTRACE_INTERRUPT)
			set_thread_flag(TIF_SIGPENDING);
	}

	/*
	 * If the ENGINE_STOP bit is clear in utrace_flags, that means
	 * utrace_reset() ran after we processed some UTRACE_STOP return
	 * values from callbacks to get here.  If all engines have detached
	 * or resumed us, we don't stop.  This check doesn't require
	 * siglock, but it should follow the interrupt/report bookkeeping
	 * steps (this can matter for UTRACE_RESUME but not UTRACE_DETACH).
	 */
	if (unlikely(!(utrace->utrace_flags & ENGINE_STOP))) {
		utrace_reset(task, utrace);
		if (utrace->utrace_flags & ENGINE_STOP)
			goto relock;
		return;
	}

	/*
	 * The siglock protects us against signals.  As well as SIGKILL
	 * waking us up, we must synchronize with the signal bookkeeping
	 * for stop signals and SIGCONT.
	 */
	spin_lock_irq(&task->sighand->siglock);

	if (unlikely(__fatal_signal_pending(task))) {
		spin_unlock_irq(&task->sighand->siglock);
		stp_spin_unlock(&utrace->lock);
		return;
	}

	__set_current_state(TASK_TRACED);

	/*
	 * If there is a group stop in progress,
	 * we must participate in the bookkeeping.
	 */
	if (unlikely(task->signal->group_stop_count) &&
			!--task->signal->group_stop_count)
		task->signal->flags = SIGNAL_STOP_STOPPED;

	spin_unlock_irq(&task->sighand->siglock);
	stp_spin_unlock(&utrace->lock);

	schedule();

	utrace_finish_stop();

	/*
	 * While in TASK_TRACED, we were considered "frozen enough".
	 * Now that we woke up, it's crucial if we're supposed to be
	 * frozen that we freeze now before running anything substantial.
	 */
	try_to_freeze();

	/*
	 * While we were in TASK_TRACED, complete_signal() considered
	 * us "uninterested" in signal wakeups.  Now make sure our
	 * TIF_SIGPENDING state is correct for normal running.
	 */
	spin_lock_irq(&task->sighand->siglock);
	recalc_sigpending();
	spin_unlock_irq(&task->sighand->siglock);
}

/*
 * Called by release_task() with @reap set to true.
 * Called by utrace_report_death() with @reap set to false.
 * On reap, make report_reap callbacks and clean out @utrace
 * unless still making callbacks.  On death, update bookkeeping
 * and handle the reap work if release_task() came in first.
 */
static void utrace_maybe_reap(struct task_struct *target, struct utrace *utrace,
			      bool reap)
{
	struct utrace_engine *engine, *next;
	struct list_head attached;

	stp_spin_lock(&utrace->lock);

	if (reap) {
		/*
		 * If the target will do some final callbacks but hasn't
		 * finished them yet, we know because it clears these event
		 * bits after it's done.  Instead of cleaning up here and
		 * requiring utrace_report_death() to cope with it, we
		 * delay the REAP report and the teardown until after the
		 * target finishes its death reports.
		 */
		utrace->reap = 1;

		if (utrace->utrace_flags & _UTRACE_DEATH_EVENTS) {
			stp_spin_unlock(&utrace->lock);
			return;
		}
	} else {
		/*
		 * After we unlock with this flag clear, any competing
		 * utrace_control/utrace_set_events calls know that we've
		 * finished our callbacks and any detach bookkeeping.
		 */
		utrace->death = 0;

		if (!utrace->reap) {
			/*
			 * We're just dead, not reaped yet.  This will
			 * reset @target->utrace_flags so the later call
			 * with @reap set won't hit the check above.
			 */
			utrace_reset(target, utrace);
			return;
		}
	}

	/*
	 * utrace_add_engine() checks ->utrace_flags != 0.  Since
	 * @utrace->reap is set, nobody can set or clear UTRACE_EVENT(REAP)
	 * in @engine->flags or change @engine->ops and nobody can change
	 * @utrace->attached after we drop the lock.
	 */
	utrace->utrace_flags = 0;

	/*
	 * We clear out @utrace->attached before we drop the lock so
	 * that find_matching_engine() can't come across any old engine
	 * while we are busy tearing it down.
	 */
	list_replace_init(&utrace->attached, &attached);
	list_splice_tail_init(&utrace->attaching, &attached);

	stp_spin_unlock(&utrace->lock);

	list_for_each_entry_safe(engine, next, &attached, entry) {
		if (engine->flags & UTRACE_EVENT(REAP))
			engine->ops->report_reap(engine, target);

		engine->ops = NULL;
		engine->flags = 0;
		list_del_init(&engine->entry);

		utrace_engine_put(engine);
	}
}

/*
 * You can't do anything to a dead task but detach it.
 * If release_task() has been called, you can't do that.
 *
 * On the exit path, DEATH and QUIESCE event bits are set only
 * before utrace_report_death() has taken the lock.  At that point,
 * the death report will come soon, so disallow detach until it's
 * done.  This prevents us from racing with it detaching itself.
 *
 * Called only when @target->exit_state is nonzero.
 */
static inline int utrace_control_dead(struct task_struct *target,
				      struct utrace *utrace,
				      enum utrace_resume_action action)
{
	lockdep_assert_held(&utrace->lock);

	if (action != UTRACE_DETACH || unlikely(utrace->reap))
		return -ESRCH;

	if (unlikely(utrace->death))
		/*
		 * We have already started the death report.  We can't
		 * prevent the report_death and report_reap callbacks,
		 * so tell the caller they will happen.
		 */
		return -EALREADY;

	return 0;
}

/**
 * utrace_control - control a thread being traced by a tracing engine
 * @target:		thread to affect
 * @engine:		attached engine to affect
 * @action:		&enum utrace_resume_action for thread to do
 *
 * This is how a tracing engine asks a traced thread to do something.
 * This call is controlled by the @action argument, which has the
 * same meaning as the &enum utrace_resume_action value returned by
 * event reporting callbacks.
 *
 * If @target is already dead (@target->exit_state nonzero),
 * all actions except %UTRACE_DETACH fail with -%ESRCH.
 *
 * The following sections describe each option for the @action argument.
 *
 * UTRACE_DETACH:
 *
 * After this, the @engine data structure is no longer accessible,
 * and the thread might be reaped.  The thread will start running
 * again if it was stopped and no longer has any attached engines
 * that want it stopped.
 *
 * If the @report_reap callback may already have begun, this fails
 * with -%ESRCH.  If the @report_death callback may already have
 * begun, this fails with -%EALREADY.
 *
 * If @target is not already stopped, then a callback to this engine
 * might be in progress or about to start on another CPU.  If so,
 * then this returns -%EINPROGRESS; the detach happens as soon as
 * the pending callback is finished.  To synchronize after an
 * -%EINPROGRESS return, see utrace_barrier().
 *
 * If @target is properly stopped before utrace_control() is called,
 * then after successful return it's guaranteed that no more callbacks
 * to the @engine->ops vector will be made.
 *
 * The only exception is %SIGKILL (and exec or group-exit by another
 * thread in the group), which can cause asynchronous @report_death
 * and/or @report_reap callbacks even when %UTRACE_STOP was used.
 * (In that event, this fails with -%ESRCH or -%EALREADY, see above.)
 *
 * UTRACE_STOP:
 *
 * This asks that @target stop running.  This returns 0 only if
 * @target is already stopped, either for tracing or for job
 * control.  Then @target will remain stopped until another
 * utrace_control() call is made on @engine; @target can be woken
 * only by %SIGKILL (or equivalent, such as exec or termination by
 * another thread in the same thread group).
 *
 * This returns -%EINPROGRESS if @target is not already stopped.
 * Then the effect is like %UTRACE_REPORT.  A @report_quiesce
 * callback will be made soon.  Your callback can
 * then return %UTRACE_STOP to keep @target stopped.
 *
 * This does not interrupt system calls in progress, including ones
 * that sleep for a long time.
 *
 * UTRACE_RESUME:
 *
 * Just let @target continue running normally, reversing the effect
 * of a previous %UTRACE_STOP.  If another engine is keeping @target
 * stopped, then it remains stopped until all engines let it resume.
 * If @target was not stopped, this has no effect.
 *
 * UTRACE_REPORT:
 *
 * This is like %UTRACE_RESUME, but also ensures that there will be
 * a @report_quiesce callback made soon.  If
 * @target had been stopped, then there will be a callback before it
 * resumes running normally.  If another engine is keeping @target
 * stopped, then there might be no callbacks until all engines let
 * it resume.
 *
 * Since this is meaningless unless @report_quiesce callbacks will
 * be made, it returns -%EINVAL if @engine lacks %UTRACE_EVENT(%QUIESCE).
 *
 * UTRACE_INTERRUPT:
 *
 * This is like %UTRACE_REPORT, but ensures that @target will make a
 * callback before it resumes or delivers signals.  If @target was in
 * a system call or about to enter one, work in progress will be
 * interrupted as if by %SIGSTOP.  If another engine is keeping
 * @target stopped, then there might be no callbacks until all engines
 * let it resume.
 */
static int utrace_control(struct task_struct *target,
			  struct utrace_engine *engine,
			  enum utrace_resume_action action)
{
	struct utrace *utrace;
	bool reset;
	int ret;

	if (unlikely(action >= UTRACE_RESUME_MAX)) {
		WARN(1, "invalid action argument to utrace_control()!");
		return -EINVAL;
	}

	/*
	 * This is a sanity check for a programming error in the caller.
	 * Their request can only work properly in all cases by relying on
	 * a follow-up callback, but they didn't set one up!  This check
	 * doesn't do locking, but it shouldn't matter.  The caller has to
	 * be synchronously sure the callback is set up to be operating the
	 * interface properly.
	 */
	if (action >= UTRACE_REPORT && action < UTRACE_RESUME &&
	    unlikely(!(engine->flags & UTRACE_EVENT(QUIESCE)))) {
		WARN(1, "utrace_control() with no QUIESCE callback in place!");
		return -EINVAL;
	}

	utrace = get_utrace_lock(target, engine, true);
	if (unlikely(IS_ERR(utrace)))
		return PTR_ERR(utrace);

	reset = task_is_traced(target);
	ret = 0;

	/*
	 * ->exit_state can change under us, this doesn't matter.
	 * We do not care about ->exit_state in fact, but we do
	 * care about ->reap and ->death. If either flag is set,
	 * we must also see ->exit_state != 0.
	 */
	if (unlikely(target->exit_state)) {
		ret = utrace_control_dead(target, utrace, action);
		if (ret) {
			stp_spin_unlock(&utrace->lock);
			return ret;
		}
		reset = true;
	}

	switch (action) {
	case UTRACE_STOP:
		mark_engine_wants_stop(utrace, engine);
		if (!reset && !utrace_do_stop(target, utrace))
			ret = -EINPROGRESS;
		reset = false;
		break;

	case UTRACE_DETACH:
		if (engine_wants_stop(engine))
			utrace->utrace_flags &= ~ENGINE_STOP;
		mark_engine_detached(engine);
		reset = reset || utrace_do_stop(target, utrace);
		if (!reset) {
			/*
			 * As in utrace_set_events(), this barrier ensures
			 * that our engine->flags changes have hit before we
			 * examine utrace->reporting, pairing with the barrier
			 * in start_callback().  If @target has not yet hit
			 * finish_callback() to clear utrace->reporting, we
			 * might be in the middle of a callback to @engine.
			 */
			smp_mb();
			if (utrace->reporting == engine)
				ret = -EINPROGRESS;
		}
		break;

	case UTRACE_RESUME:
		clear_engine_wants_stop(engine);
		break;

	case UTRACE_REPORT:
		/*
		 * Make the thread call tracehook_notify_resume() soon.
		 * But don't bother if it's already been interrupted.
		 * In that case, utrace_get_signal() will be reporting soon.
		 */
		clear_engine_wants_stop(engine);
		if (action < utrace->resume) {
			utrace->resume = action;
			stp_task_notify_resume(target, utrace);
		}
		break;

	case UTRACE_INTERRUPT:
		/*
		 * Make the thread call tracehook_get_signal() soon.
		 */
		clear_engine_wants_stop(engine);
		if (utrace->resume == UTRACE_INTERRUPT)
			break;
		utrace->resume = UTRACE_INTERRUPT;

		/*
		 * If it's not already stopped, interrupt it now.  We need
		 * the siglock here in case it calls recalc_sigpending()
		 * and clears its own TIF_SIGPENDING.  By taking the lock,
		 * we've serialized any later recalc_sigpending() after our
		 * setting of utrace->resume to force it on.
		 */
		stp_task_notify_resume(target, utrace);
		if (reset) {
			/*
			 * This is really just to keep the invariant that
			 * TIF_SIGPENDING is set with UTRACE_INTERRUPT.
			 * When it's stopped, we know it's always going
			 * through utrace_get_signal() and will recalculate.
			 */
			set_tsk_thread_flag(target, TIF_SIGPENDING);
		} else {
			struct sighand_struct *sighand;
			unsigned long irqflags;
			sighand = stp_lock_task_sighand(target, &irqflags);
			if (likely(sighand)) {
				stp_signal_wake_up(target, 0);
				unlock_task_sighand(target, &irqflags);
			}
		}
		break;

	default:
		BUG();		/* We checked it on entry.  */
	}

	/*
	 * Let the thread resume running.  If it's not stopped now,
	 * there is nothing more we need to do.
	 */
	if (reset)
		utrace_reset(target, utrace);
	else
		stp_spin_unlock(&utrace->lock);

	return ret;
}

/**
 * utrace_barrier - synchronize with simultaneous tracing callbacks
 * @target:		thread to affect
 * @engine:		engine to affect (can be detached)
 *
 * This blocks while @target might be in the midst of making a callback to
 * @engine.  It can be interrupted by signals and will return -%ERESTARTSYS.
 * A return value of zero means no callback from @target to @engine was
 * in progress.  Any effect of its return value (such as %UTRACE_STOP) has
 * already been applied to @engine.
 *
 * It's not necessary to keep the @target pointer alive for this call.
 * It's only necessary to hold a ref on @engine.  This will return
 * safely even if @target has been reaped and has no task refs.
 *
 * A successful return from utrace_barrier() guarantees its ordering
 * with respect to utrace_set_events() and utrace_control() calls.  If
 * @target was not properly stopped, event callbacks just disabled might
 * still be in progress; utrace_barrier() waits until there is no chance
 * an unwanted callback can be in progress.
 */
static int utrace_barrier(struct task_struct *target,
			  struct utrace_engine *engine)
{
	struct utrace *utrace;
	int ret = -ERESTARTSYS;

	if (unlikely(target == current))
		return 0;

	/* If we get here, we might call
	 * schedule_timeout_interruptible(), which sleeps. */
	might_sleep();
	do {
		utrace = get_utrace_lock(target, engine, false);
		if (unlikely(IS_ERR(utrace))) {
			ret = PTR_ERR(utrace);
			if (ret != -ERESTARTSYS)
				break;
		} else {
			/*
			 * All engine state changes are done while
			 * holding the lock, i.e. before we get here.
			 * Since we have the lock, we only need to
			 * worry about @target making a callback.
			 * When it has entered start_callback() but
			 * not yet gotten to finish_callback(), we
			 * will see utrace->reporting == @engine.
			 * When @target doesn't take the lock, it uses
			 * barriers to order setting utrace->reporting
			 * before it examines the engine state.
			 */
			if (utrace->reporting != engine)
				ret = 0;
			stp_spin_unlock(&utrace->lock);
			if (!ret)
				break;
		}
		schedule_timeout_interruptible(1);
	} while (!signal_pending(current));

	return ret;
}

/*
 * This is local state used for reporting loops, perhaps optimized away.
 */
struct utrace_report {
	u32 result;
	enum utrace_resume_action action;
	enum utrace_resume_action resume_action;
	bool detaches;
	bool spurious;
};

#define INIT_REPORT(var)			\
	struct utrace_report var = {		\
		.action = UTRACE_RESUME,	\
		.resume_action = UTRACE_RESUME,	\
		.spurious = true 		\
	}

/*
 * We are now making the report, so clear the flag saying we need one.
 * When there is a new attach, ->pending_attach is set just so we will
 * know to do splice_attaching() here before the callback loop.
 */
static enum utrace_resume_action start_report(struct utrace *utrace)
{
	enum utrace_resume_action resume = utrace->resume;
	if (utrace->pending_attach ||
	    (resume > UTRACE_STOP && resume < UTRACE_RESUME)) {
		stp_spin_lock(&utrace->lock);
		splice_attaching(utrace);
		resume = utrace->resume;
		if (resume > UTRACE_STOP)
			utrace->resume = UTRACE_RESUME;
		stp_spin_unlock(&utrace->lock);
	}
	return resume;
}

static inline void finish_report_reset(struct task_struct *task,
				       struct utrace *utrace,
				       struct utrace_report *report)
{
	if (unlikely(report->spurious || report->detaches)) {
		stp_spin_lock(&utrace->lock);
		if (utrace_reset(task, utrace))
			report->action = UTRACE_RESUME;
	}
}

/*
 * Complete a normal reporting pass, pairing with a start_report()
 * call.  This handles any UTRACE_DETACH or UTRACE_REPORT returns from
 * engine callbacks.  If @will_not_stop is true and any engine's last
 * callback used UTRACE_STOP, we do UTRACE_REPORT here to ensure we
 * stop before user mode.  If there were no callbacks made, it will
 * recompute @task->utrace_flags to avoid another false-positive.
 */
static void finish_report(struct task_struct *task, struct utrace *utrace,
			  struct utrace_report *report, bool will_not_stop)
{
	enum utrace_resume_action resume = report->action;

	if (resume == UTRACE_STOP)
		resume = will_not_stop ? UTRACE_REPORT : UTRACE_RESUME;

	if (resume < utrace->resume) {
		stp_spin_lock(&utrace->lock);
		utrace->resume = resume;
		stp_task_notify_resume(task, utrace);
		if (resume == UTRACE_INTERRUPT)
			set_tsk_thread_flag(task, TIF_SIGPENDING);
		stp_spin_unlock(&utrace->lock);
	}

	finish_report_reset(task, utrace, report);
}

static void finish_callback_report(struct task_struct *task,
				   struct utrace *utrace,
				   struct utrace_report *report,
				   struct utrace_engine *engine,
				   enum utrace_resume_action action)
{
	if (action == UTRACE_DETACH) {
		/*
		 * By holding the lock here, we make sure that
		 * utrace_barrier() (really get_utrace_lock()) sees the
		 * effect of this detach.  Otherwise utrace_barrier() could
		 * return 0 after this callback had returned UTRACE_DETACH.
		 * This way, a 0 return is an unambiguous indicator that any
		 * callback returning UTRACE_DETACH has indeed caused detach.
		 */
		stp_spin_lock(&utrace->lock);
		engine->ops = &utrace_detached_ops;
		stp_spin_unlock(&utrace->lock);
	}

	/*
	 * If utrace_control() was used, treat that like UTRACE_DETACH here.
	 */
	if (engine->ops == &utrace_detached_ops) {
		report->detaches = true;
		return;
	}

	if (action < report->action)
		report->action = action;

	if (action != UTRACE_STOP) {
		if (action < report->resume_action)
			report->resume_action = action;

		if (engine_wants_stop(engine)) {
			stp_spin_lock(&utrace->lock);
			clear_engine_wants_stop(engine);
			stp_spin_unlock(&utrace->lock);
		}

		return;
	}

	if (!engine_wants_stop(engine)) {
		stp_spin_lock(&utrace->lock);
		/*
		 * If utrace_control() came in and detached us
		 * before we got the lock, we must not stop now.
		 */
		if (unlikely(engine->ops == &utrace_detached_ops))
			report->detaches = true;
		else
			mark_engine_wants_stop(utrace, engine);
		stp_spin_unlock(&utrace->lock);
	}
}

/*
 * Apply the return value of one engine callback to @report.
 * Returns true if @engine detached and should not get any more callbacks.
 */
static bool finish_callback(struct task_struct *task, struct utrace *utrace,
			    struct utrace_report *report,
			    struct utrace_engine *engine,
			    u32 ret)
{
	report->result = ret & ~UTRACE_RESUME_MASK;
	finish_callback_report(task, utrace, report, engine,
			       utrace_resume_action(ret));

	/*
	 * Now that we have applied the effect of the return value,
	 * clear this so that utrace_barrier() can stop waiting.
	 * A subsequent utrace_control() can stop or resume @engine
	 * and know this was ordered after its callback's action.
	 *
	 * We don't need any barriers here because utrace_barrier()
	 * takes utrace->lock.  If we touched engine->flags above,
	 * the lock guaranteed this change was before utrace_barrier()
	 * examined utrace->reporting.
	 */
	utrace->reporting = NULL;

	/*
	 * We've just done an engine callback.  These are *not*
	 * allowed to sleep, unlike the original utrace (since
	 * tracepiont handlers aren't allowed to sleep).
	 */

	return engine->ops == &utrace_detached_ops;
}

/*
 * Start the callbacks for @engine to consider @event (a bit mask).
 * This makes the report_quiesce() callback first.  If @engine wants
 * a specific callback for @event, we return the ops vector to use.
 * If not, we return NULL.  The return value from the ops->callback
 * function called should be passed to finish_callback().
 */
static const struct utrace_engine_ops *start_callback(
	struct utrace *utrace, struct utrace_report *report,
	struct utrace_engine *engine, struct task_struct *task,
	unsigned long event)
{
	const struct utrace_engine_ops *ops;
	unsigned long want;

#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - utrace %p, report %p, engine %p, task %p, event %ld\n",
	       __FUNCTION__, __LINE__, utrace, report, engine, task, event);
#endif

	/*
	 * This barrier ensures that we've set utrace->reporting before
	 * we examine engine->flags or engine->ops.  utrace_barrier()
	 * relies on this ordering to indicate that the effect of any
	 * utrace_control() and utrace_set_events() calls is in place
	 * by the time utrace->reporting can be seen to be NULL.
	 */
	utrace->reporting = engine;
	smp_mb();

	/*
	 * This pairs with the barrier in mark_engine_detached().
	 * It makes sure that we never see the old ops vector with
	 * the new flags, in case the original vector had no report_quiesce.
	 */
	want = engine->flags;
	smp_rmb();
	ops = engine->ops;

	if ((want & UTRACE_EVENT(QUIESCE)) || ops == &utrace_detached_ops) {
#ifdef STP_TF_DEBUG
		printk(KERN_ERR "%s:%d - quiescing, ops %p, ops->report_quiesce %p\n",
		       __FUNCTION__, __LINE__, ops,
		       (ops == NULL ? 0 : ops->report_quiesce));
#endif
		if (finish_callback(task, utrace, report, engine,
				    (*ops->report_quiesce)(report->action,
							   engine, event)))
			return NULL;

		if (!event) {
			/* We only got here to report QUIESCE */
			report->spurious = false;
			return NULL;
		}

		/*
		 * finish_callback() reset utrace->reporting after the
		 * quiesce callback.  Now we set it again (as above)
		 * before re-examining engine->flags, which could have
		 * been changed synchronously by ->report_quiesce or
		 * asynchronously by utrace_control() or utrace_set_events().
		 */
		utrace->reporting = engine;
		smp_mb();
		want = engine->flags;
	}

	if (want & ENGINE_STOP)
		report->action = UTRACE_STOP;

	if (want & event) {
		report->spurious = false;
		return ops;
	}

	utrace->reporting = NULL;
	return NULL;
}

/*
 * Do a normal reporting pass for engines interested in @event.
 * @callback is the name of the member in the ops vector, and remaining
 * args are the extras it takes after the standard three args.
 */
#define REPORT_CALLBACKS(rev, task, utrace, report, event, callback, ...)     \
	do {								      \
		struct utrace_engine *engine;				      \
		const struct utrace_engine_ops *ops;			      \
		list_for_each_entry##rev(engine, &utrace->attached, entry) {  \
			ops = start_callback(utrace, report, engine, task,    \
					     event);			      \
			if (!ops)					      \
				continue;				      \
			finish_callback(task, utrace, report, engine,	      \
					(*ops->callback)(__VA_ARGS__));	      \
		}							      \
	} while (0)
#define REPORT(task, utrace, report, event, callback, ...)		      \
	do {								      \
		start_report(utrace);					      \
		REPORT_CALLBACKS(, task, utrace, report, event, callback,     \
				 (report)->action, engine, ## __VA_ARGS__);   \
		finish_report(task, utrace, report, true);		      \
	} while (0)

/*
 * Called iff UTRACE_EVENT(EXEC) flag is set.
 */
static void utrace_report_exec(void *cb_data __attribute__ ((unused)),
			       struct task_struct *task,
			       pid_t old_pid __attribute__((unused)),
			       struct linux_binprm *bprm __attribute__ ((unused)))
{
	struct utrace *utrace;

	if (atomic_read(&utrace_state) != __UTRACE_REGISTERED)
		return;
	utrace = task_utrace_struct(task);

	if (utrace && utrace->utrace_flags & UTRACE_EVENT(EXEC)) {
		INIT_REPORT(report);

		/* FIXME: Hmm, can we get regs another way? */
		REPORT(task, utrace, &report, UTRACE_EVENT(EXEC),
		       report_exec, NULL, NULL, NULL /* regs */);
	}
}

#if 0
static u32 do_report_syscall_entry(struct pt_regs *regs,
				   struct task_struct *task,
				   struct utrace *utrace,
				   struct utrace_report *report,
				   u32 resume_report)
{
	start_report(utrace);
	REPORT_CALLBACKS(_reverse, task, utrace, report,
			 UTRACE_EVENT(SYSCALL_ENTRY), report_syscall_entry,
			 resume_report | report->result | report->action,
			 engine, regs);
	finish_report(task, utrace, report, false);

	if (report->action != UTRACE_STOP)
		return 0;

	utrace_stop(task, utrace, report->resume_action);

	if (fatal_signal_pending(task)) {
		/*
		 * We are continuing despite UTRACE_STOP because of a
		 * SIGKILL.  Don't let the system call actually proceed.
		 */
		report->result = UTRACE_SYSCALL_ABORT;
	} else if (utrace->resume <= UTRACE_REPORT) {
		/*
		 * If we've been asked for another report after our stop,
		 * go back to report (and maybe stop) again before we run
		 * the system call.  The second (and later) reports are
		 * marked with the UTRACE_SYSCALL_RESUMED flag so that
		 * engines know this is a second report at the same
		 * entry.  This gives them the chance to examine the
		 * registers anew after they might have been changed
		 * while we were stopped.
		 */
		report->detaches = false;
		report->spurious = true;
		report->action = report->resume_action = UTRACE_RESUME;
		return UTRACE_SYSCALL_RESUMED;
	}

	return 0;
}
#endif

/*
 * Called iff UTRACE_EVENT(SYSCALL_ENTRY) flag is set.
 * Return true to prevent the system call.
 */
static void utrace_report_syscall_entry(void *cb_data __attribute__ ((unused)),
					struct pt_regs *regs, long id)
{
	struct task_struct *task = current;
	struct utrace *utrace;

	if (atomic_read(&utrace_state) != __UTRACE_REGISTERED)
		return;
	utrace = task_utrace_struct(task);

	/* FIXME: Is this 100% correct? */
	if (utrace
	    && utrace->utrace_flags & (UTRACE_EVENT(SYSCALL_ENTRY)|ENGINE_STOP)) {
		INIT_REPORT(report);


		/* FIXME: Hmm, original utrace called probes in reverse
		 * order.  Needed here? */
		REPORT(task, utrace, &report, UTRACE_EVENT(SYSCALL_ENTRY),
		       report_syscall_entry, regs);
	}


#if 0
	INIT_REPORT(report);
	u32 resume_report = 0;

	do {
		resume_report = do_report_syscall_entry(regs, task, utrace,
							&report, resume_report);
	} while (resume_report);

	return utrace_syscall_action(report.result) == UTRACE_SYSCALL_ABORT;
#endif
}

/*
 * Called iff UTRACE_EVENT(SYSCALL_EXIT) flag is set.
 */
static void utrace_report_syscall_exit(void *cb_data __attribute__ ((unused)),
				       struct pt_regs *regs, long ret)
{
	struct task_struct *task = current;
	struct utrace *utrace;

	if (atomic_read(&utrace_state) != __UTRACE_REGISTERED)
		return;
	utrace = task_utrace_struct(task);

	/* FIXME: Is this 100% correct? */
	if (utrace
	    && utrace->utrace_flags & (UTRACE_EVENT(SYSCALL_EXIT)|ENGINE_STOP)) {
		INIT_REPORT(report);

#ifdef STP_TF_DEBUG
		printk(KERN_ERR "%s:%d - task %p, utrace %p, utrace_flags 0x%lx\n",
		       __FUNCTION__, __LINE__, task, utrace,
		       utrace->utrace_flags);
#endif
		REPORT(task, utrace, &report, UTRACE_EVENT(SYSCALL_EXIT),
		       report_syscall_exit, regs);
	}
}

/*
 * Called iff UTRACE_EVENT(CLONE) flag is set.
 * This notification call blocks the wake_up_new_task call on the child.
 * So we must not quiesce here.  tracehook_report_clone_complete will do
 * a quiescence check momentarily.
 */
static void utrace_report_clone(void *cb_data __attribute__ ((unused)), 
				struct task_struct *task,
				struct task_struct *child)
{
	struct utrace *utrace;

	if (atomic_read(&utrace_state) != __UTRACE_REGISTERED)
		return;
	utrace = task_utrace_struct(task);

#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - parent %p, child %p, current %p\n",
	       __FUNCTION__, __LINE__, task, child, current);
#endif

	if (utrace && utrace->utrace_flags & UTRACE_EVENT(CLONE)) {
		unsigned long clone_flags = 0;
		INIT_REPORT(report);

		/* FIXME: Figure out what the clone_flags were. For
		 * task_finder's purposes, all we need is CLONE_THREAD. */
		if (task->mm == child->mm)
			clone_flags |= CLONE_VM;
		if (task->fs == child->fs)
			clone_flags |= CLONE_FS;
		if (task->files == child->files)
			clone_flags |= CLONE_FILES;
		if (task->sighand == child->sighand)
			clone_flags |= CLONE_SIGHAND;

#if 0
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
#endif
		if (! thread_group_leader(child)) /* Same thread group? */
			clone_flags |= CLONE_THREAD;

#if 0
#define CLONE_NEWNS	0x00020000	/* New namespace group? */
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
/* 0x02000000 was previously the unused CLONE_STOPPED (Start in stopped state)
   and is now available for re-use. */
#define CLONE_NEWUTS		0x04000000	/* New utsname group? */
#define CLONE_NEWIPC		0x08000000	/* New ipcs */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */
#endif


		REPORT(task, utrace, &report, UTRACE_EVENT(CLONE),
		       report_clone, clone_flags, child);


#if 0
		/*
		 * For a vfork, we will go into an uninterruptible
		 * block waiting for the child.  We need UTRACE_STOP
		 * to happen before this, not after.  For CLONE_VFORK,
		 * utrace_finish_vfork() will be called.
		 */
		if (report.action == UTRACE_STOP
		    && (clone_flags & CLONE_VFORK)) {
			spin_lock(&utrace->lock);
			utrace->vfork_stop = 1;
			spin_unlock(&utrace->lock);
		}
#endif
	}
}

/*
 * We're called after utrace_report_clone() for a CLONE_VFORK.
 * If UTRACE_STOP was left from the clone report, we stop here.
 * After this, we'll enter the uninterruptible wait_for_completion()
 * waiting for the child.
 */
static void utrace_finish_vfork(struct task_struct *task)
{
	struct utrace *utrace = task_utrace_struct(task);

	if (utrace->vfork_stop) {
		stp_spin_lock(&utrace->lock);
		utrace->vfork_stop = 0;
		stp_spin_unlock(&utrace->lock);
		utrace_stop(task, utrace, UTRACE_RESUME); /* XXX */
	}
}

/*
 * Called iff UTRACE_EVENT(DEATH) or UTRACE_EVENT(QUIESCE) flag is set.
 *
 * It is always possible that we are racing with utrace_release_task here.
 * For this reason, utrace_release_task checks for the event bits that get
 * us here, and delays its cleanup for us to do.
 */
static void utrace_report_death(void *cb_data __attribute__ ((unused)),
				struct task_struct *task)
{
	struct utrace *utrace;
	INIT_REPORT(report);

	if (atomic_read(&utrace_state) != __UTRACE_REGISTERED)
		return;
	utrace = task_utrace_struct(task);

#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - task %p, utrace %p, flags %lx\n", __FUNCTION__, __LINE__, task, utrace, utrace ? utrace->utrace_flags : 0);
#endif
	if (!utrace || !(utrace->utrace_flags & UTRACE_EVENT(DEATH)))
		return;

	/* This code is called from the 'sched_process_exit'
	 * tracepoint, which really corresponds more to UTRACE_EXIT
	 * (thread exit in progress) than to UTRACE_DEATH (thread has
	 * died).  But utrace_report_death() calls
	 * utrace_maybe_reap(), which does cleanup that we need.
	 *
	 * Because of this, 'exit_state' won't be set yet (as it would
	 * have been when the original utrace hit this code).
	 *
	 * BUG_ON(!task->exit_state);
	 */

	/*
	 * We are presently considered "quiescent"--which is accurate
	 * inasmuch as we won't run any more user instructions ever again.
	 * But for utrace_control and utrace_set_events to be robust, they
	 * must be sure whether or not we will run any more callbacks.  If
	 * a call comes in before we do, taking the lock here synchronizes
	 * us so we don't run any callbacks just disabled.  Calls that come
	 * in while we're running the callbacks will see the exit.death
	 * flag and know that we are not yet fully quiescent for purposes
	 * of detach bookkeeping.
	 */
	if (in_atomic() || irqs_disabled()) {
		if (! utrace->report_work_added) {
			int rc;
#ifdef STP_TF_DEBUG
			printk(KERN_ERR "%s:%d - adding task_work\n",
			       __FUNCTION__, __LINE__);
#endif
			rc = stp_task_work_add(task,
					       &utrace->report_work);
			if (rc == 0) {
				utrace->report_work_added = 1;
			}
			/* stp_task_work_add() returns -ESRCH if the
			 * task has already passed
			 * exit_task_work(). Just ignore this
			 * error. */
			else if (rc != -ESRCH) {
				printk(KERN_ERR
				       "%s:%d - task_work_add() returned %d\n",
				       __FUNCTION__, __LINE__, rc);
			}
		}
	}
	else {
		stp_spin_lock(&utrace->lock);
		BUG_ON(utrace->death);
		utrace->death = 1;
		utrace->resume = UTRACE_RESUME;
		splice_attaching(utrace);
		stp_spin_unlock(&utrace->lock);

		REPORT_CALLBACKS(, task, utrace, &report, UTRACE_EVENT(DEATH),
				 report_death, engine, -1/*group_dead*/,
				 -1/*signal*/);

		utrace_maybe_reap(task, utrace, false);
		utrace_free(utrace);
	}
}

/*
 * Finish the last reporting pass before returning to user mode.
 */
static void finish_resume_report(struct task_struct *task,
				 struct utrace *utrace,
				 struct utrace_report *report)
{
	finish_report_reset(task, utrace, report);

	switch (report->action) {
	case UTRACE_STOP:
		utrace_stop(task, utrace, report->resume_action);
		break;

	case UTRACE_INTERRUPT:
		if (!signal_pending(task)) {
			stp_task_notify_resume(task, utrace);
			set_tsk_thread_flag(task, TIF_SIGPENDING);
		}
		break;

	case UTRACE_REPORT:
	case UTRACE_RESUME:
	default:
		break;
	}
}

/*
 * This is called when TIF_NOTIFY_RESUME had been set (and is now clear).
 * We are close to user mode, and this is the place to report or stop.
 * When we return, we're going to user mode or into the signals code.
 */
static void utrace_resume(struct task_work *work)
{
	/*
	 * We could also do 'task_utrace_struct()' here to find the
	 * task's 'struct utrace', but 'container_of()' should be
	 * instantaneous (where 'task_utrace_struct()' has to do a
	 * hash lookup).
	 */
	struct utrace *utrace = container_of(work, struct utrace, work);
	struct task_struct *task = current;
	INIT_REPORT(report);
	struct utrace_engine *engine;

	might_sleep();
	utrace->task_work_added = 0;

	/* Make sure the task isn't exiting. */
	if (task->flags & PF_EXITING) {
		/* Remember that this task_work_func is finished. */
		stp_task_work_func_done();
		return;
	}

	/*
	 * Some machines get here with interrupts disabled.  The same arch
	 * code path leads to calling into get_signal_to_deliver(), which
	 * implicitly reenables them by virtue of spin_unlock_irq.
	 */
	local_irq_enable();

	/*
	 * Update our bookkeeping even if there are no callbacks made here.
	 */
	report.action = start_report(utrace);

	switch (report.action) {
	case UTRACE_RESUME:
		/*
		 * Anything we might have done was already handled by
		 * utrace_get_signal(), or this is an entirely spurious
		 * call.  (The arch might use TIF_NOTIFY_RESUME for other
		 * purposes as well as calling us.)
		 */

		/* Remember that this task_work_func is finished. */
		stp_task_work_func_done();
		return;
	case UTRACE_INTERRUPT:
		/*
		 * Note that UTRACE_INTERRUPT reporting was handled by
		 * utrace_get_signal() in original utrace. In this
		 * utrace version, we'll handle it here like UTRACE_REPORT.
		 *
		 * Fallthrough...
		 */
	case UTRACE_REPORT:
		if (unlikely(!(utrace->utrace_flags & UTRACE_EVENT(QUIESCE))))
			break;
		/*
		 * Do a simple reporting pass, with no specific
		 * callback after report_quiesce.
		 */
		report.action = UTRACE_RESUME;
		list_for_each_entry(engine, &utrace->attached, entry)
			start_callback(utrace, &report, engine, task, 0);
		break;
	default:
		/*
		 * Even if this report was truly spurious, there is no need
		 * for utrace_reset() now.  TIF_NOTIFY_RESUME was already
		 * cleared--it doesn't stay spuriously set.
		 */
		report.spurious = false;
		break;
	}

	/*
	 * Finish the report and either stop or get ready to resume.
	 * If utrace->resume was not UTRACE_REPORT, this applies its
	 * effect now (i.e. step or interrupt).
	 */
	finish_resume_report(task, utrace, &report);
	
	/* Remember that this task_work_func is finished. */
	stp_task_work_func_done();
}


static void utrace_report_work(struct task_work *work)
{
	/*
	 * We could also do 'task_utrace_struct()' here to find the
	 * task's 'struct utrace', but 'container_of()' should be
	 * instantaneous (where 'task_utrace_struct()' has to do a
	 * hash lookup).
	 */
	struct utrace *utrace = container_of(work, struct utrace, report_work);
	struct task_struct *task = current;
	INIT_REPORT(report);
	struct utrace_engine *engine;
	unsigned long clone_flags;

#ifdef STP_TF_DEBUG
	printk(KERN_ERR "%s:%d - atomic %d, irqs_disabled %d\n",
	       __FUNCTION__, __LINE__, in_atomic(), irqs_disabled());
#endif
	might_sleep();
	utrace->report_work_added = 0;

	stp_spin_lock(&utrace->lock);
	BUG_ON(utrace->death);
	utrace->death = 1;
	utrace->resume = UTRACE_RESUME;
	splice_attaching(utrace);
	stp_spin_unlock(&utrace->lock);

	REPORT_CALLBACKS(, task, utrace, &report, UTRACE_EVENT(DEATH),
			 report_death, engine, -1/*group_dead*/,
			 -1/*signal*/);

	utrace_maybe_reap(task, utrace, false);
	utrace_free(utrace);

	/* Remember that this task_work_func is finished. */
	stp_task_work_func_done();
}

#endif	/* _STP_UTRACE_C */
