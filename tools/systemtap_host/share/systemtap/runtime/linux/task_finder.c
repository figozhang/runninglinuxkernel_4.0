#ifndef TASK_FINDER_C
#define TASK_FINDER_C

/*
 * Which utrace shall we use?
 * (1) Built-in kernel utrace (preferred), indicated by
 * CONFIG_UTRACE.
 * (2) Internal utrace.  Requires STAPCONF_UTRACE_VIA_TRACEPOINTS.
 * (3) If we don't have either (old kernels or new kernels without all
 * the pre-requisites), error.
 */

#ifndef HAVE_TASK_FINDER
#error "Process probes not available without kernel CONFIG_UTRACE or CONFIG_TRACEPOINTS/CONFIG_ARCH_SUPPORTS_UPROBES/CONFIG_UPROBES. The latter method also requires specific tracepoints and task_work_add()."
#else  /* HAVE_TASK_FINDER */
#if !defined(CONFIG_UTRACE)
#include "task_finder2.c"
#else  /* CONFIG_UTRACE */
#include <linux/utrace.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#ifndef STAPCONF_TASK_UID
#include <linux/cred.h>
#endif
#include "../uidgid_compatibility.h"
#include "syscall.h"
#include "utrace_compatibility.h"
#include "task_finder_map.c"
#include "task_finder_vma.c"

static LIST_HEAD(__stp_task_finder_list);

struct stap_task_finder_target;

#define __STP_TF_UNITIALIZED	0
#define __STP_TF_STARTING	1
#define __STP_TF_RUNNING	2
#define __STP_TF_STOPPING	3
#define __STP_TF_STOPPED	4
static atomic_t __stp_task_finder_state = ATOMIC_INIT(__STP_TF_UNITIALIZED);
static atomic_t __stp_inuse_count = ATOMIC_INIT (0);

#define __stp_tf_handler_start() (atomic_inc(&__stp_inuse_count))
#define __stp_tf_handler_end() (atomic_dec(&__stp_inuse_count))

#ifdef DEBUG_TASK_FINDER
static atomic_t __stp_attach_count = ATOMIC_INIT (0);

#define debug_task_finder_attach() (atomic_inc(&__stp_attach_count))
#define debug_task_finder_detach() (atomic_dec(&__stp_attach_count))
#define debug_task_finder_report() (_stp_dbug(__FUNCTION__, __LINE__, \
					      "attach count: %d, inuse count: %d\n", \
					      atomic_read(&__stp_attach_count), \
					      atomic_read(&__stp_inuse_count)))
#else
#define debug_task_finder_attach()	/* empty */
#define debug_task_finder_detach()	/* empty */
#define debug_task_finder_report()	/* empty */
#endif	/* !DEBUG_TASK_FINDER */

typedef int (*stap_task_finder_callback)(struct stap_task_finder_target *tgt,
					 struct task_struct *tsk,
					 int register_p,
					 int process_p);

typedef int
(*stap_task_finder_mmap_callback)(struct stap_task_finder_target *tgt,
				  struct task_struct *tsk,
				  char *path,
				  struct dentry *dentry,
				  unsigned long addr,
				  unsigned long length,
				  unsigned long offset,
				  unsigned long vm_flags);
typedef int
(*stap_task_finder_munmap_callback)(struct stap_task_finder_target *tgt,
				    struct task_struct *tsk,
				    unsigned long addr,
				    unsigned long length);

typedef int
(*stap_task_finder_mprotect_callback)(struct stap_task_finder_target *tgt,
				      struct task_struct *tsk,
				      unsigned long addr,
				      unsigned long length,
				      int prot);

struct stap_task_finder_target {
/* private: */
	struct list_head list;		/* __stp_task_finder_list linkage */
	struct list_head callback_list_head;
	struct list_head callback_list;
	struct utrace_engine_ops ops;
	size_t pathlen;
	unsigned engine_attached:1;
	unsigned mmap_events:1;
	unsigned munmap_events:1;
	unsigned mprotect_events:1;

/* public: */
	pid_t pid;
	const char *procname;
        const char *purpose;
	stap_task_finder_callback callback;
	stap_task_finder_mmap_callback mmap_callback;
	stap_task_finder_munmap_callback munmap_callback;
	stap_task_finder_mprotect_callback mprotect_callback;
};

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_exec(struct utrace_engine *engine,
				     struct task_struct *tsk,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs);
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_exec(u32 action,
				     struct utrace_engine *engine,
				     const struct linux_binfmt *fmt,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs);
#else
static u32
__stp_utrace_task_finder_target_exec(enum utrace_resume_action action,
				     struct utrace_engine *engine,
				     struct task_struct *tsk,
				     const struct linux_binfmt *fmt,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs);
#endif
#endif

#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_exit(u32 action, struct utrace_engine *engine,
				     long orig_code, long *code);
#else
static u32
__stp_utrace_task_finder_target_exit(struct utrace_engine *engine,
				     struct task_struct *tsk,
				     long orig_code, long *code);
#endif

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_quiesce(struct utrace_engine *engine,
					struct task_struct *tsk);
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_quiesce(u32 action,
					struct utrace_engine *engine,
					unsigned long event);
#else
static u32
__stp_utrace_task_finder_target_quiesce(enum utrace_resume_action action,
					struct utrace_engine *engine,
					struct task_struct *tsk,
					unsigned long event);
#endif
#endif

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_syscall_entry(struct utrace_engine *engine,
					      struct task_struct *tsk,
					      struct pt_regs *regs);
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_syscall_entry(u32 action,
					      struct utrace_engine *engine,
					      struct pt_regs *regs);
#else
static u32
__stp_utrace_task_finder_target_syscall_entry(enum utrace_resume_action action,
					      struct utrace_engine *engine,
					      struct task_struct *tsk,
					      struct pt_regs *regs);
#endif
#endif

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_syscall_exit(struct utrace_engine *engine,
					     struct task_struct *tsk,
					     struct pt_regs *regs);
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_syscall_exit(u32 action,
					     struct utrace_engine *engine,
					     struct pt_regs *regs);
#else
static u32
__stp_utrace_task_finder_target_syscall_exit(enum utrace_resume_action action,
					     struct utrace_engine *engine,
					     struct task_struct *tsk,
					     struct pt_regs *regs);
#endif
#endif

static int
stap_register_task_finder_target(struct stap_task_finder_target *new_tgt)
{
	// Since this __stp_task_finder_list is (currently) only
	// written to in one big setup operation before the task
	// finder process is started, we don't need to lock it.
	struct list_head *node;
	struct stap_task_finder_target *tgt = NULL;
	int found_node = 0;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_UNITIALIZED) {
		_stp_error("task_finder already started, no new targets allowed");
		return EBUSY;
	}

	if (new_tgt == NULL)
		return EFAULT;

	if (new_tgt->procname != NULL)
		new_tgt->pathlen = strlen(new_tgt->procname);
	else
		new_tgt->pathlen = 0;

	// Make sure everything is initialized properly.
	new_tgt->engine_attached = 0;
	new_tgt->mmap_events = 0;
	new_tgt->munmap_events = 0;
	new_tgt->mprotect_events = 0;
	memset(&new_tgt->ops, 0, sizeof(new_tgt->ops));
	new_tgt->ops.report_exec = &__stp_utrace_task_finder_target_exec;
	new_tgt->ops.report_exit = &__stp_utrace_task_finder_target_exit;
	new_tgt->ops.report_quiesce = &__stp_utrace_task_finder_target_quiesce;
	new_tgt->ops.report_syscall_entry = \
		&__stp_utrace_task_finder_target_syscall_entry;
	new_tgt->ops.report_syscall_exit = \
		&__stp_utrace_task_finder_target_syscall_exit;

	// Search the list for an existing entry for procname/pid.
	list_for_each(node, &__stp_task_finder_list) {
		tgt = list_entry(node, struct stap_task_finder_target, list);
		if (tgt == new_tgt) {
			_stp_error("target already registered");
			return EINVAL;
		}
		if (tgt != NULL
		    /* procname-based target */
		    && ((new_tgt->pathlen > 0
			 && tgt->pathlen == new_tgt->pathlen
			 && strcmp(tgt->procname, new_tgt->procname) == 0)
			/* pid-based target (a specific pid or all
			 * pids) */
			|| (new_tgt->pathlen == 0 && tgt->pathlen == 0
			    && tgt->pid == new_tgt->pid))) {
			found_node = 1;
			break;
		}
	}

	// If we didn't find a matching existing entry, add the new
	// target to the task list.
	if (! found_node) {
		INIT_LIST_HEAD(&new_tgt->callback_list_head);
		list_add(&new_tgt->list, &__stp_task_finder_list);
		tgt = new_tgt;
	}

	// Add this target to the callback list for this task.
	list_add_tail(&new_tgt->callback_list, &tgt->callback_list_head);

	// If the new target has any m* callbacks, remember this.
	if (new_tgt->mmap_callback != NULL)
		tgt->mmap_events = 1;
	if (new_tgt->munmap_callback != NULL)
		tgt->munmap_events = 1;
	if (new_tgt->mprotect_callback != NULL)
		tgt->mprotect_events = 1;
	return 0;
}

static int
stap_utrace_detach(struct task_struct *tsk,
		   const struct utrace_engine_ops *ops)
{
	struct utrace_engine *engine;
	struct mm_struct *mm;
	int rc = 0;

	// Ignore invalid tasks.
	if (tsk == NULL || tsk->pid <= 0)
		return 0;

#ifdef PF_KTHREAD
	// Ignore kernel threads.  On systems without PF_KTHREAD,
	// we're ok, since kernel threads won't be matched by the
	// utrace_attach_task() call below.
	if (tsk->flags & PF_KTHREAD)
		return 0;
#endif

	// Notice we're not calling get_task_mm() here.  Normally we
	// avoid tasks with no mm, because those are kernel threads.
	// So, why is this function different?  When a thread is in
	// the process of dying, its mm gets freed.  Then, later the
	// thread gets in the dying state and the thread's DEATH event
	// handler gets called (if any).
	//
	// If a thread is in this "mortally wounded" state - no mm
	// but not dead - and at that moment this function is called,
	// we'd miss detaching from it if we were checking to see if
	// it had an mm.

	engine = utrace_attach_task(tsk, UTRACE_ATTACH_MATCH_OPS, ops, 0);
	if (IS_ERR(engine)) {
		rc = -PTR_ERR(engine);
		if (rc != ENOENT) {
			_stp_error("utrace_attach_task returned error %d on pid %d",
				   rc, tsk->pid);
		}
		else {
			rc = 0;
		}
	}
	else if (unlikely(engine == NULL)) {
		_stp_error("utrace_attach returned NULL on pid %d",
			   (int)tsk->pid);
		rc = EFAULT;
	}
	else {
		rc = utrace_control(tsk, engine, UTRACE_DETACH);
		switch (rc) {
		case 0:			/* success */
			debug_task_finder_detach();
			break;
		case -ESRCH:	    /* REAP callback already begun */
		case -EALREADY:	    /* DEATH callback already begun */
			rc = 0;	    /* ignore these errors */
			break;
		case -EINPROGRESS:
			do {
				rc = utrace_barrier(tsk, engine);
			} while (rc == -ERESTARTSYS);
			if (rc == 0 || rc == -ESRCH || rc == -EALREADY) {
				rc = 0;
				debug_task_finder_detach();
			} else {
				rc = -rc;
				_stp_error("utrace_barrier returned error %d on pid %d", rc, tsk->pid);
			}
			break;
		default:
			rc = -rc;
			_stp_error("utrace_control returned error %d on pid %d",
				   rc, tsk->pid);
			break;
		}
		utrace_engine_put(engine);
	}
	return rc;
}

static void
stap_utrace_detach_ops(struct utrace_engine_ops *ops)
{
	struct task_struct *grp, *tsk;
	struct utrace_engine *engine;
	pid_t pid = 0;
	int rc = 0;

	// Notice we're not calling get_task_mm() in this loop. In
	// every other instance when calling do_each_thread, we avoid
	// tasks with no mm, because those are kernel threads.  So,
	// why is this function different?  When a thread is in the
	// process of dying, its mm gets freed.  Then, later the
	// thread gets in the dying state and the thread's
	// UTRACE_EVENT(DEATH) event handler gets called (if any).
	//
	// If a thread is in this "mortally wounded" state - no mm
	// but not dead - and at that moment this function is called,
	// we'd miss detaching from it if we were checking to see if
	// it had an mm.

	rcu_read_lock();
	do_each_thread(grp, tsk) {
#ifdef PF_KTHREAD
		// Ignore kernel threads.  On systems without
		// PF_KTHREAD, we're ok, since kernel threads won't be
		// matched by the stap_utrace_detach() call.
		if (tsk->flags & PF_KTHREAD)
			continue;
#endif

		/* Notice we're purposefully ignoring errors from
		 * stap_utrace_detach().  Even if we got an error on
		 * this task, we need to keep detaching from other
		 * tasks.  But warn, we might be unloading and dangling
		 * engines are bad news. */
		rc = stap_utrace_detach(tsk, ops);
		if (rc != 0)
			_stp_error("stap_utrace_detach returned error %d on pid %d", rc, tsk->pid);
		WARN_ON(rc != 0);
	} while_each_thread(grp, tsk);
	rcu_read_unlock();
	debug_task_finder_report();
}

static void
__stp_task_finder_cleanup(void)
{
	struct list_head *tgt_node, *tgt_next;
	struct stap_task_finder_target *tgt;

	// Walk the main list, cleaning up as we go.
	list_for_each_safe(tgt_node, tgt_next, &__stp_task_finder_list) {
		tgt = list_entry(tgt_node, struct stap_task_finder_target,
				 list);
		if (tgt == NULL)
			continue;

		if (tgt->engine_attached) {
			stap_utrace_detach_ops(&tgt->ops);
			tgt->engine_attached = 0;
		}

		// Notice we're not walking the callback_list here.
		// There isn't anything to clean up and doing it would
		// mess up callbacks in progress.

		list_del(&tgt->list);
	}
}

static char *
__stp_get_mm_path(struct mm_struct *mm, char *buf, int buflen)
{
	struct file *vm_file = stap_find_exe_file(mm);
	char *rc = NULL;

	if (vm_file) {
#ifdef STAPCONF_DPATH_PATH
		rc = d_path(&(vm_file->f_path), buf, buflen);
#else
		rc = d_path(vm_file->f_dentry, vm_file->f_vfsmnt,
			    buf, buflen);
#endif
		fput(vm_file);
	}
	else {
		*buf = '\0';
		rc = ERR_PTR(-ENOENT);
	}
	return rc;
}

/*
 * All user threads get an engine with __STP_TASK_FINDER_EVENTS events
 * attached to it so the task_finder layer can monitor new thread
 * creation/death.
 */
#define __STP_TASK_FINDER_EVENTS (UTRACE_EVENT(CLONE)		\
				  | UTRACE_EVENT(EXEC)		\
				  | UTRACE_EVENT(EXIT))

/*
 * __STP_TASK_BASE_EVENTS: base events for stap_task_finder_target's
 * without map callback's
 *
 * __STP_TASK_VM_BASE_EVENTS: base events for
 * stap_task_finder_target's with map callback's
 */
#define __STP_TASK_BASE_EVENTS	(UTRACE_EVENT(EXIT)|UTRACE_EVENT(EXEC))

#define __STP_TASK_VM_BASE_EVENTS (__STP_TASK_BASE_EVENTS	\
				   | UTRACE_EVENT(SYSCALL_ENTRY)\
				   | UTRACE_EVENT(SYSCALL_EXIT))

/*
 * All "interesting" threads get an engine with
 * __STP_ATTACHED_TASK_EVENTS events attached to it.  After the thread
 * quiesces, we reset the events to __STP_ATTACHED_TASK_BASE_EVENTS
 * events.
 */
#define __STP_ATTACHED_TASK_EVENTS (UTRACE_EVENT(EXIT)		\
				    | UTRACE_EVENT(QUIESCE))

#define __STP_ATTACHED_TASK_BASE_EVENTS(tgt)			\
	(((tgt)->mmap_events || (tgt)->munmap_events		\
	  || (tgt)->mprotect_events)				\
	 ? __STP_TASK_VM_BASE_EVENTS : __STP_TASK_BASE_EVENTS)

/* Helper function for __stp_utrace_attach or __stp_utrace_attach_atomic.  */
static int
__stp_utrace_attach_flags(struct task_struct *tsk,
			  const struct utrace_engine_ops *ops, void *data,
			  unsigned long event_flags,
			  int attach_flags,
			  enum utrace_resume_action action)
{
	struct utrace_engine *engine;
	int rc = 0;

	// Ignore invalid tasks.
	if (tsk == NULL || tsk->pid <= 0)
		return EPERM;

#ifdef PF_KTHREAD
	// Ignore kernel threads
	if (tsk->flags & PF_KTHREAD)
		return EPERM;
#endif

	// Ignore threads with no mm (which are either kernel threads
	// or "mortally wounded" threads).
	//
	// Note we're not calling get_task_mm()/mmput() here.  Since
	// we're in the the context of that task, the mm should stick
	// around without locking it (and mmput() can sleep).
	if (! tsk->mm)
		return EPERM;

	engine = utrace_attach_task(tsk, UTRACE_ATTACH_CREATE | attach_flags,
				    ops, data);
	if (IS_ERR(engine)) {
		int error = -PTR_ERR(engine);
		if (error != ESRCH && error != ENOENT) {
			_stp_error("utrace_attach returned error %d on pid %d",
				   error, (int)tsk->pid);
			rc = error;
		}
	}
	else if (unlikely(engine == NULL)) {
		_stp_error("utrace_attach returned NULL on pid %d",
			   (int)tsk->pid);
		rc = EFAULT;
	}
	else {
		rc = utrace_set_events(tsk, engine, event_flags);
		if (rc == -EINPROGRESS) {
			/*
			 * It's running our callback, so we have to
			 * synchronize.  We can't keep rcu_read_lock,
			 * so the task pointer might die.  But it's
			 * safe to call utrace_barrier() even with a
			 * stale task pointer, if we have an engine
			 * ref.
			 */
			do {
				rc = utrace_barrier(tsk, engine);
			} while (rc == -ERESTARTSYS);
			if (rc != 0 && rc != -ESRCH && rc != -EALREADY)
				_stp_error("utrace_barrier returned error %d on pid %d",
					   rc, (int)tsk->pid);
		}
		if (rc == 0) {
			debug_task_finder_attach();

			if (action != UTRACE_RESUME) {
				rc = utrace_control(tsk, engine, action);
				/* If utrace_control() returns
				 * EINPROGRESS when we're trying to
				 * stop/interrupt, that means the task
				 * hasn't stopped quite yet, but will
				 * soon.  Ignore this error. */
				if (rc != 0 && rc != -EINPROGRESS) {
					_stp_error("utrace_control returned error %d on pid %d",
						   rc, (int)tsk->pid);
				}
				rc = 0;
			}
		}
		else if (rc != -ESRCH && rc != -EALREADY)
			_stp_error("utrace_set_events2 returned error %d on pid %d",
				   rc, (int)tsk->pid);
		utrace_engine_put(engine);
	}
	return rc;
}

static int
__stp_utrace_attach(struct task_struct *tsk,
		    const struct utrace_engine_ops *ops, void *data,
		    unsigned long event_flags,
		    enum utrace_resume_action action)
{
	return __stp_utrace_attach_flags(tsk, ops, data, event_flags,
					 0, action);
}

static int
__stp_utrace_attach_atomic(struct task_struct *tsk,
			   const struct utrace_engine_ops *ops, void *data,
			   unsigned long event_flags,
			   enum utrace_resume_action action)
{
	return __stp_utrace_attach_flags(tsk, ops, data, event_flags,
					 UTRACE_ATTACH_ATOMIC, action);
}

static int
stap_utrace_attach(struct task_struct *tsk,
		   const struct utrace_engine_ops *ops, void *data,
		   unsigned long event_flags)
{
	return __stp_utrace_attach(tsk, ops, data, event_flags, UTRACE_RESUME);
}

static inline void
__stp_call_callbacks(struct stap_task_finder_target *tgt,
		     struct task_struct *tsk, int register_p, int process_p)
{
	struct list_head *cb_node;
	int rc;

	if (tgt == NULL || tsk == NULL)
		return;

	list_for_each(cb_node, &tgt->callback_list_head) {
		struct stap_task_finder_target *cb_tgt;

		cb_tgt = list_entry(cb_node, struct stap_task_finder_target,
				    callback_list);
		if (cb_tgt == NULL || cb_tgt->callback == NULL)
			continue;

		rc = cb_tgt->callback(cb_tgt, tsk, register_p, process_p);
		if (rc != 0) {
			_stp_warn("task_finder %s%scallback for task %d failed: %d",
                                  (cb_tgt->purpose?:""), (cb_tgt->purpose?" ":""),
                                  (int)tsk->pid, rc);
		}
	}
}

static void
__stp_call_mmap_callbacks(struct stap_task_finder_target *tgt,
			  struct task_struct *tsk, char *path,
			  struct dentry *dentry,
			  unsigned long addr, unsigned long length,
			  unsigned long offset, unsigned long vm_flags)
{
	struct list_head *cb_node;
	int rc;

	if (tgt == NULL || tsk == NULL)
		return;

	dbug_task_vma(1,
		  "pid %d, a/l/o/p/path 0x%lx  0x%lx  0x%lx  %c%c%c%c  %s\n",
		  tsk->pid, addr, length, offset,
		  vm_flags & VM_READ ? 'r' : '-',
		  vm_flags & VM_WRITE ? 'w' : '-',
		  vm_flags & VM_EXEC ? 'x' : '-',
		  vm_flags & VM_MAYSHARE ? 's' : 'p',
		  path);
	list_for_each(cb_node, &tgt->callback_list_head) {
		struct stap_task_finder_target *cb_tgt;

		cb_tgt = list_entry(cb_node, struct stap_task_finder_target,
				    callback_list);
		if (cb_tgt == NULL || cb_tgt->mmap_callback == NULL)
			continue;

		rc = cb_tgt->mmap_callback(cb_tgt, tsk, path, dentry,
					  addr, length, offset, vm_flags);
		if (rc != 0) {
			_stp_warn("task_finder mmap %s%scallback for task %d failed: %d",
                                  (cb_tgt->purpose?:""), (cb_tgt->purpose?" ":""),
                                  (int)tsk->pid, rc);
		}
	}
}


static struct vm_area_struct *
__stp_find_file_based_vma(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma = find_vma(mm, addr);

	// I'm not positive why the checking for vm_start > addr is
	// necessary, but it seems to be (sometimes find_vma() returns
	// a vma that addr doesn't belong to).
	if (vma && (vma->vm_file == NULL || vma->vm_start > addr))
		vma = NULL;
	return vma;
}


static void
__stp_call_mmap_callbacks_with_addr(struct stap_task_finder_target *tgt,
				    struct task_struct *tsk,
				    unsigned long addr)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	char *mmpath_buf = NULL;
	char *mmpath = NULL;
	struct dentry *dentry = NULL;
	unsigned long length = 0;
	unsigned long offset = 0;
	unsigned long vm_flags = 0;

	// __stp_call_mmap_callbacks_with_addr() is only called when
	// tsk is current, so there isn't any danger of mm going
	// away.  So, we don't need to call get_task_mm()/mmput()
	// (which avoids the possibility of sleeping).
	mm = tsk->mm;
	if (! mm)
		return;

	// The down_read() function can sleep, so we'll call
	// down_read_trylock() instead, which can fail.
	if (! down_read_trylock(&mm->mmap_sem))
		return;
	vma = __stp_find_file_based_vma(mm, addr);
	if (vma) {
		// Cache information we need from the vma
		addr = vma->vm_start;
		length = vma->vm_end - vma->vm_start;
		offset = (vma->vm_pgoff << PAGE_SHIFT);
		vm_flags = vma->vm_flags;
#ifdef STAPCONF_DPATH_PATH
		dentry = vma->vm_file->f_path.dentry;
#else
		dentry = vma->vm_file->f_dentry;
#endif

		// Allocate space for a path
		mmpath_buf = _stp_kmalloc(PATH_MAX);
		if (mmpath_buf == NULL) {
			up_read(&mm->mmap_sem);
			_stp_error("Unable to allocate space for path");
			return;
		}
		else {
			// Grab the path associated with this vma.
#ifdef STAPCONF_DPATH_PATH
			mmpath = d_path(&(vma->vm_file->f_path), mmpath_buf,
					PATH_MAX);
#else
			mmpath = d_path(vma->vm_file->f_dentry,
					vma->vm_file->f_vfsmnt, mmpath_buf,
					PATH_MAX);
#endif
			if (mmpath == NULL || IS_ERR(mmpath)) {
				long err = ((mmpath == NULL) ? 0
					    : -PTR_ERR(mmpath));
				_stp_error("Unable to get path (error %ld) for pid %d",
					   err, (int)tsk->pid);
				mmpath = NULL;
			}
		}
	}

	// At this point, we're done with the vma (assuming we found
	// one).  We can't hold the 'mmap_sem' semaphore while making
	// callbacks.
	up_read(&mm->mmap_sem);
		
	if (mmpath)
		__stp_call_mmap_callbacks(tgt, tsk, mmpath, dentry, addr,
					  length, offset, vm_flags);

	// Cleanup.
	if (mmpath_buf)
		_stp_kfree(mmpath_buf);
	return;
}


static inline void
__stp_call_munmap_callbacks(struct stap_task_finder_target *tgt,
			    struct task_struct *tsk, unsigned long addr,
			    unsigned long length)
{
	struct list_head *cb_node;
	int rc;

	if (tgt == NULL || tsk == NULL)
		return;

	list_for_each(cb_node, &tgt->callback_list_head) {
		struct stap_task_finder_target *cb_tgt;

		cb_tgt = list_entry(cb_node, struct stap_task_finder_target,
				    callback_list);
		if (cb_tgt == NULL || cb_tgt->munmap_callback == NULL)
			continue;

		rc = cb_tgt->munmap_callback(cb_tgt, tsk, addr, length);
		if (rc != 0) {
			_stp_warn("task_finder munmap %s%scallback for task %d failed: %d",
                                  (cb_tgt->purpose?:""), (cb_tgt->purpose?" ":""),
                                  (int)tsk->pid, rc);
		}
	}
}

static inline void
__stp_call_mprotect_callbacks(struct stap_task_finder_target *tgt,
			      struct task_struct *tsk, unsigned long addr,
			      unsigned long length, int prot)
{
	struct list_head *cb_node;
	int rc;

	if (tgt == NULL || tsk == NULL)
		return;

	list_for_each(cb_node, &tgt->callback_list_head) {
		struct stap_task_finder_target *cb_tgt;

		cb_tgt = list_entry(cb_node, struct stap_task_finder_target,
				    callback_list);
		if (cb_tgt == NULL || cb_tgt->mprotect_callback == NULL)
			continue;

		rc = cb_tgt->mprotect_callback(cb_tgt, tsk, addr, length,
					       prot);
		if (rc != 0) {
			_stp_warn("task_finder mprotect %s%scallback for task %d failed: %d",
                                  (cb_tgt->purpose?:""), (cb_tgt->purpose?" ":""),
                                  (int)tsk->pid, rc);
		}
	}
}

static inline void
__stp_utrace_attach_match_filename(struct task_struct *tsk,
				   const char * const filename,
				   int process_p)
{
	size_t filelen;
	struct list_head *tgt_node;
	struct stap_task_finder_target *tgt;
	uid_t tsk_euid;

#ifdef STAPCONF_TASK_UID
	tsk_euid = tsk->euid;
#else
#if defined(CONFIG_USER_NS) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	tsk_euid = from_kuid_munged(current_user_ns(), task_euid(tsk));
#else
	tsk_euid = task_euid(tsk);
#endif
#endif
	filelen = strlen(filename);
	list_for_each(tgt_node, &__stp_task_finder_list) {
		int rc;

		tgt = list_entry(tgt_node, struct stap_task_finder_target,
				 list);
		// If we've got a matching procname or we're probing
		// all threads, we've got a match.  We've got to keep
		// matching since a single thread could match a
		// procname and match an "all thread" probe.
		if (tgt == NULL)
			continue;
		else if (tgt->pathlen > 0
			 && (tgt->pathlen != filelen
			     || strcmp(tgt->procname, filename) != 0))
			continue;
		/* Ignore pid-based target, they were handled at startup. */
		else if (tgt->pid != 0)
			continue;
		/* Notice that "pid == 0" (which means to probe all
		 * threads) falls through. */

#if ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPDEV) && \
    ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPSYS)
		/* Make sure unprivileged users only probe their own threads. */
		if (_stp_uid != tsk_euid) {
			if (tgt->pid != 0) {
				_stp_warn("Process %d does not belong to unprivileged user %d",
					  tsk->pid, _stp_uid);
			}
			continue;
		}
#endif


		// Set up events we need for attached tasks. We won't
		// actually call the callbacks here - we'll call them
		// when the thread gets quiesced.
		rc = __stp_utrace_attach(tsk, &tgt->ops,
					 tgt,
					 __STP_ATTACHED_TASK_EVENTS,
					 UTRACE_STOP);
		if (rc != 0 && rc != EPERM)
			break;
		tgt->engine_attached = 1;
	}
}

// This function handles the details of getting a task's associated
// procname, and calling __stp_utrace_attach_match_filename() to
// attach to it if we find the procname "interesting".  So, what's the
// difference between path_tsk and match_tsk?  Normally they are the
// same, except in one case.  In an UTRACE_EVENT(EXEC), we need to
// detach engines from the newly exec'ed process (since its path has
// changed).  In this case, we have to match the path of the parent
// (path_tsk) against the child (match_tsk).

static void
__stp_utrace_attach_match_tsk(struct task_struct *path_tsk,
			      struct task_struct *match_tsk, int process_p)
{
	struct mm_struct *mm;
	char *mmpath_buf;
	char *mmpath;

	if (path_tsk == NULL || path_tsk->pid <= 0
	    || match_tsk == NULL || match_tsk->pid <= 0)
		return;

	// Grab the path associated with the path_tsk.
	//
	// Note we're not calling get_task_mm()/mmput() here.  Since
	// we're in the the context of path_task, the mm should stick
	// around without locking it (and mmput() can sleep).
	mm = path_tsk->mm;
	if (! mm) {
		/* If the thread doesn't have a mm_struct, it is
		 * a kernel thread which we need to skip. */
		return;
	}

	// Allocate space for a path
	mmpath_buf = _stp_kmalloc(PATH_MAX);
	if (mmpath_buf == NULL) {
		_stp_error("Unable to allocate space for path");
		return;
	}

	// Grab the path associated with the new task
	mmpath = __stp_get_mm_path(mm, mmpath_buf, PATH_MAX);
	if (mmpath == NULL || IS_ERR(mmpath)) {
		int rc = -PTR_ERR(mmpath);
		if (rc != ENOENT)
			_stp_error("Unable to get path (error %d) for pid %d",
				   rc, (int)path_tsk->pid);
	}
	else {
		__stp_utrace_attach_match_filename(match_tsk, mmpath,
						   process_p);
	}

	_stp_kfree(mmpath_buf);
	return;
}

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_report_clone(struct utrace_engine *engine,
				      struct task_struct *parent,
				      unsigned long clone_flags,
				      struct task_struct *child)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_report_clone(u32 action,
				      struct utrace_engine *engine,
				      unsigned long clone_flags,
				      struct task_struct *child)
#else
static u32
__stp_utrace_task_finder_report_clone(enum utrace_resume_action action,
				      struct utrace_engine *engine,
				      struct task_struct *parent,
				      unsigned long clone_flags,
				      struct task_struct *child)
#endif
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *parent = current;
#endif
	int rc;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	__stp_tf_handler_start();

	// On clone, attach to the child.
	rc = __stp_utrace_attach(child, engine->ops, 0,
				 __STP_TASK_FINDER_EVENTS, UTRACE_RESUME);
	if (rc != 0 && rc != EPERM) {
		__stp_tf_handler_end();
		return UTRACE_RESUME;
	}

	__stp_utrace_attach_match_tsk(parent, child,
				      (clone_flags & CLONE_THREAD) == 0);
	__stp_tf_handler_end();
	return UTRACE_RESUME;
}

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_report_exec(struct utrace_engine *engine,
				     struct task_struct *tsk,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_report_exec(u32 action,
				     struct utrace_engine *engine,
				     const struct linux_binfmt *fmt,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs)
#else
static u32
__stp_utrace_task_finder_report_exec(enum utrace_resume_action action,
				     struct utrace_engine *engine,
				     struct task_struct *tsk,
				     const struct linux_binfmt *fmt,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs)
#endif
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *tsk = current;
#endif
	size_t filelen;
	struct list_head *tgt_node;
	struct stap_task_finder_target *tgt;
	int found_node = 0;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	__stp_tf_handler_start();

	// If the original task was "interesting",
	// __stp_utrace_task_finder_target_exec() will handle calling
	// callbacks. 

	// We assume that all exec's are exec'ing a new process.  Note
	// that we don't use bprm->filename, since that path can be
	// relative.
	__stp_utrace_attach_match_tsk(tsk, tsk, 1);

	__stp_tf_handler_end();
	return UTRACE_RESUME;
}


#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
stap_utrace_task_finder_report_exit(u32 action, struct utrace_engine *engine,
				    long orig_code, long *code)
#else
static u32
stap_utrace_task_finder_report_exit(struct utrace_engine *engine,
				    struct task_struct *tsk,
				    long orig_code, long *code)
#endif
{
	debug_task_finder_detach();
	return UTRACE_DETACH;
}

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_exec(struct utrace_engine *engine,
				     struct task_struct *tsk,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_exec(u32 action,
				     struct utrace_engine *engine,
				     const struct linux_binfmt *fmt,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs)
#else
static u32
__stp_utrace_task_finder_target_exec(enum utrace_resume_action action,
				     struct utrace_engine *engine,
				     struct task_struct *tsk,
				     const struct linux_binfmt *fmt,
				     const struct linux_binprm *bprm,
				     struct pt_regs *regs)
#endif
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *tsk = current;
#endif
	struct stap_task_finder_target *tgt = engine->data;
	int rc;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	__stp_tf_handler_start();

	// We'll hardcode this as a process end.  If a thread
	// calls exec() (which it isn't supposed to), the kernel
	// "promotes" it to being a process.  Call the callbacks.
	if (tgt != NULL && tsk != NULL) {
		__stp_call_callbacks(tgt, tsk, 0, 1);
	}

	// Note that we don't want to set engine_attached to 0 here -
	// only when *all* threads using this engine have been
	// detached.

	// Let __stp_utrace_task_finder_report_exec() call
	// __stp_utrace_attach_match_tsk() to figure out if the
	// exec'ed program is "interesting".

	__stp_tf_handler_end();
	debug_task_finder_detach();
	return UTRACE_DETACH;
}

#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_exit(u32 action, struct utrace_engine *engine,
				     long orig_code, long *code)
#else
static u32
__stp_utrace_task_finder_target_exit(struct utrace_engine *engine,
				     struct task_struct *tsk,
				     long orig_code, long *code)
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *tsk = current;
#endif
	struct stap_task_finder_target *tgt = engine->data;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	__stp_tf_handler_start();
	// The first implementation of this added a
	// UTRACE_EVENT(DEATH) handler to
	// __stp_utrace_task_finder_ops.  However, dead threads don't
	// have a mm_struct, so we can't find the exe's path.  So, we
	// don't know which callback(s) to call.
	//
	// So, now when an "interesting" thread is found, we add a
	// separate UTRACE_EVENT(EXIT) handler for each attached
	// handler.
	if (tgt != NULL && tsk != NULL) {
		__stp_call_callbacks(tgt, tsk, 0, (tsk->pid == tsk->tgid));
	}

	__stp_tf_handler_end();
	debug_task_finder_detach();
	return UTRACE_DETACH;
}

static void
__stp_call_mmap_callbacks_for_task(struct stap_task_finder_target *tgt,
				   struct task_struct *tsk)
{
	struct mm_struct *mm;
	char *mmpath_buf;
	char *mmpath;
	struct vm_area_struct *vma;
	int file_based_vmas = 0;
	struct vma_cache_t {
#ifdef STAPCONF_DPATH_PATH
		struct path *f_path;
#else
		struct vfsmount *f_vfsmnt;
#endif
		struct dentry *dentry;
		unsigned long addr;
		unsigned long length;
		unsigned long offset;
		unsigned long vm_flags;
	};
	struct vma_cache_t *vma_cache = NULL;
	struct vma_cache_t *vma_cache_p; 

	// Call the mmap_callback for every vma associated with
	// a file.
	//
	// Note we're not calling get_task_mm()/mmput() here.  Since
	// we're in the the context of that task, the mm should stick
	// around without locking it (and mmput() can sleep).
	mm = tsk->mm;
	if (! mm)
		return;

	// Allocate space for a path
	mmpath_buf = _stp_kmalloc(PATH_MAX);
	if (mmpath_buf == NULL) {
		_stp_error("Unable to allocate space for path");
		return;
	}

	// The down_read() function can sleep, so we'll call
	// down_read_trylock() instead, which can fail.
	if (! down_read_trylock(&mm->mmap_sem)) {
		_stp_kfree(mmpath_buf);
		return;
	}

	// First find the number of file-based vmas.
	vma = mm->mmap;
	while (vma) {
		if (vma->vm_file)
			file_based_vmas++;
		vma = vma->vm_next;
	}

	// Now allocate an array to cache vma information in.
	if (file_based_vmas > 0)
		vma_cache = _stp_kmalloc(sizeof(struct vma_cache_t)
					 * file_based_vmas);
	if (vma_cache != NULL) {
		// Loop through the vmas again, and cache needed information.
		vma = mm->mmap;
		vma_cache_p = vma_cache;
		while (vma) {
			if (vma->vm_file) {
#ifdef STAPCONF_DPATH_PATH
			    // Notice we're increasing the reference
			    // count for 'f_path'.  This way it won't
			    // get deleted from out under us.
			    vma_cache_p->f_path = &(vma->vm_file->f_path);
			    path_get(vma_cache_p->f_path);
			    vma_cache_p->dentry = vma->vm_file->f_path.dentry;
#else
			    // Notice we're increasing the reference
			    // count for 'dentry' and 'f_vfsmnt'.
			    // This way they won't get deleted from
			    // out under us.
			    vma_cache_p->dentry = vma->vm_file->f_dentry;
			    dget(vma_cache_p->dentry);
			    vma_cache_p->f_vfsmnt = vma->vm_file->f_vfsmnt;
			    mntget(vma_cache_p->f_vfsmnt);
			    vma_cache_p->dentry = vma->vm_file->f_dentry;
#endif
			    vma_cache_p->addr = vma->vm_start;
			    vma_cache_p->length = vma->vm_end - vma->vm_start;
			    vma_cache_p->offset = (vma->vm_pgoff << PAGE_SHIFT);
			    vma_cache_p->vm_flags = vma->vm_flags;
			    vma_cache_p++;
			}
			vma = vma->vm_next;
		}
	}

	// At this point, we're done with the vmas (assuming we found
	// any).  We can't hold the 'mmap_sem' semaphore while making
	// callbacks.
	up_read(&mm->mmap_sem);

	if (vma_cache) {
		int i;

		// Loop over our cached information and make callbacks
		// based on it.
		vma_cache_p = vma_cache;
		for (i = 0; i < file_based_vmas; i++) {
#ifdef STAPCONF_DPATH_PATH
			mmpath = d_path(vma_cache_p->f_path, mmpath_buf,
					PATH_MAX);
			path_put(vma_cache_p->f_path);
#else
			mmpath = d_path(vma_cache_p->dentry,
					vma_cache_p->f_vfsmnt, mmpath_buf,
					PATH_MAX);
			dput(vma_cache_p->dentry);
			mntput(vma_cache_p->f_vfsmnt);
#endif
			if (mmpath == NULL || IS_ERR(mmpath)) {
				long err = ((mmpath == NULL) ? 0
					    : -PTR_ERR(mmpath));
				_stp_error("Unable to get path (error %ld) for pid %d",
					   err, (int)tsk->pid);
			}
			else {
				__stp_call_mmap_callbacks(tgt, tsk, mmpath,
							  vma_cache_p->dentry,
							  vma_cache_p->addr,
							  vma_cache_p->length,
							  vma_cache_p->offset,
							  vma_cache_p->vm_flags);
			}
			vma_cache_p++;
		}
		_stp_kfree(vma_cache);
	}

	_stp_kfree(mmpath_buf);
}

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_quiesce(struct utrace_engine *engine,
					struct task_struct *tsk)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_quiesce(u32 action,
					struct utrace_engine *engine,
					unsigned long event)
#else
static u32
__stp_utrace_task_finder_target_quiesce(enum utrace_resume_action action,
					struct utrace_engine *engine,
					struct task_struct *tsk,
					unsigned long event)
#endif
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *tsk = current;
#endif
	struct stap_task_finder_target *tgt = engine->data;
	int rc;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	if (tgt == NULL || tsk == NULL) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	__stp_tf_handler_start();

	// Turn off quiesce handling
	rc = utrace_set_events(tsk, engine,
			       __STP_ATTACHED_TASK_BASE_EVENTS(tgt));

	if (rc == -EINPROGRESS) {
		/*
		 * It's running our callback, so we have to
		 * synchronize.  We can't keep rcu_read_lock,
		 * so the task pointer might die.  But it's
		 * safe to call utrace_barrier() even with
		 * a stale task pointer, if we have an engine ref.
		 */
		do {
			rc = utrace_barrier(tsk, engine);
		} while (rc == -ERESTARTSYS);
		if (rc == 0)
			rc = utrace_set_events(tsk, engine,
					       __STP_ATTACHED_TASK_BASE_EVENTS(tgt));
		else if (rc != -ESRCH && rc != -EALREADY)
			_stp_error("utrace_barrier returned error %d on pid %d",
				   rc, (int)tsk->pid);
	}
	if (rc != 0)
		_stp_error("utrace_set_events returned error %d on pid %d",
			   rc, (int)tsk->pid);


	/* Call the callbacks.  Assume that if the thread is a
	 * thread group leader, it is a process. */
	__stp_call_callbacks(tgt, tsk, 1, (tsk->pid == tsk->tgid));
 
	/* If this is just a thread other than the thread group leader,
           don't bother inform map callback clients about its memory map,
           since they will simply duplicate each other. */
	if (tgt->mmap_events == 1 && tsk->tgid == tsk->pid) {
		__stp_call_mmap_callbacks_for_task(tgt, tsk);
	}

	__stp_tf_handler_end();
	return UTRACE_RESUME;
}


#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_syscall_entry(struct utrace_engine *engine,
					      struct task_struct *tsk,
					      struct pt_regs *regs)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_syscall_entry(u32 action,
					      struct utrace_engine *engine,
					      struct pt_regs *regs)
#else
static u32
__stp_utrace_task_finder_target_syscall_entry(enum utrace_resume_action action,
					      struct utrace_engine *engine,
					      struct task_struct *tsk,
					      struct pt_regs *regs)
#endif
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *tsk = current;
#endif
	struct stap_task_finder_target *tgt = engine->data;
	long syscall_no;
	unsigned long args[3] = { 0L };
	int rc;
	int is_mmap_or_mmap2 = 0;
	int is_mprotect = 0;
	int is_munmap = 0;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	if (tgt == NULL)
		return UTRACE_RESUME;

	// See if syscall is one we're interested in.  On x86_64, this
	// is a potentially expensive operation (since we have to
	// check and see if it is a 32-bit task).  So, cache the
	// results.
	//
	// FIXME: do we need to handle mremap()?
	syscall_no = _stp_syscall_get_nr(tsk, regs);
	is_mmap_or_mmap2 = (syscall_no == MMAP_SYSCALL_NO(tsk)
			    || syscall_no == MMAP2_SYSCALL_NO(tsk) ? 1 : 0);
	if (!is_mmap_or_mmap2) {
		is_mprotect = (syscall_no == MPROTECT_SYSCALL_NO(tsk) ? 1 : 0);
		if (!is_mprotect) {
			is_munmap = (syscall_no == MUNMAP_SYSCALL_NO(tsk)
				     ? 1 : 0);
		}
	}
	if (!is_mmap_or_mmap2 && !is_mprotect && !is_munmap)
		return UTRACE_RESUME;

	// The syscall is one we're interested in, but do we have a
	// handler for it?
	if ((is_mmap_or_mmap2 && tgt->mmap_events == 0)
	    || (is_mprotect && tgt->mprotect_events == 0)
	    || (is_munmap && tgt->munmap_events == 0))
		return UTRACE_RESUME;

	// Save the needed arguments.  Note that for mmap, we really
	// just need the return value, so there is no need to save
	// any arguments.
	__stp_tf_handler_start();
	if (is_munmap) {
		// We need 2 arguments for munmap()
		syscall_get_arguments(tsk, regs, 0, 2, args);
	}
	else if (is_mprotect) {
		// We need 3 arguments for mprotect()
		syscall_get_arguments(tsk, regs, 0, 3, args);
	}

	// Remember the syscall information
	rc = __stp_tf_add_map(tsk, syscall_no, args[0], args[1], args[2]);
	if (rc != 0)
		_stp_error("__stp_tf_add_map returned error %d on pid %d",
			   rc, tsk->pid);
	__stp_tf_handler_end();
	return UTRACE_RESUME;
}

#ifdef UTRACE_ORIG_VERSION
static u32
__stp_utrace_task_finder_target_syscall_exit(struct utrace_engine *engine,
					     struct task_struct *tsk,
					     struct pt_regs *regs)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32
__stp_utrace_task_finder_target_syscall_exit(u32 action,
					     struct utrace_engine *engine,
					     struct pt_regs *regs)
#else
static u32
__stp_utrace_task_finder_target_syscall_exit(enum utrace_resume_action action,
					     struct utrace_engine *engine,
					     struct task_struct *tsk,
					     struct pt_regs *regs)
#endif
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *tsk = current;
#endif
	struct stap_task_finder_target *tgt = engine->data;
	unsigned long rv;
	struct __stp_tf_map_entry *entry;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		debug_task_finder_detach();
		return UTRACE_DETACH;
	}

	if (tgt == NULL)
		return UTRACE_RESUME;

	// See if we can find saved syscall info.  If we can, it must
	// be one of the syscalls we are interested in (and we must
	// have callbacks to call for it).
	entry = __stp_tf_get_map_entry(tsk);
	if (entry == NULL)
		return UTRACE_RESUME;

	// Get return value
	__stp_tf_handler_start();
	rv = syscall_get_return_value(tsk, regs);

	dbug_task_vma(1,
		  "tsk %d found %s(0x%lx), returned 0x%lx\n",
		  tsk->pid,
		  ((entry->syscall_no == MMAP_SYSCALL_NO(tsk)) ? "mmap"
		   : ((entry->syscall_no == MMAP2_SYSCALL_NO(tsk)) ? "mmap2"
		      : ((entry->syscall_no == MPROTECT_SYSCALL_NO(tsk))
			 ? "mprotect"
			 : ((entry->syscall_no == MUNMAP_SYSCALL_NO(tsk))
			    ? "munmap"
			    : "UNKNOWN")))),
		  entry->arg0, rv);

	if (entry->syscall_no == MUNMAP_SYSCALL_NO(tsk)) {
		// Call the callbacks
		__stp_call_munmap_callbacks(tgt, tsk, entry->arg0, entry->arg1);
	}
	else if (entry->syscall_no == MMAP_SYSCALL_NO(tsk)
		 || entry->syscall_no == MMAP2_SYSCALL_NO(tsk)) {
		// Call the callbacks
		__stp_call_mmap_callbacks_with_addr(tgt, tsk, rv);
	}
	else {				// mprotect
		// Call the callbacks
		__stp_call_mprotect_callbacks(tgt, tsk, entry->arg0,
					      entry->arg1, entry->arg2);
	}

	__stp_tf_handler_end();
	__stp_tf_remove_map_entry(entry);
	return UTRACE_RESUME;
}

static struct utrace_engine_ops __stp_utrace_task_finder_ops = {
	.report_clone = __stp_utrace_task_finder_report_clone,
	.report_exec = __stp_utrace_task_finder_report_exec,
	.report_exit = stap_utrace_task_finder_report_exit,
};

static int
stap_start_task_finder(void)
{
	int rc = 0;
	struct task_struct *grp, *tsk;
	char *mmpath_buf;
	uid_t tsk_euid;

	if (atomic_inc_return(&__stp_task_finder_state) != __STP_TF_STARTING) {
		atomic_dec(&__stp_task_finder_state);
		_stp_error("task_finder already started");
		return EBUSY;
	}

	mmpath_buf = _stp_kmalloc(PATH_MAX);
	if (mmpath_buf == NULL) {
		_stp_error("Unable to allocate space for path");
		return ENOMEM;
	}

        __stp_tf_map_initialize();

	atomic_set(&__stp_task_finder_state, __STP_TF_RUNNING);

	rcu_read_lock();
	do_each_thread(grp, tsk) {
		struct mm_struct *mm;
		char *mmpath;
		size_t mmpathlen;
		struct list_head *tgt_node;

		/* If in stap -c/-x mode, skip over other processes. */
		if (_stp_target && tsk->tgid != _stp_target)
			continue;

		// Called under lock, so needs atomic.
		rc = __stp_utrace_attach_atomic(tsk,
					 &__stp_utrace_task_finder_ops, 0,
					 __STP_TASK_FINDER_EVENTS,
					 UTRACE_RESUME);
		if (rc == EPERM) {
			/* Ignore EPERM errors, which mean this wasn't
			 * a thread we can attach to. */
			rc = 0;
			continue;
		}
		else if (rc != 0) {
			/* If we get a real error, quit. */
			goto stf_err;
		}

		// Grab the path associated with this task.
		//
		// Note we aren't calling get_task_mm()/mmput() here.
		// Instead we're calling task_lock()/task_unlock().
		// We really only need to lock the mm, but mmput() can
		// sleep so we can't call it.  Also note that
		// __stp_get_mm_path() grabs the mmap semaphore, which
		// should also keep us safe.
		task_lock(tsk);
		if (! tsk->mm) {
		    /* If the thread doesn't have a mm_struct, it is
		     * a kernel thread which we need to skip. */
		    continue;
		}
		mmpath = __stp_get_mm_path(tsk->mm, mmpath_buf, PATH_MAX);
		task_unlock(tsk);
		if (mmpath == NULL || IS_ERR(mmpath)) {
			rc = -PTR_ERR(mmpath);
			if (rc == ENOENT) {
				rc = 0;	/* ignore ENOENT */
				continue;
			}
			else {
				_stp_error("Unable to get path (error %d) for pid %d",
					   rc, (int)tsk->pid);
				goto stf_err;
			}
		}

		/* Check the thread's exe's path/pid against our list. */
#ifdef STAPCONF_TASK_UID
		tsk_euid = tsk->euid;
#else
#if defined(CONFIG_USER_NS) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tsk_euid = from_kuid_munged(current_user_ns(), task_euid(tsk));
#else
		tsk_euid = task_euid(tsk);
#endif
#endif
		mmpathlen = strlen(mmpath);
		list_for_each(tgt_node, &__stp_task_finder_list) {
			struct stap_task_finder_target *tgt;

			tgt = list_entry(tgt_node,
					 struct stap_task_finder_target, list);
			if (tgt == NULL)
				continue;
			/* procname-based target */
			else if (tgt->pathlen > 0
				 && (tgt->pathlen != mmpathlen
				     || strcmp(tgt->procname, mmpath) != 0))
				 continue;
			/* pid-based target */
			else if (tgt->pid != 0 && tgt->pid != tsk->pid)
				continue;
			/* Notice that "pid == 0" (which means to
			 * probe all threads) falls through. */

#if ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPDEV) && \
    ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPSYS)
			/* Make sure unprivileged users only probe their own threads.  */
			if (_stp_uid != tsk_euid) {
				if (tgt->pid != 0 || _stp_target) {
					_stp_warn("Process %d does not belong to unprivileged user %d",
						  tsk->pid, _stp_uid);
				}
				continue;
			}
#endif

			// Set up events we need for attached tasks.
			// Called under lock, so needs atomic.
			rc = __stp_utrace_attach_atomic(tsk, &tgt->ops, tgt,
						 __STP_ATTACHED_TASK_EVENTS,
						 UTRACE_STOP);
			if (rc != 0 && rc != EPERM)
				goto stf_err;
			rc = 0;		/* ignore EPERM */
			tgt->engine_attached = 1;
		}
	} while_each_thread(grp, tsk);
stf_err:
	rcu_read_unlock();
	_stp_kfree(mmpath_buf);
	debug_task_finder_report(); // report at end for utrace engine counting
	return rc;
}

static void
stap_task_finder_post_init(void)
{
	/* With the original version of utrace UTRACE_STOP also does
	 * UTRACE_INTERRUPT, so we don't really need this function. */
#if !defined(UTRACE_ORIG_VERSION)
	struct task_struct *grp, *tsk;

	if (atomic_read(&__stp_task_finder_state) != __STP_TF_RUNNING) {
		_stp_error("task_finder not running?");
		return;
	}

	rcu_read_lock();
	do_each_thread(grp, tsk) {
		struct list_head *tgt_node;

		/* If in stap -c/-x mode, skip over other processes. */
		if (_stp_target && tsk->tgid != _stp_target)
			continue;

		/* Only "poke" thread group leaders. */
		if (tsk->tgid != tsk->pid)
			continue;

		/* See if we need to "poke" this thread. */
		list_for_each(tgt_node, &__stp_task_finder_list) {
			struct stap_task_finder_target *tgt;
			struct utrace_engine *engine;

			tgt = list_entry(tgt_node,
					 struct stap_task_finder_target, list);
			if (tgt == NULL || !tgt->engine_attached)
				continue;

			// If we found an "interesting" task earlier,
			// stop it.
			engine = utrace_attach_task(tsk,
						    UTRACE_ATTACH_MATCH_OPS,
						    &tgt->ops, tgt);
			if (engine != NULL && !IS_ERR(engine)) {
				/* We found a target task. Stop it. */
				int rc = utrace_control(tsk, engine,
							UTRACE_INTERRUPT);
				/* If utrace_control() returns
				 * EINPROGRESS when we're trying to
				 * stop/interrupt, that means the task
				 * hasn't stopped quite yet, but will
				 * soon.  Ignore this error. */
				if (rc != 0 && rc != -EINPROGRESS) {
					_stp_error("utrace_control returned error %d on pid %d",
						   rc, (int)tsk->pid);
				}
				utrace_engine_put(engine);

				/* Since we only need to interrupt
				 * the task once, not once per
				 * engine, get out of this loop. */
				break;
			}
		}
	} while_each_thread(grp, tsk);
	rcu_read_unlock();
#endif
	return;
}


static void
stap_stop_task_finder(void)
{
#ifdef DEBUG_TASK_FINDER
	int i = 0;
#endif

	if (atomic_read(&__stp_task_finder_state) == __STP_TF_UNITIALIZED)
		return;

	atomic_set(&__stp_task_finder_state, __STP_TF_STOPPING);
	debug_task_finder_report();
	stap_utrace_detach_ops(&__stp_utrace_task_finder_ops);
	__stp_task_finder_cleanup();
	debug_task_finder_report();
	atomic_set(&__stp_task_finder_state, __STP_TF_STOPPED);

	/* Now that all the engines are detached, make sure
	 * all the callbacks are finished.  If they aren't, we'll
	 * crash the kernel when the module is removed. */
	while (atomic_read(&__stp_inuse_count) != 0) {
		schedule();
#ifdef DEBUG_TASK_FINDER
		i++;
#endif
	}
#ifdef DEBUG_TASK_FINDER
	if (i > 0)
		printk(KERN_ERR "it took %d polling loops to quit.\n", i);
#endif
	debug_task_finder_report();
}

#endif /* CONFIG_UTRACE */
#endif /* HAVE_TASK_FINDER */
#endif /* TASK_FINDER_C */
