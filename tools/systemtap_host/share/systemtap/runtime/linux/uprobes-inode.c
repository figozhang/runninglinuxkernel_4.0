/* -*- linux-c -*-
 * Common functions for using inode-based uprobes
 * Copyright (C) 2011-2013,2015 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _UPROBES_INODE_C_
#define _UPROBES_INODE_C_

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uprobes.h>

/* STAPIU: SystemTap Inode Uprobes */


// PR13489, inodes-uprobes export kludge
#if !defined(CONFIG_UPROBES)
#error "not to be built without CONFIG_UPROBES"
#endif

#if !defined(STAPCONF_UPROBE_REGISTER_EXPORTED)
// First get the right typeof(name) that's found in uprobes.h
#if defined(STAPCONF_OLD_INODE_UPROBES)
typedef typeof(&register_uprobe) uprobe_register_fn;
#else
typedef typeof(&uprobe_register) uprobe_register_fn;
#endif
// Then define the typecasted call via function pointer
#define uprobe_register (* (uprobe_register_fn)kallsyms_uprobe_register)
#elif defined(STAPCONF_OLD_INODE_UPROBES)
// In this case, just need to map the new name to the old
#define uprobe_register register_uprobe
#endif

#if !defined(STAPCONF_UPROBE_UNREGISTER_EXPORTED)
// First get the right typeof(name) that's found in uprobes.h
#if defined(STAPCONF_OLD_INODE_UPROBES)
typedef typeof(&unregister_uprobe) uprobe_unregister_fn;
#else
typedef typeof(&uprobe_unregister) uprobe_unregister_fn;
#endif
// Then define the typecasted call via function pointer
#define uprobe_unregister (* (uprobe_unregister_fn)kallsyms_uprobe_unregister)
#elif defined(STAPCONF_OLD_INODE_UPROBES)
// In this case, just need to map the new name to the old
#define uprobe_unregister unregister_uprobe
#endif


// uprobes started setting REG_IP itself starting in kernel commit 74e59dfc.
// There's no direct indicator of this, but commit da1816b1 in the same patch
// series defines UPROBE_HANDLER_MASK, so that's a decent trigger for us.
#ifndef UPROBE_HANDLER_MASK
#define STAPIU_NEEDS_REG_IP 1
#if !defined(STAPCONF_UPROBE_GET_SWBP_ADDR_EXPORTED)
// First typedef from the original decl, then #define it as a typecasted call.
typedef typeof(&uprobe_get_swbp_addr) uprobe_get_swbp_addr_fn;
#define uprobe_get_swbp_addr (* (uprobe_get_swbp_addr_fn)kallsyms_uprobe_get_swbp_addr)
#endif
#endif

/* A target is a specific file/inode that we want to probe.  */
struct stapiu_target {
	/* All the uprobes for this target. */
	struct list_head consumers; /* stapiu_consumer */

	/* All the processes containing this target.
	 * This may not be system-wide, e.g. only the -c process.
	 * We use task_finder to manage this list.  */
	struct list_head processes; /* stapiu_process */
	rwlock_t process_lock;

	struct stap_task_finder_target finder;

	const char * const filename;
	struct inode *inode;
	struct mutex inode_lock;
};


/* A consumer is a specific uprobe that we want to place.  */
struct stapiu_consumer {
	struct uprobe_consumer consumer;

	const unsigned return_p:1;
	unsigned registered:1;

	struct list_head target_consumer;
	struct stapiu_target * const target;

	loff_t offset; /* the probe offset within the inode */
	loff_t sdt_sem_offset; /* the semaphore offset from process->base */

	// List of perf counters used by each probe
	// This list is an index into struct stap_perf_probe,
	long perf_counters_dim;
	long *perf_counters;
	const struct stap_probe * const probe;
};


/* A process that we want to probe.  These are dynamically discovered and
 * associated using task_finder, allocated from this static array.  */
static struct stapiu_process {
	struct list_head target_process;
	unsigned long relocation; /* the mmap'ed .text address */
	unsigned long base; /* the address to apply sdt offsets against */
	pid_t tgid;
} stapiu_process_slots[MAXUPROBES];


/* This lock guards modification to stapiu_process_slots.
 * Note: target->process_lock nests inside this.  */
static DEFINE_SPINLOCK(stapiu_process_slots_lock);

#if defined(UPROBES_HITCOUNT)
static atomic_t prehandler_hitcount = ATOMIC_INIT(0);
static atomic_t handler_hitcount = ATOMIC_INIT(0);
#endif

/* The stap-generated probe handler for all inode-uprobes. */
static int
stapiu_probe_handler (struct stapiu_consumer *sup, struct pt_regs *regs);

static int
stapiu_probe_prehandler (struct uprobe_consumer *inst, struct pt_regs *regs)
{
	int ret;
	struct stapiu_consumer *sup =
		container_of(inst, struct stapiu_consumer, consumer);
	struct stapiu_target *target = sup->target;

	struct stapiu_process *p, *process = NULL;

#if defined(UPROBES_HITCOUNT)
	atomic_inc(&prehandler_hitcount);
#endif

	/* First find the related process, set by stapiu_change_plus.
	 * NB: This is a linear search performed for every probe hit!
	 * This could be an algorithmic problem if the list gets large, but
	 * we'll wait until this is demonstratedly a hotspot before optimizing.
	 */
	read_lock(&target->process_lock);
	list_for_each_entry(p, &target->processes, target_process) {
		if (p->tgid == current->tgid) {
			process = p;
			break;
		}
	}
	read_unlock(&target->process_lock);
	if (!process) {
#ifdef UPROBE_HANDLER_REMOVE
		/* Once we're past the starting phase, we can be sure that any
		 * processes which are executing code in a mapping have already
		 * been through task_finder.  So if it's not in our list of
		 * target->processes, it can safely get removed.  */
		if (stap_task_finder_complete())
			return UPROBE_HANDLER_REMOVE;
#endif
		return 0;
	}

#ifdef STAPIU_NEEDS_REG_IP
	/* Make it look like the IP is set as it would in the actual user task
	 * before calling the real probe handler.  */
	{
	unsigned long saved_ip = REG_IP(regs);
	SET_REG_IP(regs, uprobe_get_swbp_addr(regs));
#endif

#if defined(UPROBES_HITCOUNT)
	atomic_inc(&handler_hitcount);
#endif

	ret = stapiu_probe_handler(sup, regs);

#ifdef STAPIU_NEEDS_REG_IP
	/* Reset IP regs on return, so we don't confuse uprobes.  */
	SET_REG_IP(regs, saved_ip);
	}
#endif

	return ret;
}

static int
stapiu_retprobe_prehandler (struct uprobe_consumer *inst,
			    unsigned long func __attribute__((unused)),
			    struct pt_regs *regs)
{
	return stapiu_probe_prehandler(inst, regs);
}

static int
stapiu_register (struct inode* inode, struct stapiu_consumer* c)
{
	int ret = 0;

	if (!c->return_p) {
		c->consumer.handler = stapiu_probe_prehandler;
	} else {
#if defined(STAPCONF_INODE_URETPROBES)
		c->consumer.ret_handler = stapiu_retprobe_prehandler;
#else
		ret = EINVAL;
#endif
	}

	if (ret == 0)
		ret = uprobe_register (inode, c->offset, &c->consumer);

	c->registered = (ret ? 0 : 1);
	return ret;
}

static void
stapiu_unregister (struct inode* inode, struct stapiu_consumer* c)
{
	uprobe_unregister (inode, c->offset, &c->consumer);
	c->registered = 0;
}


static inline void
stapiu_target_lock(struct stapiu_target *target)
{
	mutex_lock(&target->inode_lock);
}

static inline void
stapiu_target_unlock(struct stapiu_target *target)
{
	mutex_unlock(&target->inode_lock);
}

/* Read-modify-write a semaphore, usually +/- 1.  */
static int
stapiu_write_semaphore(unsigned long addr, unsigned short delta)
{
	int rc = 0;
	unsigned short __user* sdt_addr = (unsigned short __user*) addr;
	unsigned short sdt_semaphore = 0; /* NB: fixed size */
	/* XXX: need to analyze possibility of race condition */
	rc = get_user(sdt_semaphore, sdt_addr);
	if (!rc) {
		sdt_semaphore += delta;
		rc = put_user(sdt_semaphore, sdt_addr);
	}
	return rc;
}


/* Read-modify-write a semaphore in an arbitrary task, usually +/- 1.  */
static int
stapiu_write_task_semaphore(struct task_struct* task,
			    unsigned long addr, unsigned short delta)
{
	int count, rc = 0;
	unsigned short sdt_semaphore = 0; /* NB: fixed size */
	/* XXX: need to analyze possibility of race condition */
	count = __access_process_vm_noflush(task, addr,
			&sdt_semaphore, sizeof(sdt_semaphore), 0);
	if (count != sizeof(sdt_semaphore))
		rc = 1;
	else {
		sdt_semaphore += delta;
		count = __access_process_vm_noflush(task, addr,
				&sdt_semaphore, sizeof(sdt_semaphore), 1);
		rc = (count == sizeof(sdt_semaphore)) ? 0 : 1;
	}
	return rc;
}


static void
stapiu_decrement_process_semaphores(struct stapiu_process *p,
				    struct list_head *consumers)
{
	struct task_struct *task;
	rcu_read_lock();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	/* We'd like to call find_task_by_pid_ns() here, but it isn't
	 * exported.  So, we call what it calls...  */
	task = pid_task(find_pid_ns(p->tgid, &init_pid_ns), PIDTYPE_PID);
#else
	task = find_task_by_pid(p->tgid);
#endif

	/* The task may have exited while we weren't watching.  */
	if (task) {
		struct stapiu_consumer *c;

		/* Holding the rcu read lock makes us atomic, and we
		 * can't write userspace memory while atomic (which
		 * could pagefault).  So, instead we lock the task
		 * structure, then release the rcu read lock. */
		get_task_struct(task);
		rcu_read_unlock();

		list_for_each_entry(c, consumers, target_consumer) {
			if (c->sdt_sem_offset) {
				unsigned long addr = p->base + c->sdt_sem_offset;
				stapiu_write_task_semaphore(task, addr,
						(unsigned short) -1);
			}
		}
		put_task_struct(task);
	}
	else {
		rcu_read_unlock();
	}
}


/* As part of shutdown, we need to decrement the semaphores in every task we've
 * been attached to.  */
static void
stapiu_decrement_semaphores(struct stapiu_target *targets, size_t ntargets)
{
	size_t i;
	/* NB: no stapiu_process_slots_lock needed, as the task_finder engine is
	 * already stopped by now, so no one else will mess with us.  We need
	 * to be sleepable for access_process_vm.  */
	might_sleep();
	for (i = 0; i < ntargets; ++i) {
		struct stapiu_target *ut = &targets[i];
		struct stapiu_consumer *c;
		struct stapiu_process *p;
		int has_semaphores = 0;

		list_for_each_entry(c, &ut->consumers, target_consumer) {
			if (c->sdt_sem_offset) {
				has_semaphores = 1;
				break;
			}
		}
		if (!has_semaphores)
			continue;

		list_for_each_entry(p, &ut->processes, target_process)
			stapiu_decrement_process_semaphores(p, &ut->consumers);
	}
}


/* Unregister all uprobe consumers of a target.  */
static void
stapiu_target_unreg(struct stapiu_target *target)
{
	struct stapiu_consumer *c;

	if (! target->inode)
		return;
	list_for_each_entry(c, &target->consumers, target_consumer) {
		if (c->registered)
			stapiu_unregister(target->inode, c);
	}
}


/* Register all uprobe consumers of a target.  */
static int
stapiu_target_reg(struct stapiu_target *target, struct task_struct* task)
{
	int ret = 0;
	struct stapiu_consumer *c;

	list_for_each_entry(c, &target->consumers, target_consumer) {
		if (! c->registered) {
			int i;
			for (i=0; i < c->perf_counters_dim; i++) {
                            if ((c->perf_counters)[i] > -1)
			    _stp_perf_read_init ((c->perf_counters)[i], task);
			}
			if (!c->probe->cond_enabled) {
				dbug_otf("not registering (u%sprobe) pidx %zu\n",
					 c->return_p ? "ret" : "", c->probe->index);
				continue;
			}
			if (stapiu_register(target->inode, c) != 0)
				_stp_warn("probe %s inode-offset %p registration error (rc %d)",
					  c->probe->pp, (void*) (uintptr_t) c->offset, ret);
		}
	}
	if (ret)
		stapiu_target_unreg(target);
	return ret;
}


/* Register/unregister a target's uprobe consumers if their associated probe
 * handlers have their conditions enabled/disabled. */
static void
stapiu_target_refresh(struct stapiu_target *target)
{
	struct stapiu_consumer *c;

	// go through every consumer
	list_for_each_entry(c, &target->consumers, target_consumer) {

		// should we unregister it?
		if (c->registered && !c->probe->cond_enabled) {

			dbug_otf("unregistering (u%sprobe) pidx %zu\n",
				 c->return_p ? "ret" : "", c->probe->index);
			stapiu_unregister(target->inode, c);

		// should we register it?
		} else if (!c->registered && c->probe->cond_enabled) {

			dbug_otf("registering (u%sprobe) pidx %zu\n",
				 c->return_p ? "ret" : "", c->probe->index);
			if (stapiu_register(target->inode, c) != 0)
				dbug_otf("couldn't register (u%sprobe) pidx %zu\n",
					 c->return_p ? "ret" : "", c->probe->index);
		}
	}
}


/* Cleanup every target.  */
static void
stapiu_exit_targets(struct stapiu_target *targets, size_t ntargets)
{
	size_t i;
	for (i = 0; i < ntargets; ++i) {
		struct stapiu_target *ut = &targets[i];

		stapiu_target_unreg(ut);

		/* NB: task_finder needs no unregister. */
		if (ut->inode) {
			iput(ut->inode);
			ut->inode = NULL;
		}
	}
}


/* Initialize every target.  */
static int
stapiu_init_targets(struct stapiu_target *targets, size_t ntargets)
{
	int ret = 0;
	size_t i;
	for (i = 0; i < ntargets; ++i) {
		struct stapiu_target *ut = &targets[i];
		INIT_LIST_HEAD(&ut->consumers);
		INIT_LIST_HEAD(&ut->processes);
		rwlock_init(&ut->process_lock);
		mutex_init(&ut->inode_lock);
		ret = stap_register_task_finder_target(&ut->finder);
		if (ret != 0) {
			_stp_error("Couldn't register task finder target for file '%s': %d\n",
				   ut->filename, ret);
			break;
		}
	}
	return ret;
}


/* Initialize the entire inode-uprobes subsystem.  */
static int
stapiu_init(struct stapiu_target *targets, size_t ntargets,
	    struct stapiu_consumer *consumers, size_t nconsumers)
{
	int ret = stapiu_init_targets(targets, ntargets);
	if (!ret) {
		size_t i;

		/* Connect each consumer to its target. */
		for (i = 0; i < nconsumers; ++i) {
			struct stapiu_consumer *uc = &consumers[i];
			list_add(&uc->target_consumer,
				 &uc->target->consumers);
		}
	}
	return ret;
}

/* Refresh the entire inode-uprobes subsystem.  */
static void
stapiu_refresh(struct stapiu_target *targets, size_t ntargets)
{
	size_t i;

	for (i = 0; i < ntargets; ++i) {
		struct stapiu_target *target = &targets[i];

		// we need to lock it to ensure probes don't get
		// registered under our feet
		stapiu_target_lock(target);

		if (target->inode)
			stapiu_target_refresh(target);

		stapiu_target_unlock(target);
	}
}

/* Shutdown the entire inode-uprobes subsystem.  */
static void
stapiu_exit(struct stapiu_target *targets, size_t ntargets,
	    struct stapiu_consumer *consumers, size_t nconsumers)
{
	stapiu_decrement_semaphores(targets, ntargets);
	stapiu_exit_targets(targets, ntargets);
#if defined(UPROBES_HITCOUNT)
	_stp_printf("stapiu_probe_prehandler() called %d times\n",
			atomic_read(&prehandler_hitcount));
	_stp_printf("stapiu_probe_handler() called %d times\n",
			atomic_read(&handler_hitcount));
	_stp_print_flush();
#endif
}


/* Task-finder found a process with the target that we're interested in.
 * Grab a process slot and associate with this target, so the semaphores
 * and filtering can work properly.  */
static int
stapiu_change_plus(struct stapiu_target* target, struct task_struct *task,
		   unsigned long relocation, unsigned long length,
		   unsigned long offset, unsigned long vm_flags,
		   struct inode *inode)
{
	size_t i;
	struct stapiu_process *p;
	int rc;

	/* Check the buildid of the target (if we haven't already). We
	 * lock the target so we don't have concurrency issues. */
	stapiu_target_lock(target);
	if (! target->inode) {
		if (! inode) {
			rc = -EINVAL;
			stapiu_target_unlock(target);
			return rc;
		}

		/* Grab the inode first (to prevent TOCTTOU problems). */
		target->inode = igrab(inode);
		if (!target->inode) {
			_stp_error("Couldn't get inode for file '%s'\n",
				   target->filename);
			rc = -EINVAL;
			stapiu_target_unlock(target);
			return rc;
		}

		/* Actually do the check. */
		if ((rc = _stp_usermodule_check(task, target->filename,
						relocation))) {
			/* Be sure to release the inode on failure. */
			iput(target->inode);
			target->inode = NULL;
			stapiu_target_unlock(target);
			return rc;
		}

		/* OK, we've checked the target's buildid. Now
		 * register all its consumers. */
		rc = stapiu_target_reg(target, task);
		if (rc) {
			/* Be sure to release the inode on failure. */
			iput(target->inode);
			target->inode = NULL;
			stapiu_target_unlock(target);
			return rc;
		}
	}
	stapiu_target_unlock(target);

	/* Associate this target with this process. */
	spin_lock(&stapiu_process_slots_lock);
	write_lock(&target->process_lock);
	for (i = 0; i < MAXUPROBES; ++i) {
		p = &stapiu_process_slots[i];
		if (!p->tgid) {
			p->tgid = task->tgid;
			p->relocation = relocation;

                        /* The base is used for relocating semaphores.  If the
                         * probe is in an ET_EXEC binary, then that offset
                         * already is a real address.  But stapiu_process_found
                         * calls us in this case with relocation=offset=0, so
                         * we don't have to worry about it.  */
			p->base = relocation - offset;

			list_add(&p->target_process, &target->processes);
			break;
		}
	}
	write_unlock(&target->process_lock);
	spin_unlock(&stapiu_process_slots_lock);

	return 0; /* XXX: or an error? maxskipped? */
}


/* Task-finder found a writable mapping in our interested target.
 * If any of the consumers need a semaphore, increment now.  */
static int
stapiu_change_semaphore_plus(struct stapiu_target* target, struct task_struct *task,
			     unsigned long relocation, unsigned long length)
{
	int rc = 0;
	struct stapiu_process *p, *process = NULL;
	struct stapiu_consumer *c;

	/* First find the related process, set by stapiu_change_plus.  */
	read_lock(&target->process_lock);
	list_for_each_entry(p, &target->processes, target_process) {
		if (p->tgid == task->tgid) {
			process = p;
			break;
		}
	}
	read_unlock(&target->process_lock);
	if (!process)
		return 0;

	/* NB: no lock after this point, as we need to be sleepable for
	 * get/put_user semaphore action.  The given process should be frozen
	 * while we're busy, so it's not an issue.
	 */

	/* Look through all the consumers and increment semaphores.  */
	list_for_each_entry(c, &target->consumers, target_consumer) {
		if (c->sdt_sem_offset) {
			unsigned long addr = process->base + c->sdt_sem_offset;
			if (addr >= relocation && addr < relocation + length) {
				int rc2 = stapiu_write_task_semaphore(task,
								      addr, +1);
				if (!rc)
					rc = rc2;
			}
		}
	}
	return rc;
}


/* Task-finder found a mapping that's now going away.  We don't need to worry
 * about the semaphores, so we can just release the process slot.  */
static int
stapiu_change_minus(struct stapiu_target* target, struct task_struct *task,
		    unsigned long relocation, unsigned long length)
{
	struct stapiu_process *p, *tmp;

	/* NB: we aren't unregistering uprobes and releasing the
	 * inode here.  The registration is system-wide, based on
	 * inode, not process based.  */

	spin_lock(&stapiu_process_slots_lock);
	write_lock(&target->process_lock);
	list_for_each_entry_safe(p, tmp, &target->processes, target_process) {
		if (p->tgid == task->tgid && (relocation <= p->relocation &&
					      p->relocation < relocation+length)) {
			list_del(&p->target_process);
			memset(p, 0, sizeof(*p));
		}
	}
	write_unlock(&target->process_lock);
	spin_unlock(&stapiu_process_slots_lock);
	return 0;
}


static struct inode *
stapiu_get_task_inode(struct task_struct *task)
{
	struct mm_struct *mm;
	struct file* vm_file;
	struct inode *inode = NULL;

	// Grab the inode associated with the task.
	//
	// Note we're not calling get_task_mm()/mmput() here.  Since
	// we're in the the context of task, the mm should stick
	// around without locking it (and mmput() can sleep).
	mm = task->mm;
	if (! mm) {
		/* If the thread doesn't have a mm_struct, it is
		 * a kernel thread which we need to skip. */
		return NULL;
	}

	vm_file = stap_find_exe_file(mm);
	if (vm_file) {
		if (vm_file->f_path.dentry)
			inode = vm_file->f_path.dentry->d_inode;
		fput(vm_file);
	}
	return inode;
}


/* The task_finder_callback we use for ET_EXEC targets. */
static int
stapiu_process_found(struct stap_task_finder_target *tf_target,
		     struct task_struct *task, int register_p, int process_p)
{
	struct stapiu_target *target =
		container_of(tf_target, struct stapiu_target, finder);

	if (!process_p)
		return 0; /* ignore threads */

	/* ET_EXEC events are like shlib events, but with 0 relocation bases */
	if (register_p) {
		int rc = -EINVAL;
		struct inode *inode = stapiu_get_task_inode(task);

		if (inode) {
			rc = stapiu_change_plus(target, task, 0, TASK_SIZE,
						0, 0, inode);
			stapiu_change_semaphore_plus(target, task, 0,
						     TASK_SIZE);
		}
		return rc;
	} else
		return stapiu_change_minus(target, task, 0, TASK_SIZE);
}


/* The task_finder_mmap_callback */
static int
stapiu_mmap_found(struct stap_task_finder_target *tf_target,
		  struct task_struct *task,
		  char *path, struct dentry *dentry,
		  unsigned long addr, unsigned long length,
		  unsigned long offset, unsigned long vm_flags)
{
	int rc = 0;
	struct stapiu_target *target =
		container_of(tf_target, struct stapiu_target, finder);

	/* Sanity check that the inodes match (if the target's inode
	 * is set). Doesn't guarantee safety, but it's a start.  If
	 * the target's inode isn't set, this is the first time we've
	 * seen this target.
	 */
	if (target->inode && dentry->d_inode != target->inode)
		return 0;

	/* The file path must match too. */
	if (!path || strcmp (path, target->filename))
		return 0;

	/* 1 - shared libraries' executable segments load from offset 0
	 *   - ld.so convention offset != 0 is now allowed
	 *     so stap_uprobe_change_plus can set a semaphore,
	 *     i.e. a static extern, in a shared object
	 * 2 - the shared library we're interested in
	 * 3 - mapping should be executable or writeable (for
	 *     semaphore in .so)
	 *     NB: or both, on kernels that lack noexec mapping
	 */

	/* Check non-writable, executable sections for probes. */
	if ((vm_flags & VM_EXEC) && !(vm_flags & VM_WRITE))
		rc = stapiu_change_plus(target, task, addr, length,
					offset, vm_flags, dentry->d_inode);

	/* Check writeable sections for semaphores.
	 * NB: They may have also been executable for the check above,
	 *     if we're running a kernel that lacks noexec mappings.
	 *     So long as there's no error (rc == 0), we need to look
	 *     for semaphores too. 
	 */
	if ((rc == 0) && (vm_flags & VM_WRITE))
		rc = stapiu_change_semaphore_plus(target, task, addr, length);

	return rc;
}


/* The task_finder_munmap_callback */
static int
stapiu_munmap_found(struct stap_task_finder_target *tf_target,
		    struct task_struct *task,
		    unsigned long addr, unsigned long length)
{
	struct stapiu_target *target =
		container_of(tf_target, struct stapiu_target, finder);

	return stapiu_change_minus(target, task, addr, length);
}


/* The task_finder_callback we use for ET_DYN targets.
 * This just forces an unmap of everything as the process exits. (PR11151)
 */
static int
stapiu_process_munmap(struct stap_task_finder_target *tf_target,
		      struct task_struct *task,
		      int register_p, int process_p)
{
	struct stapiu_target *target =
		container_of(tf_target, struct stapiu_target, finder);

	if (!process_p)
		return 0; /* ignore threads */

	/* Covering 0->TASK_SIZE means "unmap everything" */
	if (!register_p)
		return stapiu_change_minus(target, task, 0, TASK_SIZE);
	return 0;
}


#endif /* _UPROBES_INODE_C_ */
