/*
 * user space instruction tracing
 * Copyright (C) 2005, 2006, 2007, 2008, 2009 IBM Corp.
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/utrace.h>
#include "ptrace_compatibility.h"

/* PR10171: To avoid ia64 lockups, disable itrace on ia64. */
#if defined(__ia64__)
#error "Unsupported itrace architecture"
#endif

/* PR9974: Adapt to struct renaming. */
#ifdef UTRACE_API_VERSION
#define utrace_attached_engine utrace_engine
#endif

#include <asm/string.h>
#include "uprobes/uprobes.h"
#include "utrace_compatibility.h"

#ifndef put_task_struct
#define put_task_struct(t)	\
	BUG_ON(atomic_dec_and_test(&tsk->usage))
#endif

#ifdef CONFIG_PPC
struct bpt_info {
        unsigned long addr;
        unsigned int instr;
};

struct atomic_ss_info {
        int step_over_atomic;
        struct bpt_info end_bpt;
        struct bpt_info br_bpt;
};

static int handle_ppc_atomic_seq(struct task_struct *tsk, struct pt_regs *regs,
	struct atomic_ss_info *ss_info);
static void remove_atomic_ss_breakpoint (struct task_struct *tsk, 
	struct bpt_info *bpt);
#endif

struct itrace_info {
	u32 step_flag;
	struct stap_itrace_probe *itrace_probe;
#ifdef CONFIG_PPC
	struct atomic_ss_info ppc_atomic_ss;
#endif
	struct task_struct *tsk;
	struct utrace_attached_engine *engine;
	struct list_head link;
};

static u32 debug = 0 /* 1 */;

static LIST_HEAD(usr_itrace_info);
static spinlock_t itrace_lock;
static struct itrace_info *create_itrace_info(
	struct task_struct *tsk, u32 step_flag,
	struct stap_itrace_probe *itrace_probe);


/* Note: __access_process_vm moved to access_process_vm.h */

#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_quiesce(struct utrace_attached_engine *engine,
					struct task_struct *tsk)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32 usr_itrace_report_quiesce(u32 action,
				struct utrace_attached_engine *engine,
				unsigned long event)
#else
static u32 usr_itrace_report_quiesce(enum utrace_resume_action action,
				struct utrace_attached_engine *engine,
				struct task_struct *tsk,
				unsigned long event)
#endif
#endif
{
	int status;
	struct itrace_info *ui;

	rcu_read_lock();
	ui = rcu_dereference(engine->data);
	rcu_read_unlock();
	WARN_ON(!ui);

#ifdef UTRACE_ORIG_VERSION
	return (ui->step_flag | UTRACE_ACTION_NEWSTATE);
#else
	return (event == 0 ? ui->step_flag : UTRACE_RESUME);
#endif
}


#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_signal(
			     struct utrace_attached_engine *engine,
			     struct task_struct *tsk,
			     struct pt_regs *regs,
                             u32 action, siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32 usr_itrace_report_signal(u32 action,
			     struct utrace_attached_engine *engine,
			     struct pt_regs *regs,
			     siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka)
#else
static u32 usr_itrace_report_signal(u32 action,
			     struct utrace_attached_engine *engine,
			     struct task_struct *tsk,
			     struct pt_regs *regs,
			     siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka)
#endif
#endif
{
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
	struct task_struct *tsk = current;
#endif
	struct itrace_info *ui;
	u32 return_flags;
	unsigned long data = 0;
#ifdef CONFIG_PPC
	data = mfspr(SPRN_SDAR);
#endif

	rcu_read_lock();
	ui = rcu_dereference(engine->data);
	rcu_read_unlock();
	WARN_ON(!ui);

#if defined(UTRACE_ORIG_VERSION) 
        if (info->si_signo != SIGTRAP || !ui)
	  return UTRACE_RESUME;
#else
	if (utrace_signal_action(action) == UTRACE_SIGNAL_HANDLER ||
            utrace_signal_action(action) == UTRACE_SIGNAL_REPORT ||
	    info->si_signo != SIGTRAP || !ui)
	  return UTRACE_RESUME | utrace_signal_action(action);
#endif

#if defined(UTRACE_ORIG_VERSION) && defined(CONFIG_PPC)
	/* Because of a ppc utrace bug, we need to stop the task here.
	   usr_itrace_report_quiesce() will continue stepping the task. */
	return_flags = UTRACE_SIGNAL_IGN | UTRACE_STOP | UTRACE_ACTION_NEWSTATE;
#else
	/* normal case: continue stepping */
	return_flags =  ui->step_flag | UTRACE_SIGNAL_IGN;
#endif
#ifdef CONFIG_PPC
	if (ui->ppc_atomic_ss.step_over_atomic) {
		remove_atomic_ss_breakpoint(tsk, &ui->ppc_atomic_ss.end_bpt);
		if (ui->ppc_atomic_ss.br_bpt.addr)
			remove_atomic_ss_breakpoint(tsk,
				&ui->ppc_atomic_ss.br_bpt);
		ui->ppc_atomic_ss.step_over_atomic = 0;
	}
	
	if (handle_ppc_atomic_seq(tsk, regs, &ui->ppc_atomic_ss))
		return_flags = UTRACE_RESUME | UTRACE_SIGNAL_IGN;
#endif

	enter_itrace_probe(ui->itrace_probe, regs, (void *)&data);

	return return_flags;
}



#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_clone(
		struct utrace_attached_engine *engine,
		struct task_struct *parent,
                unsigned long clone_flags,
		struct task_struct *child)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32 usr_itrace_report_clone(u32 action,
		struct utrace_attached_engine *engine,
		unsigned long clone_flags,
		struct task_struct *child)
#else
static u32 usr_itrace_report_clone(enum utrace_resume_action action,
		struct utrace_attached_engine *engine,
		struct task_struct *parent, unsigned long clone_flags,
		struct task_struct *child)
#endif
#endif
{
	return UTRACE_RESUME;
}

#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_death(struct utrace_attached_engine *e,
                                   struct task_struct *tsk)
#else
#if defined(UTRACE_API_VERSION) && (UTRACE_API_VERSION >= 20091216)
static u32 usr_itrace_report_death(struct utrace_attached_engine *e,
	bool group_dead, int signal)
#else
static u32 usr_itrace_report_death(struct utrace_attached_engine *e,
	struct task_struct *tsk, bool group_dead, int signal)
#endif
#endif
{
	struct itrace_info *ui;
	rcu_read_lock();
	ui = rcu_dereference(e->data);
	rcu_read_unlock();
	WARN_ON(!ui);

	return (UTRACE_DETACH);
}

static const struct utrace_engine_ops utrace_ops =
{
	.report_quiesce = usr_itrace_report_quiesce,
	.report_signal = usr_itrace_report_signal,
	.report_clone = usr_itrace_report_clone,
	.report_death = usr_itrace_report_death
};


static struct itrace_info *create_itrace_info(
	struct task_struct *tsk, u32 step_flag,
	struct stap_itrace_probe *itrace_probe)
{
	struct itrace_info *ui;
	int status;

	if (debug)
		printk(KERN_INFO "create_itrace_info: tid=%d\n", tsk->pid);
	/* initialize ui */
	ui = _stp_kzalloc(sizeof(struct itrace_info));
	if (ui == NULL) {
		printk(KERN_ERR "%s:%d: Unable to allocate memory\n",
		       __FUNCTION__, __LINE__);
		return NULL;
	}
	ui->tsk = tsk;
	ui->step_flag = step_flag;
	ui->itrace_probe = itrace_probe;
#ifdef CONFIG_PPC
	ui->ppc_atomic_ss.step_over_atomic = 0;
#endif
	INIT_LIST_HEAD(&ui->link);

	/* push ui onto usr_itrace_info */
	spin_lock(&itrace_lock);
	list_add(&ui->link, &usr_itrace_info);
	spin_unlock(&itrace_lock);

	/* attach a single stepping engine.  create_itrace_info is called
	   under rcu read lock, so needs atomic.  */
	ui->engine = utrace_attach_task(ui->tsk,
					(UTRACE_ATTACH_CREATE
					 | UTRACE_ATTACH_ATOMIC),
					&utrace_ops, ui);
	if (IS_ERR(ui->engine)) {
		printk(KERN_ERR "utrace_attach returns %ld\n",
			PTR_ERR(ui->engine));
		return NULL;
	}
	status = utrace_set_events(tsk, ui->engine, ui->engine->flags |
		UTRACE_EVENT(QUIESCE) |
		UTRACE_EVENT(CLONE) | UTRACE_EVENT_SIGNAL_ALL |
		UTRACE_EVENT(DEATH));
	if (status < 0) {
		printk(KERN_ERR "utrace_attach returns %d\n", status);
		utrace_engine_put(ui->engine);
		return NULL;
	}

	status = utrace_control(tsk, ui->engine, UTRACE_STOP);
	if (status == 0) {
		status = utrace_control(tsk, ui->engine, step_flag);
		if (status < 0) {
			printk(KERN_ERR "utrace_control(%d) returns %d\n",
				step_flag, status);
			utrace_engine_put(ui->engine);
			return NULL;
		}
	}

	utrace_engine_put(ui->engine);
	return ui;
}

static struct itrace_info *find_itrace_info(struct task_struct *tsk)
{
	struct itrace_info *ui = NULL;

	spin_lock(&itrace_lock);
	list_for_each_entry(ui, &usr_itrace_info, link) {
		if (ui->tsk == tsk)
			goto done;
	}
	ui = NULL;
done:
	spin_unlock(&itrace_lock);
	return ui;
}


static int usr_itrace_init(int single_step, struct task_struct *tsk, struct stap_itrace_probe *p)
{
	struct itrace_info *ui;

	spin_lock_init(&itrace_lock);
	rcu_read_lock();
	if (tsk == NULL) {
		printk(KERN_ERR "usr_itrace_init: Invalid task\n");
		rcu_read_unlock();
		return 1;
	}

	get_task_struct(tsk);
	ui = create_itrace_info(tsk, 
		(single_step ?
			UTRACE_SINGLESTEP : UTRACE_BLOCKSTEP), p);
	if (!ui)
		return 1;

	put_task_struct(tsk);
	rcu_read_unlock();

        if (debug)
		printk(KERN_INFO "usr_itrace_init: completed for tid = %d\n",
		       tsk->pid);

	return 0;
}

void static remove_usr_itrace_info(struct itrace_info *ui)
{
	struct itrace_info *tmp;
	int status;

	if (!ui)
		return;

	if (debug)
		printk(KERN_INFO "remove_usr_itrace_info: tid=%d\n",
		       (ui->tsk ? ui->tsk->pid : -1));

	if (ui->tsk && ui->engine) {
		status = utrace_control(ui->tsk, ui->engine, UTRACE_DETACH);
		if (status == -EINPROGRESS) {
			do {
				status = utrace_barrier(ui->tsk, ui->engine);
			} while (status == -ERESTARTSYS);
		}
		if (status < 0 && status != -ESRCH && status != -EALREADY)
			printk(KERN_ERR
			       "utrace_control(UTRACE_DETACH) returns %d\n",
			       status);
	}
	spin_lock(&itrace_lock);
	list_del(&ui->link);
	spin_unlock(&itrace_lock);
	_stp_kfree(ui);
}

void static cleanup_usr_itrace(void)
{
	struct itrace_info *tmp;
	struct itrace_info *ui;

	if (debug)
		printk(KERN_INFO "cleanup_usr_itrace called\n");

	list_for_each_entry_safe(ui, tmp, &usr_itrace_info, link) {
		remove_usr_itrace_info(ui);
	}
}


#ifdef CONFIG_PPC
#define PPC_INSTR_SIZE 4
#define TEXT_SEGMENT_BASE 1

/* Instruction masks used during single-stepping of atomic sequences.  */
#define LWARX_MASK 0xfc0007fe
#define LWARX_INSTR 0x7c000028
#define LDARX_INSTR 0x7c0000A8
#define STWCX_MASK 0xfc0007ff
#define STWCX_INSTR 0x7c00012d
#define STDCX_INSTR 0x7c0001ad
#define BC_MASK 0xfc000000
#define BC_INSTR 0x40000000
#define ATOMIC_SEQ_LENGTH 16
#define BPT_TRAP 0x7fe00008
#define INSTR_SZ sizeof(int)

static int get_instr(unsigned long addr, char *msg)
{
	unsigned int instr;

	if (copy_from_user(&instr, (const void __user *) addr,
			sizeof(instr))) {
		printk(KERN_ERR "get_instr failed: %s\n", msg);
		WARN_ON(1);
	}
	return instr;

}

static void insert_atomic_ss_breakpoint (struct task_struct *tsk,
	struct bpt_info *bpt)
{
	unsigned int bp_instr = BPT_TRAP;
	unsigned int cur_instr;

	cur_instr = get_instr(bpt->addr, "insert_atomic_ss_breakpoint");
	if (cur_instr != BPT_TRAP) {
		bpt->instr = cur_instr;
		WARN_ON(__access_process_vm(tsk, bpt->addr, &bp_instr, INSTR_SZ, 1) !=
			INSTR_SZ);
	}
}

static void remove_atomic_ss_breakpoint (struct task_struct *tsk,
	struct bpt_info *bpt)
{
	WARN_ON(__access_process_vm(tsk, bpt->addr, &bpt->instr, INSTR_SZ, 1) !=
		INSTR_SZ);
}

/* locate the branch destination.  Return -1 if not a branch.  */
static unsigned long
branch_dest (int opcode, int instr, struct pt_regs *regs, unsigned long pc)
{
	unsigned long dest;
	int immediate;
	int absolute;
	int ext_op;

	absolute = (int) ((instr >> 1) & 1);

	switch (opcode) {
	case 18:
		immediate = ((instr & ~3) << 6) >> 6;	/* br unconditional */
		if (absolute)
			dest = immediate;
		else
			dest = pc + immediate;
		break;

	case 16:
		immediate = ((instr & ~3) << 16) >> 16;	/* br conditional */
		if (absolute)
			dest = immediate;
		else
			dest = pc + immediate;
		break;

	case 19:
		ext_op = (instr >> 1) & 0x3ff;

		if (ext_op == 16) {
			/* br conditional register */
			dest = regs->link & ~3;
			/* FIX: we might be in a signal handler */
			WARN_ON(dest > 0);
		} else if (ext_op == 528) {
			/* br cond to ctr reg */
			dest = regs->ctr & ~3;

			/* for system call dest < TEXT_SEGMENT_BASE */
			if (dest < TEXT_SEGMENT_BASE)
				dest = regs->link & ~3;
		} else
			return -1;
		break;

	default:
		return -1;
	}
	return dest;
}

/* Checks for an atomic sequence of instructions beginning with a LWARX/LDARX
   instruction and ending with a STWCX/STDCX instruction.  If such a sequence
   is found, attempt to step through it.  A breakpoint is placed at the end of 
   the sequence.  */

static int handle_ppc_atomic_seq(struct task_struct *tsk, struct pt_regs *regs,
	struct atomic_ss_info *ss_info)
{
	unsigned long ip = regs->nip;
	unsigned long start_addr;
	unsigned int instr;
	int got_stx = 0;
	int i;
	int ret;

	unsigned long br_dest; /* bpt at branch instr's destination */
	int bc_instr_count = 0; /* conditional branch instr count  */

	instr = get_instr(regs->nip, "handle_ppc_atomic_seq:1");
	/* Beginning of atomic sequence starts with lwarx/ldarx instr */
	if ((instr & LWARX_MASK) != LWARX_INSTR
		&& (instr & LWARX_MASK) != LDARX_INSTR)
		return 0;

	start_addr = regs->nip;
	for (i = 0; i < ATOMIC_SEQ_LENGTH; ++i) {
		ip += INSTR_SZ;
		instr = get_instr(ip, "handle_ppc_atomic_seq:2");

		/* look for at most one conditional branch in the sequence
		 * and put a bpt at it's destination address
		 */
		if ((instr & BC_MASK) == BC_INSTR) {
			if (bc_instr_count >= 1)
				return 0; /* only handle a single branch */

			br_dest = branch_dest (BC_INSTR >> 26, instr, regs, ip);

			if (br_dest != -1 &&
				br_dest >= TEXT_SEGMENT_BASE) {
				ss_info->br_bpt.addr = br_dest;
				bc_instr_count++;
			}
		}

		if ((instr & STWCX_MASK) == STWCX_INSTR
			|| (instr & STWCX_MASK) == STDCX_INSTR) {
			got_stx = 1;
			break;
		}
	}

	/* Atomic sequence ends with a stwcx/stdcx instr */
	if (!got_stx)
		return 0;

	ip += INSTR_SZ;
	instr = get_instr(ip, "handle_ppc_atomic_seq:3");
	if ((instr & BC_MASK) == BC_INSTR) {
		ip += INSTR_SZ;
		instr = get_instr(ip, "handle_ppc_atomic_seq:4");
	}

	/* Insert a breakpoint right after the end of the atomic sequence.  */
	ss_info->end_bpt.addr = ip;

	/* Check for duplicate bpts */
	if (bc_instr_count && (ss_info->br_bpt.addr >= start_addr &&
		ss_info->br_bpt.addr <= ss_info->end_bpt.addr))
		ss_info->br_bpt.addr = 0;

	insert_atomic_ss_breakpoint (tsk, &ss_info->end_bpt);
	if (ss_info->br_bpt.addr)
		insert_atomic_ss_breakpoint (tsk, &ss_info->br_bpt);

	ss_info->step_over_atomic = 1;
	return 1;
}
#endif
