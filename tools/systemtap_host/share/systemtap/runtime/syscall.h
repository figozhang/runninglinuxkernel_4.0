/*
 * syscall defines and inlines
 * Copyright (C) 2008-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _SYSCALL_H_ /* -*- linux-c -*- */
#define _SYSCALL_H_

#if defined(__i386__) || defined(CONFIG_IA32_EMULATION)
#define __MMAP_SYSCALL_NO_IA32		90
#define __MMAP2_SYSCALL_NO_IA32		192
#define __MPROTECT_SYSCALL_NO_IA32	125
#define __MUNMAP_SYSCALL_NO_IA32	91
#define __MREMAP_SYSCALL_NO_IA32	163
# if !defined(CONFIG_IA32_EMULATION)
#define MMAP_SYSCALL_NO(tsk) __MMAP_SYSCALL_NO_IA32
#define MMAP2_SYSCALL_NO(tsk) __MMAP2_SYSCALL_NO_IA32
#define MPROTECT_SYSCALL_NO(tsk) __MPROTECT_SYSCALL_NO_IA32
#define MUNMAP_SYSCALL_NO(tsk) __MUNMAP_SYSCALL_NO_IA32
#define MREMAP_SYSCALL_NO(tsk) __MREMAP_SYSCALL_NO_IA32
# endif
#endif

#if defined(__x86_64__)
#define __MMAP_SYSCALL_NO_X86_64	9
/* x86_64 doesn't have a mmap2 system call.  So, we'll use a number
 * that doesn't map to a real system call. */
#define __MMAP2_SYSCALL_NO_X86_64	((unsigned long)-1)
#define __MPROTECT_SYSCALL_NO_X86_64	10
#define __MUNMAP_SYSCALL_NO_X86_64	11
#define __MREMAP_SYSCALL_NO_X86_64	25
# if defined(CONFIG_IA32_EMULATION)
#define MMAP_SYSCALL_NO(tsk) ((test_tsk_thread_flag((tsk), TIF_IA32))	\
			      ? __MMAP_SYSCALL_NO_IA32			\
			      : __MMAP_SYSCALL_NO_X86_64)
#define MMAP2_SYSCALL_NO(tsk) ((test_tsk_thread_flag((tsk), TIF_IA32))	\
			       ? __MMAP2_SYSCALL_NO_IA32		\
			       : __MMAP2_SYSCALL_NO_X86_64)
#define MPROTECT_SYSCALL_NO(tsk) ((test_tsk_thread_flag((tsk), TIF_IA32)) \
				  ? __MPROTECT_SYSCALL_NO_IA32		\
				  : __MPROTECT_SYSCALL_NO_X86_64)
#define MUNMAP_SYSCALL_NO(tsk) ((test_tsk_thread_flag((tsk), TIF_IA32)) \
				  ? __MUNMAP_SYSCALL_NO_IA32		\
				  : __MUNMAP_SYSCALL_NO_X86_64)
#define MREMAP_SYSCALL_NO(tsk) ((test_tsk_thread_flag((tsk), TIF_IA32)) \
				  ? __MREMAP_SYSCALL_NO_IA32		\
				  : __MREMAP_SYSCALL_NO_X86_64)
# else
#define MMAP_SYSCALL_NO(tsk) __MMAP_SYSCALL_NO_X86_64
#define MMAP2_SYSCALL_NO(tsk) __MMAP2_SYSCALL_NO_X86_64
#define MPROTECT_SYSCALL_NO(tsk) __MPROTECT_SYSCALL_NO_X86_64
#define MUNMAP_SYSCALL_NO(tsk) __MUNMAP_SYSCALL_NO_X86_64
#define MREMAP_SYSCALL_NO(tsk) __MREMAP_SYSCALL_NO_X86_64
# endif
#endif

#if defined(__powerpc__)
#define MMAP_SYSCALL_NO(tsk)		90
/* MMAP2 only exists on a 32-bit kernel.  On a 64-bit kernel, we'll
 * never see mmap2 (but that's OK). */
#define MMAP2_SYSCALL_NO(tsk)		192
#define MPROTECT_SYSCALL_NO(tsk)	125
#define MUNMAP_SYSCALL_NO(tsk)		91
#define MREMAP_SYSCALL_NO(tsk)		163
#endif

#if defined(__ia64__)
#define MMAP_SYSCALL_NO(tsk)		1151
#define MMAP2_SYSCALL_NO(tsk)		1172
#define MPROTECT_SYSCALL_NO(tsk)	1155
#define MUNMAP_SYSCALL_NO(tsk)		1152
#define MREMAP_SYSCALL_NO(tsk)		1156
#endif

#if defined(__s390__) || defined(__s390x__)
#define MMAP_SYSCALL_NO(tsk)		90
#define MMAP2_SYSCALL_NO(tsk)		192
#define MPROTECT_SYSCALL_NO(tsk)	125
#define MUNMAP_SYSCALL_NO(tsk)		91
#define MREMAP_SYSCALL_NO(tsk)		163
#endif

#if defined(__arm__)
#define MMAP_SYSCALL_NO(tsk)		90
#define MMAP2_SYSCALL_NO(tsk)		192
#define MPROTECT_SYSCALL_NO(tsk)	125
#define MUNMAP_SYSCALL_NO(tsk)		91
#define MREMAP_SYSCALL_NO(tsk)		163
#endif

#if defined(__aarch64__)
#define MMAP_SYSCALL_NO(tsk)		222
#define MMAP2_SYSCALL_NO(tsk)		222
#define MPROTECT_SYSCALL_NO(tsk)	226
#define MUNMAP_SYSCALL_NO(tsk)		215
#define MREMAP_SYSCALL_NO(tsk)		216
#endif

#if !defined(MMAP_SYSCALL_NO) || !defined(MMAP2_SYSCALL_NO)		\
	|| !defined(MPROTECT_SYSCALL_NO) || !defined(MUNMAP_SYSCALL_NO)	\
	|| !defined(MREMAP_SYSCALL_NO)
#error "Unimplemented architecture"
#endif

#ifdef STAPCONF_ASM_SYSCALL_H

/* If the system has asm/syscall.h, use defines from it. */
#include <asm/syscall.h>

#if defined(__arm__)
/* The syscall_get_nr() function on 3.17.1-302.fc21.armv7hl always
 * returns 0 (since it was designed to be used with ftrace syscall
 * tracing, not called from any context). So, let's use our function
 * instead. */
static inline long
_stp_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->ARM_r7;
}
#else
#define _stp_syscall_get_nr syscall_get_nr
#endif

#else  /* !STAPCONF_ASM_SYSCALL_H */

/* If the system doesn't have asm/syscall.h, use our defines. */
#if defined(__i386__) || defined(__x86_64__)
static inline long
_stp_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
#if defined(STAPCONF_X86_UNIREGS)
	return regs->orig_ax;
#elif defined(__x86_64__)
	return regs->orig_rax;
#elif defined (__i386__)
	return regs->orig_eax;
#endif
}
#endif

#if defined(__powerpc__)
static inline long
_stp_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->gpr[0];
}
#endif

#if defined(__ia64__)
static inline long
_stp_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	if ((long)regs->cr_ifs < 0) /* Not a syscall */
		return -1;

#ifdef CONFIG_IA32_SUPPORT
	if (IS_IA32_PROCESS(regs))
		return regs->r1;
#endif

	return regs->r15;
}
#endif

#if defined(__s390__) || defined(__s390x__)
static inline long
_stp_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	// might need to be 'orig_gpr2'
	return regs->gprs[2];
}
#endif

#if defined(__aarch64__)
static inline long
_stp_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->syscallno;
}
#endif

#if defined(__arm__)
static inline long
_stp_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->ARM_r7;
}
#endif

#if defined(__i386__) || defined(__x86_64__)
static inline long
syscall_get_return_value(struct task_struct *task, struct pt_regs *regs)
{
#ifdef CONFIG_IA32_EMULATION
// This code works, but isn't what we need.  Since
// syscall_get_syscall_arg() doesn't sign-extend, a value passed in as
// an argument and then returned won't compare correctly anymore.  So,
// for now, disable this code.
# if 0
	if (test_tsk_thread_flag(task, TIF_IA32))
		// Sign-extend the value so (int)-EFOO becomes (long)-EFOO
		// and will match correctly in comparisons.
		regs->ax = (long) (int) regs->ax;
# endif
#endif
#if defined(STAPCONF_X86_UNIREGS)
	return regs->ax;
#elif defined(__x86_64__)
	return regs->rax;
#elif defined (__i386__)
	return regs->eax;
#endif
}
#endif

#if defined(__powerpc__)
static inline long
syscall_get_return_value(struct task_struct *task, struct pt_regs *regs)
{
	return regs->gpr[3];
} 
#endif

#if defined(__ia64__)
static inline long
syscall_get_return_value(struct task_struct *task, struct pt_regs *regs)
{
	return regs->r8;
}
#endif

#if defined(__s390__) || defined(__s390x__)
static inline long
syscall_get_return_value(struct task_struct *task, struct pt_regs *regs)
{
	return regs->gprs[2];
}
#endif

#if defined(__arm__)
static inline long
syscall_get_return_value(struct task_struct *task, struct pt_regs *regs)
{
	return regs->ARM_r0;
}

#endif
#if defined(__i386__) || defined(__x86_64__)
static inline void
syscall_get_arguments(struct task_struct *task, struct pt_regs *regs,
		      unsigned int i, unsigned int n, unsigned long *args)
{
	if (i + n > 6) {
		_stp_error("invalid syscall arg request");
		return;
	}
#if defined(__i386__)
#if defined(STAPCONF_X86_UNIREGS)
	memcpy(args, &regs->bx + i, n * sizeof(args[0]));
#else
	memcpy(args, &regs->ebx + i, n * sizeof(args[0]));
#endif
#elif defined(__x86_64__)
#ifdef CONFIG_IA32_EMULATION
	if (test_tsk_thread_flag(task, TIF_IA32)) {
		switch (i) {
#if defined(STAPCONF_X86_UNIREGS)
		case 0:
			if (!n--) break;
			*args++ = regs->bx;
		case 1:
			if (!n--) break;
			*args++ = regs->cx;
		case 2:
			if (!n--) break;
			*args++ = regs->dx;
		case 3:
			if (!n--) break;
			*args++ = regs->si;
		case 4:
			if (!n--) break;
			*args++ = regs->di;
		case 5:
			if (!n--) break;
			*args++ = regs->bp;
#else
		case 0:
			if (!n--) break;
			*args++ = regs->rbx;
		case 1:
			if (!n--) break;
			*args++ = regs->rcx;
		case 2:
			if (!n--) break;
			*args++ = regs->rdx;
		case 3:
			if (!n--) break;
			*args++ = regs->rsi;
		case 4:
			if (!n--) break;
			*args++ = regs->rdi;
		case 5:
			if (!n--) break;
			*args++ = regs->rbp;
#endif
		}
		return;
	}
#endif /* CONFIG_IA32_EMULATION */
	switch (i) {
#if defined(STAPCONF_X86_UNIREGS)
	case 0:
		if (!n--) break;
		*args++ = regs->di;
	case 1:
		if (!n--) break;
		*args++ = regs->si;
	case 2:
		if (!n--) break;
		*args++ = regs->dx;
	case 3:
		if (!n--) break;
		*args++ = regs->r10;
	case 4:
		if (!n--) break;
		*args++ = regs->r8;
	case 5:
		if (!n--) break;
		*args++ = regs->r9;
#else
	case 0:
		if (!n--) break;
		*args++ = regs->rdi;
	case 1:
		if (!n--) break;
		*args++ = regs->rsi;
	case 2:
		if (!n--) break;
		*args++ = regs->rdx;
	case 3:
		if (!n--) break;
		*args++ = regs->r10;
	case 4:
		if (!n--) break;
		*args++ = regs->r8;
	case 5:
		if (!n--) break;
		*args++ = regs->r9;
#endif
	}
#endif /* CONFIG_X86_32 */
	return;
}
#endif

#if defined(__powerpc__)
static inline void
syscall_get_arguments(struct task_struct *task, struct pt_regs *regs,
		      unsigned int i, unsigned int n, unsigned long *args)
{
	if (i + n > 6) {
		_stp_error("invalid syscall arg request");
		return;
	}
#ifdef CONFIG_PPC64
	if (test_tsk_thread_flag(task, TIF_32BIT)) {
		/*
		 * Zero-extend 32-bit argument values.  The high bits are
		 * garbage ignored by the actual syscall dispatch.
		 */
		while (n-- > 0)
			args[n] = (u32) regs->gpr[3 + i + n];
		return;
	}
#endif
	memcpy(args, &regs->gpr[3 + i], n * sizeof(args[0]));
}
#endif

#if defined(__ia64__)

/* Return TRUE if PT was created due to kernel-entry via a system-call.  */

static inline int
in_syscall (struct pt_regs *pt)
{
	return (long) pt->cr_ifs >= 0;
}

struct syscall_get_set_args {
	unsigned int i;
	unsigned int n;
	unsigned long *args;
	struct pt_regs *regs;
	int rw;
};

#define CFM_SOF(cfm) ((cfm) & 0x7f)			/* Size of frame */
#define CFM_SOL(cfm) (((cfm) >> 7) & 0x7f)		/* Size of locals */
#define CFM_OUT(cfm) (CFM_SOF(cfm) - CFM_SOL(cfm))	/* Size of outputs */

static void syscall_get_set_args_cb(struct unw_frame_info *info, void *data)
{
	struct syscall_get_set_args *args = data;
	struct pt_regs *pt = args->regs;
	unsigned long *krbs, cfm, ndirty;
	int i, count;

	if (unw_unwind_to_user(info) < 0)
		return;

	cfm = pt->cr_ifs;
	krbs = (unsigned long *)info->task + IA64_RBS_OFFSET/8;
	ndirty = ia64_rse_num_regs(krbs, krbs + (pt->loadrs >> 19));

	count = 0;
	if (in_syscall(pt))
		/* args->i + args->n must be less equal than nr outputs */
		count = min_t(int, args->n, CFM_OUT(cfm) - args->i);

	for (i = 0; i < count; i++) {
		/* Skips dirties and locals */
		if (args->rw)
			*ia64_rse_skip_regs(krbs,
				ndirty + CFM_SOL(cfm) + args->i + i) =
				args->args[i];
		else
			args->args[i] = *ia64_rse_skip_regs(krbs,
				ndirty + CFM_SOL(cfm) + args->i + i);
	}

	if (!args->rw) {
		while (i < args->n) {
			args->args[i] = 0;
			i++;
		}
	}
}

void ia64_syscall_get_set_arguments(struct task_struct *task,
	struct pt_regs *regs, unsigned int i, unsigned int n,
	unsigned long *args, int rw)
{
	struct syscall_get_set_args data = {
		.i = i,
		.n = n,
		.args = args,
		.regs = regs,
		.rw = rw,
	};

	if (task == current)
		unw_init_running(syscall_get_set_args_cb, &data);
	else {
		struct unw_frame_info ufi;
		memset(&ufi, 0, sizeof(ufi));
		unw_init_from_blocked_task(&ufi, task);
		syscall_get_set_args_cb(&ufi, &data);
	}
}

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
	BUG_ON(i + n > 6);

#ifdef CONFIG_IA32_SUPPORT
	if (IS_IA32_PROCESS(regs)) {
		switch (i + n) {
		case 6:
			if (!n--) break;
			*args++ = regs->r13;
		case 5:
			if (!n--) break;
			*args++ = regs->r15;
		case 4:
			if (!n--) break;
			*args++ = regs->r14;
		case 3:
			if (!n--) break;
			*args++ = regs->r10;
		case 2:
			if (!n--) break;
			*args++ = regs->r9;
		case 1:
			if (!n--) break;
			*args++ = regs->r11;
		case 0:
			if (!n--) break;
		default:
			BUG();
			break;
		}

		return;
	}
#endif
	ia64_syscall_get_set_arguments(task, regs, i, n, args, 0);
}
#endif

#if defined(__s390__) || defined(__s390x__)
static inline void
syscall_get_arguments(struct task_struct *task, struct pt_regs *regs,
		      unsigned int i, unsigned int n, unsigned long *args)
{
	unsigned long mask = -1UL;

	if (i + n > 6) {
		_stp_error("invalid syscall arg request");
		return;
	}
#ifdef CONFIG_COMPAT
	if (test_tsk_thread_flag(task, TIF_31BIT))
		mask = 0xffffffff;
#endif
	switch (i) {
	case 0:
		if (!n--) break;
		*args++ = regs->orig_gpr2 & mask;
	case 1:
		if (!n--) break;
		*args++ = regs->gprs[3] & mask;
	case 2:
		if (!n--) break;
		*args++ = regs->gprs[4] & mask;
	case 3:
		if (!n--) break;
		*args++ = regs->gprs[5] & mask;
	case 4:
		if (!n--) break;
		*args++ = regs->gprs[6] & mask;
	case 5:
		if (!n--) break;
		*args++ = regs->args[0] & mask;
	}
}
#endif

#if defined(__arm__)
static inline void
syscall_get_arguments(struct task_struct *task, struct pt_regs *regs,
		      unsigned int i, unsigned int n, unsigned long *args)
{
	if (i + n > 6) {
		_stp_error("invalid syscall arg request");
		return;
	}

	memcpy(args, &regs->uregs[i], n * sizeof(args[0]));
}
#endif

#endif /* !STAPCONF_ASM_SYSCALL_H */
#endif /* _SYSCALL_H_ */
