/* -*- linux-c -*-
 *
 * x86_64 dwarf unwinder header file
 * Copyright (C) 2008, 2010, 2011, 2014 Red Hat Inc.
 * Copyright (C) 2002-2006 Novell, Inc.
 * 
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_X86_64_UNWIND_H
#define _STP_X86_64_UNWIND_H

/*
 * Copyright (C) 2002-2006 Novell, Inc.
 *	Jan Beulich <jbeulich@novell.com>
 * This code is released under version 2 of the GNU GPL.
 */

#include <linux/sched.h>
#include <asm/ptrace.h>

/* these are simple for x86_64 */
#define _stp_get_unaligned(ptr) (*(ptr))

#ifdef STAPCONF_X86_UNIREGS
#define UNW_PC(frame)        (frame)->regs.ip
#define UNW_SP(frame)        (frame)->regs.sp
#else
#define UNW_PC(frame)        (frame)->regs.rip
#define UNW_SP(frame)        (frame)->regs.rsp
#endif /* STAPCONF_X86_UNIREGS */

/* Might need to account for the special exception and interrupt handling
   stacks here, since normally
	EXCEPTION_STACK_ORDER < THREAD_ORDER < IRQSTACK_ORDER,
   but the construct is needed only for getting across the stack switch to
   the interrupt stack - thus considering the IRQ stack itself is unnecessary,
   and the overhead of comparing against all exception handling stacks seems
   not desirable. */
#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

#ifdef STAPCONF_X86_UNIREGS
#define UNW_REGISTER_INFO \
	PTREGS_INFO(ax), \
	PTREGS_INFO(dx), \
	PTREGS_INFO(cx), \
	PTREGS_INFO(bx), \
	PTREGS_INFO(si), \
	PTREGS_INFO(di), \
	PTREGS_INFO(bp), \
	PTREGS_INFO(sp), \
	PTREGS_INFO(r8), \
	PTREGS_INFO(r9), \
	PTREGS_INFO(r10), \
	PTREGS_INFO(r11), \
	PTREGS_INFO(r12), \
	PTREGS_INFO(r13), \
	PTREGS_INFO(r14), \
	PTREGS_INFO(r15), \
	PTREGS_INFO(ip)	/* Note, placeholder for "fake" dwarf ret reg. */
#else
#define UNW_REGISTER_INFO \
	PTREGS_INFO(rax), \
	PTREGS_INFO(rdx), \
	PTREGS_INFO(rcx), \
	PTREGS_INFO(rbx), \
	PTREGS_INFO(rsi), \
	PTREGS_INFO(rdi), \
	PTREGS_INFO(rbp), \
	PTREGS_INFO(rsp), \
	PTREGS_INFO(r8), \
	PTREGS_INFO(r9), \
	PTREGS_INFO(r10), \
	PTREGS_INFO(r11), \
	PTREGS_INFO(r12), \
	PTREGS_INFO(r13), \
	PTREGS_INFO(r14), \
	PTREGS_INFO(r15), \
	PTREGS_INFO(rip) /* Note, placeholder for "fake" dwarf ret reg. */
#endif /* STAPCONF_X86_UNIREGS */

/* DWARF registers are ordered differently on 32-bit architectures*/
#define COMPAT_REG_MAP(r)					\
        ((r >= 9 && r <= 16) ? r /* r9 - r15  && ip/rip  */	\
         : (r == 0) ? r /* ax/rax */				\
         : (r == 1) ? 2 /* dx/rdx */				\
         : (r == 2) ? 1 /* cx/rcx */				\
         : (r == 3) ? r /* bx/rbx */				\
         : (r == 4) ? 7 /* sp/rsp */				\
         : (r == 5) ? 6 /* bp/rpp */				\
         : (r == 6) ? 4 /* si/rsi */				\
         : (r == 7) ? 5 /* di/rdi */				\
         : (r == 8) ? 16 /* ip/rip */				\
         : 9999)

#define UNW_PC_IDX 16
#define UNW_SP_IDX 7

#define UNW_NR_REAL_REGS 16
#define UNW_PC_FROM_RA 0 /* Because rip == return address column already. */

static inline void arch_unw_init_frame_info(struct unwind_frame_info *info,
                                            /*const*/ struct pt_regs *regs,
					    int sanitize)
{
        if(regs == NULL){
		/* NB: This uses an "=m" output constraint to indicate we're
		 * writing all of info->regs, but then uses an "r" input
		 * pointer for the actual writes.  This is to be sure we have
		 * something we can offset properly.  */
		asm("lea (%%rip), %1 \n\t"
		    "mov %%r15,   0(%2) \n\t"
		    "mov %%r14,   8(%2) \n\t"
		    "mov %%r13,  16(%2) \n\t"
		    "mov %%r12,  24(%2) \n\t"
		    "mov %%rbp,  32(%2) \n\t"
		    "mov %%rbx,  40(%2) \n\t"
		    "mov %%r11,  48(%2) \n\t"
		    "mov %%r10,  56(%2) \n\t"
		    "mov %%r9,   64(%2) \n\t"
		    "mov %%r8,   72(%2) \n\t"
		    "mov %%rax,  80(%2) \n\t"
		    "mov %%rcx,  88(%2) \n\t"
		    "mov %%rdx,  96(%2) \n\t"
		    "mov %%rsi, 104(%2) \n\t"
		    "mov %%rdi, 112(%2) \n\t"
		    /* "mov %%orig_rax, 120(%2) \n\t" */
		    /* "mov %%rip, 128(%2) \n\t" */
		    "mov %%cs, 136(%2) \n\t"
		    /* "mov %%eflags, 144(%2) \n\t" */
		    "mov %%rsp, 152(%2) \n\t"
		    "mov %%ss, 160(%2) \n\t"
		    : "=m" (info->regs),
#ifdef STAPCONF_X86_UNIREGS
		      "=r" (info->regs.ip)
#else
		      "=r" (info->regs.rip)
#endif /* STAPCONF_X86_UNIREGS */
		    : "r" (&info->regs)
		    );
	        return;
        }

	if (&info->regs == regs) { /* happens when unwinding kernel->user */
		info->call_frame = 1;
		return;
	}

	memset(info, 0, sizeof(*info));
	if (sanitize) {
		info->regs.r11 = regs->r11;
		info->regs.r10 = regs->r10;
		info->regs.r9 = regs->r9;
		info->regs.r8 = regs->r8;
#ifdef STAPCONF_X86_UNIREGS
		info->regs.ax = regs->ax;
		info->regs.cx = regs->cx;
		info->regs.dx = regs->dx;
		info->regs.si = regs->si;
		info->regs.di = regs->di;
		info->regs.orig_ax = regs->orig_ax;
		info->regs.ip = regs->ip;
		info->regs.flags = regs->flags;
		info->regs.sp = regs->sp;
#else
		info->regs.rax = regs->rax;
		info->regs.rcx = regs->rcx;
		info->regs.rdx = regs->rdx;
		info->regs.rsi = regs->rsi;
		info->regs.rdi = regs->rdi;
		info->regs.orig_rax = regs->orig_rax;
		info->regs.rip = regs->rip;
		info->regs.eflags = regs->eflags;
		info->regs.rsp = regs->rsp;
#endif
		info->regs.cs = regs->cs;
		info->regs.ss = regs->ss;
	} else {
		info->regs = *regs;
	}
}

#endif /* _STP_X86_64_UNWIND_H */
