/* -*- linux-c -*-
 *
 * 32-bit x86 dwarf unwinder header file
 * Copyright (C) 2008, 2010, 2014 Red Hat Inc.
 * Copyright (C) 2002-2006 Novell, Inc.
 * 
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_I386_UNWIND_H
#define _STP_I386_UNWIND_H

#include <linux/sched.h>
#include <asm/fixmap.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>

/* these are simple for i386 */
#define _stp_get_unaligned(ptr) (*(ptr))

#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

#ifdef STAPCONF_X86_UNIREGS

#define UNW_PC(frame)        (frame)->regs.ip
#define UNW_SP(frame)        (frame)->regs.sp

#define UNW_REGISTER_INFO \
	PTREGS_INFO(ax), \
	PTREGS_INFO(cx), \
	PTREGS_INFO(dx), \
	PTREGS_INFO(bx), \
	PTREGS_INFO(sp), \
	PTREGS_INFO(bp), \
	PTREGS_INFO(si), \
	PTREGS_INFO(di), \
	PTREGS_INFO(ip) /* Note, placeholder for "fake" dwarf ret reg. */

#else /* !STAPCONF_X86_UNIREGS */

#define UNW_PC(frame)        (frame)->regs.eip
#define UNW_SP(frame)        (frame)->regs.esp

#define UNW_REGISTER_INFO \
	PTREGS_INFO(eax), \
	PTREGS_INFO(ecx), \
	PTREGS_INFO(edx), \
	PTREGS_INFO(ebx), \
	PTREGS_INFO(esp), \
	PTREGS_INFO(ebp), \
	PTREGS_INFO(esi), \
	PTREGS_INFO(edi), \
	PTREGS_INFO(eip) /* Note, placeholder for "fake" dwarf ret reg. */

#endif /* STAPCONF_X86_UNIREGS */

#define UNW_PC_IDX 8
#define UNW_SP_IDX 4

#define UNW_NR_REAL_REGS 8
#define UNW_PC_FROM_RA 0 /* Because [e]ip == return address column already. */


/* 2.6.9-era compatibility */
#ifndef user_mode_vm
#define user_mode_vm(regs)  user_mode(regs)
#endif

static inline void arch_unw_init_frame_info(struct unwind_frame_info *info,
                                            /*const*/ struct pt_regs *regs,
					    int sanitize)
{
        if (!regs) {
		/* NB: This uses an "=m" output constraint to indicate we're
		 * writing all of info->regs, but then uses an "r" input
		 * pointer for the actual writes.  This is to be sure we have
		 * something we can offset properly.
		 * NB2: kernel pt_regs haven't always included fs and gs, which
		 * means the offsets of the fields after have changed over
		 * time.  We'll reconvene at orig_eax to fill the end.  */
		asm("movl $1f, %1; 1: \n\t"
		    "mov %%ebx, 0(%2) \n\t"
		    "mov %%ecx, 4(%2) \n\t"
		    "mov %%edx, 8(%2) \n\t"
		    "mov %%esi, 12(%2) \n\t"
		    "mov %%edi, 16(%2) \n\t"
		    "mov %%ebp, 20(%2) \n\t"
		    "mov %%eax, 24(%2) \n\t"
		    "mov %%ds, 28(%2) \n\t"
		    "mov %%es, 32(%2) \n\t"
#if defined(STAPCONF_X86_XFS) || defined (STAPCONF_X86_FS)
		    "mov %%fs, 36(%2) \n\t"
#endif
#ifdef STAPCONF_X86_GS
		    "mov %%gs, 40(%2) \n\t"
#endif
		    /* "mov %%orig_eax, 0(%3) \n\t" */
		    /* "mov %%eip, 4(%3) \n\t" */
		    "mov %%cs, 8(%3) \n\t"
		    /* "mov %%eflags, 12(%3) \n\t" */
		    "mov %%esp, 16(%3) \n\t"
		    "mov %%ss, 20(%3) \n\t"
		    : "=m" (info->regs),
#ifdef STAPCONF_X86_UNIREGS
		      "=m" (info->regs.ip)
#else
		      "=m" (info->regs.eip)
#endif /* STAPCONF_X86_UNIREGS */
		    : "r"(&info->regs),
#ifdef STAPCONF_X86_UNIREGS
		      "r" (&info->regs.orig_ax)
#else
		      "r" (&info->regs.orig_eax)
#endif /* STAPCONF_X86_UNIREGS */
		    );

		return;
	}

	if (&info->regs == regs) { /* happens when unwinding kernel->user */
		info->call_frame = 1;
		return;
	}

	memset(info, 0, sizeof(*info));
	if (sanitize) /* We are only prepared to use full reg sets. */
		_stp_error("Impossible to sanitize i386 pr_regs");

	if (user_mode_vm(regs))
		info->regs = *regs;
	else {
#ifdef STAPCONF_X86_UNIREGS
		memcpy(&info->regs, regs, offsetof(struct pt_regs, sp));
		info->regs.sp = (unsigned long)&regs->sp;
		info->regs.ss = __KERNEL_DS;
#else
		memcpy(&info->regs, regs, offsetof(struct pt_regs, esp));
		info->regs.esp = (unsigned long)&regs->esp;
		info->regs.xss = __KERNEL_DS;		
#endif
		
	}
}

#endif /* _STP_I386_UNWIND_H */
