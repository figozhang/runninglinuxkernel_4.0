/* -*- linux-c -*-
 *
 * ARM dwarf unwinder header file
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_ARM64_UNWIND_H
#define _STP_ARM64_UNWIND_H

#include <linux/sched.h>
#include <asm/ptrace.h>

#define _stp_get_unaligned(ptr) (*(ptr))

#define UNW_PC(frame)        (frame)->regs.pc
#define UNW_SP(frame)        (frame)->regs.sp

#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

#define UNW_REGISTER_INFO \
	PTREGS_INFO(regs[0]), \
	PTREGS_INFO(regs[1]), \
	PTREGS_INFO(regs[2]), \
	PTREGS_INFO(regs[3]), \
	PTREGS_INFO(regs[4]), \
	PTREGS_INFO(regs[5]), \
	PTREGS_INFO(regs[6]), \
	PTREGS_INFO(regs[7]), \
	PTREGS_INFO(regs[8]), \
	PTREGS_INFO(regs[9]), \
	PTREGS_INFO(regs[10]), \
	PTREGS_INFO(regs[11]), \
	PTREGS_INFO(regs[12]), \
	PTREGS_INFO(regs[13]), \
	PTREGS_INFO(regs[14]), \
	PTREGS_INFO(regs[15]), \
	PTREGS_INFO(regs[16]), \
	PTREGS_INFO(regs[17]), \
	PTREGS_INFO(regs[18]), \
	PTREGS_INFO(regs[19]), \
	PTREGS_INFO(regs[20]), \
	PTREGS_INFO(regs[21]), \
	PTREGS_INFO(regs[22]), \
	PTREGS_INFO(regs[23]), \
	PTREGS_INFO(regs[24]), \
	PTREGS_INFO(regs[25]), \
	PTREGS_INFO(regs[26]), \
	PTREGS_INFO(regs[27]), \
	PTREGS_INFO(regs[28]), \
	PTREGS_INFO(regs[29]), \
	PTREGS_INFO(regs[30]), \
	PTREGS_INFO(sp), \
	PTREGS_INFO(pc) \

#define DWARF_REG_MAP(r) \
        ((r >= 0 && r <= 31) ? r /* regs[0-30] + sp */	\
         : 9999)

#define UNW_PC_IDX 32
#define UNW_SP_IDX 31

/* Use default rules. The stack pointer should be set from the CFA.
   And the instruction pointer should be set from the return address
   column (which normally is the link register (regs[30]). */

static inline void arch_unw_init_frame_info(struct unwind_frame_info *info,
                                            /*const*/ struct pt_regs *regs,
					    int sanitize)
{
	/* FIXME The synthetic generation of pt_regs information does not work. */
	if (regs == NULL) {
	    asm("1:\n\t"
		"stp x0, x1, [%2, #0]\n\t"
		"stp x2, x3, [%2, #16]\n\t"
		"stp x4, x5, [%2, #32]\n\t"
		"stp x6, x7, [%2, #48]\n\t"
		"stp x8, x9, [%2, #64]\n\t"
		"stp x10, x11, [%2, #80]\n\t"
		"stp x12, x13, [%2, #96]\n\t"
		"stp x14, x15, [%2, #112]\n\t"
		"stp x16, x17, [%2, #128]\n\t"
		"stp x18, x19, [%2, #144]\n\t"
		"stp x20, x21, [%2, #160]\n\t"
		"stp x22, x23, [%2, #176]\n\t"
		"stp x24, x25, [%2, #192]\n\t"
		"stp x26, x27, [%2, #208]\n\t"
		"stp x29, x30, [%2, #224]\n\t"
		"mov sp, x16\n\t"
		"str x16, [%2, #240]\n\t"
		"adr x17, 1b\n\t"
		"str x17, [%1, #240]\n\t"
		"ldp x16, x17, [%2, #128]\n\t"
		: "=m" (info->regs),
		  "=r" (info->regs.pc)
		: "r" (&info->regs)
		);
	    return;
	}

	if (&info->regs == regs) { /* happens when unwinding kernel->user */
		info->call_frame = 1;
		return;
	}

	memset(info, 0, sizeof(*info));
	info->regs = *regs;
}

#endif /* _STP_ARM64_UNWIND_H */
