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
#ifndef _STP_ARM_UNWIND_H
#define _STP_ARM_UNWIND_H

#include <linux/sched.h>
#include <asm/ptrace.h>

#define _stp_get_unaligned(ptr) (*(ptr))

#define UNW_PC(frame)        (frame)->regs.ARM_pc /* uregs[15] */
#define UNW_SP(frame)        (frame)->regs.ARM_sp /* uregs[13] */

#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

#define UNW_REGISTER_INFO \
	PTREGS_INFO(uregs[0]), \
	PTREGS_INFO(uregs[1]), \
	PTREGS_INFO(uregs[2]), \
	PTREGS_INFO(uregs[3]), \
	PTREGS_INFO(uregs[4]), \
	PTREGS_INFO(uregs[5]), \
	PTREGS_INFO(uregs[6]), \
	PTREGS_INFO(uregs[7]), \
	PTREGS_INFO(uregs[8]), \
	PTREGS_INFO(uregs[9]), \
	PTREGS_INFO(uregs[10]), \
	PTREGS_INFO(uregs[11]), \
	PTREGS_INFO(uregs[12]), \
	PTREGS_INFO(uregs[13]), \
	PTREGS_INFO(uregs[14]), \
	PTREGS_INFO(uregs[15]) \

#define DWARF_REG_MAP(r) \
        ((r >= 0 && r <= 15) ? r /* uregs[0-15] */	\
         : 9999)

#define UNW_PC_IDX 15
#define UNW_SP_IDX 13

/* Use default rules. The stack pointer should be set from the CFA.
   And the instruction pointer should be set from the return address
   column (which normally is the link register (uregs[14]). */

static inline void arch_unw_init_frame_info(struct unwind_frame_info *info,
                                            /*const*/ struct pt_regs *regs,
					    int sanitize)
{
	if (&info->regs == regs) { /* happens when unwinding kernel->user */
		info->call_frame = 1;
		return;
	}

	memset(info, 0, sizeof(*info));
	/* XXX handle sanitize??? */
	info->regs = *regs;
}

#endif /* _STP_ARM_UNWIND_H */
