/* -*- linux-c -*-
 *
 * ppc64 dwarf unwinder header file
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_PPC64_UNWIND_H
#define _STP_PPC64_UNWIND_H

#include <linux/sched.h>
#include <asm/ptrace.h>

#define _stp_get_unaligned(ptr) (*(ptr))

#define UNW_PC(frame)        (frame)->regs.nip
#define UNW_SP(frame)        (frame)->regs.gpr[1]

#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

#define UNW_REGISTER_INFO \
	PTREGS_INFO(gpr[0]), \
	PTREGS_INFO(gpr[1]), \
	PTREGS_INFO(gpr[2]), \
	PTREGS_INFO(gpr[3]), \
	PTREGS_INFO(gpr[4]), \
	PTREGS_INFO(gpr[5]), \
	PTREGS_INFO(gpr[6]), \
	PTREGS_INFO(gpr[7]), \
	PTREGS_INFO(gpr[8]), \
	PTREGS_INFO(gpr[9]), \
	PTREGS_INFO(gpr[10]), \
	PTREGS_INFO(gpr[11]), \
	PTREGS_INFO(gpr[12]), \
	PTREGS_INFO(gpr[13]), \
	PTREGS_INFO(gpr[14]), \
	PTREGS_INFO(gpr[15]), \
	PTREGS_INFO(gpr[16]), \
	PTREGS_INFO(gpr[17]), \
	PTREGS_INFO(gpr[18]), \
	PTREGS_INFO(gpr[19]), \
	PTREGS_INFO(gpr[20]), \
	PTREGS_INFO(gpr[21]), \
	PTREGS_INFO(gpr[22]), \
	PTREGS_INFO(gpr[23]), \
	PTREGS_INFO(gpr[24]), \
	PTREGS_INFO(gpr[25]), \
	PTREGS_INFO(gpr[26]), \
	PTREGS_INFO(gpr[27]), \
	PTREGS_INFO(gpr[28]), \
	PTREGS_INFO(gpr[29]), \
	PTREGS_INFO(gpr[30]), \
	PTREGS_INFO(gpr[31]), \
	PTREGS_INFO(softe), \
	PTREGS_INFO(ctr), \
	PTREGS_INFO(link), \
	PTREGS_INFO(nip)

/* These are slightly strange since they don't really use dwarf register
   mappings, but gcc internal register numbers. There is some confusion about
   the numbering see http://gcc.gnu.org/ml/gcc/2004-01/msg00025.html
   We just handle the 32 fixed point registers, mq, count and link and
   ignore status registers, floating point, vectors and special registers
   (most of which aren't available in pt_regs anyway). Also we placed nip
   last since we use that as UNW_PC register and it needs to be filled in.
   Note that we handle both the .eh_frame and .debug_frame numbering at
   the same time. There is potential overlap though. 64 maps to cr in one
   and mq in the other...
   Everything else is mapped to an invalid register number 9999. */
#define DWARF_REG_MAP(r) \
        ((r >= 0 && r <= 31) ? r /* r0 - r31 */			\
         : (r == 64 || r == 100) ? 32 /* mq/softe/spr0 */	\
         : (r == 65 || r == 108) ? 34 /* link */		\
         : (r == 66 || r == 109) ? 33 /* ctr */			\
         : 9999)

#define UNW_PC_IDX 35
#define UNW_SP_IDX 1

#define UNW_NR_REAL_REGS 35 /* We don't count nip. */

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

#endif /* _STP_PPC64_UNWIND_H */
