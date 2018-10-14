/* -*- linux-c -*-
 *
 * s390x dwarf unwinder header file
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_S390X_UNWIND_H
#define _STP_S390X_UNWIND_H

#include <linux/sched.h>
#include <asm/ptrace.h>

#define _stp_get_unaligned(ptr) (*(ptr))

#define UNW_PC(frame)        (frame)->regs.psw.addr
#define UNW_SP(frame)        (frame)->regs.gprs[15]

#define STACK_LIMIT(ptr)     (((ptr) - 1) & ~(THREAD_SIZE - 1))

#define UNW_REGISTER_INFO \
	PTREGS_INFO(gprs[0]), \
	PTREGS_INFO(gprs[1]), \
	PTREGS_INFO(gprs[2]), \
	PTREGS_INFO(gprs[3]), \
	PTREGS_INFO(gprs[4]), \
	PTREGS_INFO(gprs[5]), \
	PTREGS_INFO(gprs[6]), \
	PTREGS_INFO(gprs[7]), \
	PTREGS_INFO(gprs[8]), \
	PTREGS_INFO(gprs[9]), \
	PTREGS_INFO(gprs[10]), \
	PTREGS_INFO(gprs[11]), \
	PTREGS_INFO(gprs[12]), \
	PTREGS_INFO(gprs[13]), \
	PTREGS_INFO(gprs[14]), \
	PTREGS_INFO(gprs[15]), \
	PTREGS_INFO(psw.addr), \
	PTREGS_INFO(psw.mask)

#define DWARF_REG_MAP(r) \
        ((r >= 0 && r <= 15) ? r /* gpr0-15 */	\
         : (r == 64) ? 16 /* PSW addr */	\
         : (r == 65) ? 17 /* PSW mask */	\
         : 9999)

#define UNW_PC_IDX 16
#define UNW_SP_IDX 15

#define UNW_SP_FROM_CFA 0 /* Stack pointer is just gprs15, normal cfi. */

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

#endif /* _STP_S390X_UNWIND_H */
