/* common register includes used in multiple modules
 * Copyright (C) 2005-2008 Red Hat Inc.
 * Copyright (C) 2005 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _REGS_H_ /* -*- linux-c -*- */
#define _REGS_H_

#if defined  (STAPCONF_X86_UNIREGS) && (defined (__x86_64__) || defined (__i386__))

#define REG_IP(regs) regs->ip
#define REG_SP(regs) regs->sp
#define REG_FP(regs) regs->bp

#elif defined  (__x86_64__)

#define REG_IP(regs) regs->rip
#define REG_SP(regs) regs->rsp

#elif defined (__i386__)

#define REG_IP(regs) regs->eip
#define REG_SP(regs) regs->esp
#define REG_FP(regs) regs->ebp

#elif defined (__ia64__)

#define REG_IP(regs)    ((regs)->cr_iip +ia64_psr(regs)->ri)
#define REG_SP(regs)    ((regs)->r12)
#define SET_REG_IP(regs, x) \
  (((regs)->cr_iip = (x) & ~3UL), (ia64_psr(regs)->ri = (x) & 3UL))


#elif defined (__powerpc__)

#define REG_IP(regs) regs->nip
#define REG_SP(regs) regs->gpr[1]
#define REG_LINK(regs) regs->link

#elif defined (__aarch64__)

#define REG_IP(regs) regs->pc
#define REG_SP(regs) regs->sp
#define REG_LINK(regs) regs->regs[30]

#elif defined (__arm__)

#define REG_IP(regs) regs->ARM_pc
#define REG_SP(regs) regs->ARM_sp
#define REG_LINK(regs) regs->ARM_lr

#elif defined (__s390__) || defined (__s390x__)

#ifndef __s390x__
#define PSW_ADDR_AMODE	0x80000000UL
#define PSW_ADDR_INSN	0x7FFFFFFFUL
#else /* __s390x__ */
#define PSW_ADDR_AMODE	0x0000000000000000UL
#define PSW_ADDR_INSN	0xFFFFFFFFFFFFFFFFUL
#endif /* __s390x__ */
#define REG_IP(regs)	(((regs)->psw.addr) & PSW_ADDR_INSN)
#define REG_SP(regs)	(regs)->gprs[15]
#define SET_REG_IP(regs,x) (regs)->psw.addr = (x) | PSW_ADDR_AMODE

#else
#error "Unimplemented architecture"
#endif

#ifndef SET_REG_IP
#define SET_REG_IP(regs, x) REG_IP(regs) = x
#endif

static void _stp_print_regs(struct pt_regs * regs);

#endif /* _REGS_H_ */
