/* -*- linux-c -*- 
 * Functions to access the members of pt_regs struct
 * Copyright (C) 2005, 2007 Red Hat Inc.
 * Copyright (C) 2005 Intel Corporation.
 * Copyright (C) 2007 Quentin Barnes.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_REGS_C_
#define _LINUX_REGS_C_

#include "compatdefs.h"

/** Get the current return address for a return probe.
 * Call from kprobe return probe.
 * @param ri Pointer to the struct kretprobe_instance.
 * @return The return address
 */
#define _stp_ret_addr_r(ri) (ri->ret_addr)

/** Get the probe address for a kprobe.
 * Call from a kprobe. This will return the
 * address of the function that is being probed.
 * @param kp Pointer to the struct kprobe.
 * @return The function's address
 */
#define _stp_probe_addr(kp) (kp->addr)

/** Get the probe address for a return probe.
 * Call from kprobe return probe. This will return the
 * address of the function that is being probed.
 * @param ri Pointer to the struct kretprobe_instance.
 * @return The function's address
 */
#define _stp_probe_addr_r(ri) (ri->rp->kp.addr)

#if defined  (__x86_64__)

#ifdef STAPCONF_X86_UNIREGS
#define EREG(nm, regs) ((regs)->nm)
#define RREG(nm, regs) ((regs)->nm)
#else
#define EREG(nm, regs) ((regs)->e##nm)
#define RREG(nm, regs) ((regs)->r##nm)
#endif

static void _stp_print_regs(struct pt_regs * regs)
{
	unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L, fs, gs, shadowgs;
	unsigned int fsindex, gsindex;
	unsigned int ds, cs, es;

	_stp_printf("RIP: %016lx\nRSP: %016lx  EFLAGS: %08lx\n",
			RREG(ip, regs), RREG(sp, regs), EREG(flags, regs));
	_stp_printf("RAX: %016lx RBX: %016lx RCX: %016lx\n",
			RREG(ax, regs), RREG(bx, regs), RREG(cx, regs));
	_stp_printf("RDX: %016lx RSI: %016lx RDI: %016lx\n",
			RREG(dx, regs), RREG(si, regs), RREG(di, regs));
	_stp_printf("RBP: %016lx R08: %016lx R09: %016lx\n",
			RREG(bp, regs), regs->r8, regs->r9);
	_stp_printf("R10: %016lx R11: %016lx R12: %016lx\n",
			regs->r10, regs->r11, regs->r12);
	_stp_printf("R13: %016lx R14: %016lx R15: %016lx\n",
			regs->r13, regs->r14, regs->r15);

	asm("movl %%ds,%0" : "=r" (ds));
	asm("movl %%cs,%0" : "=r" (cs));
	asm("movl %%es,%0" : "=r" (es));
	asm("movl %%fs,%0" : "=r" (fsindex));
	asm("movl %%gs,%0" : "=r" (gsindex));

	rdmsrl(MSR_FS_BASE, fs);
	rdmsrl(MSR_GS_BASE, gs);
	rdmsrl(MSR_KERNEL_GS_BASE, shadowgs);

	asm("movq %%cr0, %0": "=r" (cr0));
	asm("movq %%cr2, %0": "=r" (cr2));
	asm("movq %%cr3, %0": "=r" (cr3));
	asm("movq %%cr4, %0": "=r" (cr4));

	_stp_printf("FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\n",
			fs, fsindex, gs, gsindex, shadowgs);
	_stp_printf("CS:  %04x DS: %04x ES: %04x CR0: %016lx\n", cs, ds, es, cr0);
	_stp_printf("CR2: %016lx CR3: %016lx CR4: %016lx\n", cr2, cr3, cr4);
}

#elif defined (__i386__)

#ifdef STAPCONF_X86_UNIREGS
#define EREG(nm, regs) ((regs)->nm)
#define XREG(nm, regs) ((regs)->nm)
#else
#define EREG(nm, regs) ((regs)->e##nm)
#define XREG(nm, regs) ((regs)->x##nm)
#endif

/** Write the registers to a string.
 * @param regs The pt_regs saved by the kprobe.
 * @note i386 and x86_64 only so far. 
 */
static void _stp_print_regs(struct pt_regs * regs)
{
	unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L;

	_stp_printf ("EIP: %08lx\n", EREG(ip, regs));
	_stp_printf ("ESP: %08lx\n", EREG(sp, regs));
	_stp_printf ("EAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx\n",
			EREG(ax, regs), EREG(bx, regs), EREG(cx, regs), EREG(dx, regs));
	_stp_printf ("ESI: %08lx EDI: %08lx EBP: %08lx",
			EREG(si, regs), EREG(di, regs), EREG(bp, regs));
	_stp_printf (" DS: %04x ES: %04x\n",
			0xffff & XREG(ds, regs), 0xffff & XREG(es, regs));

	__asm__("movl %%cr0, %0": "=r" (cr0));
	__asm__("movl %%cr2, %0": "=r" (cr2));
	__asm__("movl %%cr3, %0": "=r" (cr3));
	/* This could fault if %cr4 does not exist */
	__asm__("1: movl %%cr4, %0		\n"
		"2:				\n"
		".section __ex_table,\"a\"	\n"
		".long 1b,2b			\n"
		".previous			\n"
		: "=r" (cr4): "0" (0));
	_stp_printf ("CR0: %08lx CR2: %08lx CR3: %08lx CR4: %08lx\n", cr0, cr2, cr3, cr4);
}

#elif defined (__ia64__)
static void _stp_print_regs(struct pt_regs * regs)
{
     unsigned long ip = regs->cr_iip + ia64_psr(regs)->ri;

	_stp_printf("\nPid: %d, CPU %d, comm: %20s\n", current->pid,
		smp_processor_id(), current->comm);
	_stp_printf("psr : %016lx ifs : %016lx ip  : [<%016lx>]  \n",
		regs->cr_ipsr, regs->cr_ifs, ip);
	_stp_printf("unat: %016lx pfs : %016lx rsc : %016lx\n",
		regs->ar_unat, regs->ar_pfs, regs->ar_rsc);
	_stp_printf("rnat: %016lx bsps: %016lx pr  : %016lx\n",
		regs->ar_rnat, regs->ar_bspstore, regs->pr);
	_stp_printf("ldrs: %016lx ccv : %016lx fpsr: %016lx\n",
		regs->loadrs, regs->ar_ccv, regs->ar_fpsr);
	_stp_printf("csd : %016lx ssd : %016lx\n",
		regs->ar_csd, regs->ar_ssd);
	_stp_printf("b0  : %016lx b6  : %016lx b7  : %016lx\n",
		regs->b0, regs->b6, regs->b7);
	_stp_printf("f6  : %05lx%016lx f7  : %05lx%016lx\n",
		regs->f6.u.bits[1], regs->f6.u.bits[0],
		regs->f7.u.bits[1], regs->f7.u.bits[0]);
	_stp_printf("f8  : %05lx%016lx f9  : %05lx%016lx\n",
		regs->f8.u.bits[1], regs->f8.u.bits[0],
		regs->f9.u.bits[1], regs->f9.u.bits[0]);
	_stp_printf("f10 : %05lx%016lx f11 : %05lx%016lx\n",
		regs->f10.u.bits[1], regs->f10.u.bits[0],
		regs->f11.u.bits[1], regs->f11.u.bits[0]);
}

#elif defined (__powerpc64__)

static void _stp_print_regs(struct pt_regs * regs)
{
	int i;

	_stp_printf("NIP: %016lX XER: %08X LR: %016lX CTR: %016lX\n",
	       regs->nip, (unsigned int)regs->xer, regs->link, regs->ctr);
	_stp_printf("REGS: %016lx TRAP: %04lx\n", (long)regs, regs->trap);
	_stp_printf("MSR: %016lx CR: %08X\n",
			regs->msr, (unsigned int)regs->ccr);
	_stp_printf("DAR: %016lx DSISR: %016lx\n",
		       	regs->dar, regs->dsisr);

#ifdef CONFIG_SMP
	_stp_printf(" CPU: %d", smp_processor_id());
#endif /* CONFIG_SMP */

	for (i = 0; i < 32; i++) {
		if ((i % 4) == 0) {
			_stp_printf("\n GPR%02d: ", i);
		}

		_stp_printf("%016lX ", regs->gpr[i]);
		if (i == 13 && !FULL_REGS(regs))
			break;
	}
	_stp_printf("\nNIP [%016lx] ", regs->nip);
	_stp_printf("LR [%016lx]\n", regs->link);
}

#elif defined (__aarch64__)
static void _stp_print_regs(struct pt_regs * regs)
{
	int i, top_reg;
	u64 lr, sp;

	if (compat_user_mode(regs)) {
		lr = regs->compat_lr;
		sp = regs->compat_sp;
		top_reg = 12;
	} else {
		lr = regs->regs[30];
		sp = regs->sp;
		top_reg = 29;
	}

	_stp_printf("pc : [<%016llx>] lr : [<%016llx>] pstate: %08llx\n",
	       regs->pc, lr, regs->pstate);
	_stp_printf("sp : %016llx\n", sp);
	for (i = top_reg; i >= 0; i--) {
		_stp_printf("x%-2d: %016llx ", i, regs->regs[i]);
		if (i % 2 == 0)
			_stp_printf("\n");
	}
	_stp_printf("\n");
}

#elif defined (__arm__)

static const char *processor_modes[]=
{ "USER_26", "FIQ_26" , "IRQ_26" , "SVC_26" , "UK4_26" , "UK5_26" , "UK6_26" , "UK7_26" ,
  "UK8_26" , "UK9_26" , "UK10_26", "UK11_26", "UK12_26", "UK13_26", "UK14_26", "UK15_26",
  "USER_32", "FIQ_32" , "IRQ_32" , "SVC_32" , "UK4_32" , "UK5_32" , "UK6_32" , "ABT_32" ,
  "UK8_32" , "UK9_32" , "UK10_32", "UND_32" , "UK12_32", "UK13_32", "UK14_32", "SYS_32"
};


static void _stp_print_regs(struct pt_regs * regs)
{
	unsigned long flags = regs->ARM_cpsr;

#ifdef CONFIG_SMP
	_stp_printf(" CPU: %d", smp_processor_id());
#endif /* CONFIG_SMP */

	_stp_printf("pc : [<%08lx>]    lr : [<%08lx>]\n"
	       "sp : %08lx  ip : %08lx  fp : %08lx\n",
		instruction_pointer(regs),
		regs->ARM_lr, regs->ARM_sp,
		regs->ARM_ip, regs->ARM_fp);
	_stp_printf("r10: %08lx  r9 : %08lx  r8 : %08lx\n",
		regs->ARM_r10, regs->ARM_r9,
		regs->ARM_r8);
	_stp_printf("r7 : %08lx  r6 : %08lx  r5 : %08lx  r4 : %08lx\n",
		regs->ARM_r7, regs->ARM_r6,
		regs->ARM_r5, regs->ARM_r4);
	_stp_printf("r3 : %08lx  r2 : %08lx  r1 : %08lx  r0 : %08lx\n",
		regs->ARM_r3, regs->ARM_r2,
		regs->ARM_r1, regs->ARM_r0);
	_stp_printf("Flags: %c%c%c%c",
		flags & PSR_N_BIT ? 'N' : 'n',
		flags & PSR_Z_BIT ? 'Z' : 'z',
		flags & PSR_C_BIT ? 'C' : 'c',
		flags & PSR_V_BIT ? 'V' : 'v');
	_stp_printf("  IRQs o%s  FIQs o%s  Mode %s%s  Segment %s\n",
		interrupts_enabled(regs) ? "n" : "ff",
		fast_interrupts_enabled(regs) ? "n" : "ff",
		processor_modes[processor_mode(regs)],
		thumb_mode(regs) ? " (T)" : "",
		get_fs() == get_ds() ? "kernel" : "user");
#ifdef CONFIG_CPU_CP15
	{
		unsigned int ctrl;
		  __asm__ (
		"	mrc p15, 0, %0, c1, c0\n"
		: "=r" (ctrl));
		_stp_printf("Control: %04X\n", ctrl);
	}
#ifdef CONFIG_CPU_CP15_MMU
	{
		unsigned int transbase, dac;
		  __asm__ (
		"	mrc p15, 0, %0, c2, c0\n"
		"	mrc p15, 0, %1, c3, c0\n"
		: "=r" (transbase), "=r" (dac));
		_stp_printf("Table: %08X  DAC: %08X\n",
		  	transbase, dac);
	}
#endif
#endif
}

#elif defined (__s390x__) || defined (__s390__)

#ifdef __s390x__
#define GPRSIZE "%016lX "
#else	/* s390 */
#define GPRSIZE "%08lX "
#endif

static void _stp_print_regs(struct pt_regs * regs)
{
	char *mode;
	int i;

	mode = (regs->psw.mask & PSW_MASK_PSTATE) ? "User" : "Krnl";
	_stp_printf("%s PSW : ["GPRSIZE"] ["GPRSIZE"]",
		mode, (void *) regs->psw.mask,
		(void *) regs->psw.addr);

#ifdef CONFIG_SMP
	_stp_printf(" CPU: %d", smp_processor_id());
#endif /* CONFIG_SMP */

	for (i = 0; i < 16; i++) {
		if ((i % 4) == 0) {
			_stp_printf("\n GPRS%02d: ", i);
		}
		_stp_printf(GPRSIZE, regs->gprs[i]);
	}
	_stp_printf("\n");
}

#endif


#endif /* _LINUX_REGS_C_ */
