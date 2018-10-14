/* -*- linux-c -*- 
 * IA64 register access functions
 * Copyright (C) 2005 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _REGS_IA64_C_
#define _REGS_IA64_C_

#if defined __ia64__

struct ia64_stap_get_arbsp_param {
	unsigned long ip;
	unsigned long *address;
};

static void ia64_stap_get_arbsp(struct unw_frame_info *info, void *arg)
{
	unsigned long ip;
	struct ia64_stap_get_arbsp_param *lp = arg;

	do {
		unw_get_ip(info, &ip);
		if (ip == 0)
			break;
		if (ip == lp->ip) {
			unw_get_bsp(info, (unsigned long*)&lp->address);
			return;
		}
	} while (unw_unwind(info) >= 0);
	lp->address = 0;
}

/*
 * bspcache: get cached unwound address from current BSP and
 * 	     set a static local cache of the offset of unwound address
 * 	     if the static local cache(variable) is not set.
 * 	     The unwound address means the BSP value when the kprobe
 * 	     was hit. This macro stores the difference of BSP between
 * 	     when the kprobe was hit and when this macro was called.
 * 	     Since the difference depends on how much stack is consumed
 * 	     from when the kprobe was hit, this macro *MUST NOT* be put
 * 	     on the path which several functions execute (in that case,
 * 	     each time the difference is changed and this macro can't
 * 	     return correct unwound address).
 */
#define bspcache(cache, regs)\
	if(regs) {\
		static unsigned __offset = 0; /* probe local cache */\
		static void * __ip = NULL; /* reference ip */\
		unsigned long *bsp;\
		asm volatile("{ flushrs }\n"); /* flushrs for fixing bsp */\
		bsp = (void*)ia64_getreg(_IA64_REG_AR_BSP);\
		if (__offset == 0) {\
			struct ia64_stap_get_arbsp_param pa;\
			pa.ip = regs->cr_iip;\
			unw_init_running(ia64_stap_get_arbsp, &pa);\
			if (pa.address != 0) {\
				__offset = ia64_rse_num_regs(pa.address, bsp)\
					-(regs->cr_ifs & 127);\
				__ip = (void *)REG_IP(regs);\
				cache = pa.address;\
			}\
		} else if ((void *)REG_IP(regs) == __ip)\
			cache = ia64_rse_skip_regs(bsp,\
				-(__offset + (regs->cr_ifs & 127)));\
	}

static long *
__ia64_fetch_register(int regno, struct pt_regs *pt_regs, unsigned long **cache)
{
	struct ia64_stap_get_arbsp_param pa;

	if (regno == 12)
		return &pt_regs->r12;

	if (regno >= 8 && regno <= 11)
		return (long *)(&pt_regs->r8 + regno - 8);
	else if (regno < 32 || regno > 127)
		return NULL;

	if (!*cache) {
		pa.ip = pt_regs->cr_iip;
		unw_init_running(ia64_stap_get_arbsp, &pa);
		if (pa.address == 0)
			return NULL;
		*cache = pa.address;
	}

	return ia64_rse_skip_regs(*cache, regno-32);
}

static long
ia64_fetch_register(int regno, struct pt_regs *pt_regs, unsigned long **cache)
{
	long *reg;
	reg = __ia64_fetch_register(regno, pt_regs, cache);
	return (reg != NULL)? *reg : 0;
}

static void ia64_store_register(int regno,
		struct pt_regs *pt_regs,
		unsigned long value)
{
	struct ia64_stap_get_arbsp_param pa;
	unsigned long rsc_save = 0;
	unsigned long *addr;

	if (regno >= 8 && regno <= 11) {
		addr =&pt_regs->r8;
		addr += regno - 8;
		*(addr) = value;
		return;
	}
	else if (regno < 32 || regno > 127)
		return;

	pa.ip = pt_regs->cr_iip;
	unw_init_running(ia64_stap_get_arbsp, &pa);
	if (pa.address == 0)
		return;
	*ia64_rse_skip_regs(pa.address, regno-32) = value;
	//Invalidate all stacked registers outside the current frame
	asm volatile( "mov %0=ar.rsc;;\n\t"
			"mov ar.rsc=0;;\n\t"
			"{\n\tloadrs;;\n\t\n\t\n\t}\n\t"
			"mov ar.rsc=%1\n\t"
			:"=r" (rsc_save):"r" (rsc_save):"memory");

	return;
}

#endif /* if defined __ia64__ */


#endif /* _REGS_IA64_C_ */
