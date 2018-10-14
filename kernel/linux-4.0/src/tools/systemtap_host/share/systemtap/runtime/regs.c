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

#ifndef _REGS_C_
#define _REGS_C_

#include "regs.h"

#if defined(__KERNEL__)

#include "linux/regs.c"

#elif defined(__DYNINST__)

#include "dyninst/regs.c"

#endif


/* Function arguments */

#define _STP_REGPARM 0x8000
#define _STP_REGPARM_MASK ((_STP_REGPARM) - 1)

/*
 * x86_64 and i386 are especially ugly because:
 * 1)  the pt_reg member names changed as part of the x86 merge.  We use
 * either the pre-merge name or the post-merge name, as needed.
 * 2) -m32 apps on x86_64 look like i386 apps, so we need to support
 * those semantics on both i386 and x86_64.
 */

#ifdef __i386__

static long _stp_get_sp(struct pt_regs *regs)
{
	if (!user_mode(regs))
		return (long) &EREG(sp, regs);
	return EREG(sp, regs);
}

#endif	/* __i386__ */

#ifdef __x86_64__

static long _stp_get_sp(struct pt_regs *regs)
{
	return RREG(sp, regs);
}

#endif	/* __x86_64__ */

#if defined(__x86_64__) || defined(__ia64__)

/* Ensure that the upper 32 bits of val are a sign-extension of the lower 32. */
static int64_t __stp_sign_extend32(int64_t val)
{
	int32_t *val_ptr32 = (int32_t*) &val;
	return *val_ptr32;
}

#endif	/* __x86_64__ || __ia64__ */

#if defined(__i386__) || defined(__x86_64__)
/*
 * Use this for i386 kernel and apps, and for 32-bit apps running on x86_64.
 * Does arch-specific work for fetching function arg #argnum (1 = first arg).
 * nr_regargs is the number of arguments that reside in registers (e.g.,
 * 3 for fastcall functions).
 * Returns:
 * 0 if the arg resides in a register.  *val contains its value.
 * 1 if the arg resides on the kernel stack.  *val contains its address.
 * 2 if the arg resides on the user stack.  *val contains its address.
 * -1 if the arg number is invalid.
 * We assume that the regs pointer is valid.
 */

#if defined(__i386__)
#define ERREG(nm, regs) EREG(nm, regs)
#else  /* x86_64 */
#define ERREG(nm, regs) RREG(nm, regs)
#endif

static int _stp_get_arg32_by_number(int n, int nr_regargs,
					struct pt_regs *regs, long *val)
{
	if (nr_regargs < 0)
		return -1;
	if (n > nr_regargs) {
		/*
		 * The typical case: arg n is on the stack.
		 * stack[0] = return address
		 */
		int stack_index = n - nr_regargs;
		int32_t *stack = (int32_t*) _stp_get_sp(regs);
		*val = (long) &stack[stack_index];
		return (user_mode(regs) ? 2 : 1);
	} else {
		switch (n) {
		case 1: *val = (int32_t)(ERREG(ax, regs)); break;
		case 2: *val = (int32_t)(ERREG(dx, regs)); break;
		case 3: *val = (int32_t)(ERREG(cx, regs)); break;
		default:
			/* gcc rejects regparm values > 3. */
			return -1;
		}
		return 0;
	}
}
#endif	/* __i386__ || __x86_64__ */

#ifdef __x86_64__
/* See _stp_get_arg32_by_number(). */
static int _stp_get_arg64_by_number(int n, int nr_regargs,
				struct pt_regs *regs, unsigned long *val)
{
	if (nr_regargs < 0)
		return -1;
	if (n > nr_regargs) {
		/* arg n is on the stack.  stack[0] = return address */
		int stack_index = n - nr_regargs;
		unsigned long *stack = (unsigned long*) _stp_get_sp(regs);
		*val = (unsigned long) &stack[stack_index];
		return (user_mode(regs) ? 2 : 1);
	} else {
		switch (n) {
		case 1: *val = RREG(di, regs); break;
		case 2: *val = RREG(si, regs); break;
		case 3: *val = RREG(dx, regs); break;
		case 4: *val = RREG(cx, regs); break;
		case 5: *val = regs->r8; break;
		case 6: *val = regs->r9; break;
		default:
			/* gcc rejects regparm values > 6. */
			return -1;
		}
		return 0;
	}
}
#endif	/* __x86_64__ */

/** @} */
#endif /* _REGS_C_ */
