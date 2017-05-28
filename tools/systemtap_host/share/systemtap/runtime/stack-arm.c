/* -*- linux-c -*-
 * arm stack tracing functions
 * Copyright (C) 2007 Quentin Barnes
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/*
 * For STR and STM instructions, an ARM core may choose to use either
 * a +8 or a +12 displacement from the current instruction's address.
 * Whichever value is chosen for a given core, it must be the same for
 * both instructions and may not change.  This function measures it.
 */

static int __init find_str_pc_offset(void)
{
	int addr;
	int scratch;
	int ret;

	__asm__("sub	%[ret], pc, #4		\n\t"
		"str	pc, %[addr]		\n\t"
		"ldr	%[scr], %[addr]		\n\t"
		"sub	%[ret], %[scr], %[ret]	\n\t"
		: [ret] "=r" (ret), [scr] "=r" (scratch), [addr] "+m" (addr) );

	return ret;
}


static void __stp_stack_print (struct pt_regs *regs, int verbose, int levels)
{
#ifdef CONFIG_FRAME_POINTER
	int		pc_offset = find_str_pc_offset();
	unsigned long	*fp = (unsigned long *)regs->ARM_fp;
	unsigned long	*next_fp, *pc;

	if (levels == 0)
		--levels;

	while (fp && levels--) {
		next_fp = (unsigned long *)*(fp - 3);
		pc      = (unsigned long *)(*fp - pc_offset);

		/* 0xe92dd8xx == stmfd sp!, { ..., fp, ip, lr, pc } */
		if ((*pc & 0xffffd800) == 0xe92dd800) {
			pc -= 1;

			/* Varargs functions have two stmfd instructions. */
			if ((*pc & 0xffff0000) == 0xe92d0000)
				pc -= 1;
		}

		_stp_print_addr((unsigned long)pc, verbose, NULL);

		/* Sanity check the next_fp. */
		if (next_fp && next_fp <= fp)
			break;

		fp = next_fp;
	}
#endif /* CONFIG_FRAME_POINTER */
}
