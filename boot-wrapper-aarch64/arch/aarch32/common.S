/*
 * arch/aarch32/common.S - common definitions useful for boot code
 *
 * Copyright (C) 2013 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <asm/cpu.h>

	/* Returns mpidr in \dest, clobbers \tmp and flags */
	.macro cpuid dest, tmp
	mrc	p15, 0, \dest, c0, c0, 5		@ MPIDR
	ldr	\tmp, =MPIDR_ID_BITS
	ands	\dest, \dest, \tmp
	.endm
