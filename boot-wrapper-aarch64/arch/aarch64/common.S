/*
 * arch/aarch64/common.S - common definitions useful for boot code
 *
 * Copyright (C) 2013 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <cpu.h>

	/* Put MPIDR into \dest, clobber \tmp and flags */
	.macro cpuid dest, tmp
	mrs	\dest, mpidr_el1
	ldr	\tmp, =MPIDR_ID_BITS
	ands	\dest, \dest, \tmp
	.endm
