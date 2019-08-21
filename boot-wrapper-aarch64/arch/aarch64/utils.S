/*
 * arch/aarch64/utils.S - basic utilities
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <cpu.h>

	.globl find_logical_id
	.globl setup_vector

	.text

/*
 * Takes masked MPIDR in x0, returns logical id in x0
 * Returns -1 for unknown MPIDRs
 * Sets the Z flag when CPU is primary
 * Clobbers x1, x2, x3
 */
find_logical_id:
	ldr	x2, =id_table
	mov	x1, xzr
1:	mov	x3, #NR_CPUS	// check we haven't walked off the end of the array
	cmp	x1, x3
	b.gt	3f
	ldr	x3, [x2, x1, lsl #3]
	cmp	x3, x0
	b.eq	2f
	add	x1, x1, #1
	b 1b
2:	subs	x0, x1, #0
	ret
3:	mov	x0, #MPIDR_INVALID
	ret

/*
 * Setup EL3 vectors
 * x0: vector address
 */
setup_vector:
	msr	VBAR_EL3, x0
	isb
	ret
