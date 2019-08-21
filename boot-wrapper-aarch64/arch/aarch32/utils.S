/*
 * arch/aarch32/utils.S - basic utilities
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <cpu.h>
#include <linkage.h>

	.text

/*
 * Takes masked MPIDR in r0, returns logical ID in r0.
 * Z flag is set when CPU is primary; cleared otherwise.
 * Returns MPIDR_INVALID for unknown MPIDRs
 * Clobbers r1, r2, r3.
 */
ENTRY(find_logical_id)
	ldr	r2, =id_table
	mov	r1, #0
1:	mov	r3, #NR_CPUS

	cmp	r1, r3
	bgt	3f
	ldr	r3, [r2, r1, lsl #2]
	cmp	r3, r0
	beq	2f
	add	r1, r1, #1
	b	1b

2:	movs	r0, r1
	bx	lr
3:	mov	r0, #MPIDR_INVALID
	bx	lr

/*
 * Setup EL3 vectors.
 * r0: vector address
 */
ENTRY(setup_vector)
	mcr	p15, 0, r0, c12, c0, 1	@ MVBAR
	isb
	bx	lr
