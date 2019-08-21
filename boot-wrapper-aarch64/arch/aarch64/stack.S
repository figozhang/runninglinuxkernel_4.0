/*
 * arch/aarch64/stack.S - stack handling
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

	.globl setup_stack
	.globl stack_top
	.globl stack_bottom

	.text
	/*
	 * Setup initial stack pointer
	 * x0: logical CPU ID
	 * Clobbers x1 and x2
	 */
setup_stack:
	mov	w1, #STACK_SIZE
	ldr	x2, =stack_top
	umsubl	x0, w0, w1, x2			// sp = st_base - cpu * st_size
	mov	sp, x0
	ret

	.section .stack
	.align 4
stack_bottom:
	.irp cpu, CPU_IDS
	.space STACK_SIZE
	.endr
stack_top:
