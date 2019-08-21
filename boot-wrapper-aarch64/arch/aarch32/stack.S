/*
 * arch/aarch32/stack.S - stack handling
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
	 * r0: logical CPU ID
	 * Clobbers r1 and r2
	 */
setup_stack:
	mov	r1, #STACK_SIZE
	ldr	r2, =stack_top
	mls	sp, r0, r1, r2
	bx	lr

	.section .stack
	.align 2
stack_bottom:
	.irp cpu, CPU_IDS
	.space STACK_SIZE
	.endr
stack_top:
