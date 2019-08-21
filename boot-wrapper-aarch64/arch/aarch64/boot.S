/*
 * arch/aarch64/boot.S - simple register setup code for stand-alone Linux booting
 *
 * Copyright (C) 2012 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include "common.S"

	.section .init

	.globl	_start
	.globl jump_kernel

_start:
	cpuid	x0, x1
	bl	find_logical_id
	cmp	x0, #MPIDR_INVALID
	beq	err_invalid_id
	bl	setup_stack

	/*
	 * EL3 initialisation
	 */
	mrs	x0, CurrentEL
	cmp	x0, #CURRENTEL_EL3
	b.eq	1f

	mov	w0, #1
	ldr	x1, =flag_no_el3
	str	w0, [x1]

	bl	setup_stack
	b	start_no_el3

1:	mov	x0, #0x30			// RES1
	orr	x0, x0, #(1 << 0)		// Non-secure EL1
	orr	x0, x0, #(1 << 8)		// HVC enable

	/* Enable pointer authentication if present */
	mrs	x1, id_aa64isar1_el1
	ldr	x2, =(((0xff) << 24) | (0xff << 4))
	and	x1, x1, x2
	cbz	x1, 1f

	orr	x0, x0, #(1 << 16)		// AP key enable
	orr	x0, x0, #(1 << 17)		// AP insn enable
1:
#ifndef KERNEL_32
	orr	x0, x0, #(1 << 10)		// 64-bit EL2
#endif
	msr	scr_el3, x0

	msr	cptr_el3, xzr			// Disable copro. traps to EL3

	mrs	x0, id_aa64pfr0_el1
	ubfx	x0, x0, #32, #4			// SVE present?
	cbz	x0, 1f				// Skip SVE init if not

	mrs	x0, cptr_el3
	orr	x0, x0, #CPTR_EL3_EZ		// enable SVE
	msr	cptr_el3, x0
	isb

	mov	x0, #ZCR_EL3_LEN_MASK		// SVE: Enable full vector len
	msr	ZCR_EL3, x0			// for EL2.

1:
	ldr	x0, =CNTFRQ
	msr	cntfrq_el0, x0

	bl	gic_secure_init

	b	start_el3

err_invalid_id:
	b	.

	/*
	 * Drop to the kernel
	 * x0:		entry address
	 * x1-x4:	arguments
	 */
jump_kernel:
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	mov	x23, x4

	ldr	x0, =SCTLR_EL1_RESET
	msr	sctlr_el1, x0

	ldr	x0, =SCTLR_EL2_RESET
	msr	sctlr_el2, x0

	cpuid	x0, x1
	bl	find_logical_id
	bl	setup_stack		// Reset stack pointer

	ldr	w0, flag_no_el3
	cmp	w0, #0			// Prepare Z flag

	mov	x0, x20
	mov	x1, x21
	mov	x2, x22
	mov	x3, x23

	b.eq	1f
	br	x19			// No EL3

1:	mov	x4, #SPSR_KERNEL

	/*
	 * If bit 0 of the kernel address is set, we're entering in AArch32
	 * thumb mode. Set SPSR.T accordingly.
	 */
	bfi	x4, x19, #5, #1

	msr	elr_el3, x19
	msr	spsr_el3, x4
	eret

	.ltorg

	.data
	.align 3
flag_no_el3:
	.long 0
