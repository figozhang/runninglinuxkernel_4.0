/*
 * arch/aarch32/boot.S - simple register setup code for stand-alone Linux booting
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <cpu.h>
#include <linkage.h>

#include "common.S"

	.arch_extension sec
	.arch_extension virt

	.section .init
ENTRY(_start)
	/* Stack initialisation */
	cpuid	r0, r1
	bl	find_logical_id
	cmp	r0, #MPIDR_INVALID
	beq	_spin_dead

	bl	setup_stack

	mrs	r0, cpsr
	and	r0, #PSR_MODE_MASK

	cmp	r0, #PSR_HYP
	bne	_switch_monitor

	mov	r0, #1
	ldr	r1, =flag_no_el3
	str	r0, [r1]
	b	start_no_el3

_switch_monitor:
	ldr	r0, =boot_vectors
	bl	setup_vector
	smc	#0

_monitor:
	/* Move the stack to Monitor mode*/
	mrs	sp, sp_svc

	/* Setup secure registers and devices */
	mov	r0, #1				@ Non-secure lower level
	orr	r0, #(1 << 8)			@ HVC enable
	mcr	p15, 0, r0, c1, c1, 0		@ SCR

	mov	r0, #(1 << 10 | 1 << 11)	@ Enable NS access to CPACR
	mcr	p15, 0, r0, c1, c1, 2		@ NSACR

	ldr	r0, =CNTFRQ
	mcr	p15, 0, r0, c14, c0, 0		@ CNTFRQ

	bl	gic_secure_init

	/* Initialise boot method */
	b	start_el3

_spin_dead:
	b	.

	.text

	/*
	 * r0: kernel address
	 * r1-r3, sp[0]: kernel arguments
	 */
ENTRY(jump_kernel)
	sub	sp, #4				@ Ignore fourth argument
	push	{r0 - r3}
	mov	r5, sp

	ldr	r0, =HSCTLR_RESET
	mcr	p15, 4, r0, c1, c0, 0		@ HSCTLR

	ldr	r0, =SCTLR_RESET
	mcr	p15, 0, r0, c1, c0, 0		@ SCTLR

	/* Reset our stack pointer */
	cpuid	r0, r1
	bl	find_logical_id
	bl	setup_stack

	ldr	lr, [r5], #4
	ldm	r5, {r0 - r2}

	ldr	r4, =flag_no_el3
	ldr	r4, [r4]
	cmp	r4, #1
	bxeq	lr				@ no EL3

	ldr	r4, =SPSR_KERNEL
	/* Return in thumb2 mode when bit 0 of address is 1 */
	tst	lr, #1
	orrne	r4, #PSR_T

	msr	spsr_cxf, r4
	movs	pc, lr

	.section .vectors
	.align 6
boot_vectors:
	b	.
	b	.
	b	_monitor
	b	.
	b	.
	b	.
	b	.
	b	.

	.section .data
	.align 2
flag_no_el3:
	.long 0
