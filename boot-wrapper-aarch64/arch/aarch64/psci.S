/*
 * arch/aarch64/psci.S - basic PSCI implementation
 *
 * Copyright (C) 2013 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#include <psci.h>

#include "common.S"

	.macro	ventry	label
	.align	7
	b	\label
	.endm

	.section .vectors, "w"

	.align 11
vector:
	// current EL, SP_EL0
	ventry	err_exception	// synchronous
	ventry	err_exception	// IRQ
	ventry	err_exception	// FIQ
	ventry	err_exception	// SError

	// current EL, SP_ELx
	ventry	err_exception
	ventry	err_exception
	ventry	err_exception
	ventry	err_exception

	// lower EL, AArch64
	ventry	smc_entry64
	ventry	err_exception
	ventry	err_exception
	ventry	err_exception

	// lower EL, AArch32
	ventry	smc_entry32
	ventry	err_exception
	ventry	err_exception
	ventry	err_exception

	.text

	.globl start_no_el3
	.globl start_el3

err_exception:
	b err_exception

	.macro branch_if val, addr
	ldr	x7, =\val
	cmp	x0, x7
	adr	x7, \addr
	b.eq	do_call
	.endm

smc_entry32:
	/* Clear upper bits */
	mov	w0, w0
	/* Pass through */

smc_entry64:
	/* SMC entry uses 112 bytes of stack */
	stp	x18, x19, [sp, #-16]!
	stp	x20, x21, [sp, #-16]!
	stp	x22, x23, [sp, #-16]!
	stp	x24, x25, [sp, #-16]!
	stp	x26, x27, [sp, #-16]!
	stp	x28, x29, [sp, #-16]!
	// Keep sp aligned to 16 bytes
	stp	x30, xzr, [sp, #-16]!

	/* If function ID matches, do_call with procedure address in x7 */
	branch_if PSCI_CPU_ON_32,	psci_cpu_on
	branch_if PSCI_CPU_ON_64,	psci_cpu_on
	branch_if PSCI_CPU_OFF,		psci_cpu_off

	/* Otherwise, return error in x0/w0 */
	mov	x0, PSCI_RET_NOT_SUPPORTED
	b	smc_exit

do_call:
	mov	x0, x1
	mov	x1, x2
	mov	x2, x3

	blr	x7

smc_exit:
	ldp	x30, xzr, [sp], #16
	ldp	x28, x29, [sp], #16
	ldp	x26, x27, [sp], #16
	ldp	x24, x25, [sp], #16
	ldp	x22, x23, [sp], #16
	ldp	x20, x21, [sp], #16
	ldp	x18, x19, [sp], #16
	eret


start_el3:
	ldr	x0, =vector
	bl	setup_vector

	/* only boot the primary cpu (entry 0 in the table) */
	cpuid	x0, x1
	bl	find_logical_id
	b	psci_first_spin

/*
 * This PSCI implementation requires EL3. Without EL3 we'll only boot the
 * primary cpu, all others will be trapped in an infinite loop.
 */
start_no_el3:
	cpuid	x0, x1
	bl	find_logical_id
	cbz	x0, psci_first_spin
spin_dead:
	wfe
	b	spin_dead
