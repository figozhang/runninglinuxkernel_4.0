/*
 * arch/aarch32/psci.S - basic PSCI implementation
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <cpu.h>
#include <linkage.h>
#include <psci.h>

#include "common.S"

	.section .vectors
	.align 6
smc_vectors:
	b	err_exception			@ Reset
	b	err_exception			@ Undef
	b	handle_smc			@ SMC
	b	err_exception			@ Prefetch abort
	b	err_exception			@ Data abort
	b	.				@ Unused
	b	err_exception			@ IRQ
	b	err_exception			@ FIQ

	.text
err_exception:
	b	.

handle_smc:
	@ Follow the SMC32 calling convention: preserve r4 - r14
	push	{r4 - r12, lr}

	ldr	r4, =PSCI_CPU_ON_32
	cmp	r4, r0
	ldr	r4, =psci_cpu_on
	beq	do_psci_call

	ldr	r4, =PSCI_CPU_OFF
	cmp	r4, r0
	ldr	r4, =psci_cpu_off
	beq	do_psci_call

	adr	r4, psci_invalid

do_psci_call:
	mov	r0, r1
	mov	r1, r2
	mov	r2, r3

	blx	r4

	pop	{r4 - r12, lr}
	movs	pc, lr

psci_invalid:
	mov	r0, #PSCI_RET_NOT_SUPPORTED
	bx	lr

ENTRY(start_el3)
	ldr	r0, =smc_vectors
	blx	setup_vector
	/* pass through */

ENTRY(start_no_el3)
	/*
	 * For no-el3, we assume that firmware launched the boot-wrapper in
	 * non-secure EL2 or EL1. We assume it has its own PSCI implementation
	 * sitting at EL3, and that this path is only taken by primary CPU.
	 */
	cpuid	r0, r1
	blx	find_logical_id
	b	psci_first_spin
