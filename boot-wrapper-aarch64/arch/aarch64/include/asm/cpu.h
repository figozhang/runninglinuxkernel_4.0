/*
 * arch/aarch64/include/asm/cpu.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#ifndef __ASM_AARCH64_CPU_H
#define __ASM_AARCH64_CPU_H

#define MPIDR_ID_BITS		0xff00ffffff

#define CURRENTEL_EL3		(3 << 2)

/*
 * RES1 bits,  little-endian, caches and MMU off, no alignment checking,
 * no WXN.
 */
#define SCTLR_EL2_RESET		(3 << 28 | 3 << 22 | 1 << 18 | 1 << 16 | 1 << 11 | 3 << 4)

#define SPSR_A			(1 << 8)	/* System Error masked */
#define SPSR_D			(1 << 9)	/* Debug masked */
#define SPSR_I			(1 << 7)	/* IRQ masked */
#define SPSR_F			(1 << 6)	/* FIQ masked */
#define SPSR_T			(1 << 5)	/* Thumb */
#define SPSR_EL2H		(9 << 0)	/* EL2 Handler mode */
#define SPSR_HYP		(0x1a << 0)	/* M[3:0] = hyp, M[4] = AArch32 */

#define CPTR_EL3_EZ		(1 << 8)

#define ZCR_EL3			s3_6_c1_c2_0
#define ZCR_EL3_LEN_MASK	0x1ff

#define SCTLR_EL1_CP15BEN	(1 << 5)
#define SCTLR_EL1_RES1		(3 << 28 | 3 << 22 | 1 << 11)

#ifdef KERNEL_32
/* 32-bit kernel decompressor uses CP15 barriers */
#define SCTLR_EL1_RESET		(SCTLR_EL1_RES1 | SCTLR_EL1_CP15BEN)
#define SPSR_KERNEL		(SPSR_A | SPSR_I | SPSR_F | SPSR_HYP)
#else
#define SCTLR_EL1_RESET		SCTLR_EL1_RES1
#define SPSR_KERNEL		(SPSR_A | SPSR_D | SPSR_I | SPSR_F | SPSR_EL2H)
#endif

#ifndef __ASSEMBLY__

#include <stdint.h>

#define sevl()		asm volatile ("sevl\n" : : : "memory")

static inline unsigned long read_mpidr(void)
{
	unsigned long mpidr;

	asm volatile ("mrs	%0, mpidr_el1\n" : "=r" (mpidr));
	return mpidr & MPIDR_ID_BITS;
}

static inline uint64_t read_id_aa64pfr0(void)
{
	uint64_t val;

	asm volatile ("mrs	%0, id_aa64pfr0_el1\n" : "=r" (val));
	return val;
}

static inline uint32_t read_clidr(void)
{
	uint32_t val;

	asm volatile ("mrs	%0, clidr_el1" : "=r" (val));
	return val;
}

static inline uint32_t read_ccsidr(void)
{
	uint32_t val;

	asm volatile ("mrs	%0, ccsidr_el1" : "=r" (val));
	return val;
}

static inline void write_csselr(uint32_t val)
{
	asm volatile ("msr	csselr_el1, %0" : : "r" (val));
}

static inline void dccisw(uint32_t val)
{
	asm volatile ("dc	cisw, %0" : : "r" (val));
}

static inline void iciallu(void)
{
	asm volatile ("ic	iallu");
}

static inline int has_gicv3_sysreg(void)
{
	return !!((read_id_aa64pfr0() >> 24) & 0xf);
}

#endif /* !__ASSEMBLY__ */

#endif
