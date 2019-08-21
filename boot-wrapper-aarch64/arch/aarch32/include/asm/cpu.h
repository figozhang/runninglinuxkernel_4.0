/*
 * arch/aarch32/include/asm/cpu.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#ifndef __ASM_AARCH32_CPU_H
#define __ASM_AARCH32_CPU_H

#define MPIDR_ID_BITS		0x00ffffff
#define MPIDR_INVALID		(-1)

/* Only RES1 bits and CP15 barriers for the kernel */
#define HSCTLR_RESET		(3 << 28 | 3 << 22 | 1 << 18 | 1 << 16 | 1 << 11 | 3 << 4)
#define SCTLR_RESET		(3 << 22 | 1 << 11 | 1 << 5 | 3 << 4)

#define PSR_SVC			0x13
#define PSR_HYP			0x1a
#define PSR_MON			0x16
#define PSR_MODE_MASK		0x1f

#define PSR_T			(1 << 5)
#define PSR_F			(1 << 6)
#define PSR_I			(1 << 7)
#define PSR_A			(1 << 8)


#define SPSR_KERNEL		(PSR_A | PSR_I | PSR_F | PSR_HYP)

#ifndef __ASSEMBLY__

#include <stdint.h>

#ifdef __ARM_ARCH_8A__
#define sevl()		asm volatile ("sevl" : : : "memory")
#else
/* sevl doesn't exist on ARMv7. Send event globally */
#define sevl()		asm volatile ("sev" : : : "memory")
#endif

static inline unsigned long read_mpidr(void)
{
	unsigned long mpidr;

	asm volatile ("mrc	p15, 0, %0, c0, c0, 5\n" : "=r" (mpidr));
	return mpidr & MPIDR_ID_BITS;
}

static inline uint32_t read_id_pfr1(void)
{
	uint32_t val;

	asm volatile ("mrc	p15, 0, %0, c0, c1, 1\n" : "=r" (val));
	return val;
}

static inline uint32_t read_clidr(void)
{
	uint32_t val;

	asm volatile ("mrc	p15, 1, %0, c0, c0, 1" : "=r" (val));
	return val;
}

static inline uint32_t read_ccsidr(void)
{
	uint32_t val;

	asm volatile ("mrc	p15, 1, %0, c0, c0, 0" : "=r" (val));
	return val;
}

static inline void write_csselr(uint32_t val)
{
	asm volatile ("mcr	p15, 2, %0, c0, c0, 0" : : "r" (val));
}

static inline void dccisw(uint32_t val)
{
	asm volatile ("mcr	p15, 0, %0, c7, c14, 2" : : "r" (val));
}

static inline void iciallu(void)
{
	uint32_t val = 0;

	asm volatile ("mcr	p15, 0, %0, c7, c5, 0" : : "r" (val));
}

static inline int has_gicv3_sysreg(void)
{
	return !!((read_id_pfr1() >> 28) & 0xf);
}

#endif /* __ASSEMBLY__ */

#endif
