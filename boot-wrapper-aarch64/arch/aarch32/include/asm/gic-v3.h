/*
 * arch/aarch32/include/asm/gic-v3.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#ifndef __ASM_AARCH32_GICV3_H
#define __ASM_AARCH32_GICV3_H

static inline uint32_t gic_read_icc_sre(void)
{
	uint32_t val;
	asm volatile ("mrc p15, 6, %0, c12, c12, 5" : "=r" (val));
	return val;
}

static inline void gic_write_icc_sre(uint32_t val)
{
	asm volatile ("mcr p15, 6, %0, c12, c12, 5" : : "r" (val));
}

static inline void gic_write_icc_ctlr(uint32_t val)
{
	asm volatile ("mcr p15, 6, %0, c12, c12, 4" : : "r" (val));
}

#endif
