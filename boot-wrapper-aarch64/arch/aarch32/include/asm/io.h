/*
 * arch/aarch32/include/asm/io.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#ifndef __ASM_AARCH32_IO_H
#define __ASM_AARCH32_IO_H

#include <stdint.h>

#ifndef __ASSEMBLY__

static inline void raw_writel(uint32_t val, void *addr)
{
	asm volatile ("str %0, [%1]\n" : : "r" (val), "r" (addr));
}

static inline uint32_t raw_readl(void *addr)
{
	uint32_t val;

	asm volatile ("ldr %0, [%1]\n" : "=r" (val) : "r" (addr));
	return val;
}

#endif /* !__ASSEMBLY__ */

#endif
