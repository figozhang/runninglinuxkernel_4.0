/*
 * arch/aarch64/include/asm/gic-v3.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#ifndef __ASM_AARCH64_GICV3_H
#define __ASM_AARCH64_GICV3_H

#define ICC_SRE_EL2	"S3_4_C12_C9_5"
#define ICC_SRE_EL3	"S3_6_C12_C12_5"
#define ICC_CTLR_EL1	"S3_0_C12_C12_4"
#define ICC_CTLR_EL3	"S3_6_C12_C12_4"
#define ICC_PMR_EL1	"S3_0_C4_C6_0"

static inline uint32_t gic_read_icc_sre(void)
{
	uint32_t val;
	asm volatile ("mrs %0, " ICC_SRE_EL3 : "=r" (val));
	return val;
}

static inline void gic_write_icc_sre(uint32_t val)
{
	asm volatile ("msr " ICC_SRE_EL3 ", %0" : : "r" (val));
}

static inline void gic_write_icc_ctlr(uint32_t val)
{
	asm volatile ("msr " ICC_CTLR_EL3 ", %0" : : "r" (val));
}

#endif
