/*
 * gic.c - Secure gic initialisation for stand-alone Linux booting
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <stdint.h>

#include <cpu.h>
#include <asm/gic-v3.h>
#include <asm/io.h>

#define GICD_CTLR			0x0
#define GICD_TYPER			0x4
#define GICD_IGROUPRn			0x80

#define GICD_CTLR_EnableGrp0		(1 << 0)
#define GICD_CTLR_EnableGrp1		(1 << 1)
#define GICD_TYPER_ITLineNumber		0x1f

#define GICC_CTLR			0x0
#define GICC_PMR			0x4

#define GICC_CTLR_EnableGrp0		(1 << 0)
#define GICC_CTLR_EnableGrp1		(1 << 1)

void gic_secure_init(void)
{
	unsigned int i;

	uint32_t cpu = read_mpidr();
	void *gicd_base = (void *)GIC_DIST_BASE;
	void *gicc_base = (void *)GIC_CPU_BASE;

	/* Set local interrupts to Group 1 (those fields are banked) */
	raw_writel(~0, gicd_base + GICD_IGROUPRn);

	if (cpu == 0) {
		uint32_t typer = raw_readl(gicd_base + GICD_TYPER);

		/* Set SPIs to Group 1 */
		for (i = 1; i < (typer & GICD_TYPER_ITLineNumber); i++)
			raw_writel(~0, gicd_base + GICD_IGROUPRn + i * 4);

		raw_writel(GICD_CTLR_EnableGrp0 | GICD_CTLR_EnableGrp1,
			   gicd_base + GICD_CTLR);
	}

	raw_writel(GICC_CTLR_EnableGrp0 | GICC_CTLR_EnableGrp1,
		   gicc_base + GICC_CTLR);

	/* Allow NS access to GICC_PMR */
	raw_writel(1 << 7, gicc_base + GICC_PMR);
}
