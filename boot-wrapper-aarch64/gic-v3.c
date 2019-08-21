/*
 * gic-v3.c
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
#define GICD_IGROUP0			0x80
#define GICD_IGRPMOD0			0xd00
#define GICD_IGROUPR0E			0x1000
#define GICD_IGRPMODR0E			0x3400

#define GICD_CTLR_EnableGrp0		(1 << 0)
#define GICD_CTLR_EnableGrp1ns		(1 << 1)
#define GICD_CTLR_EnableGrp1s		(1 << 2)
#define GICD_CTLR_ARE_S			(1 << 4)
#define GICD_CTLR_ARE_NS		(1 << 5)
#define GICD_TYPER_ITLineNumber		0x1f
#define GICD_TYPER_ESPI_range(r)	(((r) >> 27) & 0x1f)

#define GICR_WAKER			0x14

#define GICR_TYPER			0x8
#define GICR_TYPER_PPInum(r)		(((r) >> 27) & 0x1f)
#define GICR_IGROUP0			0x80
#define GICR_IGRPMOD0			0xD00

#define GICR_WAKER_ProcessorSleep	(1 << 1)
#define GICR_WAKER_ChildrenAsleep	(1 << 2)

#define GICR_TYPER_VLPIS		(1 << 1)
#define GICR_TYPER_Last			(1 << 4)

#define ICC_SRE_SRE			(1 << 0)
#define ICC_SRE_Enable			(1 << 3)

void gic_secure_init_primary(void)
{
	unsigned int i;
	void *gicr_ptr = (void *)GIC_RDIST_BASE;
	void *gicd_base = (void *)GIC_DIST_BASE;
	uint32_t typer;

	raw_writel(GICD_CTLR_EnableGrp0 | GICD_CTLR_EnableGrp1ns
		| GICD_CTLR_EnableGrp1s | GICD_CTLR_ARE_S | GICD_CTLR_ARE_NS,
		gicd_base + GICD_CTLR);

	do {
		/*
		 * Wake up redistributor: kick ProcessorSleep and wait for
		 * ChildrenAsleep to be 0.
		 */
		uint32_t waker = raw_readl(gicr_ptr + GICR_WAKER);
		waker &= ~GICR_WAKER_ProcessorSleep;
		raw_writel(waker, gicr_ptr + GICR_WAKER);
		dsb(st);
		isb();
		do {
			waker = raw_readl(gicr_ptr + GICR_WAKER);
		} while (waker & GICR_WAKER_ChildrenAsleep);

		/*
		 * GICR_TYPER is 64-bit, but we do not need the upper half that
		 * contains CPU affinity.
		 */
		typer = raw_readl(gicr_ptr + GICR_TYPER);

		gicr_ptr += 0x10000; /* Go to SGI_Base */
		for (i = 0; i < (1 + GICR_TYPER_PPInum(typer)); i++) {
			raw_writel(~0x0, gicr_ptr + GICR_IGROUP0 + i * 4);
			raw_writel(0x0, gicr_ptr + GICR_IGRPMOD0 + i * 4);
		}

		/* Next redist */
		gicr_ptr += 0x10000;
		if (typer & GICR_TYPER_VLPIS)
			gicr_ptr += 0x20000;

	} while (!(typer & GICR_TYPER_Last));

	typer = raw_readl(gicd_base + GICD_TYPER);
	for (i = 1; i < (typer & GICD_TYPER_ITLineNumber); i++) {
		raw_writel(~0x0, gicd_base + GICD_IGROUP0 + i * 4);
		raw_writel(0x0, gicd_base + GICD_IGRPMOD0 + i * 4);
	}
	for (i = 0; i < GICD_TYPER_ESPI_range(typer); i++) {
		raw_writel(~0x0, gicd_base + GICD_IGROUPR0E + i * 4);
		raw_writel(0x0, gicd_base + GICD_IGRPMODR0E + i * 4);
	}
}

void gic_secure_init(void)
{
	uint32_t cpu = read_mpidr();

	uint32_t sre;

	/*
	 * If GICv3 is not available, skip initialisation. The OS will probably
	 * fail with a warning, but this should be easier to debug than a
	 * failure within the boot wrapper.
	 */
	if (!has_gicv3_sysreg())
		return;

	if (cpu == 0)
		gic_secure_init_primary();

	sre = gic_read_icc_sre();
	sre |= ICC_SRE_Enable | ICC_SRE_SRE;
	gic_write_icc_sre(sre);
	isb();

	gic_write_icc_ctlr(0);
	isb();
}
