/*
 * platform.c - code to initialise everything required when first booting.
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <stdint.h>

#include <asm/io.h>

#define PL011_UARTDR		0x00
#define PL011_UARTFR		0x18
#define PL011_UARTIBRD		0x24
#define PL011_UARTFBRD		0x28
#define PL011_UART_LCR_H	0x2c
#define PL011_UARTCR		0x30

#define PL011_UARTFR_BUSY	(1 << 3)
#define PL011_UARTFR_FIFO_FULL	(1 << 5)

#define PL011(reg)	((void *)UART_BASE + PL011_##reg)

#define V2M_SYS_CFGDATA		0xa0
#define V2M_SYS_CFGCTRL		0xa4

#define V2M_SYS(reg)	((void *)SYSREGS_BASE + V2M_SYS_##reg)

static void print_string(const char *str)
{
	uint32_t flags;

	while (*str) {
		do
			flags = raw_readl(PL011(UARTFR));
		while (flags & PL011_UARTFR_FIFO_FULL);

		raw_writel(*str++, PL011(UARTDR));

		do
			flags = raw_readl(PL011(UARTFR));
		while (flags & PL011_UARTFR_BUSY);
	}
}

void init_platform(void)
{
	/*
	 * UART initialisation (38400 8N1)
	 */
	raw_writel(0x10,	PL011(UARTIBRD));
	raw_writel(0x0,		PL011(UARTFBRD));
	/* Set parameters to 8N1 and enable the FIFOs */
	raw_writel(0x70,	PL011(UART_LCR_H));
	/* Enable the UART, TXen and RXen */
	raw_writel(0x301,	PL011(UARTCR));

	print_string("Boot-wrapper v0.2\r\n\r\n");

	/*
	 * CLCD output site MB
	 */
	raw_writel(0x0,		V2M_SYS(CFGDATA));
	/* START | WRITE | MUXFPGA | SITE_MB */
	raw_writel((1 << 31) | (1 << 30) | (7 << 20) | (0 << 16),
				V2M_SYS(CFGCTRL));
}
