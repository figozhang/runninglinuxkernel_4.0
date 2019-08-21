/*
 * boot_common.c - common spin function for all boot methods
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#include <cpu.h>
#include <spin.h>

extern unsigned long entrypoint;
extern unsigned long dtb;

void init_platform(void);
void flush_caches(void);

void __noreturn jump_kernel(unsigned long address,
			    unsigned long a0,
			    unsigned long a1,
			    unsigned long a2,
			    unsigned long a3);

const unsigned long id_table[] = { CPU_IDS };

/**
 * Wait for an address to appear in mbox, and jump to it.
 *
 * @mbox: location to watch
 * @invalid: value of an invalid address, 0 or -1 depending on the boot method
 * @is_entry: when true, pass boot parameters to the kernel, instead of 0
 */
void __noreturn spin(unsigned long *mbox, unsigned long invalid, int is_entry)
{
	unsigned long addr = invalid;

	while (addr == invalid) {
		wfe();
		addr = *mbox;
	}

	if (is_entry)
#ifdef KERNEL_32
		jump_kernel(addr, 0, ~0, (unsigned long)&dtb, 0);
#else
		jump_kernel(addr, (unsigned long)&dtb, 0, 0, 0);
#endif

	jump_kernel(addr, 0, 0, 0, 0);

	unreachable();
}

/**
 * Primary CPU finishes platform initialisation and jumps to the kernel.
 * Secondaries are parked, waiting for their mbox to contain a valid address.
 *
 * @cpu: logical CPU number
 * @mbox: location to watch
 * @invalid: value of an invalid address, 0 or -1 depending on the boot method
 */
void __noreturn first_spin(unsigned int cpu, unsigned long *mbox,
			   unsigned long invalid)
{
	flush_caches();

	if (cpu == 0) {
		init_platform();

		*mbox = (unsigned long)&entrypoint;
		sevl();
		spin(mbox, invalid, 1);
	} else {
		*mbox = invalid;
		spin(mbox, invalid, 0);
	}

	unreachable();
}
