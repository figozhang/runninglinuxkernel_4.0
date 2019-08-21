/*
 * cache.c - simple cache clean+invalidate code
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <cpu.h>

void flush_caches(void)
{
	unsigned int level;
	uint32_t clidr = read_clidr();
	unsigned int max_level = (clidr >> 24) & 0x7;

	uint32_t ccsidr;

	if (max_level == 0)
		return;

	for (level = 0; level < max_level; level++) {
		uint32_t cache_type = (clidr >> (level * 3)) & 0x7;
		unsigned int line_size, num_ways, num_sets, way_shift;
		unsigned int way, set;

		if (cache_type == 1)
			/* No dcache at this level */
			continue;

		write_csselr(level << 1);
		isb();
		ccsidr = read_ccsidr();

		line_size = (ccsidr & 0x7) + 4; /* log2 line size */
		num_ways = ((ccsidr >> 3) & 0x3ff) + 1;
		num_sets = ((ccsidr >> 13) & 0x7fff) + 1;

		way_shift = clz(num_ways - 1);
		for (way = 0; way < num_ways; way++) {
			for (set = 0; set < num_sets; set++) {
				uint32_t command = level << 1;
				command |= way << way_shift;
				command |= set << line_size;

				dccisw(command);
				dsb(sy);
			}
		}

		dsb(sy);
	}
	dsb(sy);
	iciallu();
	dsb(sy);
	isb();
}
