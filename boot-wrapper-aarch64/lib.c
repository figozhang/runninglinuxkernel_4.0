/*
 * lib.c - Standard utilities that might be needed by GCC
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n)
{
	int i;
	char *cdest = dest;
	const char *csrc = src;

	for (i = 0; i < n; i++)
		cdest[i] = csrc[i];

	return dest;
}

void *memset(void *s, int c, size_t n)
{
	int i;
	char *cs = s;

	for (i = 0; i < n; i++)
		cs[i] = c;

	return s;
}

/* TODO: memmove and memcmp could also be called */
