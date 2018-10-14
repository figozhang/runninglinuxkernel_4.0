/* -*- linux-c -*- 
 * Syscalls Common Header File
 * Copyright (C) 2015 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _SYSCALLS_COMMON_H_
#define _SYSCALLS_COMMON_H_

typedef struct {
	long val;
	char *name;
} _stp_val_array;

/* Convenient macro to add defines to an array */
#define V(a) {a,#a}

static void
_stp_lookup_str2(const _stp_val_array * const array, long val, char *ptr,
		 int len, int base);
static inline void
_stp_lookup_str(const _stp_val_array * const array, long val, char *ptr,
		int len);
static void
_stp_lookup_or_str2(const _stp_val_array * const array, long val, char *ptr,
		    int len, int base);
static inline void
_stp_lookup_or_str(const _stp_val_array * const array, long val, char *ptr,
		   int len);

#endif /* _SYSCALLS_COMMON_H_ */
