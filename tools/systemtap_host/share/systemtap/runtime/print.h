/* -*- linux-c -*- 
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_PRINT_H_
#define _STP_PRINT_H_

static int _stp_print_init(void);
static void _stp_print_cleanup(void);
static void *_stp_reserve_bytes(int numbytes);
static void _stp_unreserve_bytes (int numbytes);
static void _stp_printf(const char *fmt, ...);
static void _stp_print(const char *str);
static inline void _stp_print_flush(void);

#include "vsprintf.h"

#endif /* _STP_PRINT_H_ */
