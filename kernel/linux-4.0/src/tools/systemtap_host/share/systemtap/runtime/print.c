/* -*- linux-c -*- 
 * Print Functions
 * Copyright (C) 2007-2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _PRINT_C_
#define _PRINT_C_


#if defined(__KERNEL__)

#include "linux/print.c"

#elif defined(__DYNINST__)

#include "dyninst/print.c"

#endif


#endif /* _PRINT_C_ */
