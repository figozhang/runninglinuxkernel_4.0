/* -*- linux-c -*- */
/* Math functions
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _ARITH_C_ 
#define _ARITH_C_


#if defined(__KERNEL__)

#include "linux/arith.c"

#elif defined(__DYNINST__)

#include "dyninst/arith.c"

#endif


#endif /* _ARITH_C_ */
