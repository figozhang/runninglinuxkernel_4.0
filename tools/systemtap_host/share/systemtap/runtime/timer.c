/* -*- linux-c -*- 
 * Timer Functions
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _TIMER_C_
#define _TIMER_C_


#if defined(__KERNEL__)

#include "linux/timer.c"

#elif defined(__DYNINST__)

#include "dyninst/timer.c"

#endif


#endif /* _TIMER_C_ */
