/* -*- linux-c -*- 
 * Timer Functions
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _TIMER_H_
#define _TIMER_H_


#if defined(__KERNEL__)

#include "linux/timer.h"

#elif defined(__DYNINST__)

#error "no dyninst/timer.h"

#endif


#endif /* _TIMER_H_ */
