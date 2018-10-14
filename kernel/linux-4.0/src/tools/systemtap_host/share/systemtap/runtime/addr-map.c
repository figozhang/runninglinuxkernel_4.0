/* -*- linux-c -*- 
 * Map of addresses to disallow.
 * Copyright (C) 2005-2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _ADDR_MAP_C_
#define _ADDR_MAP_C_ 1


#if defined(__KERNEL__)

#include "linux/addr-map.c"

#elif defined(__DYNINST__)

#include "dyninst/addr-map.c"

#endif


#endif
