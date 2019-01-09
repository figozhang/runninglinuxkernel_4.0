/* -*- linux-c -*- 
 * Memory allocation functions
 * Copyright (C) 2005-2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _ALLOC_C_
#define _ALLOC_C_


#if defined(__KERNEL__)

#include "linux/alloc.c"

#elif defined(__DYNINST__)

#include "dyninst/alloc.c"

#endif


#endif /* _ALLOC_C_ */
