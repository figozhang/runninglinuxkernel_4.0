/* -*- linux-c -*- 
 * I/O for printing warnings, errors and debug messages
 * Copyright (C) 2005-2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _IO_C_
#define _IO_C_


#if defined(__KERNEL__)

#include "linux/io.c"

#elif defined(__DYNINST__)

#include "dyninst/io.c"

#endif


#endif /* _IO_C_ */
