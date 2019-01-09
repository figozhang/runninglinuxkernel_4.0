/* -*- linux-c -*- 
 * Copy from user space functions
 * Copyright (C) 2005-2012 Red Hat Inc.
 * Copyright (C) 2005 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _COPY_C_		/* -*- linux-c -*- */
#define _COPY_C_

#include "stp_string.c"


#if defined(__KERNEL__)

#include "linux/copy.c"

#elif defined(__DYNINST__)

#include "dyninst/copy.c"

#endif


#endif /* _COPY_C_ */
