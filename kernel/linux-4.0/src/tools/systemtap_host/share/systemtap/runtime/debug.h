/* Systemtap Debug Macros
 * Copyright (C) 2008-2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_DEBUG_H_
#define _STP_DEBUG_H_


#if defined(__KERNEL__)

#include "linux/debug.h"

#elif defined(__DYNINST__)

#include "dyninst/debug.h"

#endif


#endif /* _STP_DEBUG_H_ */
