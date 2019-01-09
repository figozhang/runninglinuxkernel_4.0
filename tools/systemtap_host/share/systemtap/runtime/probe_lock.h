/* probe locking header file
 * Copyright (C) 2009-2010 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _PROBE_LOCK_H
#define _PROBE_LOCK_H


#if defined(__KERNEL__)

#include "linux/probe_lock.h"

#elif defined(__DYNINST__)

#include "dyninst/probe_lock.h"

#endif


#endif /* _PROBE_LOCK_H */
