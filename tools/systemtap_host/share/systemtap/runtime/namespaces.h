/* -*- linux-c -*- 
 * Namespace Functions
 * Copyright (C) 2015 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _NAMESPACES_H_
#define _NAMESPACES_H_


#if defined(__KERNEL__)

#include "linux/namespaces.h"

#elif defined(__DYNINST__)

#include "dyninst/namespaces.h"

#endif
#endif
