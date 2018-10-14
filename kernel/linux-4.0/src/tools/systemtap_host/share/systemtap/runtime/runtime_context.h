/*
 * Header file containing code that needs to be included after the
 * context structure is defined.
 *
 * Copyright (C) 2011 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _RUNTIME_CONTEXT_H_
#define _RUNTIME_CONTEXT_H_

#if defined(__KERNEL__)
#include "linux/runtime_context.h"
#elif defined(__DYNINST__)
#include "dyninst/runtime_context.h"
#endif

#include "print.c"
#include "io.c"				// needs to be included after print.c

#endif /* _RUNTIME_CONTEXT_H_ */
