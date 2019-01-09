/* main header file
 * Copyright (C) 2005-2012 Red Hat Inc.
 * Copyright (C) 2005-2006 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _RUNTIME_H_
#define _RUNTIME_H_

/* Forward Declarations for routines in runtime_context.h. */
static int _stp_runtime_contexts_alloc(void);
static void _stp_runtime_contexts_free(void);
static int _stp_runtime_get_data_index(void);
static struct context *_stp_runtime_entryfn_get_context(void);
static void _stp_runtime_entryfn_put_context(struct context *);
static struct context *_stp_runtime_get_context(void);

#if defined(__KERNEL__)

#include "linux/runtime.h"

#elif defined(__DYNINST__)

#include "dyninst/runtime.h"

#endif


#endif /* _RUNTIME_H_ */
