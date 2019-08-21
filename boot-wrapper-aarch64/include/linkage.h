/*
 * include/linkage.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */


#ifndef __LINKAGE_H
#define __LINKAGE_H

#ifdef __ASSEMBLY__

#define ENTRY(name)				\
	.globl name;				\
	.type  name, %function;			\
	name:

#endif /* __ASSEMBLY__ */
#endif
