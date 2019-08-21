/*
 * include/spin.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#ifndef __SPIN_H
#define __SPIN_H

#include <compiler.h>

void __noreturn spin(unsigned long *mbox, unsigned long invalid, int is_entry);

void __noreturn first_spin(unsigned int cpu, unsigned long *mbox,
			   unsigned long invalid_addr);

#endif
