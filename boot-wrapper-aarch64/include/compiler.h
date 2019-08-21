/*
 * include/compiler.h - common compiler defines
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 *
 * Note: we only support GCC.
 */
#ifndef __COMPILER_H
#define __COMPILER_H

#define unreachable()	__builtin_unreachable()

#define __noreturn	__attribute__((noreturn))
#define __packed	__attribute__((packed))

#endif
