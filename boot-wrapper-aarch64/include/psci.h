/*
 * include/psci.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */
#ifndef __PSCI_H
#define __PSCI_H

#define PSCI_CPU_OFF			0x84000002
#define PSCI_CPU_ON_32			0x84000003
#define PSCI_CPU_ON_64			0xc4000003

#define PSCI_RET_SUCCESS		0
#define PSCI_RET_NOT_SUPPORTED		(-1)
#define PSCI_RET_INVALID_PARAMETERS	(-2)
#define PSCI_RET_DENIED			(-3)
#define PSCI_RET_ALREADY_ON		(-4)
#define PSCI_RET_ON_PENDING		(-5)
#define PSCI_RET_INTERNAL_FAILURE	(-6)
#define PSCI_RET_NOT_PRESENT		(-7)
#define PSCI_RET_DISABLED		(-8)

#define PSCI_ADDR_INVALID		(-1)

#endif
