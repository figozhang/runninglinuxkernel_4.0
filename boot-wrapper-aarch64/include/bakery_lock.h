/*
 * include/bakery_lock.h
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 */

#ifndef __BAKERY_LOCK_H
#define __BAKERY_LOCK_H

#include <stdint.h>

#include <compiler.h>

/*
 * We *must* access this structure with 16 or 8 bit accesses, aligned on 16-bit.
 * Helpers read/write_ticket_once should be used for this.
 */
typedef union {
	struct __packed {
		uint16_t number		: 15;
		uint16_t choosing	: 1;
	};
	uint16_t __val;
} bakery_ticket_t;

#define write_ticket_once(ticket, choosing_, number_)			\
({									\
	bakery_ticket_t __t = {						\
		.number = (number_),					\
		.choosing = (choosing_),				\
	};								\
	*(volatile uint16_t *)&(ticket).__val = __t.__val;		\
})

#define read_ticket_once(ticket)					\
({									\
	bakery_ticket_t __t;						\
	__t.__val = *(volatile uint16_t *)&(ticket).__val;		\
	__t;								\
})

void bakery_lock(bakery_ticket_t *tickets, unsigned self);
void bakery_unlock(bakery_ticket_t *tickets, unsigned self);

#endif
