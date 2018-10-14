/* -*- linux-c -*- 
 * Locking helper function api to support preempt-rt variant raw locks
 * and keep legacy locking compatibility intact.
 *
 * Author: Santosh Shukla <sshukla@mvista.com>
 *
 * Copyright (C) 2014 Red Hat Inc.
 * 
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 * */

#ifndef _STP_HELPER_LOCK_H_
#define _STP_HELPER_LOCK_H_

#include <linux/spinlock.h>

#ifdef CONFIG_PREEMPT_RT_FULL

#define stp_spinlock_t raw_spinlock_t

#define STP_DEFINE_SPINLOCK(lock)	DEFINE_RAW_SPINLOCK(lock)

static inline void stp_spin_lock_init(raw_spinlock_t *lock)	{ raw_spin_lock_init(lock); }

static inline void stp_spin_lock(raw_spinlock_t *lock)		{ raw_spin_lock(lock); }
static inline void stp_spin_unlock(raw_spinlock_t *lock)	{ raw_spin_unlock(lock); }

static inline void stp_spin_unlock_wait(raw_spinlock_t *lock)	{ raw_spin_unlock_wait(lock); }

#define stp_spin_lock_irqsave(lock, flags)		raw_spin_lock_irqsave(lock, flags)
#define stp_spin_unlock_irqrestore(lock, flags)		raw_spin_unlock_irqrestore(lock, flags)


#define STP_DEFINE_RWLOCK(lock)		DEFINE_RAW_SPINLOCK(lock)

static inline void stp_read_lock(raw_spinlock_t *lock)		{ raw_spin_lock(lock); }
static inline void stp_read_unlock(raw_spinlock_t *lock)	{ raw_spin_unlock(lock); }
static inline void stp_write_lock(raw_spinlock_t *lock)		{ raw_spin_lock(lock); }
static inline void stp_write_unlock(raw_spinlock_t *lock)	{ raw_spin_unlock(lock); }

#define stp_read_lock_irqsave(lock, flags)		raw_spin_lock_irqsave(lock, flags)
#define stp_read_unlock_irqrestore(lock, flags)		raw_spin_unlock_irqrestore(lock, flags)
#define stp_write_lock_irqsave(lock, flags)		raw_spin_lock_irqsave(lock, flags)
#define stp_write_unlock_irqrestore(lock, flags) 	raw_spin_unlock_irqrestore(lock, flags)
  
#else

#define stp_spinlock_t spinlock_t

#define STP_DEFINE_SPINLOCK(lock)	DEFINE_SPINLOCK(lock)

static inline void stp_spin_lock_init(spinlock_t *lock)		{ spin_lock_init(lock); }

static inline void stp_spin_lock(spinlock_t *lock)		{ spin_lock(lock); }
static inline void stp_spin_unlock(spinlock_t *lock)		{ spin_unlock(lock); }

static inline void stp_spin_unlock_wait(spinlock_t *lock)	{ spin_unlock_wait(lock); }

#define stp_spin_lock_irqsave(lock, flags)		spin_lock_irqsave(lock, flags)
#define stp_spin_unlock_irqrestore(lock, flags)		spin_unlock_irqrestore(lock, flags)

#define STP_DEFINE_RWLOCK(lock)				DEFINE_RWLOCK(lock)

static inline void stp_read_lock(rwlock_t *lock)	{ read_lock(lock); }
static inline void stp_read_unlock(rwlock_t *lock)	{ read_unlock(lock); }
static inline void stp_write_lock(rwlock_t *lock)	{ write_lock(lock); }
static inline void stp_write_unlock(rwlock_t *lock)	{ write_unlock(lock); }

#define stp_read_lock_irqsave(lock, flags)		read_lock_irqsave(lock, flags)
#define stp_read_unlock_irqrestore(lock, flags)		read_unlock_irqrestore(lock, flags)
#define stp_write_lock_irqsave(lock, flags)		write_lock_irqsave(lock, flags)
#define stp_write_unlock_irqrestore(lock, flags) 	write_unlock_irqrestore(lock, flags)

#endif

#endif /* _STP_HELPER_LOCK_H_ */

