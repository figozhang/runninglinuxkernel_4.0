/* probe locking header file
 * Copyright (C) 2009-2010 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STAPLINUX_PROBE_LOCK_H
#define _STAPLINUX_PROBE_LOCK_H

#include <linux/spinlock.h>

// XXX: old 2.6 kernel hack
#ifndef read_trylock
#define read_trylock(x) ({ read_lock(x); 1; })
#endif

struct stp_probe_lock {
	#ifdef STP_TIMING
	atomic_t *skipped;
	#endif
	rwlock_t *lock;
	unsigned write_p;
};


static void
stp_unlock_probe(const struct stp_probe_lock *locks, unsigned num_locks)
{
	unsigned i;
	for (i = num_locks; i-- > 0;) {
		if (locks[i].write_p)
			write_unlock(locks[i].lock);
		else
			read_unlock(locks[i].lock);
	}
}


static unsigned
stp_lock_probe(const struct stp_probe_lock *locks, unsigned num_locks)
{
	unsigned i, retries = 0;
	for (i = 0; i < num_locks; ++i) {
		if (locks[i].write_p)
			while (!write_trylock(locks[i].lock)) {
#if !defined(STAP_SUPPRESS_TIME_LIMITS_ENABLE)
				if (++retries > MAXTRYLOCK)
					goto skip;
#endif
				udelay (TRYLOCKDELAY);
			}
		else
			while (!read_trylock(locks[i].lock)) {
#if !defined(STAP_SUPPRESS_TIME_LIMITS_ENABLE)
				if (++retries > MAXTRYLOCK)
					goto skip;
#endif
				udelay (TRYLOCKDELAY);
			}
	}
	return 1;

skip:
	atomic_inc(skipped_count());
#ifdef STP_TIMING
	atomic_inc(locks[i].skipped);
#endif
	stp_unlock_probe(locks, i);
	return 0;
}


#endif /* _STAPLINUX_PROBE_LOCK_H */
