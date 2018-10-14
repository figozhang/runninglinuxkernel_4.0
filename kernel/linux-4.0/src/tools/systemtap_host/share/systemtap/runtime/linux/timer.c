/* -*- linux-c -*- 
 * Kernel Timer Functions
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_TIMER_C_
#define _LINUX_TIMER_C_

#include "timer.h"

static void _stp_hrtimer_init(void)
{
#if defined(STAPCONF_HRTIMER_GET_RES)
	struct timespec res;
	hrtimer_get_res (CLOCK_MONOTONIC, &res);
	stap_hrtimer_resolution = timespec_to_ns(&res);
#else
	stap_hrtimer_resolution = hrtimer_resolution;
#endif
}


static inline ktime_t _stp_hrtimer_get_interval(struct stap_hrtimer_probe *stp)
{
	unsigned long nsecs;
	uint64_t i = stp->intrv;

	if (stp->rnd != 0) {
#if 1
		// XXX: why not use stp_random_pm instead of this?
	        int64_t r;
	        get_random_bytes(&r, sizeof(r));

		// ensure that r is positive
	        r &= ((uint64_t)1 << (8*sizeof(r) - 1)) - 1;
	        r = _stp_mod64(NULL, r, (2*stp->rnd+1));
	        r -= stp->rnd;
	        i += r;
#else
		i += _stp_random_pm(stp->rnd);
#endif
	}
	if (unlikely(i < stap_hrtimer_resolution))
		i = stap_hrtimer_resolution;
	nsecs = do_div(i, NSEC_PER_SEC);
	return ktime_set(i, nsecs);
}


static inline void _stp_hrtimer_update(struct stap_hrtimer_probe *stp)
{
	ktime_t time;

	time = ktime_add(hrtimer_get_expires(&stp->hrtimer),
			 _stp_hrtimer_get_interval(stp));
	hrtimer_set_expires(&stp->hrtimer, time);
}


static int
_stp_hrtimer_start(struct stap_hrtimer_probe *stp)
{
	(void)hrtimer_start(&stp->hrtimer, _stp_hrtimer_get_interval(stp),
			    HRTIMER_MODE_REL);
	return 0;
}

static int
_stp_hrtimer_create(struct stap_hrtimer_probe *stp,
		    hrtimer_return_t (*function)(struct hrtimer *))
{
	hrtimer_init(&stp->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	stp->hrtimer.function = function;
	return 0;
}

// For kernel-mode, there is no difference between cancel/delete.

static void
_stp_hrtimer_cancel(struct stap_hrtimer_probe *stp)
{
	hrtimer_cancel(&stp->hrtimer);
}

static void
_stp_hrtimer_delete(struct stap_hrtimer_probe *stp)
{
	_stp_hrtimer_cancel(stp);
}

#endif /* _LINUX_TIMER_C_ */
