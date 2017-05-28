/* -*- linux-c -*- 
 * Kernel Timer Functions
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_TIMER_H_
#define _LINUX_TIMER_H_

// If we're on kernels < 2.6.17, then hrtimers are not supported.
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#error "hrtimers not implemented"
#else /* kernel version >= 2.6.17 */
#include <linux/hrtimer.h>

static unsigned long stap_hrtimer_resolution = 0;

struct stap_hrtimer_probe {
	struct hrtimer hrtimer;
	const struct stap_probe * probe;
	int64_t intrv;
	int64_t rnd;
	unsigned enabled;
};

// The function signature changed in 2.6.21.
#ifdef STAPCONF_HRTIMER_REL
typedef int hrtimer_return_t;
#else
typedef enum hrtimer_restart hrtimer_return_t;
#endif


// autoconf: add get/set expires if missing (pre 2.6.28-rc1)
#ifndef STAPCONF_HRTIMER_GETSET_EXPIRES
#define hrtimer_get_expires(timer) ((timer)->expires)
#define hrtimer_set_expires(timer, time) (void)((timer)->expires = (time))
#endif

// autoconf: adapt to HRTIMER_REL -> HRTIMER_MODE_REL renaming near 2.6.21
#ifdef STAPCONF_HRTIMER_REL
#define HRTIMER_MODE_REL HRTIMER_REL
#endif

#endif /* kernel version >= 2.6.17 */

#endif /* _LINUX_TIMER_H_ */
