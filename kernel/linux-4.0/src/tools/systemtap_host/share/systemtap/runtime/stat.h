/* -*- linux-c -*- 
 * Statistics Header
 * Copyright (C) 2005, 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STAT_H_
#define _STAT_H_

/* maximum buckets for a linear histogram */
#ifndef STP_MAX_BUCKETS
#define STP_MAX_BUCKETS 128
#endif

/* buckets for log histogram. */
#define HIST_LOG_BUCKETS 128
#define HIST_LOG_BUCKET0 64

/** histogram type */
enum histtype { HIST_NONE, HIST_LOG, HIST_LINEAR };

/** Statistics are stored in this struct.  This is per-cpu or per-node data 
    and is variable length due to the unknown size of the histogram. */
struct stat_data {
	int64_t count;
	int64_t sum;
	int64_t min, max;
#ifdef NEED_STAT_LOCKS
#ifdef __KERNEL__
	spinlock_t lock;
#else  /* !__KERNEL__ */
	pthread_mutex_t lock;
#endif	/* !__KERNEL__ */
#endif
	int64_t histogram[];
};
typedef struct stat_data stat_data;

/** Information about the histogram data collected. This data 
    is global and not duplicated per-cpu. */

struct _Hist {
	enum histtype type;
	int start;
	int stop;
	int interval;
	int buckets;
};
typedef struct _Hist *Hist;

/* The specific runtimes define struct _Stat and its alloc/free */
#if defined(__KERNEL__)
#include "linux/stat_runtime.h"
#elif defined(__DYNINST__)
#include "dyninst/stat_runtime.h"
#endif

#endif /* _STAT_H_ */
