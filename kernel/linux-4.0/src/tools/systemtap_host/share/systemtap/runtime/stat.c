/* -*- linux-c -*-
 * Statistics Aggregation
 * Copyright (C) 2005-2008, 2012 Red Hat Inc.
 * Copyright (C) 2006 Intel Corporation
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STAT_C_
#define _STAT_C_

/** @file stat.c
 * @brief Statistics Aggregation
 */
/** @addtogroup stat Statistics Aggregation
 * The Statistics aggregations keep per-cpu statistics. You
 * must create all aggregations at probe initialization and it is
 * best to not read them until probe exit. If you must read them
 * while probes are running, the values may be slightly off due
 * to a probe updating the statistics of one cpu while another cpu attempts
 * to read the same data. This will also negatively impact performance.
 *
 * If you have a need to poll Stat data while probes are running, and
 * you want to be sure the data is accurate, you can do
 * @verbatim
#define NEED_STAT_LOCKS
@endverbatim
 * This will insert per-cpu spinlocks around all accesses to Stat data,
 * which will reduce performance some.
 *
 * Stats keep track of count, sum, min and max. Average is computed
 * from the sum and count when required. Histograms are optional.
 * If you want a histogram, you must set "type" to HIST_LOG
 * or HIST_LINEAR when you call _stp_stat_init().
 *
 * @{
 */

#include "stat-common.c"


/** Initialize a Stat.
 * Call this during probe initialization to create a Stat.
 *
 * @param type HIST_NONE, HIST_LOG, or HIST_LINEAR
 *
 * For HIST_LOG, the following additional parametrs are required:
 * @param buckets - An integer specifying the number of buckets.
 *
 * For HIST_LINEAR, the following additional parametrs are required:
 * @param start - An integer. The start of the histogram.
 * @param stop - An integer. The stopping value. Should be > start.
 * @param interval - An integer. The interval.
 */
static Stat _stp_stat_init (int type, ...)
{
	int size, buckets=0, start=0, stop=0, interval=0;
	Stat st;

	if (type != HIST_NONE) {
		va_list ap;
		va_start (ap, type);

		if (type == HIST_LOG) {
			buckets = HIST_LOG_BUCKETS;
		} else {
			start = va_arg(ap, int);
			stop = va_arg(ap, int);
			interval = va_arg(ap, int);

			buckets = _stp_stat_calc_buckets(stop, start, interval);
			if (!buckets) {
				va_end (ap);
				return NULL;
			}
		}
		va_end (ap);
	}

	size = buckets * sizeof(int64_t) + sizeof(stat_data);
	st = _stp_stat_alloc (size);
	if (st == NULL)
		return NULL;

	if (_stp_stat_initialize_locks(st) != 0) {
		_stp_stat_free(st);
		return NULL;
	}

	st->hist.type = type;
	st->hist.start = start;
	st->hist.stop = stop;
	st->hist.interval = interval;
	st->hist.buckets = buckets;
	return st;
}

/** Delete Stat.
 * Call this to free all memory allocated during initialization.
 *
 * @param st Stat
 */
static void _stp_stat_del (Stat st)
{
	if (st) {
		_stp_stat_destroy_locks(st);
		_stp_stat_free(st);
	}
}

/** Add to a Stat.
 * Add an int64 to a Stat.
 *
 * @param st Stat
 * @param val Value to add
 */
static void _stp_stat_add (Stat st, int64_t val)
{
	stat_data *sd = _stp_stat_per_cpu_ptr (st, STAT_GET_CPU());
	STAT_LOCK(sd);
	__stp_stat_add (&st->hist, sd, val);
	STAT_UNLOCK(sd);
	STAT_PUT_CPU();
}


static void _stp_stat_clear_data (Stat st, stat_data *sd)
{
        int j;
        sd->count = sd->sum = sd->min = sd->max = 0;
        if (st->hist.type != HIST_NONE) {
                for (j = 0; j < st->hist.buckets; j++)
                        sd->histogram[j] = 0;
        }
}

/** Get Stats.
 * Gets the aggregated Stats for all CPUs.
 *
 * @param st Stat
 * @param clear Set if you want the data cleared after the read. Useful
 * for polling.
 * @returns A pointer to a stat.
 */
static stat_data *_stp_stat_get (Stat st, int clear)
{
	int i, j;
	stat_data *agg = _stp_stat_get_agg(st);
	stat_data *sd;
	STAT_LOCK(agg);
	_stp_stat_clear_data (st, agg);

	for_each_possible_cpu(i) {
		stat_data *sd = _stp_stat_per_cpu_ptr (st, i);
		STAT_LOCK(sd);
		if (sd->count) {
			if (agg->count == 0) {
				agg->min = sd->min;
				agg->max = sd->max;
			}
			agg->count += sd->count;
			agg->sum += sd->sum;
			if (sd->max > agg->max)
				agg->max = sd->max;
			if (sd->min < agg->min)
				agg->min = sd->min;
			if (st->hist.type != HIST_NONE) {
				for (j = 0; j < st->hist.buckets; j++)
					agg->histogram[j] += sd->histogram[j];
			}
			if (clear)
				_stp_stat_clear_data (st, sd);
		}
		STAT_UNLOCK(sd);
	}

	/*
	 * Originally this function returned the aggregate still
	 * locked and it was the caller's responsibility to unlock the
	 * aggregate. However the translator generated code that called
	 * this function wasn't unlocking it...
	 *
	 * But, the translator generates its own locks for global
	 * variables (like stats), so we don't need to return the
	 * aggregate still locked.
	 *
	 * It is possible we could even skip locking the aggregate in
	 * this function, but to be a bit paranoid lets keep the
	 * locking.
	 */
	STAT_UNLOCK(agg);
	return agg;
}


/** Clear Stats.
 * Clears the Stats.
 *
 * @param st Stat
 */
static void _stp_stat_clear (Stat st)
{
	int i;

	for_each_possible_cpu(i) {
		stat_data *sd = _stp_stat_per_cpu_ptr (st, i);
		STAT_LOCK(sd);
		_stp_stat_clear_data (st, sd);
		STAT_UNLOCK(sd);
	}
}
/** @} */
#endif /* _STAT_C_ */
