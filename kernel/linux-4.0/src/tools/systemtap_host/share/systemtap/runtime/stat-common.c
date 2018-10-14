/* -*- linux-c -*- 
 * common stats functions for aggragations and maps
 * Copyright (C) 2005, 2006, 2007, 2008 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STAT_COMMON_C_
#define _STAT_COMMON_C_
#include "stat.h"

static int _stp_stat_calc_buckets(int stop, int start, int interval)
{
	int buckets;

	if (interval == 0) {
		_stp_warn("histogram: interval cannot be zero.\n");
		return 0;
	}

	/* don't forget buckets for underflow and overflow */
	buckets = (stop - start) / interval + 3;

	if (buckets > STP_MAX_BUCKETS || buckets < 3) {
		_stp_warn("histogram: Number of buckets must be between 1 and %d\n"
			  "Number_of_buckets = (stop - start) / interval.\n"
			  "Please adjust your start, stop, and interval values.\n",
			  STP_MAX_BUCKETS-2);
		return 0;
	}
	return buckets;
}

static int needed_space(int64_t v)
{
	int space = 0;
	uint64_t tmp;

	if (v == 0)
		return 1;

	if (v < 0) {
		space++;
		v = -v;
	}
	tmp = v;
	while (tmp) {
		/* v /= 10; */
		do_div(tmp, 10);
		space++;
	}
	return space;
}

/* Given a bucket number for a log histogram, return the value. */
static int64_t _stp_bucket_to_val(int num)
{
	if (num == HIST_LOG_BUCKET0)
		return 0;
	if (num < HIST_LOG_BUCKET0) {
		int64_t val = 0x8000000000000000LL;
		return  val >> num;
	} else
		return 1LL << (num - HIST_LOG_BUCKET0 - 1);
}

/* Implements a log base 2 function. Returns a bucket 
 * number from 0 to HIST_LOG_BUCKETS.
 */
static int _stp_val_to_bucket(int64_t val)
{
	int neg = 0, res = HIST_LOG_BUCKETS;
	
	if (val == 0)
		return HIST_LOG_BUCKET0;

	if (val < 0) {
		val = -val;
		neg = 1;
	}
	
	/* shortcut. most values will be 16-bit */
	if (unlikely(val & 0xffffffffffff0000ull)) {
		if (!(val & 0xffffffff00000000ull)) {
			val <<= 32;
			res -= 32;
		}
		
		if (!(val & 0xffff000000000000ull)) {
			val <<= 16;
			res -= 16;
		}
	} else {
		val <<= 48;
		res -= 48;
	}
	
	if (!(val & 0xff00000000000000ull)) {
		val <<= 8;
		res -= 8;
	}
	
	if (!(val & 0xf000000000000000ull)) {
		val <<= 4;
		res -= 4;
	}
	
	if (!(val & 0xc000000000000000ull)) {
		val <<= 2;
		res -= 2;
	}

	if (!(val & 0x8000000000000000ull)) {
		val <<= 1;
		res -= 1;
	}
	if (neg)
		res = HIST_LOG_BUCKETS - res;

	return res;
}

#ifndef HIST_WIDTH
#define HIST_WIDTH 50
#endif

#ifndef HIST_ELISION
#define HIST_ELISION 2 /* zeroes before and after */
#endif


static void _stp_stat_print_histogram_buf(char *buf, size_t size, Hist st,
					  stat_data *sd)
{
	int scale, i, j, val_space, cnt_space;
	int low_bucket = -1, high_bucket = 0, over = 0, under = 0;
	int64_t val, valmax = 0;
	uint64_t v;
	int eliding = 0;
	char *cur_buf = buf, *fake = buf;
	char **bufptr = (buf == NULL ? &fake : &cur_buf);

#define HIST_PRINTF(fmt, args...) \
	(*bufptr += _stp_snprintf(cur_buf, buf + size - cur_buf, fmt, ## args))

	if (st->type != HIST_LOG && st->type != HIST_LINEAR)
		return;

	/* Get the maximum value, for scaling. Also calculate the low
	   and high values to bound the reporting range. */
	for (i = 0; i < st->buckets; i++) {
		if (sd->histogram[i] > 0 && low_bucket == -1)
			low_bucket = i;
		if (sd->histogram[i] > 0)
			high_bucket = i;
		if (sd->histogram[i] > valmax)
			valmax = sd->histogram[i];
	}

	/* Touch up the bucket margin to show up to two zero-slots on
	   either side of the data range, seems aesthetically pleasant. */
	for (i = 0; i < 2; i++) {
		if (st->type == HIST_LOG) {
			/* For log histograms, don't go negative */
			/* unless there are negative values. */
			if (low_bucket != HIST_LOG_BUCKET0 && low_bucket > 0)
				low_bucket--;
		} else {
			if (low_bucket > 0)
				low_bucket--;
		}
		if (high_bucket < (st->buckets-1))
			high_bucket++;
	}
	if (st->type == HIST_LINEAR) {
		/* Don't include under or overflow if they are 0. */
		if (low_bucket == 0 && sd->histogram[0] == 0)
			low_bucket++;
		if (high_bucket == st->buckets-1 && sd->histogram[high_bucket] == 0)
			high_bucket--;
		if (low_bucket == 0)
			under = 1;
		if (high_bucket == st->buckets-1)
			over = 1;
	}

	if (valmax <= HIST_WIDTH)
		scale = 1;
	else {
		uint64_t tmp = valmax;
		int rem = do_div(tmp, HIST_WIDTH);
		scale = tmp;
		if (rem) scale++;
	}

	/* count space */
	cnt_space = needed_space(valmax);

	/* Compute value space */
	if (st->type == HIST_LINEAR) {
		val_space = max(needed_space(st->start) + under,
				needed_space(st->start +  st->interval * high_bucket) + over);
	} else {
		val_space = max(needed_space(_stp_bucket_to_val(high_bucket)),
				needed_space(_stp_bucket_to_val(low_bucket)));
	}
	val_space = max(val_space, 5 /* = sizeof("value") */);

	//_stp_warn("%s:%d - low_bucket = %d, high_bucket = %d, valmax = %lld, scale = %d, val_space = %d", __FUNCTION__, __LINE__, low_bucket, high_bucket, valmax, scale, val_space);

	/* print header */
	HIST_PRINTF("%*s |", val_space, "value");
	for (j = 0; j < HIST_WIDTH; ++j)
		HIST_PRINTF("-");
	HIST_PRINTF(" count\n");

	eliding = 0;
	for (i = low_bucket; i <= high_bucket; i++) {
		const char *val_prefix = "";

		/* Elide consecutive zero buckets.  Specifically, skip
		   this row if it is zero and some of its nearest
		   neighbours are also zero. Don't elide zero buckets
		   if HIST_ELISION is negative */
		if ((long)HIST_ELISION >= 0) {
			int k, elide = 1;
			/* Can't elide more than the total # of buckets */
			int max_elide = min_t(long, HIST_ELISION, st->buckets);
			int min_bucket = low_bucket;
			int max_bucket = high_bucket;

			if (i - max_elide > min_bucket)
				min_bucket = i - max_elide;
			if (i + max_elide < max_bucket)
				max_bucket = i + max_elide;
			for (k = min_bucket; k <= max_bucket; k++) {
				if (sd->histogram[k] != 0)
					elide = 0;
			}
			if (elide) {
				eliding = 1;
				continue;
			}

			/* State change: we have elided some rows, but now are
			   about to print a new one.  So let's print a mark on
			   the vertical axis to represent the missing rows. */
			if (eliding) {
				HIST_PRINTF("%*s ~\n", val_space, "");
				eliding = 0;
			}
		}

		if (st->type == HIST_LINEAR) {
			if (i == 0) {
				/* underflow */
				val = st->start;
				val_prefix = "<";
			} else if (i == st->buckets-1) {
				/* overflow */
				val = st->start + (int64_t)(i - 2) * st->interval;
				val_prefix = ">";
			} else
				val = st->start + (int64_t)(i - 1) * st->interval;
		} else
			val = _stp_bucket_to_val(i);

		HIST_PRINTF("%*s%lld |", val_space - needed_space(val), val_prefix, val);

		/* v = s->histogram[i] / scale; */
		v = sd->histogram[i];
		do_div(v, scale);

		for (j = 0; j < v; ++j)
			HIST_PRINTF("@");
		HIST_PRINTF("%*lld\n", (int)(HIST_WIDTH - v + 1 + cnt_space), sd->histogram[i]);
	}
	HIST_PRINTF("\n");
#undef HIST_PRINTF
}

static void _stp_stat_print_histogram(Hist st, stat_data *sd)
{
	_stp_stat_print_histogram_buf(NULL, 0, st, sd);
	_stp_print_flush();
}

static void __stp_stat_add(Hist st, stat_data *sd, int64_t val)
{
	int n;
	if (sd->count == 0) {
		sd->count = 1;
		sd->sum = sd->min = sd->max = val;
	} else {
		sd->count++;
		sd->sum += val;
		if (val > sd->max)
			sd->max = val;
		if (val < sd->min)
			sd->min = val;
	}
	switch (st->type) {
	case HIST_LOG:
		n = _stp_val_to_bucket (val);
		if (n >= st->buckets)
			n = st->buckets - 1;
		sd->histogram[n]++;
		break;
	case HIST_LINEAR:
		val -= st->start;

		/* underflow */
		if (val < 0)
			val = 0;
		else {
			uint64_t tmp = val;

			do_div(tmp, st->interval);
			val = tmp;
			val++;
		}

		/* overflow */
		if (val >= st->buckets - 1)
			val = st->buckets - 1;

		sd->histogram[val]++;
	default:
		break;
	}
}

#endif /* _STAT_COMMON_C_ */
