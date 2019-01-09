/* -*- linux-c -*- 
 * map functions to handle statistics
 * Copyright (C) 2005-2016 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/** @file map-stat.c
 * @brief Map functions to handle statistics.
 */

#include "stat-common.c"

static void _stp_map_print_histogram (MAP map, stat_data *sd)
{
	_stp_stat_print_histogram (&map->hist, sd);
}

static MAP _stp_map_new_hstat (unsigned max_entries, int wrap, int node_size)
{
	MAP m = _stp_map_new (max_entries, wrap, node_size, -1);
	if (m) {
		m->hist.type = HIST_NONE;
	}
	return m;
}

static MAP _stp_map_new_hstat_log (unsigned max_entries, int wrap, int node_size)
{
	MAP m;

	/* the node already has stat_data, just add size for buckets */
	node_size += HIST_LOG_BUCKETS * sizeof(int64_t);
	m = _stp_map_new (max_entries, wrap, node_size, -1);
	if (m) {
		m->hist.type = HIST_LOG;
		m->hist.buckets = HIST_LOG_BUCKETS;
	}
	return m;
}

static MAP
_stp_map_new_hstat_linear (unsigned max_entries, int wrap, int node_size,
			   int start, int stop, int interval)
{
	MAP m;
	int buckets = _stp_stat_calc_buckets(stop, start, interval);
	if (!buckets)
		return NULL;

	/* the node already has stat_data, just add size for buckets */
	node_size += buckets * sizeof(int64_t);

	m = _stp_map_new (max_entries, wrap, node_size, -1);
	if (m) {
		m->hist.type = HIST_LINEAR;
		m->hist.start = start;
		m->hist.stop = stop;
		m->hist.interval = interval;
		m->hist.buckets = buckets;
	}
	return m;
}


static PMAP
_stp_pmap_new_hstat_linear (unsigned max_entries, int wrap, int node_size,
			    int start, int stop, int interval)
{
	PMAP pmap;
	int buckets = _stp_stat_calc_buckets(stop, start, interval);
	if (!buckets)
		return NULL;

	/* the node already has stat_data, just add size for buckets */
	node_size += buckets * sizeof(int64_t);

	pmap = _stp_pmap_new (max_entries, wrap, node_size);
	if (pmap) {
		int i;
		MAP m;

		for_each_possible_cpu(i) {
			m = _stp_pmap_get_map (pmap, i);
			m->hist.type = HIST_LINEAR;
			m->hist.start = start;
			m->hist.stop = stop;
			m->hist.interval = interval;
			m->hist.buckets = buckets;
		}
		/* now set agg map params */
		m = _stp_pmap_get_agg(pmap);
		m->hist.type = HIST_LINEAR;
		m->hist.start = start;
		m->hist.stop = stop;
		m->hist.interval = interval;
		m->hist.buckets = buckets;
	}
	return pmap;
}

static PMAP
_stp_pmap_new_hstat_log (unsigned max_entries, int wrap, int node_size)
{
	PMAP pmap;

	/* the node already has stat_data, just add size for buckets */
	node_size += HIST_LOG_BUCKETS * sizeof(int64_t);
	pmap = _stp_pmap_new (max_entries, wrap, node_size);
	if (pmap) {
		int i;
		MAP m;
		for_each_possible_cpu(i) {
			m = _stp_pmap_get_map (pmap, i);
			m->hist.type = HIST_LOG;
			m->hist.buckets = HIST_LOG_BUCKETS;
		}
		/* now set agg map params */
		m = _stp_pmap_get_agg(pmap);
		m->hist.type = HIST_LOG;
		m->hist.buckets = HIST_LOG_BUCKETS;
	}
	return pmap;
}

static PMAP
_stp_pmap_new_hstat (unsigned max_entries, int wrap, int node_size)
{
	PMAP pmap = _stp_pmap_new (max_entries, wrap, node_size);
	if (pmap) {
		int i;
		MAP m;
		for_each_possible_cpu(i) {
			m = _stp_pmap_get_map (pmap, i);
			m->hist.type = HIST_NONE;
		}
		/* now set agg map params */
		m = _stp_pmap_get_agg(pmap);
		m->hist.type = HIST_NONE;
	}
	return pmap;
}
