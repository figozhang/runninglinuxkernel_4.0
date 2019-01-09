/* -*- linux-c -*- 
 * Perf Read Header File
 * Copyright (C) 2006-2013 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _PERF_READ_H_
#define _PERF_READ_H_

/** @file perf.h
 * @brief Header file for performance monitoring hardware support
 */

#ifdef _HAVE_PERF_
// perf counter probes call _stp_perf_read
struct task_struct;
static int _stp_perf_read_init (unsigned i, struct task_struct* pid);
static long _stp_perf_read (int ncpu, unsigned i);
#else
// stapiu_target_reg references _stp_perf_read_init
// but will only call it for a perf counter probe
struct task_struct;
static int _stp_perf_read_init (unsigned i, struct task_struct* pid) {return 0;};
static long _stp_perf_read (int ncpu, unsigned i) {return 0;};
#endif

#endif /* _PERF_READ_H_ */
