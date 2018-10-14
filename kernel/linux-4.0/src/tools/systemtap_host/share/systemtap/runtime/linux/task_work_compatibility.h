/*
 * task_work compatibility defines and inlines
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _TASK_WORK_COMPATIBILITY_H_
#define _TASK_WORK_COMPATIBILITY_H_

#include <linux/task_work.h>

/*
 * Define all the old task_work stuff in terms of the new
 * interface/names - except for the name of the structure
 * itself. Originally the task_work stuff had a custom structure,
 * called 'struct task_work'. The new interface uses a common
 * structure, 'struct callback_head'.  If we define 'callback_head' to
 * be a 'task_work', then we could never use the common structure on
 * systems with the old interface.
 */

#ifdef STAPCONF_TASK_WORK_STRUCT

static inline void
stp_init_task_work(struct task_work *twork, task_work_func_t func)
{
	init_task_work(twork, func, NULL);
}

#else  /* !STAPCONF_TASK_WORK_STRUCT */

#define task_work callback_head

static inline void
stp_init_task_work(struct task_work *twork, task_work_func_t func)
{
	init_task_work(twork, func);
}

#endif	/* !STAPCONF_TASK_WORK_STRUCT */

#endif	/* _TASK_WORK_COMPATIBILITY_H_ */
