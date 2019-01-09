/*
 * utrace compatibility defines and inlines
 * Copyright (C) 2008-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _UTRACE_COMPATIBILITY_H_
#define _UTRACE_COMPATIBILITY_H_

#include <linux/utrace.h>

/* PR9974: Adapt to struct renaming. */
#ifndef UTRACE_API_VERSION
#define utrace_engine utrace_attached_engine
#endif

/* We really need this when calling UTRACE_CREATE under a lock
 * or from interrupt context.  But it is only available in
 * newer utrace versions.
 */
#ifndef UTRACE_ATTACH_ATOMIC
#define UTRACE_ATTACH_ATOMIC 0
#endif

#ifdef UTRACE_ACTION_RESUME

/* 
 * If UTRACE_ACTION_RESUME is defined after including utrace.h, we've
 * got the original version of utrace.  So that utrace clients can be
 * written using the new interface (mostly), provide a (very thin)
 * compatibility layer that hides the differences.
 */

#define UTRACE_ORIG_VERSION

enum utrace_resume_action {
	UTRACE_STOP = UTRACE_ACTION_QUIESCE,
	UTRACE_INTERRUPT = UTRACE_ACTION_QUIESCE,
	UTRACE_RESUME = UTRACE_ACTION_RESUME,
	UTRACE_DETACH = UTRACE_ACTION_DETACH,
	UTRACE_SINGLESTEP = UTRACE_ACTION_SINGLESTEP,
	UTRACE_BLOCKSTEP = UTRACE_ACTION_BLOCKSTEP,
};

static inline struct utrace_engine *
utrace_attach_task(struct task_struct *target, int flags,
		   const struct utrace_engine_ops *ops, void *data)
{
	return utrace_attach(target, flags, ops, data);
}

static inline int __must_check
utrace_control(struct task_struct *target,
	       struct utrace_engine *engine,
	       enum utrace_resume_action action)
{
	switch (action) {
	case UTRACE_DETACH:
		return utrace_detach(target, engine);
	case UTRACE_STOP:
		return utrace_set_flags(target, engine,
					(engine->flags | UTRACE_ACTION_QUIESCE));
        case UTRACE_SINGLESTEP:
        case UTRACE_BLOCKSTEP:
          return utrace_set_flags(target, engine,
                                  engine->flags | action);

	default:
		return -EINVAL;
	}
}

static inline int __must_check
utrace_set_events(struct task_struct *target,
		  struct utrace_engine *engine,
		  unsigned long eventmask)
{
	return utrace_set_flags(target, engine, eventmask);
}

static inline void
utrace_engine_put(struct utrace_engine *engine)
{
	return;
}

static inline int __must_check
utrace_barrier(struct task_struct *target,
	       struct utrace_engine *engine)
{
	return 0;
}
#else
#ifdef UTRACE_HIDE_EVENT
/* This is only for some fedora 9 2.6.26 kernels that don't have
 * UTRACE_ACTION_RESUME defined, but do define UTRACE_HIDE_EVENT.
 * It isn't really a recommended version, but it does compile and
 * run mostly. It has one renamed function.
 */
#define utrace_attach_task utrace_attach
static inline void
utrace_engine_put(struct utrace_engine *engine)
{
	return;
}

static inline int __must_check
utrace_barrier(struct task_struct *target,
	       struct utrace_engine *engine)
{
	return 0;
}
#endif /* UTRACE_HIDE_EVENT */
#endif /* UTRACE_ACTION_RESUME */

#endif	/* _UTRACE_COMPATIBILITY_H_ */
