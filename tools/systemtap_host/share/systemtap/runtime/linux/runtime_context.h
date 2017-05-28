/* -*- linux-c -*- 
 * Context Runtime Functions
 * Copyright (C) 2014 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_RUNTIME_CONTEXT_H_
#define _LINUX_RUNTIME_CONTEXT_H_

static struct context *contexts[NR_CPUS] = { NULL };
static struct context *free_contexts[NR_CPUS] = { NULL };

static int _stp_runtime_contexts_alloc(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		/* Module init, so in user context, safe to use
		 * "sleeping" allocation. */
		struct context *c = _stp_vzalloc_node(sizeof (struct context),
						      cpu_to_node(cpu));
		if (c == NULL) {
			_stp_error ("context (size %lu per cpu) allocation failed",
				    (unsigned long) sizeof (struct context));
			return -ENOMEM;
		}
		rcu_assign_pointer(contexts[cpu], c);
	}
	return 0;
}

/* We should be free of all probes by this time, but for example the timer for
 * _stp_ctl_work_callback may still be running and looking for contexts.  We
 * use RCU-sched synchronization to be sure its safe to free them.  */
static void _stp_runtime_contexts_free(void)
{
	int cpu;

	/* First clear all pointers to prevent new readers.  */
	for_each_possible_cpu(cpu) {
		free_contexts[cpu] = contexts[cpu];
		rcu_assign_pointer(contexts[cpu], NULL);
	}

	/* Sync to make sure existing readers are done.  */
	stp_synchronize_sched();

	/* Now we can actually free the contexts.  */
	for_each_possible_cpu(cpu) {
		struct context *c = free_contexts[cpu];
		if (c != NULL) {
			free_contexts[cpu] = NULL;
			_stp_vfree(c);
		}
	}
}

static inline struct context * _stp_runtime_get_context(void)
{
	return rcu_dereference_sched(contexts[smp_processor_id()]);
}

static struct context * _stp_runtime_entryfn_get_context(void)
{
	struct context* __restrict__ c = NULL;
	preempt_disable ();
	c = _stp_runtime_get_context();
	if (c != NULL) {
		if (atomic_inc_return(&c->busy) == 1)
			return c;
		atomic_dec(&c->busy);
	}
	preempt_enable_no_resched();
	return NULL;
}

static inline void _stp_runtime_entryfn_put_context(struct context *c)
{
	if (c && c == _stp_runtime_get_context()) {
		atomic_dec(&c->busy);
		preempt_enable_no_resched();
	}
	/* else, warn about bad state? */
	return;
}

static void _stp_runtime_context_wait(void)
{
	int holdon;
	unsigned long hold_start;
	int hold_index;

	hold_start = jiffies;
	hold_index = -1;
	do {
		int i;

		holdon = 0;
		for_each_possible_cpu(i) {
			if (contexts[i] != NULL
			    && atomic_read (& contexts[i]->busy)) {
				holdon = 1;

				/* Just in case things are really
				 * stuck, let's print some diagnostics. */
				if (time_after(jiffies, hold_start + HZ)  // > 1 second
				    && (i > hold_index)) { // not already printed
					hold_index = i;
					printk(KERN_ERR "%s context[%d] stuck: %s\n", THIS_MODULE->name, i, contexts[i]->probe_point);
				}
			}
		}

		/*
		 * Just in case things are really really stuck, a
		 * handler probably suffered a fault, and the kernel
		 * probably killed a task/thread already.  We can't be
		 * quite sure in what state everything is in, however
		 * auxiliary stuff like kprobes / uprobes / locks have
		 * already been unregistered.  So it's *probably* safe
		 * to pretend/assume/hope everything is OK, and let
		 * the cleanup finish.
		 *
		 * In the worst case, there may occur a fault, as a
		 * genuinely running probe handler tries to access
		 * script globals (about to be freed), or something
		 * accesses module memory (about to be unloaded).
		 * This is sometimes stinky, so the alternative
		 * (default) is to change from a livelock to a
		 * livelock that sleeps awhile.
		 */
#ifdef STAP_OVERRIDE_STUCK_CONTEXT
		if (time_after(jiffies, hold_start + HZ*10)) {  // > 10 seconds
			printk(KERN_ERR "%s overriding stuck context to allow module shutdown.", THIS_MODULE->name);
			holdon = 0; // allow loop to exit
		}
#else
		/* at least stop sucking down the staprun cpu */
		msleep(250);
#endif

		/* NB: we run at least one of these during the
		 * shutdown sequence: */
		yield();	    /* aka schedule() and then some */
	} while (holdon);
}

#endif /* _LINUX_RUNTIME_CONTEXT_H_ */
