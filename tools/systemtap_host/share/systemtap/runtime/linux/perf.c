/* -*- linux-c -*- 
 * Perf Functions
 * Copyright (C) 2006-2014 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _PERF_C_
#define _PERF_C_

#include <linux/perf_event.h>
#include <linux/workqueue.h>

#include "perf.h"

#ifndef INIT_WORK_ONSTACK
#define INIT_WORK_ONSTACK(_work, _func) INIT_WORK((_work), (_func))
#define destroy_work_on_stack(_work) do { (void)(_work); } while (0)
#endif

/** @file perf.c
 * @brief Implements performance monitoring hardware support
 */

/** Initialize performance sampling
 * Call this during probe initialization to set up performance event sampling
 * for all online cpus.  Returns non-zero on error.
 *
 * @param stp Handle for the event to be registered.
 */
static long _stp_perf_init (struct stap_perf_probe *stp, struct task_struct* task)
{
	int cpu;

	if (!stp->system_wide) {
	  if (task == 0) /* need to setup later when we know the task */
	    return 0;
	  else  {
	    if (stp->e.t.per_thread_event != 0) /* already setup */
	      return 0;
	    stp->e.t.per_thread_event = perf_event_create_kernel_counter(&stp->attr,
								     -1, 
#if defined(STAPCONF_PERF_STRUCTPID) || defined (STAPCONF_PERF_COUNTER_CONTEXT)
								     task,
#else
								     task->pid,
#endif
								     stp->callback
#ifdef STAPCONF_PERF_COUNTER_CONTEXT
								     , NULL
#endif
								     );
	    if (IS_ERR(stp->e.t.per_thread_event)) {
	      long rc = PTR_ERR(stp->e.t.per_thread_event);
	      stp->e.t.per_thread_event = NULL;

	      /*
	       * PPC returns ENXIO for HW counters until 2.6.37
	       * (behavior changed with commit b0a873e).
	       */
	      if (rc == -EINVAL || rc == -ENOSYS || rc == -ENOENT
		  || rc == -EOPNOTSUPP || rc == -ENXIO) {
	        _stp_warn("perf probe '%s' is not supported by this kernel (%ld).",
#ifdef STP_NEED_PROBE_NAME
			  stp->probe->pn,
#else
			  stp->probe->pp,
#endif
			  rc);
		/* Lie and return 0. This way the more generic
		 * task_finder warning won't be printed. */
		rc = 0;
	      }
	      return rc;
	    }
	  }
	}
	else {
	  /* allocate space for the event descriptor for each cpu */
	  stp->e.events = _stp_alloc_percpu (sizeof(struct perf_event*));
	  if (stp->e.events == NULL) {
	    return -ENOMEM;
	  }

	  /* initialize event on each processor */
	  for_each_possible_cpu(cpu) {
	    struct perf_event **event = per_cpu_ptr (stp->e.events, cpu);
	    if (cpu_is_offline(cpu)) {
	      *event = NULL;
	      continue;
	    }
	    *event = perf_event_create_kernel_counter(&stp->attr,
						      cpu,
#if defined(STAPCONF_PERF_STRUCTPID) || defined (STAPCONF_PERF_COUNTER_CONTEXT)
						      NULL,
#else
						      -1,
#endif
						      stp->callback
#ifdef STAPCONF_PERF_COUNTER_CONTEXT
						      , NULL
#endif
						      );

	    if (IS_ERR(*event)) {
	      long rc = PTR_ERR(*event);
	      *event = NULL;
	      _stp_perf_del(stp);
	      return rc;
	    }
	  }
	} /* (stp->system_wide) */
	return 0;
}

/** Delete performance event.
 * Call this to shutdown one performance event sampling
 *
 * @param stp Handle for the event to be unregistered.
 */
static void _stp_perf_del (struct stap_perf_probe *stp)
{
  int cpu;
  if (! stp || !stp->e.events)
    return;

  /* shut down performance event sampling */
  if (stp->system_wide) {
    for_each_possible_cpu(cpu) {
      struct perf_event **event = per_cpu_ptr (stp->e.events, cpu);
      if (*event) {
	perf_event_release_kernel(*event);
      }
    }
    _stp_free_percpu (stp->e.events);
    stp->e.events = NULL;
  }
  else {
    if (stp->e.t.per_thread_event) {
      perf_event_release_kernel(stp->e.t.per_thread_event);
    }
    stp->e.t.per_thread_event = NULL;
  }
}

/** Delete many performance events in reverse order.
 * Call this to shutdown all performance event sampling
 *
 * @param probes A pointer array for the events to be unregistered.
 * @param n The number of events in the array.
 */
static void _stp_perf_del_n (struct stap_perf_probe *probes, size_t n)
{
  while (n--)
    _stp_perf_del(&probes[n]);
}

struct _stp_perf_work {
  struct work_struct work;
  struct stap_perf_probe *probes;
  size_t nprobes;
  const char* probe_point;
  int rc;
};

/** Initialize many performance events from a workqueue
 * Even though we're using the kernel interface, perf checks CAP_SYS_ADMIN,
 * which our mere @stapdev user may not have.  By running via a workqueue,
 * we'll be in an events/X kernel thread with sufficient privileges.
 *
 * @param work The _stp_perf_work encapsulating _stp_perf_init_n parameters.
 */
static void _stp_perf_init_work (struct work_struct *work)
{
  size_t i;
  struct _stp_perf_work *pwork =
    container_of(work, struct _stp_perf_work, work);

  for (i = 0; i < pwork->nprobes; ++i) {
    struct stap_perf_probe* stp = &pwork->probes[i];

    if (stp->system_wide)
      pwork->rc = _stp_perf_init(stp, NULL);
    else if (stp->task_finder)
#ifdef STP_PERF_USE_TASK_FINDER
      pwork->rc = stap_register_task_finder_target(&stp->e.t.tgt);
#else
      pwork->rc = EINVAL;
#endif

    if (pwork->rc) {
      pwork->probe_point = stp->probe->pp;
      _stp_perf_del_n(pwork->probes, i);
      break;
    }
  }
}

/** Initialize many performance events
 * Call this to start all performance event sampling
 *
 * @param probes A pointer array for the events to be registered.
 * @param n The number of events in the array.
 * @param ppfail A pointer to return the probe_point on failure.
 */
static int _stp_perf_init_n (struct stap_perf_probe *probes, size_t n,
			     const char **ppfail)
{
  struct _stp_perf_work pwork = { .probes = probes, .nprobes = n };
  INIT_WORK_ONSTACK(&pwork.work, _stp_perf_init_work);
  schedule_work(&pwork.work);
  flush_work(&pwork.work);
  if (pwork.rc)
    *ppfail = pwork.probe_point;
  destroy_work_on_stack(&pwork.work);
  return pwork.rc;
}


/*
The first call to _stp_perf_init, via systemtap_module_init at runtime, is for
setting up aggregate counters.  Per thread counters need to be setup when the
thread is known.  This is done by calling _stp_perf_init later when the thread
is known.  A per thread perf counter is defined by a counter("var") suffix on
the perf probe.  It is defined by perf_builder.  This counter is read on demand 
via the "@perf("var")" builtin which is treated as an expression right hand side
which reads the perf counter associated with the previously defined perf
counter.  It is expanded by dwarf_var_expanding_visitor
*/

static int _stp_perf_read_init (unsigned i, struct task_struct* task)
{
  /* Choose the stap_perf_probes entry */
  struct stap_perf_probe* stp = & stap_perf_probes[i];

  return _stp_perf_init (stp, task);
}


long _stp_perf_read (int ncpu, unsigned i)
{
  /* Choose the stap_perf_probes entry */
  struct stap_perf_probe* stp;
  u64 enabled, running;

  if (i > sizeof(stap_perf_probes)/sizeof(struct stap_perf_probe))
    {
      _stp_error ("_stp_perf_read - out of range");
      return 0;
    }
  stp = & stap_perf_probes[i]; 
    
  if (stp == NULL || stp->e.t.per_thread_event == NULL)
    {
      _stp_error ("_stp_perf_read - probe '%s' is not supported by this kernel",
#ifdef STP_NEED_PROBE_NAME
		  (stp ? stp->probe->pn : "unknown")
#else
		  (stp ? stp->probe->pp : "unknown")
#endif
	      );
      return 0;
    }

  might_sleep();
  return perf_event_read_value (stp->e.t.per_thread_event, &enabled, &running);

}


#endif /* _PERF_C_ */
