/* SystemTap tracepoint interface header
 * Copyright (C) 2014 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_TRACEPOINT_H_
#define _STP_TRACEPOINT_H_

#include <linux/tracepoint.h>

#define intptr_t long


/* Starting in 2.6.35, at the same time NOARGS was added, the callback
 * always has a void* as the first parameter.  PR11599 */
#ifdef DECLARE_TRACE_NOARGS
#define STAPCONF_TRACEPOINT_HAS_DATA
#endif


#ifdef STAPCONF_TRACEPOINT_HAS_DATA

#define STP_TRACE_ENTER(fn, args...)	\
  void fn (void *__data __attribute__ ((unused)), ##args)
#define STP_TRACE_ENTER_NOARGS(fn) STP_TRACE_ENTER(fn)

#ifdef STAPCONF_TRACEPOINT_STRINGS

#define STP_TRACE_REGISTER(name, fn) register_trace_##name(fn, NULL)
#define STP_TRACE_UNREGISTER(name, fn) unregister_trace_##name(fn, NULL)

#else /* STAPCONF_TRACEPOINT_STRINGS */

#define STAP_NEED_TRACEPOINTS 1

int stp_tracepoint_probe_register(const char *name, void *probe, void *data);
int stp_tracepoint_probe_unregister(const char *name, void *probe, void *data);

/* Type-checked wrappers to make sure the fn signature is correct.  */
#define STP_TRACE_REGISTER(name, fn) ({				\
    check_trace_callback_type_##name(fn);			\
    stp_tracepoint_probe_register(#name, (void*)fn, NULL);	\
    })
#define STP_TRACE_UNREGISTER(name, fn) ({			\
    check_trace_callback_type_##name(fn);			\
    stp_tracepoint_probe_unregister(#name, (void*)fn, NULL);	\
    })

#endif /* STAPCONF_TRACEPOINT_STRINGS */

#else /* STAPCONF_TRACEPOINT_HAS_DATA */

#define STP_TRACE_ENTER(fn, args...) void fn (args)
#define STP_TRACE_ENTER_NOARGS(fn) STP_TRACE_ENTER(fn, void)
#define STP_TRACE_REGISTER(name, fn) register_trace_##name(fn)
#define STP_TRACE_UNREGISTER(name, fn) unregister_trace_##name(fn)

#endif /* STAPCONF_TRACEPOINT_HAS_DATA */


#define STP_TRACE_ENTER_REAL(fn, args...) void fn (args)
#define STP_TRACE_ENTER_REAL_NOARGS(fn) STP_TRACE_ENTER_REAL(fn, void)


#endif /* _STP_TRACEPOINT_H_ */
