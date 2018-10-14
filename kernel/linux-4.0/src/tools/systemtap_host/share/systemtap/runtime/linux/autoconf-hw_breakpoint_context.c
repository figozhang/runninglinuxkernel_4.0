#include <linux/hw_breakpoint.h>

/* void *context parameter is new since linux commit 4dc0da. */
struct perf_event * __percpu *
hw_breakpoint_context(struct perf_event_attr *attr,
		      perf_overflow_handler_t triggered,
		      void *context)
{
  return register_wide_hw_breakpoint(attr, triggered, context);
}
