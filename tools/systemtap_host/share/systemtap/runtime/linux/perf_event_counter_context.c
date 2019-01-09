#include <linux/perf_event.h>

/* void *context parameter is new since linux commit 4dc0da. */
struct perf_event *
pref_ec_context(struct perf_event_attr *attr,
		int cpu,
		struct task_struct *task,
		perf_overflow_handler_t callback,
		void *context)
{
  return perf_event_create_kernel_counter(attr, cpu, task, callback, context);
}
