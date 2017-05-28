#include <linux/perf_event.h>

void fn (void) {
  struct perf_event_attr *attr = NULL;
  int cpu = 0;
  struct task_struct *tsk = NULL;
  perf_overflow_handler_t callback = NULL;

  /* linux-2.6 commit 38a81da2205f94 */
  (void) perf_event_create_kernel_counter(attr,
                                   cpu,                  
                                   tsk, /* as opposed to int pid */
                                   callback);  
}
