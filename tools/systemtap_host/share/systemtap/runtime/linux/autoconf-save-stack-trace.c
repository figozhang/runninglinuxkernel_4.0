#include <linux/string.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>

void foo(struct task_struct *foo)
{
  struct stack_trace trace;
  unsigned long backtrace[20];
  memset(&trace, 0, sizeof(trace));
  trace.entries = &backtrace[0];
  trace.max_entries = 20;
  trace.skip = 0;
  save_stack_trace_tsk(foo, &trace);
}

static const struct stacktrace_ops print_stack_ops;

void dumper(struct task_struct *foo)
{
  dump_trace(foo, 0, 0, 0, &print_stack_ops, 0);
}
