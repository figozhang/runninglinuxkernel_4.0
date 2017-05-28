/* Some kernels have an extra stacktrace_ops field walk_stack. */
#include <linux/sched.h>
#include <asm/stacktrace.h>

void foo (void)
{
  struct stacktrace_ops t;
  t.walk_stack = print_context_stack;
  (void) t;
}
