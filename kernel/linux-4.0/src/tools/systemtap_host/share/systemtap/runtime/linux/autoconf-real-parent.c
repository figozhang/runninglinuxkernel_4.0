/* PR6732 - In RHEL5 and F[678] kernels, the utrace patch removed the
 * ptrace-related parent field and renamed real_parent to parent.  In
 * future Fedora kernels, there may or may not be a ptrace-related
 * parent field, but the real useful field will go back to being called
 * real_parent.
 */
#include <linux/sched.h>

struct task_struct t;

void foo (void)
{
  struct task_struct *p;
  p = t.real_parent; 
  (void) p;
}
