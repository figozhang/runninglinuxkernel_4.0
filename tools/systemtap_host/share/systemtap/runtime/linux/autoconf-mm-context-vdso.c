#include <linux/sched.h>

int context_vdso(struct task_struct *tsk)
{
  return (tsk->mm->context.vdso == NULL);
}
