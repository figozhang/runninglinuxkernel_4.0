#include <linux/sched.h>

int bar (struct task_struct *foo) { 
  return (foo->uid = 0); 
}
/* as opposed to linux/cred.h wrappers current_uid() etc. */
