#include <linux/task_work.h>

/* Original task_work code used 'struct task_work' (and
 * init_task_work() had 3 arguments). */
void __autoconf_func(void)
{
	struct task_work work;

	init_task_work(&work, NULL, NULL);
}
