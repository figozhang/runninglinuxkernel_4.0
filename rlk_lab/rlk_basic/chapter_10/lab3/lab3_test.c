#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/delay.h>

static void my_timefunc(unsigned long);
static DEFINE_TIMER(my_timer, my_timefunc, 0, 0);
static atomic_t flags;
wait_queue_head_t wait_head;

static void my_timefunc(unsigned long dummy)
{
	atomic_set(&flags, 1);
	//printk("%s: set flags %d\n", __func__, atomic_read(&flags));
	wake_up_interruptible(&wait_head);
	mod_timer(&my_timer, jiffies + msecs_to_jiffies(2000));
}

static void my_try_to_sleep(void)
{
	DEFINE_WAIT(wait);

	if (freezing(current) || kthread_should_stop())
		return;

	prepare_to_wait(&wait_head, &wait, TASK_INTERRUPTIBLE);

	if (!atomic_read(&flags))
		schedule();
	
	finish_wait(&wait_head, &wait);
}

static void show_reg(void)
{
	unsigned int cpsr, sp;
	struct task_struct *task = current;
	
	asm("mrs %0, cpsr" : "=r" (cpsr) : : "cc");
	asm("mov %0, sp" : "=r" (sp) : : "cc");

	printk("%s: %s, pid:%d\n", __func__, task->comm, task->pid);
	printk("cpsr:0x%x, sp:0x%x\n", cpsr, sp);
}

static int my_thread(void *nothing)
{
	set_freezable();
	set_user_nice(current, 0);

	while (!kthread_should_stop()) {
		my_try_to_sleep();
		atomic_set(&flags, 0);
		show_reg();
	}
	return 0;
}


static struct task_struct *thread;

static int __init my_init(void)
{
	printk("ben: my lockdep module init\n");
	
	/*创建一个线程来处理某些事情*/
	thread = kthread_run(my_thread, NULL, "ktest");
	
	/*创建一个定时器来模拟某些异步事件，比如中断等*/
	my_timer.expires = jiffies + msecs_to_jiffies(500);
	add_timer(&my_timer);

	init_waitqueue_head(&wait_head);

 	return 0;
}

static void __exit my_exit(void)
{
	printk("goodbye\n");

	kthread_stop(thread);
}
MODULE_LICENSE("GPL");
module_init(my_init);
module_exit(my_exit);
