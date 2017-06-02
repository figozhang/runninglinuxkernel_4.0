#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/delay.h>

static DEFINE_MUTEX(mutex_a);
static struct delayed_work delay_task;
static void lockdep_timefunc(unsigned long);
static DEFINE_TIMER(lockdep_timer, lockdep_timefunc, 0, 0);

static void lockdep_timefunc(unsigned long dummy)
{
	schedule_delayed_work(&delay_task, 10);
	mod_timer(&lockdep_timer, jiffies + msecs_to_jiffies(100));
}

static void lockdep_test_worker(struct work_struct *work)
{
	mutex_lock(&mutex_a);
	mdelay(300); //处理一些事情，这里用mdelay代替
	mutex_unlock(&mutex_a);
}

static int lockdep_thread(void *nothing)
{
	set_freezable();
	set_user_nice(current, 0);

	while (!kthread_should_stop()) {
		mdelay(500); //处理一些事情，这里用mdelay代替
		
		//遇到某些特殊情况，需要取消delay_task
		mutex_lock(&mutex_a);
		cancel_delayed_work_sync(&delay_task); 
		mutex_unlock(&mutex_a);
		
	}
	return 0;
}

static int __init lockdep_test_init(void)
{
	struct task_struct *lock_thread;
	printk("figo: my lockdep module init\n");
	
	/*创建一个线程来处理某些事情*/
	lock_thread = kthread_run(lockdep_thread, NULL, "lockdep_test");
	
	/*创建一个delay worker*/
	INIT_DELAYED_WORK(&delay_task, lockdep_test_worker);
	
	/*创建一个定时器来模拟某些异步事件，比如中断等*/
	lockdep_timer.expires = jiffies + msecs_to_jiffies(500);
	add_timer(&lockdep_timer);
 	return 0;
}

static void __exit lockdep_test_exit(void)
{
	printk("goodbye\n");
}
MODULE_LICENSE("GPL");
module_init(lockdep_test_init);
module_exit(lockdep_test_exit);
