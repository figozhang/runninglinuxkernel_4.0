#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/delay.h>

static DEFINE_SPINLOCK(hack_spinA);
static struct page *page;
static struct task_struct *lock_thread;

static int nest_lock(void) 
{
	int order = 5;

	spin_lock(&hack_spinA);
	page = alloc_pages(GFP_KERNEL, order);
	if (!page) {
		printk("cannot alloc pages\n");
		return -ENOMEM;
	}

	spin_lock(&hack_spinA);
	msleep(10);
	__free_pages(page, order);
	spin_unlock(&hack_spinA);
	spin_unlock(&hack_spinA);

	return 0;
}

static int lockdep_thread(void *nothing)
{
	set_freezable();
	set_user_nice(current, 0);

	while (!kthread_should_stop()) {
		msleep(10);
		nest_lock();
	}
}

static int __init my_init(void)
{

	lock_thread = kthread_run(lockdep_thread, NULL, "lockdep_test");
	if (IS_ERR(lock_thread)) {
		printk("create kthread fail\n");
		return PTR_ERR(lock_thread);
	}

	return 0;
}

static void __exit my_exit(void)
{
	kthread_stop(lock_thread);
}

MODULE_LICENSE("GPL");
module_init(my_init);
module_exit(my_exit);
