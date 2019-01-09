#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/delay.h>

static spinlock_t lock;

static struct list_head g_test_list;

struct foo {
	int a;
	struct list_head list;
};

static int list_del_thread(void *data)
{
	struct foo *entry;

	while (!kthread_should_stop()) {
		if (!list_empty(&g_test_list)) {
			spin_lock(&lock);
			entry = list_entry(g_test_list.next, struct foo, list);
			list_del(&entry->list);
			//kfree(entry);
			spin_unlock(&lock);
		}
		msleep(1);
	}

	return 0;
}

static int list_remove_thread(void *data)
{
	struct foo *entry;

	while (!kthread_should_stop()) {
		spin_lock(&lock);
		while (!list_empty(&g_test_list)) {
			entry = list_entry(g_test_list.next, struct foo, list);
			list_del(&entry->list);
			kfree(entry);
		}
		spin_unlock(&lock);
		mdelay(10);
	}

	return 0;
}

static int list_add_thread(void *p)
{
	int i;

	while (!kthread_should_stop()) {
		spin_lock(&lock);
		for (i = 0; i < 1000; i++) {
			struct foo *new_ptr = kmalloc(sizeof (struct foo), GFP_ATOMIC);
			new_ptr->a = i;
			list_add_tail(&new_ptr->list, &g_test_list);
		}
		spin_unlock(&lock);
		msleep(20);
	}

	return 0;
}     

static int __init my_test_init(void)
{   
	struct task_struct *thread1;
	struct task_struct *thread2;
	struct task_struct *thread3;

	printk("figo: my module init\n");

	spin_lock_init(&lock);
	INIT_LIST_HEAD(&g_test_list);

	thread1 = kthread_run(list_add_thread, NULL, "list_add");
	thread2 = kthread_run(list_remove_thread, NULL, "list_remove");
	thread3 = kthread_run(list_del_thread, NULL, "list_del");

	return 0;
}
static void __exit my_test_exit(void)
{
	printk("goodbye\n");
}
MODULE_LICENSE("GPL");
module_init(my_test_init);
module_exit(my_test_exit);
