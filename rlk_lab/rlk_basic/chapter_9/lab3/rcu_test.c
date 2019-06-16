#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/kthread.h>
#include <linux/delay.h>

struct foo {
	int a;
	struct rcu_head rcu;
};

static struct foo *g_ptr;

static int myrcu_reader_thread1(void *data) //读者线程1
{
	struct foo *p1 = NULL;

	while (1) {
		if(kthread_should_stop())
			break;
		msleep(20);
		rcu_read_lock();
		mdelay(200);
		p1 = rcu_dereference(g_ptr);
		if (p1)
			printk("%s: read a=%d\n", __func__, p1->a);
		rcu_read_unlock();
	}

	return 0;
}

static int myrcu_reader_thread2(void *data) //读者线程2
{
	struct foo *p2 = NULL;

	while (1) {
		if(kthread_should_stop())
			break;
		msleep(30);
		rcu_read_lock();
		mdelay(100);
		p2 = rcu_dereference(g_ptr);
		if (p2)
			printk("%s: read a=%d\n", __func__, p2->a);
		
		rcu_read_unlock();
	}

	return 0;
}

static void myrcu_del(struct rcu_head *rh)
{
	struct foo *p = container_of(rh, struct foo, rcu);
	printk("%s: a=%d\n", __func__, p->a);
	kfree(p);
}

static int myrcu_writer_thread(void *p) //写者线程
{
	struct foo *old;
	struct foo *new_ptr;
	int value = (unsigned long)p;

	while (1) {
		if(kthread_should_stop())
			break;
		msleep(250);
		new_ptr = kmalloc(sizeof (struct foo), GFP_KERNEL);
		old = g_ptr;
		*new_ptr = *old;
		new_ptr->a = value;
		rcu_assign_pointer(g_ptr, new_ptr);
		call_rcu(&old->rcu, myrcu_del); 
		printk("%s: write to new %d\n", __func__, value);
		value++;
	}

	return 0;
}     

static struct task_struct *reader_thread1;
static struct task_struct *reader_thread2;
static struct task_struct *writer_thread;

static int __init my_test_init(void)
{   
	int value = 5;

	printk("figo: my module init\n");
	g_ptr = kzalloc(sizeof (struct foo), GFP_KERNEL);

	reader_thread1 = kthread_run(myrcu_reader_thread1, NULL, "rcu_reader1");
	reader_thread2 = kthread_run(myrcu_reader_thread2, NULL, "rcu_reader2");
	writer_thread = kthread_run(myrcu_writer_thread, (void *)(unsigned long)value, "rcu_writer");

	return 0;
}
static void __exit my_test_exit(void)
{
	printk("goodbye\n");
	kthread_stop(reader_thread1);
	kthread_stop(reader_thread2);
	kthread_stop(writer_thread);
	if (g_ptr)
		kfree(g_ptr);
}
MODULE_LICENSE("GPL");
module_init(my_test_init);
module_exit(my_test_exit);
