#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/delay.h>

static DEFINE_SPINLOCK(hack_spinA);
static struct page *page;

static int __init my_init(void)
{
	int order = 5;

	spin_lock(&hack_spinA);
	page = alloc_pages(GFP_KERNEL, order);
	if (!page) {
		printk("cannot alloc pages\n");
		return -ENOMEM;
	}

	/* we sleep here to simulate that allocate memory under pressure */
	msleep(10000);

	spin_unlock(&hack_spinA);

	return 0;
}

static void __exit my_exit(void)
{
	__free_pages(page, 5);
}

MODULE_LICENSE("GPL");
module_init(my_init);
module_exit(my_exit);
