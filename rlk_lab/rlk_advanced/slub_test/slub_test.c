#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

static char *buf;

static void create_slub_error(void)
{
	buf = kmalloc(32, GFP_KERNEL);
	if (buf) {
		*buf = *(buf-1);
	}
	kfree(buf);
}
static int __init my_test_init(void)
{
	printk("figo: my module init\n");
	create_slub_error();
	return 0;
}
static void __exit my_test_exit(void)
{
	printk("goodbye\n");
}
MODULE_LICENSE("GPL");
module_init(my_test_init);
module_exit(my_test_exit);
