#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

static char *buf;

static void create_kmemleak(void)
{
	buf = kmalloc(120, GFP_KERNEL);
	buf = vmalloc(4096);
	buf = vmalloc(4096);
}
static int __init my_test_init(void)
{
	printk("figo: my module init\n");
	create_kmemleak();
	return 0;
}
static void __exit my_test_exit(void)
{
	printk("goodbye\n");
}
MODULE_LICENSE("GPL");
module_init(my_test_init);
module_exit(my_test_exit);
