#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>


int set_reg(unsigned int reg, unsigned int val)
{
	printk("reg=0x%x, val=0x%x\n", reg, val);

	return 0;
}

int create_crash(void *p)
{
	set_reg(*(unsigned int *)p, *(unsigned int *)(p+4));	
	return 0;
}

static int __init my_oops_init(void)
{
	int ret;
	char *buf;

	buf = kmalloc(8, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	printk("%s, gvma=%p\n", __func__, buf);
	*(unsigned int *)(buf) = 0x30043c;
	*(unsigned int *)(buf + 4) = 0x1;

	ret = create_crash(buf);

	return 0;
}

static void __exit my_oops_exit(void)
{
	printk("goodbye\n");
}

module_init(my_oops_init);
module_exit(my_oops_exit);
