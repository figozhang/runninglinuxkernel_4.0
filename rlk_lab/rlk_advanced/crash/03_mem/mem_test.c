#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>

struct timer_list timer;
static struct vm_area_struct *gvma;

static void mem_timefunc(unsigned long dummy)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)(dummy);
	
	printk("%s: set vma = %p\n", __func__, vma);

	vma->vm_flags = 1;
	vma->vm_pgoff = 1;

}

int create_oops(struct vm_area_struct **p)
{
	unsigned long flags;
	struct vm_area_struct *vma = *p;

	flags = vma->vm_flags;

	printk("flags=0x%lx\n", flags);

	printk("%s: free vma %p\n", __func__, vma);

	kfree(*p);
	*p = NULL;
	printk("%s: gvma %p, vma %p\n", __func__, gvma, *p);
	
	return 0;
}

static int __init my_oops_init(void)
{
	int ret;

	gvma = kmalloc(sizeof (*gvma), GFP_ATOMIC);
	if (!gvma)
		return -ENOMEM;

	printk("%s, gvma=%p\n", __func__, gvma);

	ret = create_oops(&gvma);

	timer.expires = jiffies + msecs_to_jiffies(10);
	setup_timer(&timer, mem_timefunc, (unsigned long)gvma); 
	add_timer(&timer);

	return 0;
}

static void __exit my_oops_exit(void)
{
	printk("goodbye\n");
}

module_init(my_oops_init);
module_exit(my_oops_exit);
