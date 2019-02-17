#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/slab.h>

int create_oops(struct vm_area_struct *vma)
{
	unsigned long flags;

	flags = vma->vm_flags;
	printk("flags=0x%lx\n", flags);
	
	return 0;
}

static int __init my_oops_init(void)
{
	int ret;
	struct vm_area_struct *vma = NULL;

	vma = kmalloc(sizeof (*vma), GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	kfree(vma);
	vma = NULL;

	smp_mb();

	ret = create_oops(vma);

	return 0;
}

static void __exit my_oops_exit(void)
{
	printk("goodbye\n");
}

module_init(my_oops_init);
module_exit(my_oops_exit);
