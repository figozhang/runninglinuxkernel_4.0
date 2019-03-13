#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/vmalloc.h>

static int __init my_init(void)
{
	char *kbuf;
	unsigned long order = 0;
	size_t count = 0;

	/* try __get_free_pages__ */
	for (;;) {
		kbuf = (char *)alloc_pages(GFP_KERNEL, order);
		if (!kbuf) {
			pr_err("have alloc %d pages, but continue alloc failed\n", count);
			break;
		}
		count += (order << 1);
	}

	return 0;
}

static void __exit my_exit(void)
{
	pr_info("Module exit\n");
}

module_init(my_init);
module_exit(my_exit);

MODULE_AUTHOR("Ben ShuShu");
MODULE_LICENSE("GPL v2");
