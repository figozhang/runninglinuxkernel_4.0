#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/debugfs.h>

#define NODE "benshushu"

static int param = 100;
struct dentry *debugfs_dir;

#define KS 32
static char kstring[KS];	/* should be less sloppy about overflows :) */

static ssize_t
my_read(struct file *file, char __user *buf, size_t lbuf, loff_t *ppos)
{
	int nbytes = sprintf(kstring, "%d\n", param);
	return simple_read_from_buffer(buf, lbuf, ppos, kstring, nbytes);
}

static ssize_t my_write(struct file *file, const char __user *buf, size_t lbuf,
			loff_t *ppos)
{
	ssize_t rc;
	rc = simple_write_to_buffer(kstring, lbuf, ppos, buf, lbuf);
	sscanf(kstring, "%d", &param);
	//pr_info("param has been set to %d\n", param);
	return rc;
}

static const struct file_operations mydebugfs_ops = {
	.owner = THIS_MODULE,
	.read = my_read,
	.write = my_write,
};

static int __init my_init(void)
{
	struct dentry *debug_file;

	debugfs_dir = debugfs_create_dir(NODE, NULL);
	if (IS_ERR(debugfs_dir)) {
		printk("create debugfs dir fail\n");
		return -EFAULT;
	}

	debug_file = debugfs_create_file("my_debug", 0444,
			debugfs_dir, NULL, &mydebugfs_ops);
	if (IS_ERR(debug_file)) {
		printk("create debugfs file fail\n");
		debugfs_remove_recursive(debugfs_dir);
		return -EFAULT;
	}

	pr_info("I created %s on debugfs\n", NODE);
	return 0;
}

static void __exit my_exit(void)
{
	if (debugfs_dir) {
		debugfs_remove_recursive(debugfs_dir);
		pr_info("Removed %s\n", NODE);
	}
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
