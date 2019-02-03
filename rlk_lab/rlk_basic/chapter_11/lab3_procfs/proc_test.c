#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>

#define NODE "benshushu/my_proc"

static int param = 100;
static struct proc_dir_entry *my_proc;
static struct proc_dir_entry *my_root;

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
	pr_info("param has been set to %d\n", param);
	return rc;
}

static const struct file_operations my_proc_fops = {
	.owner = THIS_MODULE,
	.read = my_read,
	.write = my_write,
};

static int __init my_init(void)
{
	my_root = proc_mkdir("benshushu", NULL);
	if (IS_ERR(my_root)){
		pr_err("I failed to make benshushu dir\n");
		return -1;
	}

	my_proc = proc_create(NODE, 0, NULL, &my_proc_fops);
	if (IS_ERR(my_proc)){
		pr_err("I failed to make %s\n", NODE);
		return -1;
	}
	pr_info("I created %s\n", NODE);
	return 0;
}

static void __exit my_exit(void)
{
	if (my_proc) {
		proc_remove(my_proc);
		proc_remove(my_root);
		pr_info("Removed %s\n", NODE);
	}
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
