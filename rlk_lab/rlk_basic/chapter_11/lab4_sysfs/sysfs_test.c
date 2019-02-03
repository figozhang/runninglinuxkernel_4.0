#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>

#define NODE "benshushu/my_proc"

static int param = 100;
static struct proc_dir_entry *my_proc;
static struct proc_dir_entry *my_root;
static struct platform_device *my_device;

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

static ssize_t data_show(struct device *d,
		struct device_attribute *attr,  char *buf)
{
	return sprintf(buf, "%d\n", param);
}

static ssize_t data_store(struct device *d,
		 struct device_attribute *attr,
		 const char *buf, size_t count)
{
	sscanf(buf, "%d", &param);
	dev_dbg(d, ": write %d into data\n", param);

	return strnlen(buf, count);
}

static DEVICE_ATTR_RW(data);

static struct attribute *ben_sysfs_entries[] = {
	&dev_attr_data.attr,
	NULL
};

static struct attribute_group mydevice_attr_group = {
	.name = "benshushu",
	.attrs = ben_sysfs_entries,
};

static int __init my_init(void)
{
	int ret;

	my_root = proc_mkdir("benshushu", NULL);
	my_proc = proc_create(NODE, 0, NULL, &my_proc_fops);
	if (IS_ERR(my_proc)) {
		pr_err("I failed to make %s\n", NODE);
		return PTR_ERR(my_proc);
	}
	pr_info("I created %s on procfs\n", NODE);

	my_device = platform_device_register_simple("benshushu", -1, NULL, 0);
	if (IS_ERR(my_device)) {
		printk("platfrom device register fail\n");
		ret = PTR_ERR(my_device);
		goto proc_fail;
	}

	ret = sysfs_create_group(&my_device->dev.kobj, &mydevice_attr_group);
	if (ret) {
		printk("create sysfs group fail\n");
		goto register_fail;
	}

	pr_info("create sysfs node done\n");

	return 0;

register_fail:
	platform_device_unregister(my_device);
proc_fail:
	return ret;
}

static void __exit my_exit(void)
{
	if (my_proc) {
		proc_remove(my_proc);
		proc_remove(my_root);
		pr_info("Removed %s\n", NODE);
	}

	sysfs_remove_group(&my_device->dev.kobj, &mydevice_attr_group);

	platform_device_unregister(my_device);
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
