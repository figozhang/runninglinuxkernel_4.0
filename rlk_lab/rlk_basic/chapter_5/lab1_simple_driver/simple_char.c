#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/cdev.h>

#define DEMO_NAME "my_demo_dev"
static dev_t dev;
static struct cdev *demo_cdev;
static signed count = 1;

static int demodrv_open(struct inode *inode, struct file *file)
{
	int major = MAJOR(inode->i_rdev);
	int minor = MINOR(inode->i_rdev);

	printk("%s: major=%d, minor=%d\n", __func__, major, minor);

	return 0;
}

static int demodrv_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t
demodrv_read(struct file *file, char __user *buf, size_t lbuf, loff_t *ppos)
{
	printk("%s enter\n", __func__);
	return 0;
}

static ssize_t
demodrv_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos)
{
	printk("%s enter\n", __func__);
	return 0;

}

static const struct file_operations demodrv_fops = {
	.owner = THIS_MODULE,
	.open = demodrv_open,
	.release = demodrv_release,
	.read = demodrv_read,
	.write = demodrv_write
};


static int __init simple_char_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&dev, 0, count, DEMO_NAME);
	if (ret) {
		printk("failed to allocate char device region");
		return ret;
	}

	demo_cdev = cdev_alloc();
	if (!demo_cdev) {
		printk("cdev_alloc failed\n");
		goto unregister_chrdev;
	}

	cdev_init(demo_cdev, &demodrv_fops);
	
	ret = cdev_add(demo_cdev, dev, count);
	if (ret) {
		printk("cdev_add failed\n");
		goto cdev_fail;
	}

	printk("succeeded register char device: %s\n", DEMO_NAME);
	printk("Major number = %d, minor number = %d\n",
			MAJOR(dev), MINOR(dev));

	return 0;

cdev_fail:
	cdev_del(demo_cdev);
unregister_chrdev:
	unregister_chrdev_region(dev, count);

	return ret;
}

static void __exit simple_char_exit(void)
{
	printk("removing device\n");

	if (demo_cdev)
		cdev_del(demo_cdev);

	unregister_chrdev_region(dev, count);
}

module_init(simple_char_init);
module_exit(simple_char_exit);

MODULE_AUTHOR("Benshushu");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("simpe character device");
