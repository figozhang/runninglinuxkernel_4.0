#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/sched.h>

#define DEMO_NAME "my_demo_dev"
DEFINE_KFIFO(mydemo_fifo, char, 64);

struct mydemo_device {
	const char *name;
	struct device *dev;
	struct miscdevice *miscdev;
        wait_queue_head_t read_queue;
	wait_queue_head_t write_queue;	
};

struct mydemo_private_data {
	struct mydemo_device *device;
};

static struct mydemo_device *mydemo_device; 

static int demodrv_open(struct inode *inode, struct file *file)
{
	struct mydemo_private_data *data;
	struct mydemo_device *device = mydemo_device;

	printk("%s: major=%d, minor=%d\n", __func__, 
			MAJOR(inode->i_rdev), MINOR(inode->i_rdev));

	data = kmalloc(sizeof(struct mydemo_private_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->device = device;

	file->private_data = data;

	return 0;
}

static int demodrv_release(struct inode *inode, struct file *file)
{
	struct mydemo_private_data *data = file->private_data;
	
	kfree(data);

	return 0;
}

static ssize_t
demodrv_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct mydemo_private_data *data = file->private_data;
	struct mydemo_device *device = data->device;
	int actual_readed;
	int ret;

	if (kfifo_is_empty(&mydemo_fifo)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		printk("%s: pid=%d, going to sleep\n", __func__, current->pid);
		ret = wait_event_interruptible(device->read_queue,
					!kfifo_is_empty(&mydemo_fifo));
		if (ret)
			return ret;
	}

	ret = kfifo_to_user(&mydemo_fifo, buf, count, &actual_readed);
	if (ret)
		return -EIO;

	if (!kfifo_is_full(&mydemo_fifo))
		wake_up_interruptible(&device->write_queue);
	
	printk("%s, pid=%d, actual_readed=%d, pos=%lld\n",__func__,
			current->pid, actual_readed, *ppos);
	return actual_readed;
}

static ssize_t
demodrv_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct mydemo_private_data *data = file->private_data;
	struct mydemo_device *device = data->device;

	unsigned int actual_write;
	int ret;

	if (kfifo_is_full(&mydemo_fifo)){
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		printk("%s: pid=%d, going to sleep\n", __func__, current->pid);
		ret = wait_event_interruptible(device->write_queue,
				!kfifo_is_full(&mydemo_fifo));
		if (ret)
			return ret;
	}

	ret = kfifo_from_user(&mydemo_fifo, buf, count, &actual_write);
	if (ret)
		return -EIO;

	if (!kfifo_is_empty(&mydemo_fifo))
		wake_up_interruptible(&device->read_queue);

	printk("%s: pid=%d, actual_write =%d, ppos=%lld, ret=%d\n", __func__,
			current->pid, actual_write, *ppos, ret);

	return actual_write;
}

static const struct file_operations demodrv_fops = {
	.owner = THIS_MODULE,
	.open = demodrv_open,
	.release = demodrv_release,
	.read = demodrv_read,
	.write = demodrv_write
};

static struct miscdevice mydemodrv_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEMO_NAME,
	.fops = &demodrv_fops,
};

static int __init simple_char_init(void)
{
	int ret;

	struct mydemo_device *device = kmalloc(sizeof(struct mydemo_device), GFP_KERNEL);
	if (!device)
		return -ENOMEM;	

	ret = misc_register(&mydemodrv_misc_device);
	if (ret) {
		printk("failed register misc device\n");
		goto free_device;
	}

	device->dev = mydemodrv_misc_device.this_device;
	device->miscdev = &mydemodrv_misc_device;

	init_waitqueue_head(&device->read_queue);
	init_waitqueue_head(&device->write_queue);

	mydemo_device = device;
	printk("succeeded register char device: %s\n", DEMO_NAME);

	return 0;

free_device:
	kfree(device);
	return ret;
}

static void __exit simple_char_exit(void)
{
	printk("removing device\n");

	struct mydemo_device *dev = mydemo_device;

	misc_deregister(dev->miscdev);
	kfree(dev);
}

module_init(simple_char_init);
module_exit(simple_char_exit);

MODULE_AUTHOR("Benshushu");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("simpe character device");
