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
#include <linux/cdev.h>
#include <linux/poll.h>

#define DEMO_NAME "my_demo_dev"
#define MYDEMO_FIFO_SIZE 64

static dev_t dev;
static struct cdev *demo_cdev;

struct mydemo_device {
	char name[64];
	struct device *dev;
};

struct mydemo_private_data {
	struct mydemo_device *device;
	char name[64];
	struct kfifo mydemo_fifo;
        wait_queue_head_t read_queue;
	wait_queue_head_t write_queue;	
};

#define MYDEMO_MAX_DEVICES  8
static struct mydemo_device *mydemo_device[MYDEMO_MAX_DEVICES]; 

static int demodrv_open(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(inode);
	struct mydemo_private_data *data;
	struct mydemo_device *device = mydemo_device[minor];
	int ret;
	

	printk("%s: major=%d, minor=%d, device=%s\n", __func__, 
			MAJOR(inode->i_rdev), MINOR(inode->i_rdev), device->name);

	data = kmalloc(sizeof(struct mydemo_private_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	sprintf(data->name, "private_data_%d", minor);

	ret = kfifo_alloc(&data->mydemo_fifo,
			MYDEMO_FIFO_SIZE,
			GFP_KERNEL);
	if (ret) {
		kfree(data);
		return -ENOMEM;
	}

	init_waitqueue_head(&data->read_queue);
	init_waitqueue_head(&data->write_queue);

	data->device = device;

	file->private_data = data;

	return 0;
}

static int demodrv_release(struct inode *inode, struct file *file)
{
	struct mydemo_private_data *data = file->private_data;
	
	kfree(data);
        kfifo_free(&data->mydemo_fifo);

	return 0;
}

static ssize_t
demodrv_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct mydemo_private_data *data = file->private_data;
	struct mydemo_device *device = data->device;
	int actual_readed;
	int ret;

	if (kfifo_is_empty(&data->mydemo_fifo)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		printk("%s:%s pid=%d, going to sleep, %s\n", __func__, device->name, current->pid, data->name);
		ret = wait_event_interruptible(data->read_queue,
					!kfifo_is_empty(&data->mydemo_fifo));
		if (ret)
			return ret;
	}

	ret = kfifo_to_user(&data->mydemo_fifo, buf, count, &actual_readed);
	if (ret)
		return -EIO;

	if (!kfifo_is_full(&data->mydemo_fifo))
		wake_up_interruptible(&data->write_queue);
	
	printk("%s:%s, pid=%d, actual_readed=%d, pos=%lld\n",__func__,
			device->name, current->pid, actual_readed, *ppos);
	return actual_readed;
}

static ssize_t
demodrv_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct mydemo_private_data *data = file->private_data;
	struct mydemo_device *device = data->device;

	unsigned int actual_write;
	int ret;

	if (kfifo_is_full(&data->mydemo_fifo)){
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		printk("%s:%s pid=%d, going to sleep\n", __func__, device->name, current->pid);
		ret = wait_event_interruptible(data->write_queue,
				!kfifo_is_full(&data->mydemo_fifo));
		if (ret)
			return ret;
	}

	ret = kfifo_from_user(&data->mydemo_fifo, buf, count, &actual_write);
	if (ret)
		return -EIO;

	if (!kfifo_is_empty(&data->mydemo_fifo)) {
		printk("wait up read queue, %s\n", data->name);
		wake_up_interruptible(&data->read_queue);
	}

	printk("%s:%s pid=%d, actual_write =%d, ppos=%lld, ret=%d\n", __func__,
			device->name, current->pid, actual_write, *ppos, ret);

	return actual_write;
}

static unsigned int demodrv_poll(struct file *file, poll_table *wait)
{
	int mask = 0;
	struct mydemo_private_data *data = file->private_data;

	poll_wait(file, &data->read_queue, wait);
        poll_wait(file, &data->write_queue, wait);
	printk("In poll at jiffies=%ld\n", jiffies);

	if (!kfifo_is_empty(&data->mydemo_fifo)) {
		printk("%s, kfifo is not empty\n", __func__);
		mask |= POLLIN | POLLRDNORM;
	}
	if (!kfifo_is_full(&data->mydemo_fifo))
		mask |= POLLOUT | POLLWRNORM;
	
	return mask;
}

static const struct file_operations demodrv_fops = {
	.owner = THIS_MODULE,
	.open = demodrv_open,
	.release = demodrv_release,
	.read = demodrv_read,
	.write = demodrv_write,
        .poll = demodrv_poll,
};

static int __init simple_char_init(void)
{
	int ret;
	int i;
	struct mydemo_device *device;
	
	ret = alloc_chrdev_region(&dev, 0, MYDEMO_MAX_DEVICES, DEMO_NAME);
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
	
	ret = cdev_add(demo_cdev, dev, MYDEMO_MAX_DEVICES);
	if (ret) {
		printk("cdev_add failed\n");
		goto cdev_fail;
	}

	for (i = 0; i < MYDEMO_MAX_DEVICES; i++) {
		device = kmalloc(sizeof(struct mydemo_device), GFP_KERNEL);
		if (!device) {
			ret = -ENOMEM;
			goto free_device;
		}

		sprintf(device->name, "%s%d", DEMO_NAME, i);
		mydemo_device[i] = device;
	}

	printk("succeeded register char device: %s\n", DEMO_NAME);

	return 0;

free_device:
	for (i =0; i < MYDEMO_MAX_DEVICES; i++)
		if (mydemo_device[i])
			kfree(mydemo_device[i]);
cdev_fail:
	cdev_del(demo_cdev);
unregister_chrdev:
	unregister_chrdev_region(dev, MYDEMO_MAX_DEVICES);
	return ret;
}

static void __exit simple_char_exit(void)
{
	int i;
	printk("removing device\n");

	if (demo_cdev)
		cdev_del(demo_cdev);

	unregister_chrdev_region(dev, MYDEMO_MAX_DEVICES);

	for (i =0; i < MYDEMO_MAX_DEVICES; i++)
		if (mydemo_device[i])
			kfree(mydemo_device[i]);	
}

module_init(simple_char_init);
module_exit(simple_char_exit);

MODULE_AUTHOR("Benshushu");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("simpe character device");
