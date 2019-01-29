#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/highmem.h>

#define DEMO_NAME "my_demo_dev"
static struct device *mydemodrv_device;

#define MYDEMO_READ 0
#define MYDEMO_WRITE 1 

/*virtual FIFO device's buffer*/
static char *device_buffer;
#define MAX_DEVICE_BUFFER_SIZE (1 * PAGE_SIZE)

#define MYDEV_CMD_GET_BUFSIZE 1	/* defines our IOCTL cmd */

static size_t
demodrv_read_write(void *buf, size_t len,
		int rw)
{
	int ret, npages, i;
	struct page **pages;
	struct mm_struct *mm = current->mm;
	char *kmap_addr, *dev_buf;
	size_t size = 0;
	size_t count = 0;

	dev_buf = device_buffer;

	/* how mange pages? */
	npages = DIV_ROUND_UP(len, PAGE_SIZE);

	printk("%s: len=%d, npage=%d\n", __func__, len, npages);

	pages = kmalloc(npages * sizeof(pages), GFP_KERNEL);
	if (!pages) {
		printk("alloc pages fail\n");
		return -ENOMEM;
	}

	down_read(&mm->mmap_sem);

	ret = get_user_pages_fast((unsigned long)buf, npages, 1, pages);
	if (ret < npages) {
		printk("pin page fail\n");
		goto fail_pin_pages;
	}

	up_read(&mm->mmap_sem);

	printk("pin %d pages from user done\n", npages);

	for (i = 0; i < npages; i++) {
		kmap_addr = kmap(pages[i]);
		//print_hex_dump_bytes("kmap:", DUMP_PREFIX_OFFSET, kmap_addr, PAGE_SIZE);
		size = min_t(size_t, PAGE_SIZE, len);
		switch(rw) {
		case MYDEMO_READ:
			memcpy(kmap_addr, dev_buf + PAGE_SIZE *i,
					size);
			//print_hex_dump_bytes("read:", DUMP_PREFIX_OFFSET, kmap_addr, size);
			break;
		case MYDEMO_WRITE:
			memcpy(dev_buf + PAGE_SIZE*i, kmap_addr,
					size);
			//print_hex_dump_bytes("write:", DUMP_PREFIX_OFFSET, dev_buf + PAGE_SIZE*i, size);
			break;
		default:
			break;
		}
		put_page(pages[i]);
		kunmap(pages[i]);
		len -= size;
		count += size;
	}

	kfree(pages);

	printk("%s: %s user buffer %d bytes done\n", __func__, rw ? "write":"read", count);

	return count;

fail_pin_pages:
	up_read(&mm->mmap_sem);
	for (i = 0; i < ret; i++)
		put_page(pages[i]);
	kfree(pages);

	return -EFAULT;
}

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
demodrv_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	size_t nbytes = 
		demodrv_read_write(buf, count, MYDEMO_READ); 

	printk("%s: read nbytes=%d done at pos=%d\n",
		 __func__, nbytes, (int)*ppos);

	return nbytes;
}

static ssize_t
demodrv_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	
	size_t nbytes = 
		demodrv_read_write((void *)buf, count, MYDEMO_WRITE);

	printk("%s: write nbytes=%d done at pos=%d\n",
		 __func__, nbytes, (int)*ppos);

	return nbytes;
}

static int 
demodrv_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pfn;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long len = vma->vm_end - vma->vm_start;

	if (offset >= MAX_DEVICE_BUFFER_SIZE)
		return -EINVAL;
	if (len > (MAX_DEVICE_BUFFER_SIZE - offset))
		return -EINVAL;

	printk("%s: mapping %ld bytes of device buffer at offset %ld\n",
		 __func__, len, offset);

	/*    pfn = page_to_pfn (virt_to_page (ramdisk + offset)); */
	pfn = virt_to_phys(device_buffer + offset) >> PAGE_SHIFT;

	if (remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static long
demodrv_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned long tbs = MAX_DEVICE_BUFFER_SIZE;
	void __user *ioargp = (void __user *)arg;

	switch (cmd) {
	default:
		return -EINVAL;

	case MYDEV_CMD_GET_BUFSIZE:
		if (copy_to_user(ioargp, &tbs, sizeof(tbs)))
			return -EFAULT;
		return 0;
	}
}

static const struct file_operations demodrv_fops = {
	.owner = THIS_MODULE,
	.open = demodrv_open,
	.release = demodrv_release,
	.read = demodrv_read,
	.write = demodrv_write,
	.mmap = demodrv_mmap,
	.unlocked_ioctl = demodrv_unlocked_ioctl,
};

static struct miscdevice mydemodrv_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEMO_NAME,
	.fops = &demodrv_fops,
};

static int __init simple_char_init(void)
{
	int ret;

	device_buffer = kmalloc(MAX_DEVICE_BUFFER_SIZE, GFP_KERNEL);
	if (!device_buffer)
		return -ENOMEM;

	ret = misc_register(&mydemodrv_misc_device);
	if (ret) {
		printk("failed register misc device\n");
		kfree(device_buffer);
		return ret;
	}

	mydemodrv_device = mydemodrv_misc_device.this_device;

	printk("succeeded register char device: %s\n", DEMO_NAME);

	return 0;
}

static void __exit simple_char_exit(void)
{
	printk("removing device\n");

	kfree(device_buffer);
	misc_deregister(&mydemodrv_misc_device);
}

module_init(simple_char_init);
module_exit(simple_char_exit);

MODULE_AUTHOR("Benshushu");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("simpe character device");
