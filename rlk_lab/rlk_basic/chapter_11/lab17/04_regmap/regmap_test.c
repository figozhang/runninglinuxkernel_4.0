#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/regmap.h>

struct mydev_struct {
	struct regmap *regmap;
	struct device *dev;
};

static const struct regmap_config mydev_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.fast_io = true,
};

static int _reg_write(void *context, unsigned int reg,
				unsigned int val)
{
	void __iomem *base = context;

	printk("%s: reg=0x%x, val=0x%x\n", __func__, reg, val);

	*(unsigned int *)(base + reg) = val;

	return 0;
}

static int _reg_read(void *context, unsigned int reg,
			unsigned int *val)
{
          void __iomem *base = context;

	printk("%s: reg=0x%x\n", __func__, reg);

          *val = *(unsigned int *)(base + reg);

	printk("%s: reg=0x%x, val=0x%x\n", __func__, reg, *val);

          return 0;
  }

static int reg_gather_write(void *context,
                                     const void *reg, size_t reg_len,
                                     const void *val, size_t val_len)
{
        return -ENOTSUPP;
}

static int reg_read(void *context, const void *addr, size_t reg_size,
                void *val, size_t val_size)
{
        BUG_ON(!addr);
        BUG_ON(!val);
        BUG_ON(reg_size != 4);
        BUG_ON(val_size != 4);

        return _reg_read(context, *(u32 *)addr, val);
}

static int reg_write(void *context, const void *data, size_t count)
{
	unsigned int reg;
	unsigned int val;
        BUG_ON(!data);

	reg = *(unsigned int *)data;
	val = *((unsigned int *)(data+4));

        if (WARN_ONCE(count < 4, "Invalid register access"))
                return -EINVAL;

        return _reg_write(context, reg, val);
}

static const struct regmap_bus mydev_regmap_bus = {
	.gather_write = reg_gather_write,
	.write = reg_write,
	.read = reg_read,
	.reg_format_endian_default = REGMAP_ENDIAN_NATIVE,
	.val_format_endian_default = REGMAP_ENDIAN_NATIVE,
};

static int __init my_regmap_test_init(void)
{
	struct mydev_struct *mydev;
	char addr[100];
	unsigned int val;

	mydev = kzalloc(sizeof (*mydev), GFP_KERNEL);
	if (!mydev)
		return -ENOMEM;

	mydev->regmap = devm_regmap_init(NULL, &mydev_regmap_bus, addr,
				&mydev_regmap_config);
	if (IS_ERR(mydev->regmap)) {
		printk("regmap init fail\n");
		goto err;
	}	

	regmap_write(mydev->regmap, 0, 0x30043c);
	regmap_read(mydev->regmap, 0, &val);
	printk("read register 0 = 0x%x\n", val);
		
	return 0;

err:
	kfree(mydev);
	return -ENOMEM;
}

static void __exit my_regmap_test_exit(void)
{
	printk("goodbye\n");
}

module_init(my_regmap_test_init);
module_exit(my_regmap_test_exit);
MODULE_LICENSE("GPL");
