#include <linux/path.h>
#include <linux/dcache.h>

void ____autoconf_func(struct path *p)
{
	(void)d_path(p, NULL, 0);
}
