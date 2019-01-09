#include <linux/ktime.h>

void ____autoconf_func(struct timespec *ts)
{
	ktime_get_real_ts(ts);
}
