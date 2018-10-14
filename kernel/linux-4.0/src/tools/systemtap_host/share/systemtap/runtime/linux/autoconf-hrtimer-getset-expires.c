#include <linux/hrtimer.h>

void ____autoconf_func(struct hrtimer *t)
{
    hrtimer_set_expires(t, hrtimer_get_expires(t));
}
