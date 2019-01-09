// We'd like to use the existence of __NR_timerfd_create to know it is
// safe to include timerfd.h, but RHEL5 x86_64 (2.6.18-398.el5) has
// __NR_timerfd_create but no timerfd.h. So, we have to test it.
#include <linux/timerfd.h>

