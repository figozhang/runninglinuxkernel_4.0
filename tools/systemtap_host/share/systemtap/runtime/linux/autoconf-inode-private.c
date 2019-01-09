#include <linux/fs.h>

/* check 2.6.18 inode diet patch which changed */
/* u.generic_ip to i_private */

struct inode i  __attribute__ ((unused)) = {.i_private=(void *)0};
