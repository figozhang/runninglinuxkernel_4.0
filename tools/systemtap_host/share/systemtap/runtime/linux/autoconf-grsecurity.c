/* PR10551: pax/grsecurity changes linux/module.h */

#include <linux/module.h>

struct module *t;
unsigned size;

void foo (void)
{
   size += t->init_size_rw + t->init_size_rx + t->core_size_rw + t->core_size_rx;  
}
