#include <linux/uaccess.h>

int foo (int c)
{
        pagefault_disable();
        c ++;
        pagefault_enable();
        return c;
}
