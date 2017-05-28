#include <linux/kernel.h>
#include <linux/smp.h>

void foo (void *arg)
{
        (void) arg;
}

void bar (void)
{
        smp_call_function_single (0, &foo, 0, 1, 0);
}
