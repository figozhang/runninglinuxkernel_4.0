/*
 * PRs 6923 and 6967:
 * #include <linux/smp.h> should be sufficient, but there are some
 * problems with #include hygiene in this area:
 * i386, recent kernels: linux/smp.h needs linux/irqflags.h.
 * s390, RHEL5.2: linux/irqflags.h needs asm/system.h (and
 * linux/kernel.h, which asm/system.h includes).
 *
 * #include <linux/kernel.h> is probably redundant here, since
 * everybody's <asm/system.h> seems to include it, but nobody
 * seems to #include <asm/system.h> without <linux/kernel.h> first.
 *
 * <asm/system.h> includes <linux/irqflags.h> on most architectures,
 * so we don't explicitly include it here.  The exception is ia64,
 * but <linux/smp.h> alone seemed to be sufficient for ia64 here.
 */
#include <linux/kernel.h>
#include <asm/system.h>
#include <linux/smp.h>

static void no_op(void *arg)
{
}

void ____autoconf_func(void)
{
    /* Older on_each_cpu() calls had a "retry" parameter */
    (void)on_each_cpu(no_op, NULL, 0, 0);
}
