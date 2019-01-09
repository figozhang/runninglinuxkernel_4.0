#if defined(CONFIG_UTRACE)
#if defined(CONFIG_UPROBES) || defined(CONFIG_UPROBES_MODULE)
#include <linux/uprobes.h>
#else
#include "uprobes/uprobes.h"
#endif

unsigned long foo (struct uretprobe_instance *ri, unsigned long pc, unsigned long sp)
{
  return uprobe_get_pc (ri, pc, sp);
}
#else
#error "need CONFIG_UTRACE" /* XXX: at least, uretprobe-capable uprobes */
#endif
