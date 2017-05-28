#if defined(CONFIG_ARCH_SUPPORTS_UPROBES) && defined(CONFIG_UPROBES)
#include <linux/wait.h>
#include <linux/uprobes.h>
/* Check whether we have the old inode-uprobes api.
 * (It was later changed to uprobe_register and uprobe_unregister.)
 */
void *reg = register_uprobe;
void *ureg = unregister_uprobe;

#else
#error "not an inode-uprobes kernel"
#endif

