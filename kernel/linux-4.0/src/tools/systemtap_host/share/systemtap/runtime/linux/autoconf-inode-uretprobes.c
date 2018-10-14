#if defined(CONFIG_ARCH_SUPPORTS_UPROBES) && defined(CONFIG_UPROBES)
#include <linux/wait.h>
#include <linux/uprobes.h>
/* Check whether we have uretprobes. */
struct uprobe_consumer uc = { .ret_handler = NULL };
#else
#error "not an inode-uprobes kernel"
#endif

