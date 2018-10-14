#include <linux/kallsyms.h>

#ifdef CONFIG_PPC64
#error kallsyms_on_each_symbol optimization not supported on ppc64.
#endif

void foo (void) {
   (void) kallsyms_on_each_symbol(NULL, NULL);
}
