#include <linux/proc_fs.h>

/* kernel commit 4d38a69c6 */

void bar (void) {
        struct proc_dir_entry foo;
	foo.owner = (void*) 0;
        (void) foo;
}
