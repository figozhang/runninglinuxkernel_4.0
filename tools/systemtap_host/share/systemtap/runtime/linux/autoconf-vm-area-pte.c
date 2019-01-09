#include <linux/vmalloc.h>

/* kernel commit cd12909cb576d373 */
struct vm_struct * foo (void) {
   return alloc_vm_area(PAGE_SIZE, NULL);
}
