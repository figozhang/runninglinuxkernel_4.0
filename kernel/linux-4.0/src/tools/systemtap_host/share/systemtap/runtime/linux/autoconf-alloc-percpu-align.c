#include <linux/percpu.h>

/* kernel commit f2a8205c */
void foo (void) {
   (void) __alloc_percpu(sizeof(int), 8);
}
