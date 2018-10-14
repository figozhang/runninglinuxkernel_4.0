#include <linux/tracepoint.h>

/* Until 3.15 (commit de7b2973903c), tracepoints used strings to register.  */
void foo (void) {
	(void) tracepoint_probe_register("foo", NULL, NULL);
	tracepoint_probe_unregister("foo", NULL, NULL);
}
