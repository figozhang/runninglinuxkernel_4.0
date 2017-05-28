#include <linux/perf_event.h>

/* nmi parameter was removed with linux commit a8b0ca. */
static void enter_perf_probe(struct perf_event *e,
			     int nmi,
			     struct perf_sample_data *d,
			     struct pt_regs *r) { }

perf_overflow_handler_t callback = enter_perf_probe;
