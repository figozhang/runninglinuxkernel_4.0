/* If uprobes isn't in the kernel, pull it in from the runtime. */
#ifndef _UPROBES_INC_H_
#define _UPROBES_INC_H_

#if defined(CONFIG_UTRACE)      /* uprobes doesn't work without utrace */
#if defined(CONFIG_UPROBES) || defined(CONFIG_UPROBES_MODULE)
#include <linux/uprobes.h>
#else
#include "uprobes/uprobes.h"
#endif
#ifndef UPROBES_API_VERSION
#define UPROBES_API_VERSION 1
#endif
#else
struct uretprobe_instance { unsigned long ret_addr; };
#endif

#endif	/* _UPROBES_INC_H_ */
