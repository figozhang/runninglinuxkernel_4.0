#include <asm/ptrace.h>

#if defined (__i386__)
struct pt_regs regs = {.xfs = 0x0};
#endif
