#include <asm/ptrace.h>

#if defined (__i386__)
struct pt_regs regs = {.gs = 0x0};
#endif
