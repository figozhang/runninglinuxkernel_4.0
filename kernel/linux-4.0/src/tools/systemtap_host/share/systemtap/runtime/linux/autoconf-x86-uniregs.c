#include <asm/ptrace.h>

#if defined (__i386__) || defined (__x86_64__)
struct pt_regs regs = {.ax = 0x0};
#endif

