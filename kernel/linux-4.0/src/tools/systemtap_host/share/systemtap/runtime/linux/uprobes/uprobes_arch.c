#if defined (__x86_64__)
#include "uprobes_x86_64.c"
#elif defined (__i386__)
#include "uprobes_i386.c"
#elif defined (__powerpc__)
#include "uprobes_ppc.c"
#elif defined (__s390__) || defined (__s390x__)
#include "uprobes_s390.c"
#else
#error "Unsupported architecture"
#endif
