#if defined (__x86_64__)
#include "uprobes_x86_64.h"
#elif defined (__i386__)
#include "uprobes_i386.h"
#elif defined (__powerpc__)
#include "uprobes_ppc.h"
#elif defined (__s390__) || defined (__s390x__)
#include "uprobes_s390.h"
#else
#error "Unsupported architecture"
#endif
