#ifndef _K_SYMS_H_
#define _K_SYMS_H_

#if defined(__powerpc64__) && !_LITTLE_ENDIAN
#define KERNEL_RELOC_SYMBOL ".__start"
#else
#define KERNEL_RELOC_SYMBOL "_stext"
#endif

#endif
