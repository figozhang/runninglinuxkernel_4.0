/* target operations in the Linux kernel mode
 * Copyright (C) 2005-2012 Red Hat Inc.
 * Copyright (C) 2005-2007 Intel Corporation.
 * Copyright (C) 2007 Quentin Barnes.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_LOC2C_RUNTIME_H_
#define _LINUX_LOC2C_RUNTIME_H_

#ifdef STAPCONF_LINUX_UACCESS_H
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#include <linux/types.h>
#define intptr_t long
#define uintptr_t unsigned long

#include "../loc2c-runtime.h"


#ifndef STAPCONF_PAGEFAULT_DISABLE  /* before linux commit a866374a */
#define pagefault_disable() preempt_disable()
#define pagefault_enable() preempt_enable_no_resched()
#endif


#define k_fetch_register(regno) \
  pt_regs_fetch_register(c->kregs, regno)
#define k_store_register(regno, value) \
  pt_regs_store_register(c->kregs, regno, value)


/* PR 10601: user-space (user_regset) register access.
   Needs arch specific code, only i386 and x86_64 for now.  */
#if ((defined(STAPCONF_REGSET) || defined(STAPCONF_UTRACE_REGSET)) \
     && (defined (__i386__) || defined (__x86_64__)))

#if defined(STAPCONF_REGSET)
#include <linux/regset.h>
#endif

#if defined(STAPCONF_UTRACE_REGSET)
#include <linux/tracehook.h>
/* adapt new names to old decls */
#define user_regset_view utrace_regset_view
#define user_regset utrace_regset
#define task_user_regset_view utrace_native_view

#else // PR13489, inodes-uprobes export kludge
#if !defined(STAPCONF_TASK_USER_REGSET_VIEW_EXPORTED)
// First typedef from the original decl, then #define it as a typecasted call.
// NB: not all archs actually have the function, but the decl is universal in regset.h
typedef typeof(&task_user_regset_view) task_user_regset_view_fn;
/* Special macro to tolerate the kallsyms function pointer being zero. */
#define task_user_regset_view(t) (kallsyms_task_user_regset_view ? \
                                  (* (task_user_regset_view_fn)(kallsyms_task_user_regset_view))((t)) : \
                                  NULL)
#endif
#endif

struct usr_regset_lut {
  char *name;
  unsigned rsn;
  unsigned pos;
};


/* DWARF register number -to- user_regset bank/offset mapping table.
   The register numbers come from the processor-specific ELF documents.
   The user-regset bank/offset values come from kernel $ARCH/include/asm/user*.h
   or $ARCH/kernel/ptrace.c. */
#if defined (__i386__) || defined (__x86_64__)
static const struct usr_regset_lut url_i386[] = {
  { "ax", NT_PRSTATUS, 6*4 },
  { "cx", NT_PRSTATUS, 1*4 },
  { "dx", NT_PRSTATUS, 2*4 },
  { "bx", NT_PRSTATUS, 0*4 },
  { "sp", NT_PRSTATUS, 15*4 },
  { "bp", NT_PRSTATUS, 5*4 },
  { "si", NT_PRSTATUS, 3*4 },
  { "di", NT_PRSTATUS, 4*4 },
  { "ip", NT_PRSTATUS, 12*4 },
};
#endif

#if defined (__x86_64__)
static const struct usr_regset_lut url_x86_64[] = {
  { "rax", NT_PRSTATUS, 10*8 },
  { "rdx", NT_PRSTATUS, 12*8 },
  { "rcx", NT_PRSTATUS, 11*8 },
  { "rbx", NT_PRSTATUS, 5*8 },
  { "rsi", NT_PRSTATUS, 13*8 },
  { "rdi", NT_PRSTATUS, 14*8 },
  { "rbp", NT_PRSTATUS, 4*8 },
  { "rsp", NT_PRSTATUS, 19*8 },
  { "r8", NT_PRSTATUS, 9*8 },
  { "r9", NT_PRSTATUS, 8*8 }, 
  { "r10", NT_PRSTATUS, 7*8 },  
  { "r11", NT_PRSTATUS, 6*8 }, 
  { "r12", NT_PRSTATUS, 3*8 }, 
  { "r13", NT_PRSTATUS, 2*8 }, 
  { "r14", NT_PRSTATUS, 1*8 }, 
  { "r15", NT_PRSTATUS, 0*8 }, 
  { "rip", NT_PRSTATUS, 16*8 }, 
  /* XXX: SSE registers %xmm0-%xmm7 */ 
  /* XXX: SSE2 registers %xmm8-%xmm15 */
  /* XXX: FP registers %st0-%st7 */
  /* XXX: MMX registers %mm0-%mm7 */
};
#endif
/* XXX: insert other architectures here. */


static u32 ursl_fetch32 (const struct usr_regset_lut* lut, unsigned lutsize, int e_machine, unsigned regno)
{
  u32 value = ~0;
  const struct user_regset_view *rsv = task_user_regset_view(current); 
  unsigned rsi;
  int rc;
  unsigned rsn;
  unsigned pos;
  unsigned count;

  WARN_ON (!rsv);
  if (!rsv) goto out;
  WARN_ON (regno >= lutsize);
  if (regno >= lutsize) goto out;
  if (rsv->e_machine != e_machine) goto out;

  rsn = lut[regno].rsn;
  pos = lut[regno].pos;
  count = sizeof(value);

  for (rsi=0; rsi<rsv->n; rsi++)
    if (rsv->regsets[rsi].core_note_type == rsn)
      {
        const struct user_regset *rs = & rsv->regsets[rsi];
        rc = (rs->get)(current, rs, pos, count, & value, NULL);
        WARN_ON (rc);
        /* success */
        goto out;
      }
  WARN_ON (1); /* did not find appropriate regset! */
  
 out:
  return value;
}


static void ursl_store32 (const struct usr_regset_lut* lut,unsigned lutsize,  int e_machine, unsigned regno, u32 value)
{
  const struct user_regset_view *rsv = task_user_regset_view(current); 
  unsigned rsi;
  int rc;
  unsigned rsn;
  unsigned pos;
  unsigned count;

  WARN_ON (!rsv);
  if (!rsv) goto out;
  WARN_ON (regno >= lutsize);
  if (regno >= lutsize) goto out;
  if (rsv->e_machine != e_machine) goto out;

  rsn = lut[regno].rsn;
  pos = lut[regno].pos;
  count = sizeof(value);

  for (rsi=0; rsi<rsv->n; rsi++)
    if (rsv->regsets[rsi].core_note_type == rsn)
      {
        const struct user_regset *rs = & rsv->regsets[rsi];
        rc = (rs->set)(current, rs, pos, count, & value, NULL);
        WARN_ON (rc);
        /* success */
        goto out;
      }
  WARN_ON (1); /* did not find appropriate regset! */
  
 out:
  return;
}


static u64 ursl_fetch64 (const struct usr_regset_lut* lut, unsigned lutsize, int e_machine, unsigned regno)
{
  u64 value = ~0;
  const struct user_regset_view *rsv = task_user_regset_view(current); 
  unsigned rsi;
  int rc;
  unsigned rsn;
  unsigned pos;
  unsigned count;

  if (!rsv) goto out;
  if (regno >= lutsize) goto out;
  if (rsv->e_machine != e_machine) goto out;

  rsn = lut[regno].rsn;
  pos = lut[regno].pos;
  count = sizeof(value);

  for (rsi=0; rsi<rsv->n; rsi++)
    if (rsv->regsets[rsi].core_note_type == rsn)
      {
        const struct user_regset *rs = & rsv->regsets[rsi];
        rc = (rs->get)(current, rs, pos, count, & value, NULL);
        if (rc)
          goto out;
        /* success */
        return value;
      }
 out:
  printk (KERN_WARNING "process %d mach %d regno %d not available for fetch.\n", current->tgid, e_machine, regno);
  return value;
}


static void ursl_store64 (const struct usr_regset_lut* lut,unsigned lutsize,  int e_machine, unsigned regno, u64 value)
{
  const struct user_regset_view *rsv = task_user_regset_view(current); 
  unsigned rsi;
  int rc;
  unsigned rsn;
  unsigned pos;
  unsigned count;

  WARN_ON (!rsv);
  if (!rsv) goto out;
  WARN_ON (regno >= lutsize);
  if (regno >= lutsize) goto out;
  if (rsv->e_machine != e_machine) goto out;

  rsn = lut[regno].rsn;
  pos = lut[regno].pos;
  count = sizeof(value);

  for (rsi=0; rsi<rsv->n; rsi++)
    if (rsv->regsets[rsi].core_note_type == rsn)
      {
        const struct user_regset *rs = & rsv->regsets[rsi];
        rc = (rs->set)(current, rs, pos, count, & value, NULL);
        if (rc)
          goto out;
        /* success */
        return;
      }
  
 out:
  printk (KERN_WARNING "process %d mach %d regno %d not available for store.\n", current->tgid, e_machine, regno);
  return;
}


#if defined (__i386__)

#define u_fetch_register(regno) ursl_fetch32(url_i386, ARRAY_SIZE(url_i386), EM_386, regno)
#define u_store_register(regno,value) ursl_store32(url_i386, ARRAY_SIZE(url_i386), EM_386, regno, value)

#elif defined (__x86_64__)

#define u_fetch_register(regno) (_stp_is_compat_task() ? ursl_fetch32(url_i386, ARRAY_SIZE(url_i386), EM_386, regno) : ursl_fetch64(url_x86_64, ARRAY_SIZE(url_x86_64), EM_X86_64, regno))
#define u_store_register(regno,value)  (_stp_is_compat_task() ? ursl_store32(url_i386, ARRAY_SIZE(url_i386), EM_386, regno, value) : ursl_store64(url_x86_64, ARRAY_SIZE(url_x86_64), EM_X86_64, regno, value))

#endif

#else /* ! STAPCONF_REGSET */

/* Downgrade to pt_dwarf_register access. */

#define u_store_register(regno, value) \
  pt_regs_store_register(c->uregs, regno, value)

/* If we're in a 32/31-bit task in a 64-bit kernel, we need to emulate
 * 32-bitness by masking the output of pt_regs_fetch_register() */
#ifndef CONFIG_COMPAT
#define u_fetch_register(regno) \
  pt_regs_fetch_register(c->uregs, regno)
#else
#define u_fetch_register(regno) \
  (_stp_is_compat_task() ? (0xffffffff & pt_regs_fetch_register(c->uregs, regno)) \
                         : pt_regs_fetch_register(c->uregs, regno))
#endif

#endif /* STAPCONF_REGSET */


/* The deref and store_deref macros are called to safely access addresses
   in the probe context.  These macros are used only for kernel addresses.
   The macros must handle bogus addresses here gracefully (as from
   corrupted data structures, stale pointers, etc), by doing a "goto
   deref_fault".

   On most machines, the asm/uaccess.h macros __get_user_asm and
   __put_user_asm do exactly the low-level work we need to access memory
   with fault handling, and are not actually specific to user-address
   access at all.  Each machine's definition of deref and deref_store here
   must work right for kernel addresses, and can use whatever existing
   machine-specific kernel macros are convenient.  */


/* NB: this autoconf is always disabled, pending further performance eval. */
#if 0 && defined STAPCONF_PROBE_KERNEL

/* Kernel 2.6.26 adds probe_kernel_{read,write}, which lets us write
 * architecture-neutral implementations of kread, kwrite, deref, and
 * store_deref.
 *
 * NB: deref and store_deref shouldn't be used with 64-bit values on 32-bit
 * platforms, because they will lose data in the conversion to intptr_t.  We
 * generally want to encourage using kread and kwrite instead.
 */

#define kread(ptr) ({ \
        typeof(*(ptr)) _v = 0; \
        if (lookup_bad_addr((unsigned long)(ptr), sizeof (*(ptr))) ||	\
            probe_kernel_read((void *)&_v, (void *)(ptr), sizeof(*(ptr)))) \
          DEREF_FAULT(ptr); \
        _v; \
    })
#define uread kread

#define kwrite(ptr, value) ({ \
        typeof(*(ptr)) _v; \
        _v = (typeof(*(ptr)))(value); \
        if (lookup_bad_addr((unsigned long)addr, sizeof (*(ptr))) ||	\
            probe_kernel_write((void *)(ptr), (void *)&_v, sizeof(*(ptr)))) \
          STORE_DEREF_FAULT(ptr); \
    })
#define uwrite kwrite

#define uderef(size, addr) ({ \
    intptr_t _i = 0; \
    switch (size) { \
      case 1: _i = kread((u8 *)(addr)); break; \
      case 2: _i = kread((u16 *)(addr)); break; \
      case 4: _i = kread((u32 *)(addr)); break; \
      case 8: _i = kread((u64 *)(addr)); break; \
      default: __deref_bad(); \
    } \
    _i; \
  })
#define kderef uderef

#define store_uderef(size, addr, value) ({ \
    switch (size) { \
      case 1: kwrite((u8 *)(addr), (value)); break; \
      case 2: kwrite((u16 *)(addr), (value)); break; \
      case 4: kwrite((u32 *)(addr), (value)); break; \
      case 8: kwrite((u64 *)(addr), (value)); break; \
      default: __store_deref_bad(); \
    } \
  })
#define store_kderef store_uderef


extern void __deref_bad(void);
extern void __store_deref_bad(void);

#else /* !STAPCONF_PROBE_KERNEL */

#if defined __i386__

#define _stp_deref(size, addr, seg)                                           \
  ({									      \
    int _bad = 0;							      \
    intptr_t _v = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
        case 1: { u8 _b; __get_user_asm(_b,addr,_bad,"b","b","=q",1); _v = _b; } break; \
        case 2: { u16 _w; __get_user_asm(_w,addr,_bad,"w","w","=r",1); _v = _w; } break; \
        case 4: { u32 _l; __get_user_asm(_l,addr,_bad,"l","","=r",1); _v = _l; } break; \
        default: _v = __get_user_bad();                                       \
        }                                                                     \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)                                                                 \
      DEREF_FAULT(addr);						      \
    _v;									      \
  })

#define _stp_store_deref(size, addr, value, seg)                              \
  ({									      \
    int _bad = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
        case 1: __put_user_asm(((u8)(value)),addr,_bad,"b","b","iq",1); break;\
        case 2: __put_user_asm(((u16)(value)),addr,_bad,"w","w","ir",1); break;\
        case 4: __put_user_asm(((u32)(value)),addr,_bad,"l","k","ir",1); break;\
        default: __put_user_bad();                                            \
        }                                                                     \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)                                                                 \
      STORE_DEREF_FAULT(addr);                                                \
  })


#elif defined __x86_64__

#define _stp_deref(size, addr, seg)                                           \
  ({									      \
    int _bad = 0;							      \
    intptr_t _v = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
        case 1: { u8 _b; __get_user_asm(_b,(unsigned long)addr,_bad,"b","b","=q",1); _v = _b; } break; \
        case 2: { u16 _w; __get_user_asm(_w,(unsigned long)addr,_bad,"w","w","=r",1); _v = _w; } break; \
        case 4: { u32 _l; __get_user_asm(_l,(unsigned long)addr,_bad,"l","","=r",1); _v = _l; } break; \
        case 8: { u64 _q; __get_user_asm(_q,(unsigned long)addr,_bad,"q","","=r",1); _v = _q; } break; \
        default: _v = __get_user_bad();                                       \
        }                                                                     \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)								      \
      DEREF_FAULT(addr);						      \
    _v;									      \
  })

#define _stp_store_deref(size, addr, value, seg)                              \
  ({									      \
    int _bad = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
        case 1: __put_user_asm(((u8)(value)),addr,_bad,"b","b","iq",1); break; \
        case 2: __put_user_asm(((u16)(value)),addr,_bad,"w","w","ir",1); break;\
        case 4: __put_user_asm(((u32)(value)),addr,_bad,"l","k","ir",1); break;\
        case 8: __put_user_asm(((u64)(value)),addr,_bad,"q","","Zr",1); break; \
        default: __put_user_bad();                                      \
        }                                                               \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)								      \
      STORE_DEREF_FAULT(addr);						      \
  })

#elif defined __ia64__

#define _stp_deref(size, addr, seg)					\
  ({									\
     int _bad = 0;							\
     intptr_t _v=0;							\
     mm_segment_t _oldfs = get_fs();                                    \
     set_fs(seg);                                                       \
     pagefault_disable();                                               \
     if (lookup_bad_addr((unsigned long)addr, size))			\
       _bad = 1;                                                        \
     else {								\
       switch (size) {                                                  \
	 case 1: __get_user_size(_v, addr, 1, _bad); break; 		\
	 case 2: __get_user_size(_v, addr, 2, _bad); break;  		\
	 case 4: __get_user_size(_v, addr, 4, _bad); break;  		\
	 case 8: __get_user_size(_v, addr, 8, _bad); break;  		\
	 default: __get_user_unknown(); break;				\
	  }								\
     }									\
     pagefault_enable();                                                \
     set_fs(_oldfs);                                                    \
     if (_bad) 								\
       DEREF_FAULT(addr);						\
     _v;								\
   })

#define _stp_store_deref(size, addr, value, seg)                        \
  ({									\
    int _bad=0;								\
    mm_segment_t _oldfs = get_fs();                                     \
    set_fs(seg);                                                        \
    pagefault_disable();                                                \
    if (lookup_bad_addr((unsigned long)addr, size))			\
      _bad = 1;                                                         \
    else                                                                \
      switch (size){							\
      case 1: __put_user_size(value, addr, 1, _bad); break;		\
      case 2: __put_user_size(value, addr, 2, _bad); break;		\
      case 4: __put_user_size(value, addr, 4, _bad); break;		\
      case 8: __put_user_size(value, addr, 8, _bad); break;		\
      default: __put_user_unknown(); break;				\
      }                                                                 \
    pagefault_enable();                                                 \
    set_fs(_oldfs);                                                     \
    if (_bad)								\
	   STORE_DEREF_FAULT(addr);					\
   })

#elif defined __powerpc__ || defined __powerpc64__

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#define __stp_get_user_size(x, ptr, size, retval)		\
		__get_user_size(x, ptr, size, retval)
#define __stp_put_user_size(x, ptr, size, retval)		\
		__put_user_size(x, ptr, size, retval)
#else
#define __stp_get_user_size(x, ptr, size, retval)		\
		__get_user_size(x, ptr, size, retval, -EFAULT)
#define __stp_put_user_size(x, ptr, size, retval)		\
		__put_user_size(x, ptr, size, retval, -EFAULT)
#endif

#define _stp_deref(size, addr, seg)                                           \
  ({									      \
    int _bad = 0;							      \
    intptr_t _v = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
	case 1: __stp_get_user_size(_v, addr, 1, _bad); break;                \
	case 2: __stp_get_user_size(_v, addr, 2, _bad); break;                \
	case 4: __stp_get_user_size(_v, addr, 4, _bad); break;                \
	case 8: __stp_get_user_size(_v, addr, 8, _bad); break;                \
        default: _v = __get_user_bad();                                       \
        }                                                                     \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)								      \
      DEREF_FAULT(addr);						      \
    _v;									      \
  })

#define _stp_store_deref(size, addr, value, seg)                              \
  ({									      \
    int _bad = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
	case 1: __stp_put_user_size(((u8)(value)), addr, 1, _bad); break;     \
	case 2: __stp_put_user_size(((u16)(value)), addr, 2, _bad); break;    \
	case 4: __stp_put_user_size(((u32)(value)), addr, 4, _bad); break;    \
	case 8: __stp_put_user_size(((u64)(value)), addr, 8, _bad); break;    \
        default: __put_user_bad();                                            \
        }                                                                     \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)								      \
      STORE_DEREF_FAULT(addr);						      \
  })

#elif defined (__aarch64__)

#define _stp_deref(size, addr, seg)                                           \
  ({									      \
    int _bad = 0;							      \
    intptr_t _v = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
	case 1: __get_user_asm("ldrb", "%w", _v, (unsigned long)addr, _bad); break;\
	case 2: __get_user_asm("ldrh", "%w",_v, (unsigned long)addr, _bad); break;\
	case 4: __get_user_asm("ldr", "%w",_v,  (unsigned long)addr, _bad); break;\
	case 8: __get_user_asm("ldr", "%",_v,  (unsigned long)addr, _bad); break;\
        default: BUILD_BUG();			                              \
        }                                                                     \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)								      \
      DEREF_FAULT(addr);						      \
    _v;									      \
  })

#define _stp_store_deref(size, addr, value, seg)                              \
  ({									      \
    int _bad = 0;							      \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			      \
      _bad = 1;                                                               \
    else                                                                      \
      switch (size)                                                           \
        {                                                                     \
	case 1: __put_user_asm("strb", "%w", ((u8)(value)), addr, _bad); break;\
	case 2: __put_user_asm("strh", "%w", ((u16)(value)), addr, _bad); break;\
	case 4: __put_user_asm("str", "%w", ((u32)(value)), addr, _bad); break;\
	case 8: __put_user_asm("str", "%", ((u64)(value)), addr, _bad); break;\
        default: BUILD_BUG();                                                 \
        }                                                                     \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad)								      \
      STORE_DEREF_FAULT(addr);						      \
  })

#elif defined (__arm__)

/* Macros for ARM lifted from 2.6.21.1's linux/include/asm-arm/uaccess.h
 * and slightly altered. */

#define __stp_get_user_asm_byte(x,addr,err)			\
	__asm__ __volatile__(					\
	"1:	ldrb	%1,[%2],#0\n"				\
	"2:\n"							\
	"	.section .fixup,\"ax\"\n"			\
	"	.align	2\n"					\
	"3:	mov	%0, %3\n"				\
	"	mov	%1, #0\n"				\
	"	b	2b\n"					\
	"	.previous\n"					\
	"	.section __ex_table,\"a\"\n"			\
	"	.align	3\n"					\
	"	.long	1b, 3b\n"				\
	"	.previous"					\
	: "+r" (err), "=&r" (x)					\
	: "r" (addr), "i" (-EFAULT)				\
	: "cc")

#ifndef __ARMEB__
#define __stp_get_user_asm_half(x,__gu_addr,err)		\
({								\
	unsigned long __b1, __b2;				\
	__stp_get_user_asm_byte(__b1, __gu_addr, err);		\
	__stp_get_user_asm_byte(__b2, __gu_addr + 1, err);	\
	(x) = __b1 | (__b2 << 8);				\
})
#else
#define __stp_get_user_asm_half(x,__gu_addr,err)		\
({								\
	unsigned long __b1, __b2;				\
	__stp_get_user_asm_byte(__b1, __gu_addr, err);		\
	__stp_get_user_asm_byte(__b2, __gu_addr + 1, err);	\
	(x) = (__b1 << 8) | __b2;				\
})
#endif

#define __stp_get_user_asm_word(x,addr,err)			\
	__asm__ __volatile__(					\
	"1:	ldr	%1,[%2],#0\n"				\
	"2:\n"							\
	"	.section .fixup,\"ax\"\n"			\
	"	.align	2\n"					\
	"3:	mov	%0, %3\n"				\
	"	mov	%1, #0\n"				\
	"	b	2b\n"					\
	"	.previous\n"					\
	"	.section __ex_table,\"a\"\n"			\
	"	.align	3\n"					\
	"	.long	1b, 3b\n"				\
	"	.previous"					\
	: "+r" (err), "=&r" (x)					\
	: "r" (addr), "i" (-EFAULT)				\
	: "cc")

#define __stp_put_user_asm_byte(x,__pu_addr,err)		\
	__asm__ __volatile__(					\
	"1:	strb	%1,[%2],#0\n"				\
	"2:\n"							\
	"	.section .fixup,\"ax\"\n"			\
	"	.align	2\n"					\
	"3:	mov	%0, %3\n"				\
	"	b	2b\n"					\
	"	.previous\n"					\
	"	.section __ex_table,\"a\"\n"			\
	"	.align	3\n"					\
	"	.long	1b, 3b\n"				\
	"	.previous"					\
	: "+r" (err)						\
	: "r" (x), "r" (__pu_addr), "i" (-EFAULT)		\
	: "cc")

#ifndef __ARMEB__
#define __stp_put_user_asm_half(x,__pu_addr,err)			\
({									\
	unsigned long __temp = (unsigned long)(x);			\
	__stp_put_user_asm_byte(__temp, __pu_addr, err);		\
	__stp_put_user_asm_byte(__temp >> 8, __pu_addr + 1, err);	\
})
#else
#define __stp_put_user_asm_half(x,__pu_addr,err)			\
({									\
	unsigned long __temp = (unsigned long)(x);			\
	__stp_put_user_asm_byte(__temp >> 8, __pu_addr, err);		\
	__stp_put_user_asm_byte(__temp, __pu_addr + 1, err);		\
})
#endif

#define __stp_put_user_asm_word(x,__pu_addr,err)		\
	__asm__ __volatile__(					\
	"1:	str	%1,[%2],#0\n"				\
	"2:\n"							\
	"	.section .fixup,\"ax\"\n"			\
	"	.align	2\n"					\
	"3:	mov	%0, %3\n"				\
	"	b	2b\n"					\
	"	.previous\n"					\
	"	.section __ex_table,\"a\"\n"			\
	"	.align	3\n"					\
	"	.long	1b, 3b\n"				\
	"	.previous"					\
	: "+r" (err)						\
	: "r" (x), "r" (__pu_addr), "i" (-EFAULT)		\
	: "cc")

#define _stp_deref(size, addr, seg)					\
  ({									\
     unsigned long __gu_addr = (unsigned long)(addr);			\
     int _bad = 0;							\
     intptr_t _v=0;							\
     mm_segment_t _oldfs = get_fs();                                    \
     set_fs(seg);                                                       \
     pagefault_disable();                                               \
     if (lookup_bad_addr(__gu_addr, size))				\
      _bad = 1;                                                         \
     else                                                               \
      switch (size){							\
      case 1: __stp_get_user_asm_byte(_v, __gu_addr, _bad); break;	\
      case 2: __stp_get_user_asm_half(_v, __gu_addr, _bad); break;	\
      case 4: __stp_get_user_asm_word(_v, __gu_addr, _bad); break;	\
      default: __get_user_bad(); break;                                 \
      }                                                                 \
    pagefault_enable();                                                 \
    set_fs(_oldfs);                                                     \
    if (_bad)  								\
	DEREF_FAULT(addr);						\
     _v;								\
   })

#define _stp_store_deref(size, addr, value, seg)                        \
  ({									\
    unsigned long __pu_addr = (unsigned long)(addr);			\
    int _bad=0;								\
    mm_segment_t _oldfs = get_fs();					\
    set_fs(seg);							\
    pagefault_disable();						\
    if (lookup_bad_addr(__pu_addr, size))				\
      _bad = 1;                                                         \
    else                                                                \
      switch (size){							\
      case 1: __stp_put_user_asm_byte(value, __pu_addr, _bad); break;	\
      case 2: __stp_put_user_asm_half(value, __pu_addr, _bad); break;	\
      case 4: __stp_put_user_asm_word(value, __pu_addr, _bad); break;	\
      default: __put_user_bad(); break;                                 \
      }                                                                 \
    pagefault_enable();							\
    set_fs(_oldfs);							\
    if (_bad)								\
	   STORE_DEREF_FAULT(addr);						\
   })

#elif defined (__s390__) || defined (__s390x__)

/* Use same __get_user() and __put_user() for both user and kernel
   addresses, but make sure set_fs() is called appropriately first. */

#define _stp_deref(size, addr, seg) ({ \
    u8 _b; u16 _w; u32 _l; u64 _q; \
    uintptr_t _a = (uintptr_t) addr; \
    intptr_t _v = 0; \
    int _bad = 0; \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			\
      _bad = 1;                                                         \
    else switch (size) { \
      case 1: _bad = __get_user(_b, (u8 *)(_a)); _v = _b; break; \
      case 2: _bad = __get_user(_w, (u16 *)(_a)); _v = _w; break; \
      case 4: _bad = __get_user(_l, (u32 *)(_a)); _v = _l; break; \
      case 8: _bad = __get_user(_q, (u64 *)(_a)); _v = _q; break; \
      default: __get_user_bad(); \
    } \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad) \
      DEREF_FAULT(addr); \
    _v; \
  })

#define _stp_store_deref(size, addr, value, seg) ({ \
    int _bad = 0; \
    mm_segment_t _oldfs = get_fs();                                           \
    set_fs(seg);                                                              \
    pagefault_disable();                                                      \
    if (lookup_bad_addr((unsigned long)addr, size))			\
      _bad = 1;                                                         \
    else switch (size) {		                                \
      case 1: _bad = __put_user(((u8)(value)), ((u8 *)(addr))); break; \
      case 2: _bad = __put_user(((u16)(value)), ((u16 *)(addr))); break; \
      case 4: _bad = __put_user(((u32)(value)), ((u32 *)(addr))); break; \
      case 8: _bad = __put_user(((u64)(value)), ((u64 *)(addr))); break; \
      default: __put_user_bad(); \
    } \
    pagefault_enable();                                                       \
    set_fs(_oldfs);                                                           \
    if (_bad) \
	STORE_DEREF_FAULT(addr); \
  })

#endif /* (s390) || (s390x) */


/* Map kderef/uderef to the generic segment-aware deref macros. */ 

#ifndef kderef
#define kderef(s,a) _stp_deref(s,a,KERNEL_DS)
#endif

#ifndef store_kderef
#define store_kderef(s,a,v) _stp_store_deref(s,a,v,KERNEL_DS)
#endif

#ifndef uderef
#define uderef(s,a) _stp_deref(s,a,USER_DS)
#endif

#ifndef store_uderef
#define store_uderef(s,a,v) _stp_store_deref(s,a,v,USER_DS)
#endif



#if defined (__i386__) || defined (__arm__)

/* x86 and arm can't do 8-byte put/get_user_asm, so we have to split it */

#define __Xread(ptr, Xderef)				\
  ((sizeof(*(ptr)) == 8) ?				\
       *(typeof(ptr))&(u32[2]) {			\
	 (u32) Xderef(4, &((u32 *)(ptr))[0]),		\
	 (u32) Xderef(4, &((u32 *)(ptr))[1]) }		\
     : (typeof(*(ptr))) Xderef(sizeof(*(ptr)), (ptr)))

#define __Xwrite(ptr, value, store_Xderef)				     \
  ({									     \
    if (sizeof(*(ptr)) == 8) {						     \
      union { typeof(*(ptr)) v; u32 l[2]; } _kw;			     \
      _kw.v = (typeof(*(ptr)))(value);					     \
      store_Xderef(4, &((u32 *)(ptr))[0], _kw.l[0]);			     \
      store_Xderef(4, &((u32 *)(ptr))[1], _kw.l[1]);			     \
    } else								     \
      store_Xderef(sizeof(*(ptr)), (ptr), (long)(typeof(*(ptr)))(value));     \
  })

#else

#define __Xread(ptr, Xderef) \
  ( (typeof(*(ptr))) Xderef(sizeof(*(ptr)), (ptr)) )
#define __Xwrite(ptr, value, store_Xderef) \
  ( store_Xderef(sizeof(*(ptr)), (ptr), (long)(typeof(*(ptr)))(value)) )

#endif

#define kread(ptr) __Xread((ptr), kderef)
#define uread(ptr) __Xread((ptr), uderef)

#define kwrite(ptr, value) __Xwrite((ptr), (value), store_kderef)
#define uwrite(ptr, value) __Xwrite((ptr), (value), store_uderef)

#endif /* STAPCONF_PROBE_KERNEL */

/* Dereference a kernel buffer ADDR of size MAXBYTES. Put the bytes in
 * address DST (which can be NULL).
 *
 * This function is useful for reading memory when the size isn't a
 * size that kderef() handles.  This function is very similar to
 * kderef_string(), but kderef_buffer() doesn't quit when finding a
 * '\0' byte or append a '\0' byte.
 */

#define kderef_buffer(dst, addr, maxbytes)				      \
  ({									      \
    uintptr_t _addr;							      \
    size_t _len;							      \
    unsigned char _c;							      \
    char *_d = (dst);							      \
    for (_len = (maxbytes), _addr = (uintptr_t)(addr);			      \
	 _len > 1;							      \
	 --_len, ++_addr)						      \
      _c = kderef (1, _addr);						      \
      if (_d)								      \
	 *_d++ = _c;							      \
    (dst);								      \
  })

/* The following is for kernel strings, see the uconversions.stp
   tapset for user_string functions. */

#define kderef_string(dst, addr, maxbytes)				      \
  ({									      \
    uintptr_t _addr;							      \
    size_t _len;							      \
    unsigned char _c;							      \
    char *_d = (dst);							      \
    for (_len = (maxbytes), _addr = (uintptr_t)(addr);			      \
	 _len > 1 && (_c = kderef (1, _addr)) != '\0';			      \
	 --_len, ++_addr)						      \
      if (_d)								      \
	 *_d++ = _c;							      \
    if (_d)								      \
      *_d = '\0';							      \
    (dst);								      \
  })

#define store_kderef_string(src, addr, maxbytes)			      \
  ({									      \
    uintptr_t _addr;							      \
    size_t _len;							      \
    char *_s = (src);							      \
    for (_len = (maxbytes), _addr = (uintptr_t)(addr);			      \
	 _len > 1 && _s && *_s != '\0'; --_len, ++_addr)		      \
      store_kderef(1, _addr, *_s++);					      \
    store_kderef(1, _addr, '\0');					      \
  })


#endif /* _LINUX_LOC2C_RUNTIME_H_ */
