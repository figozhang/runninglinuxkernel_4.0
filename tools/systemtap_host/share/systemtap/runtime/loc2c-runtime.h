/* target operations
 * Copyright (C) 2005-2012 Red Hat Inc.
 * Copyright (C) 2005-2007 Intel Corporation.
 * Copyright (C) 2007 Quentin Barnes.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LOC2C_RUNTIME_H_
#define _LOC2C_RUNTIME_H_

/* See also the linux/ and dyninst/ runtime specializations. */


/* These three macro definitions are generic, just shorthands
   used by the generated code.  */

#define op_abs(x)	(x < 0 ? -x : x)

#define fetch_bitfield(target, base, higherbits, nbits)			      \
  target = (((base) >> (sizeof (base) * 8 - (higherbits) - (nbits)))	      \
	    & (((__typeof (base)) 1 << (nbits)) - 1))

#define store_bitfield(target, base, higherbits, nbits)			      \
  target = ((target							      \
	     &~ ((((__typeof (target)) 1 << (nbits)) - 1)		      \
		 << (sizeof (target) * 8 - (higherbits) - (nbits))))	      \
	    | ((((__typeof (target)) (base))				      \
		& (((__typeof (target)) 1 << (nbits)) - 1))		      \
	       << (sizeof (target) * 8 - (higherbits) - (nbits))))


/* dwarf_div_op and dwarf_mod_op do division and modulo operations catching any
   divide by zero issues.  When they detect div_by_zero they "fault"
   by jumping to the (slightly misnamed) deref_fault label.  */
#define dwarf_div_op(a,b) ({							\
    if (b == 0) {							\
	snprintf(c->error_buffer, sizeof(c->error_buffer),		\
		 STAP_MSG_LOC2C_03, "DW_OP_div");			\
	c->last_error = c->error_buffer;				\
	goto deref_fault;						\
    }									\
    a / b;								\
})
#define dwarf_mod_op(a,b) ({							\
    if (b == 0) {							\
	snprintf(c->error_buffer, sizeof(c->error_buffer),		\
		 STAP_MSG_LOC2C_03, "DW_OP_mod");			\
	c->last_error = c->error_buffer;				\
	goto deref_fault;						\
    }									\
    a % b;								\
})


/* Given a DWARF register number, fetch its intptr_t (long) value from the
   probe context, or store a new value into the probe context.

   The register number argument is always a canonical decimal number, so it
   can be pasted into an identifier name.  These definitions turn it into a
   per-register macro, defined below for machines with individually-named
   registers.  */
#define pt_regs_fetch_register(pt_regs, regno) \
  ((intptr_t) pt_dwarf_register_##regno (pt_regs))
#define pt_regs_store_register(pt_regs, regno, value) \
  (pt_dwarf_register_##regno (pt_regs) = (value))


#if defined (STAPCONF_X86_UNIREGS) && defined (__i386__)

#define pt_dwarf_register_0(regs)  regs->ax
#define pt_dwarf_register_1(regs)  regs->cx
#define pt_dwarf_register_2(regs)  regs->dx
#define pt_dwarf_register_3(regs)  regs->bx
#define pt_dwarf_register_4(regs)  ((long) &regs->sp)
#define pt_dwarf_register_5(regs)  regs->bp
#define pt_dwarf_register_6(regs)  regs->si
#define pt_dwarf_register_7(regs)  regs->di

#elif defined (STAPCONF_X86_UNIREGS) && defined (__x86_64__)

#define pt_dwarf_register_0(regs)  regs->ax
#define pt_dwarf_register_1(regs)  regs->dx
#define pt_dwarf_register_2(regs)  regs->cx
#define pt_dwarf_register_3(regs)  regs->bx
#define pt_dwarf_register_4(regs)  regs->si
#define pt_dwarf_register_5(regs)  regs->di
#define pt_dwarf_register_6(regs)  regs->bp
#define pt_dwarf_register_7(regs)  regs->sp
#define pt_dwarf_register_8(regs)  regs->r8
#define pt_dwarf_register_9(regs)  regs->r9
#define pt_dwarf_register_10(regs) regs->r10
#define pt_dwarf_register_11(regs) regs->r11
#define pt_dwarf_register_12(regs) regs->r12
#define pt_dwarf_register_13(regs) regs->r13
#define pt_dwarf_register_14(regs) regs->r14
#define pt_dwarf_register_15(regs) regs->r15

#elif defined __i386__

/* The stack pointer is unlike other registers.  When a trap happens in
   kernel mode, it is not saved in the trap frame (struct pt_regs).
   The `esp' (and `xss') fields are valid only for a user-mode trap.
   For a kernel mode trap, the interrupted state's esp is actually an
   address inside where the `struct pt_regs' on the kernel trap stack points. */

#define pt_dwarf_register_0(regs)	regs->eax
#define pt_dwarf_register_1(regs)	regs->ecx
#define pt_dwarf_register_2(regs)	regs->edx
#define pt_dwarf_register_3(regs)	regs->ebx
#define pt_dwarf_register_4(regs)	(user_mode(regs) ? regs->esp : (long)&regs->esp)
#define pt_dwarf_register_5(regs)	regs->ebp
#define pt_dwarf_register_6(regs)	regs->esi
#define pt_dwarf_register_7(regs)	regs->edi

#elif defined __ia64__

#undef pt_regs_fetch_register
#undef pt_regs_store_register

#define pt_regs_fetch_register(pt_regs,regno)	\
  ia64_fetch_register(regno, pt_regs, &c->unwaddr)
#define pt_regs_store_register(pt_regs,regno,value) \
  ia64_store_register(regno, pt_regs, value)

#elif defined __x86_64__

#define pt_dwarf_register_0(regs)	regs->rax
#define pt_dwarf_register_1(regs)	regs->rdx
#define pt_dwarf_register_2(regs)	regs->rcx
#define pt_dwarf_register_3(regs)	regs->rbx
#define pt_dwarf_register_4(regs)	regs->rsi
#define pt_dwarf_register_5(regs)	regs->rdi
#define pt_dwarf_register_6(regs)	regs->rbp
#define pt_dwarf_register_7(regs)	regs->rsp
#define pt_dwarf_register_8(regs)	regs->r8
#define pt_dwarf_register_9(regs)	regs->r9
#define pt_dwarf_register_10(regs)	regs->r10
#define pt_dwarf_register_11(regs)	regs->r11
#define pt_dwarf_register_12(regs)	regs->r12
#define pt_dwarf_register_13(regs)	regs->r13
#define pt_dwarf_register_14(regs)	regs->r14
#define pt_dwarf_register_15(regs)	regs->r15

#elif defined __powerpc__

#undef pt_regs_fetch_register
#undef pt_regs_store_register
#define pt_regs_fetch_register(pt_regs,regno) \
  ((intptr_t) pt_regs->gpr[regno])
#define pt_regs_store_register(pt_regs,regno,value) \
  (pt_regs->gpr[regno] = (value))

#elif defined (__aarch64__)

#define pt_dwarf_register_0(pt_regs)	pt_regs->regs[0]
#define pt_dwarf_register_1(pt_regs)	pt_regs->regs[1]
#define pt_dwarf_register_2(pt_regs)	pt_regs->regs[2]
#define pt_dwarf_register_3(pt_regs)	pt_regs->regs[3]
#define pt_dwarf_register_4(pt_regs)	pt_regs->regs[4]
#define pt_dwarf_register_5(pt_regs)	pt_regs->regs[5]
#define pt_dwarf_register_6(pt_regs)	pt_regs->regs[6]
#define pt_dwarf_register_7(pt_regs)	pt_regs->regs[7]
#define pt_dwarf_register_8(pt_regs)	pt_regs->regs[8]
#define pt_dwarf_register_9(pt_regs)	pt_regs->regs[9]

#define pt_dwarf_register_10(pt_regs)	pt_regs->regs[10]
#define pt_dwarf_register_11(pt_regs)	pt_regs->regs[11]
#define pt_dwarf_register_12(pt_regs)	pt_regs->regs[12]
#define pt_dwarf_register_13(pt_regs)	pt_regs->regs[13]
#define pt_dwarf_register_14(pt_regs)	pt_regs->regs[14]
#define pt_dwarf_register_15(pt_regs)	pt_regs->regs[15]
#define pt_dwarf_register_16(pt_regs)	pt_regs->regs[16]
#define pt_dwarf_register_17(pt_regs)	pt_regs->regs[17]
#define pt_dwarf_register_18(pt_regs)	pt_regs->regs[18]
#define pt_dwarf_register_19(pt_regs)	pt_regs->regs[19]

#define pt_dwarf_register_20(pt_regs)	pt_regs->regs[20]
#define pt_dwarf_register_21(pt_regs)	pt_regs->regs[21]
#define pt_dwarf_register_22(pt_regs)	pt_regs->regs[22]
#define pt_dwarf_register_23(pt_regs)	pt_regs->regs[23]
#define pt_dwarf_register_24(pt_regs)	pt_regs->regs[24]
#define pt_dwarf_register_25(pt_regs)	pt_regs->regs[25]
#define pt_dwarf_register_26(pt_regs)	pt_regs->regs[26]
#define pt_dwarf_register_27(pt_regs)	pt_regs->regs[27]
#define pt_dwarf_register_28(pt_regs)	pt_regs->regs[28]
#define pt_dwarf_register_29(pt_regs)	pt_regs->regs[29]

#define pt_dwarf_register_30(pt_regs)	pt_regs->regs[30]
#define pt_dwarf_register_31(pt_regs)	pt_regs->sp

#elif defined (__arm__)

#undef pt_regs_fetch_register
#undef pt_regs_store_register
#define pt_regs_fetch_register(pt_regs,regno) \
  ((long) pt_regs->uregs[regno])
#define pt_regs_store_register(pt_regs,regno,value) \
  (pt_regs->uregs[regno] = (value))

#elif defined (__s390__) || defined (__s390x__)

#undef pt_regs_fetch_register
#undef pt_regs_store_register
#define pt_regs_fetch_register(pt_regs,regno) \
  ((intptr_t) pt_regs->gprs[regno])
#define pt_regs_store_register(pt_regs,regno,value) \
  (pt_regs->gprs[regno] = (value))

#endif


#if STP_SKIP_BADVARS
#define DEREF_FAULT(addr) ({0; })
#define STORE_DEREF_FAULT(addr) ({0; })
#define CATCH_DEREF_FAULT() ({0; })
#else
#define DEREF_FAULT(addr) ({						    \
    snprintf(c->error_buffer, sizeof(c->error_buffer),			    \
      STAP_MSG_LOC2C_01, (void *)(intptr_t)(addr), #addr);   \
    c->last_error = c->error_buffer;					    \
    goto deref_fault;							    \
    })

#define STORE_DEREF_FAULT(addr) ({					    \
    snprintf(c->error_buffer, sizeof(c->error_buffer),			    \
      STAP_MSG_LOC2C_02, (void *)(intptr_t)(addr), #addr);  \
    c->last_error = c->error_buffer;					    \
    goto deref_fault;							    \
    })

#define CATCH_DEREF_FAULT()				\
  if (0) {						\
deref_fault: ;						\
  }
#endif

#endif /* _LOC2C_RUNTIME_H_ */
