/*  -*- linux-c -*-
 * Stack tracing functions
 * Copyright (C) 2005-2009, 2014 Red Hat Inc.
 * Copyright (C) 2005 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/*
  The translator will only include this file if the session needs any
  of the backtrace functions.  Currently indicated by having the session
  need_unwind flag, which is set by tapset functions marked with
  pragme:unwind.
*/

#ifndef _STACK_C_
#define _STACK_C_

/* Maximum number of backtrace levels. */
#ifndef MAXBACKTRACE
#define MAXBACKTRACE 20
#endif

/** @file stack.c
 * @brief Stack Tracing Functions
 */

/** @addtogroup stack Stack Tracing Functions
 *
 * @{
 */

#include "sym.c"
#include "regs.h"

#include "linux/uprobes-inc.h"

#if defined(STAPCONF_KERNEL_STACKTRACE) || defined(STAPCONF_KERNEL_STACKTRACE_NO_BP)
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#endif

static void _stp_stack_print_fallback(unsigned long, int, int, int);

#ifdef STP_USE_DWARF_UNWINDER
#ifdef STAPCONF_LINUX_UACCESS_H
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#include <linux/types.h>
#define intptr_t long
#define uintptr_t unsigned long

static int _stp_valid_pc_addr(unsigned long addr, struct task_struct *tsk)
{
	/* Just a simple check of whether the the address can be accessed
	   as a user space address. Zero is always bad. */

/* FIXME for s390x PR13350. */
#if defined (__s390__) || defined (__s390x__)
       return addr != 0L;
#else
	int ok;
	mm_segment_t oldfs = get_fs();
	set_fs(USER_DS);
	ok = access_ok(VERIFY_READ, (long *) (intptr_t) addr, sizeof(long));
	set_fs(oldfs);
	return addr != 0L && tsk != NULL ? ok : ! ok;
#endif
}
#endif

#if defined (__ia64__)
#include "stack-ia64.c"
#elif defined (__arm__)
#include "stack-arm.c"
#elif defined (__s390__)
#include "stack-s390.c"
#else
#ifndef STP_USE_DWARF_UNWINDER
#error "Unsupported architecture"
#endif
#endif

#if defined(STAPCONF_KERNEL_STACKTRACE) || defined(STAPCONF_KERNEL_STACKTRACE_NO_BP)

struct print_stack_data
{
        int flags;
        int levels;
        int skip;
};

#if defined(STAPCONF_STACKTRACE_OPS_WARNING)
static void print_stack_warning(void *data, char *msg)
{
}

static void
print_stack_warning_symbol(void *data, char *msg, unsigned long symbol)
{
}
#endif

static int print_stack_stack(void *data, char *name)
{
	return -1;
}

static void print_stack_address(void *data, unsigned long addr, int reliable)
{
	struct print_stack_data *sdata = data;
	if (sdata->skip > 0)
		sdata->skip--;
	else if (sdata->levels > 0) {
		_stp_print_addr(addr,
				sdata->flags | (reliable ? 0 :_STP_SYM_INEXACT),
				NULL);
		sdata->levels--;
	}
}

static const struct stacktrace_ops print_stack_ops = {
#if defined(STAPCONF_STACKTRACE_OPS_WARNING)
	.warning = print_stack_warning,
	.warning_symbol = print_stack_warning_symbol,
#endif
	.stack = print_stack_stack,
	.address = print_stack_address,
#if defined(STAPCONF_WALK_STACK)
	.walk_stack = print_context_stack,
#endif
};

/* Used for kernel backtrace printing when other mechanisms fail. */
static void _stp_stack_print_fallback(unsigned long stack,
				      int sym_flags, int levels, int skip)
{
        struct print_stack_data print_data;
        print_data.flags = sym_flags;
        print_data.levels = levels;
        print_data.skip = skip;
#if defined(STAPCONF_KERNEL_STACKTRACE)
        dump_trace(current, NULL, (long *)stack, 0, &print_stack_ops,
                   &print_data);
#else
	/* STAPCONF_KERNEL_STACKTRACE_NO_BP */
        dump_trace(current, NULL, (long *)stack, &print_stack_ops,
                   &print_data);
#endif
}
#else
static void _stp_stack_print_fallback(unsigned long s, int v, int l, int k) {
	/* Don't guess, just give up. */
	_stp_print_addr(0, v | _STP_SYM_INEXACT, NULL);
}

#endif /* defined(STAPCONF_KERNEL_STACKTRACE) || defined(STAPCONF_KERNEL_STACKTRACE_NO_BP) */


/** Gets user space registers when available, also sets context
 * full_uregs_p if appropriate.  Should be used instead of accessing
 * context uregs field directly when (full) uregs are needed from
 * kernel context.
 */
static struct pt_regs *_stp_get_uregs(struct context *c)
{
  /* When the probe occurred in user context uregs are always complete. */
  if (c->uregs && c->user_mode_p)
    c->full_uregs_p = 1;
  else if (c->uregs == NULL)
    {
      dbug_unwind(1, "computing uregs\n");
      /* First try simple recovery through task_pt_regs,
	 on some platforms that already provides complete uregs. */
      c->uregs = _stp_current_pt_regs();
      if (c->uregs && _stp_task_pt_regs_valid(current, c->uregs))
	c->full_uregs_p = 1;

/* Sadly powerpc does support the dwarf unwinder, but doesn't have enough
   CFI in the kernel to recover fully to user space. */
#if defined(STP_USE_DWARF_UNWINDER) && !defined (__powerpc__)
      else if (c->uregs != NULL && c->kregs != NULL && !c->user_mode_p)
	{
	  struct unwind_frame_info *info = &c->uwcontext_kernel.info;
	  int ret = 0;
	  int levels;

	  /* We might be lucky and this probe already ran the kernel
	     unwind to end up in the user regs. */
	  if (UNW_PC(info) == REG_IP(c->uregs))
	    {
	      levels = 0;
	      dbug_unwind(1, "feeling lucky, info pc == uregs pc\n");
	    }
	  else
	    {
	      /* Try to recover the uregs by unwinding from the the kernel
		 probe location. */
	      levels = MAXBACKTRACE;
	      arch_unw_init_frame_info(info, c->kregs, 0);
	      dbug_unwind(1, "Trying to recover... searching for 0x%llx\n",
			  (unsigned long long) REG_IP(c->uregs));

	      /* Mark the kernel unwind cache as invalid
		 (uwcache_kernel.depth is no longer consistent with
		 the actual current depth of the unwind).

		 We don't save PCs in the cache at this point because
		 this kernel unwind procedure does not fetch the top
		 level PC, so uwcache_kernel.pc[0] would be left
		 unpopulated. We would have to either fetch the
		 current PC here, or specially represent this state of
		 the cache, something we don't bother with at this
		 stage.

	         XXX: this can create (tolerable amounts of) inefficiency
	         if the probe intersperses user and kernel unwind calls,
	         since the other unwind code can clear uregs, triggering
	         a redundant unwind the next time we need them. */
	      dbug_unwind(1, "clearing kernel unwind cache\n");
	      c->uwcache_kernel.state = uwcache_uninitialized;
	    }

	  while (levels > 0 && ret == 0 && UNW_PC(info) != REG_IP(c->uregs))
	    {
	      levels--;
	      ret = unwind(&c->uwcontext_kernel, 0);
	      dbug_unwind(1, "unwind levels: %d, ret: %d, pc=0x%llx\n",
			  levels, ret, (unsigned long long) UNW_PC(info));
	    }

	  /* Have we arrived where we think user space currently is? */
	  if (ret == 0 && UNW_PC(info) == REG_IP(c->uregs))
	    {
	      /* Note we need to clear this state again when the unwinder
		 has been rerun. See __stp_stack_print invocation below. */
	      UNW_SP(info) = REG_SP(c->uregs); /* Fix up user stack */
	      c->uregs = &info->regs;
	      c->full_uregs_p = 1;
	      dbug_unwind(1, "recovered with pc=0x%llx sp=0x%llx\n",
			  (unsigned long long) UNW_PC(info),
			  (unsigned long long) UNW_SP(info));
	    }
	  else
	    dbug_unwind(1, "failed to recover user reg state\n");
	}
#endif
    }
  return c->uregs;
}


static unsigned long _stp_stack_unwind_one_kernel(struct context *c, unsigned depth)
{
	struct pt_regs *regs = NULL;
	struct unwind_frame_info *info = NULL;
	int ret;

	if (depth == 0) { /* Start by fetching the current PC. */
		dbug_unwind(1, "STARTING kernel unwind\n");

		if (! c->kregs) {
			/* Even the current PC is unknown; so we have
			 * absolutely no data at any depth.
			 *
			 * Note that unlike _stp_stack_kernel_print(),
			 * we can't fall back to calling dump_trace()
			 * to obtain the backtrace -- since that
			 * returns a string, which we would have to
			 * tokenize. Callers that want to use the
			 * dump_trace() fallback should call
			 * _stp_stack_kernel_print() and do their own
			 * tokenization of the result. */
#if defined (__i386__) || defined (__x86_64__)
		        arch_unw_init_frame_info(&c->uwcontext_kernel.info, NULL, 0);
		        return UNW_PC(&c->uwcontext_kernel.info);
#else
			return 0;
#endif
		} else if (c->probe_type == stp_probe_type_kretprobe
			   && c->ips.krp.pi) {
			return (unsigned long)_stp_ret_addr_r(c->ips.krp.pi);
		} else {
			return REG_IP(c->kregs);
		}
	}

#ifdef STP_USE_DWARF_UNWINDER
	/* Otherwise, use the DWARF unwinder to unwind one step. */

	regs = c->kregs;

	info = &c->uwcontext_kernel.info;

	dbug_unwind(1, "CONTINUING kernel unwind to depth %d\n", depth);

	if (depth == 1) {
                /* First step of actual DWARF unwind;
		   need to clear uregs& set up uwcontext->info. */
		if (c->uregs == &c->uwcontext_kernel.info.regs) {
			dbug_unwind(1, "clearing uregs\n");
			/* Unwinder needs the reg state, clear uregs ref. */
			c->uregs = NULL;
			c->full_uregs_p = 0;
		}

		arch_unw_init_frame_info(info, regs, 0);
	}

	ret = unwind(&c->uwcontext_kernel, 0);
	dbug_unwind(1, "ret=%d PC=%llx SP=%llx\n", ret,
		    (unsigned long long) UNW_PC(info),
		    (unsigned long long) UNW_SP(info));

	/* check if unwind hit an error */
	if (ret || ! _stp_valid_pc_addr(UNW_PC(info), NULL)) {
		return 0;
	}

	return UNW_PC(info);
#else
	return 0;
#endif
}

static unsigned long _stp_stack_kernel_get(struct context *c, unsigned depth)
{
	unsigned long pc = 0;

	if (c->uwcache_kernel.state == uwcache_uninitialized) {
		c->uwcache_kernel.depth = 0;
		c->uwcache_kernel.state = uwcache_partial;
	}

	if (unlikely(depth >= MAXBACKTRACE))
		return 0;

	/* Obtain cached value if available. */
	if (depth < c->uwcache_kernel.depth)
		return c->uwcache_kernel.pc[depth];
	else if (c->uwcache_kernel.state == uwcache_finished)
		return 0; /* unwind does not reach this far */

	/* Advance uwcontext to the required depth. */
	while (c->uwcache_kernel.depth <= depth) {
		pc = c->uwcache_kernel.pc[c->uwcache_kernel.depth]
		   = _stp_stack_unwind_one_kernel(c, c->uwcache_kernel.depth);
		c->uwcache_kernel.depth ++;
		if (pc == 0 || pc == _stp_kretprobe_trampoline) {
			/* Mark unwind completed. */
			c->uwcache_kernel.state = uwcache_finished;
			break;
			/* XXX: is there a way to unwind across kretprobe trampolines? PR9999 */
		}
	}

	/* Return the program counter at the current depth. */
	return pc;
}

/** Prints the stack backtrace
 * @param regs A pointer to the struct pt_regs.
 * @param verbose _STP_SYM_FULL or _STP_SYM_BRIEF
 */

static void _stp_stack_kernel_print(struct context *c, int sym_flags)
{
	unsigned n, remaining;
	unsigned long l;

	/* print the current address */
	if (c->probe_type == stp_probe_type_kretprobe && c->ips.krp.pi
	    && (sym_flags & _STP_SYM_FULL) == _STP_SYM_FULL) {
		_stp_print("Returning from: ");
		_stp_print_addr((unsigned long)_stp_probe_addr_r(c->ips.krp.pi),
				sym_flags, NULL);
		_stp_print("Returning to  : ");
	}
	_stp_print_addr(_stp_stack_kernel_get(c, 0), sym_flags, NULL);

#ifdef STP_USE_DWARF_UNWINDER
	for (n = 1; n < MAXBACKTRACE; n++) {
		l = _stp_stack_kernel_get(c, n);
		if (l == 0) {
			remaining = MAXBACKTRACE - n;
			_stp_stack_print_fallback(UNW_SP(&c->uwcontext_kernel.info),
						  sym_flags, remaining, 0);
			break;
		} else {
			_stp_print_addr(l, sym_flags, NULL);
		}
	}
#else
	if (! c->kregs) {
		/* This is a fatal block for _stp_stack_kernel_get,
		 * but when printing a backtrace we can use this
		 * inexact fallback.
		 *
		 * When compiled with frame pointers we can do
		 * a pretty good guess at the stack value,
		 * otherwise let dump_stack guess it
		 * (and skip some framework frames). */
#if defined(STAPCONF_KERNEL_STACKTRACE) || defined(STAPCONF_KERNEL_STACKTRACE_NO_BP)
		unsigned long sp;
		int skip;
#ifdef CONFIG_FRAME_POINTER
		sp  = *(unsigned long *) __builtin_frame_address (0);
		skip = 1; /* Skip just this frame. */
#else
		sp = 0;
		skip = 5; /* yes, that many framework frames. */
#endif
		_stp_stack_print_fallback(sp, sym_flags,
					  MAXBACKTRACE, skip);
#else
		if (sym_flags & _STP_SYM_SYMBOL)
			_stp_printf("<no kernel backtrace at %s>\n",
				    c->probe_point);
		else
			_stp_print("\n");
#endif
		return;
	}
	else
		/* Arch specific fallback for kernel backtraces. */
		__stp_stack_print(c->kregs, sym_flags, MAXBACKTRACE);
#endif
}

static unsigned long _stp_stack_unwind_one_user(struct context *c, unsigned depth)
{
	struct pt_regs *regs = NULL;
	int uregs_valid = 0;
	struct uretprobe_instance *ri = NULL;
	struct unwind_frame_info *info = NULL;
	int ret;
#ifdef STAPCONF_UPROBE_GET_PC
	unsigned long maybe_pc;
#endif

	if (c->probe_type == stp_probe_type_uretprobe)
		ri = c->ips.ri;
#ifdef STAPCONF_UPROBE_GET_PC
	else if (c->probe_type == stp_probe_type_uprobe)
		ri = GET_PC_URETPROBE_NONE;
#endif

	/* XXX: The computation that gives this is cached, so calling
	 * _stp_get_uregs multiple times is okay... probably. */
	regs = _stp_get_uregs(c);
	uregs_valid = c->full_uregs_p;

	if (! current->mm || ! regs)
		return 0; // no user backtrace at this probe point

	if (depth == 0) { /* Start by fetching the current PC. */
		dbug_unwind(1, "STARTING user unwind\n");

#ifdef STAPCONF_UPROBE_GET_PC
		if (c->probe_type == stp_probe_type_uretprobe && ri) {
			return ri->ret_addr;
		} else {
			return REG_IP(regs);
		}
#else
		return REG_IP(regs);
#endif
	}

#ifdef STP_USE_DWARF_UNWINDER
	info = &c->uwcontext_user.info;

	dbug_unwind(1, "CONTINUING user unwind to depth %d\n", depth);

	if (depth == 1) { /* need to clear uregs & set up uwcontext->info */
		if (c->uregs == &c->uwcontext_user.info.regs) {
			dbug_unwind(1, "clearing uregs\n");
			/* Unwinder needs the reg state, clear uregs ref. */
			c->uregs = NULL;
			c->full_uregs_p = 0;
		}

		arch_unw_init_frame_info(info, regs, 0);
	}

	ret = unwind(&c->uwcontext_user, 1);
#ifdef STAPCONF_UPROBE_GET_PC
	maybe_pc = 0;
	if (ri) {
		maybe_pc = uprobe_get_pc(ri, UNW_PC(info), UNW_SP(info));
		if (!maybe_pc)
			printk("SYSTEMTAP ERROR: uprobe_get_return returned 0\n");
		else
			UNW_PC(info) = maybe_pc;
	}
#endif
	dbug_unwind(1, "ret=%d PC=%llx SP=%llx\n", ret,
		    (unsigned long long) UNW_PC(info), (unsigned long long) UNW_SP(info));

	/* check if unwind hit an error */
	if (ret || ! _stp_valid_pc_addr(UNW_PC(info), current)) {
		return 0;
	}

	return UNW_PC(info);
#else
	/* User stack traces only supported for arches with dwarf unwinder. */
	return 0;
#endif
}

static unsigned long _stp_stack_user_get(struct context *c, unsigned depth)
{
	unsigned long pc = 0;

	if (c->uwcache_user.state == uwcache_uninitialized) {
		c->uwcache_user.depth = 0;
		c->uwcache_user.state = uwcache_partial;
	}

	if (unlikely(depth >= MAXBACKTRACE))
		return 0;

	/* Obtain cached value if available. */
	if (depth < c->uwcache_user.depth)
		return c->uwcache_user.pc[depth];
	else if (c->uwcache_user.state == uwcache_finished)
		return 0; /* unwind does not reach this far */

	/* Advance uwcontext to the required depth. */
	while (c->uwcache_user.depth <= depth) {
		pc = c->uwcache_user.pc[c->uwcache_user.depth]
		   = _stp_stack_unwind_one_user(c, c->uwcache_user.depth);
		c->uwcache_user.depth ++;
		if (pc == 0) {
			/* Mark unwind completed. */
			c->uwcache_user.state = uwcache_finished;
			break;
		}
	}

	/* Return the program counter at the current depth. */
	return pc;
}

static void _stp_stack_user_print(struct context *c, int sym_flags)
{
	struct pt_regs *regs = NULL;
	struct uretprobe_instance *ri = NULL;
	unsigned n; unsigned long l;

	if (c->probe_type == stp_probe_type_uretprobe)
		ri = c->ips.ri;
#ifdef STAPCONF_UPROBE_GET_PC
	else if (c->probe_type == stp_probe_type_uprobe)
		ri = GET_PC_URETPROBE_NONE;
#endif

	regs = _stp_get_uregs(c);

	if (! current->mm || ! regs) {
		if (sym_flags & _STP_SYM_SYMBOL)
			_stp_printf("<no user backtrace at %s>\n",
				    c->probe_point);
		else
			_stp_print("\n");
		return;
	}

	/* print the current address */
#ifdef STAPCONF_UPROBE_GET_PC
	if (c->probe_type == stp_probe_type_uretprobe && ri) {
		if ((sym_flags & _STP_SYM_FULL) == _STP_SYM_FULL) {
			_stp_print("Returning from: ");
			/* ... otherwise this dereference fails */
			_stp_print_addr(ri->rp->u.vaddr, sym_flags, current);
			_stp_print("Returning to  : ");
		}
	}
#endif
	_stp_print_addr(_stp_stack_user_get(c, 0), sym_flags, current);

	/* print rest of stack... */
#ifdef STP_USE_DWARF_UNWINDER
	for (n = 1; n < MAXBACKTRACE; n++) {
		l = _stp_stack_user_get(c, n);
		if (l == 0) break; // No user space fallback available
		_stp_print_addr(l, sym_flags, current);
	}
#else
	/* User stack traces only supported for arches with dwarf unwinder. */
	if (sym_flags & _STP_SYM_SYMBOL)
		_stp_printf("<no user backtrace support on arch>\n");
	else
		_stp_print("\n");
#endif
}

/** Writes stack backtrace to a string
 *
 * @param str string
 * @param regs A pointer to the struct pt_regs.
 * @returns void
 */
static void _stp_stack_kernel_sprint(char *str, int size, struct context* c,
				     int sym_flags)
{
	/* To get an hex string, we use a simple trick.
	 * First flush the print buffer,
	 * then call _stp_stack_print,
	 * then copy the result into the output string
	 * and clear the print buffer. */
	_stp_pbuf *pb = per_cpu_ptr(Stp_pbuf, smp_processor_id());
	_stp_print_flush();

	_stp_stack_kernel_print(c, sym_flags);

	strlcpy(str, pb->buf, size < (int)pb->len ? size : (int)pb->len);
	pb->len = 0;
}

static void _stp_stack_user_sprint(char *str, int size, struct context* c,
				   int sym_flags)
{
	/* To get an hex string, we use a simple trick.
	 * First flush the print buffer,
	 * then call _stp_stack_print,
	 * then copy the result into the output string
	 * and clear the print buffer. */
	_stp_pbuf *pb = per_cpu_ptr(Stp_pbuf, smp_processor_id());
	_stp_print_flush();

	_stp_stack_user_print(c, sym_flags);

	strlcpy(str, pb->buf, size < (int)pb->len ? size : (int)pb->len);
	pb->len = 0;
}

#endif /* _STACK_C_ */
