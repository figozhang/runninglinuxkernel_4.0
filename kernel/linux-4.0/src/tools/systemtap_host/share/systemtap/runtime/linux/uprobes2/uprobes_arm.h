#ifndef _ASM_UPROBES_H
#define _ASM_UPROBES_H
/*
 *  Userspace Probes (UProbes)
 *  uprobes.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2011 (C) Mentor Graphics Corporation
 */
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <asm/thread_info.h>
#include <asm/cacheflush.h>
#include <asm/smp_plat.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>

/* Normally defined in Kconfig */
#define CONFIG_URETPROBES 1

typedef u32 uprobe_opcode_t;
#define BREAKPOINT_INSTRUCTION 0xe7ffdefe
#define BP_INSN_SIZE 4
#define MAX_UINSN_BYTES 4

#define BREAKPOINT_SIGNAL SIGILL
#define SSTEP_SIGNAL SIGILL

/* Architecture specific switch for where the IP points after a bp hit */
#define ARCH_BP_INST_PTR(inst_ptr)	(inst_ptr)

struct uprobe_probept;

typedef void (uprobe_insn_handler_t)(struct uprobe_probept *, struct pt_regs *);
typedef unsigned long (uprobe_check_cc)(unsigned long);
typedef void (uprobe_insn_fn_t)(void);

#define MAX_INSN_SIZE 2
struct uprobe_probept_arch_info {
	uprobe_opcode_t			insn[MAX_INSN_SIZE];
	uprobe_insn_handler_t		*insn_handler;
	uprobe_check_cc			*insn_check_cc;
	uprobe_insn_fn_t		*insn_fn;
};

struct uprobe_task_arch_info {};

struct uprobe_probept;
struct uprobe_task;

static int arch_validate_probed_insn(struct uprobe_probept *ppt,
		struct task_struct *tsk);

static inline unsigned long arch_get_probept(struct pt_regs *regs)
{
	return regs->ARM_pc;
}


static inline void arch_reset_ip_for_sstep(struct pt_regs *regs)
{
}


static long arch_hijack_uret_addr(unsigned long trampoline_addr,
		struct pt_regs *regs, struct uprobe_task *utask)
{
	unsigned long orig_ret_addr = regs->ARM_lr;

	regs->ARM_lr = trampoline_addr;
	return orig_ret_addr;
}

static inline void arch_restore_uret_addr(unsigned long ret_addr,
		struct pt_regs *regs)
{
	regs->ARM_pc = ret_addr;
}

static inline unsigned long arch_get_cur_sp(struct pt_regs *regs)
{
	return regs->ARM_sp;
}

static inline unsigned long arch_predict_sp_at_ret(struct pt_regs *regs,
		struct task_struct *tsk)
{
	return regs->ARM_sp;
}

/* copy_to_user_page() is not exported.  Implement our own version.*/
#ifndef copy_to_user_page
#define copy_to_user_page(vma, page, vaddr, dst, src, len)	\
	do {							\
		memcpy(dst, src, len);				\
		flush_icache_range((unsigned long)dst,		\
				   (unsigned long)dst + len);	\
	} while (0)
#endif

#endif				/* _ASM_UPROBES_H */
