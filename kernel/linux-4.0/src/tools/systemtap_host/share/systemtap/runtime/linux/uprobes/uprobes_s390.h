#ifndef _ASM_UPROBES_H
#define _ASM_UPROBES_H
/*
 *  Userspace Probes (UProbes)
 *  include/asm-s390/uprobes.h
 *
 *  Adapted from include/asm-i386/uprobes.h by:
 *  David Wilder <dwilder.us.ibm.com> 2007
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
 * Copyright (C) IBM Corporation, 2006
 */
#include <linux/types.h>
#include <linux/ptrace.h>

/* Normally defined in Kconfig */
#define CONFIG_URETPROBES 1
#define CONFIG_UPROBES_SSOL 1

typedef u16 uprobe_opcode_t;

#define BREAKPOINT_INSTRUCTION	0x0002
#define BP_INSN_SIZE 2
#define MAX_UINSN_BYTES 6

#define BREAKPOINT_SIGNAL SIGILL
#define SSTEP_SIGNAL SIGTRAP

#ifdef CONFIG_COMPAT
#define SLOT_IP(tsk) (test_tsk_thread_flag(tsk, TIF_31BIT) ? 0x04 : 0x08)
#else
#define SLOT_IP(tsk) 0x08
#endif

#define FIXUP_PSW_NORMAL        0x08
#define FIXUP_BRANCH_NOT_TAKEN  0x04
#define FIXUP_RETURN_REGISTER   0x02
#define FIXUP_NOT_REQUIRED      0x01

struct uprobe_probept_arch_info {};
struct uprobe_task_arch_info {};

/* Architecture specific switch for where the IP points after a bp hit */
#define ARCH_BP_INST_PTR(inst_ptr)	(inst_ptr - BP_INSN_SIZE)

struct uprobe_probept;
struct uprobe_task;
static int arch_validate_probed_insn(struct uprobe_probept *ppt,
						struct task_struct *tsk);

/*
 * On s390, a trap leaves the instruction pointer pointing past the
 * trap instruction.
 */
static inline unsigned long arch_get_probept(struct pt_regs *regs)
{
	return (unsigned long) (regs->psw.addr - BP_INSN_SIZE);
}

static inline void arch_reset_ip_for_sstep(struct pt_regs *regs)
{
	regs->psw.addr -= BP_INSN_SIZE;
}

#ifdef CONFIG_URETPROBES
static inline void arch_restore_uret_addr(unsigned long ret_addr,
					  struct pt_regs *regs)
{
	regs->psw.addr = ret_addr;
}

static unsigned long arch_hijack_uret_addr(unsigned long trampoline_addr,
			struct pt_regs *regs, struct uprobe_task *utask);

static inline unsigned long arch_get_cur_sp(struct pt_regs *regs)
{
	return regs->gprs[15];
}

/* The stack pointer is the same upon return as it is upon function entry. */
static inline unsigned long arch_predict_sp_at_ret(struct pt_regs *regs,
					struct task_struct *tsk)
{
	return regs->gprs[15];
}

#endif /* CONFIG_URETPROBES */
#endif				/* _ASM_UPROBES_H */
