#ifndef _ASM_UPROBES_H
#define _ASM_UPROBES_H
/*
 * Userspace Probes (UProbes) for PowerPC
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
 * Copyright IBM Corporation, 2007
 */
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/signal.h>

#define BREAKPOINT_SIGNAL SIGTRAP
#define SSTEP_SIGNAL SIGTRAP

/* Normally defined in Kconfig */
#define CONFIG_UPROBES_SSOL
#define CONFIG_URETPROBES 1

typedef unsigned int uprobe_opcode_t;
#define BREAKPOINT_INSTRUCTION	0x7fe00008	/* trap */
#define BP_INSN_SIZE 4
#define MAX_UINSN_BYTES 4
#define SLOT_IP(tsk) 32	/* instruction pointer slot from include/asm/elf.h */

struct uprobe_probept_arch_info {};
struct uprobe_task_arch_info {};

/* Architecture specific switch for where the IP points after a bp hit */
#define ARCH_BP_INST_PTR(inst_ptr)	(inst_ptr)

struct uprobe_probept;
struct uprobe_task;
struct task_struct;

/* On powerpc, nip points to the trap. */
static inline unsigned long arch_get_probept(struct pt_regs *regs)
{
	return (unsigned long)(regs->nip);
}

static inline void arch_reset_ip_for_sstep(struct pt_regs *regs)
{
}

static inline int arch_validate_probed_insn(struct uprobe_probept *ppt,
						struct task_struct *tsk);

static unsigned long arch_hijack_uret_addr(unsigned long trampoline_addr,
		struct pt_regs *regs, struct uprobe_task *utask);

static inline void arch_restore_uret_addr(unsigned long ret_addr,
		struct pt_regs *regs)
{
	regs->nip = ret_addr;
}

static unsigned long arch_get_cur_sp(struct pt_regs *regs)
{
	return (unsigned long)(regs->gpr[1]);
}

static unsigned long arch_predict_sp_at_ret(struct pt_regs *regs,
		struct task_struct *tsk)
{
	return (unsigned long)(regs->gpr[1]);
}

#endif				/* _ASM_UPROBES_H */
