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
 * Copyright (C) IBM Corporation, 2008
 */
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <asm/thread_info.h>

/* Normally defined in Kconfig */
#define CONFIG_URETPROBES 1
#define CONFIG_UPROBES_SSOL 1

typedef u8 uprobe_opcode_t;
#define BREAKPOINT_INSTRUCTION	0xcc
#define BP_INSN_SIZE 1
#define MAX_UINSN_BYTES 16

// SLOT_IP should be 16 for 64-bit apps (include/asm-x86_64/elf.h)
// but 12 for 32-bit apps (arch/x86_64/ia32/ia32_binfmt.c)
#ifdef CONFIG_X86_32
#define SLOT_IP(tsk) 12
#else
#define SLOT_IP(tsk) (test_tsk_thread_flag(tsk, TIF_IA32) ? 12 : 16)
#endif

#define BREAKPOINT_SIGNAL SIGTRAP
#define SSTEP_SIGNAL SIGTRAP

/* Architecture specific switch for where the IP points after a bp hit */
#define ARCH_BP_INST_PTR(inst_ptr)	(inst_ptr - BP_INSN_SIZE)

#define UPFIX_RIP_RAX 0x1	/* (%rip) insn rewritten to use (%rax) */
#define UPFIX_RIP_RCX 0x2	/* (%rip) insn rewritten to use (%rcx) */
#define UPFIX_ABS_IP  0x4	/* %ip after SS needs no fixup */
#define UPFIX_RETURN  0x8	/* need to adjust return address on stack */

#ifdef CONFIG_X86_64
struct uprobe_probept_arch_info {
	unsigned long flags;
	unsigned long rip_target_address;
};

struct uprobe_task_arch_info {
	unsigned long saved_scratch_register;
};
#else
struct uprobe_probept_arch_info {
	unsigned long flags;
};

struct uprobe_task_arch_info {};
#endif

struct uprobe_probept;
struct uprobe_task;

static int arch_validate_probed_insn(struct uprobe_probept *ppt,
						struct task_struct *tsk);

/* On x86, the int3 traps leaves ip pointing past the int3 instruction. */
static inline unsigned long arch_get_probept(struct pt_regs *regs)
{
	return (unsigned long) (regs->ip - BP_INSN_SIZE);
}

static inline void arch_reset_ip_for_sstep(struct pt_regs *regs)
{
	regs->ip -= BP_INSN_SIZE;
}

static inline void arch_restore_uret_addr(unsigned long ret_addr,
	struct pt_regs *regs)
{
	regs->ip = ret_addr;
}

static inline unsigned long arch_get_cur_sp(struct pt_regs *regs)
{
	return (unsigned long) regs->sp;
}

/*
 * On x86_32, if a function returns a struct or union, the return
 * value is copied into an area created by the caller.  The address
 * of this area is passed on the stack as a "hidden" first argument.
 * When such a function returns, it uses a "ret $4" instruction to pop
 * not only the return address but also the hidden arg.  To accommodate
 * such functions, we add 4 bytes of slop when predicting the return
 * address. See PR #10078.
 */
#define STRUCT_RETURN_SLOP 4

static inline unsigned long arch_predict_sp_at_ret(struct pt_regs *regs,
		struct task_struct *tsk)
{
	if (test_tsk_thread_flag(tsk, TIF_IA32))
		return (unsigned long) (regs->sp + 4 + STRUCT_RETURN_SLOP);
	else
		return (unsigned long) (regs->sp + 8);
}

static unsigned long arch_hijack_uret_addr(unsigned long trampoline_addr,
				struct pt_regs*, struct uprobe_task*);
#endif				/* _ASM_UPROBES_H */
