/*
 *  Userspace Probes (UProbes)
 *  arch/i386/kernel/uprobes_i386.c
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
/*
 * In versions of uprobes built in the SystemTap runtime, this file
 * is #included at the end of uprobes.c.
 */
#include <linux/uaccess.h>

/* Adapted from arch/x86_64/kprobes.c */
#undef W
#define W(row,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf)		      \
	(((b0##UL << 0x0)|(b1##UL << 0x1)|(b2##UL << 0x2)|(b3##UL << 0x3) |   \
	  (b4##UL << 0x4)|(b5##UL << 0x5)|(b6##UL << 0x6)|(b7##UL << 0x7) |   \
	  (b8##UL << 0x8)|(b9##UL << 0x9)|(ba##UL << 0xa)|(bb##UL << 0xb) |   \
	  (bc##UL << 0xc)|(bd##UL << 0xd)|(be##UL << 0xe)|(bf##UL << 0xf))    \
	 << (row % 32))
	static const volatile unsigned long good_insns[256 / 32] = {
		/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
		/*      -------------------------------         */
		W(0x00, 1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,0)| /* 00 */
		W(0x10, 1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,0), /* 10 */
		W(0x20, 1,1,1,1,1,1,0,1,1,1,1,1,1,1,0,1)| /* 20 */
		W(0x30, 1,1,1,1,1,1,0,1,1,1,1,1,1,1,0,1), /* 30 */
		W(0x40, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 40 */
		W(0x50, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* 50 */
		W(0x60, 1,1,1,0,1,1,0,0,1,1,1,1,0,0,0,0)| /* 60 */
		W(0x70, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* 70 */
		W(0x80, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 80 */
		W(0x90, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* 90 */
		W(0xa0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* a0 */
		W(0xb0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* b0 */
		W(0xc0, 1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0)| /* c0 */
		W(0xd0, 1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1), /* d0 */
		W(0xe0, 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0)| /* e0 */
		W(0xf0, 0,0,1,1,0,1,1,1,1,1,0,0,1,1,1,1)  /* f0 */
		/*      -------------------------------         */
		/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	};

	static const volatile unsigned long good_2byte_insns[256 / 32] = {
		/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
		/*      -------------------------------         */
		W(0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1)| /* 00 */
		W(0x10, 1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1), /* 10 */
		W(0x20, 1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1)| /* 20 */
		W(0x30, 0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0), /* 30 */
		W(0x40, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 40 */
		W(0x50, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* 50 */
		W(0x60, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 60 */
		W(0x70, 1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1), /* 70 */
		W(0x80, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 80 */
		W(0x90, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* 90 */
		W(0xa0, 1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1)| /* a0 */
		W(0xb0, 1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1), /* b0 */
		W(0xc0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* c0 */
		W(0xd0, 0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* d0 */
		W(0xe0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* e0 */
		W(0xf0, 0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0)  /* f0 */
		/*      -------------------------------         */
		/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	};

/*
 * TODO:
 * - Where necessary, examine the modrm byte and allow only valid instructions
 * in the different Groups and fpu instructions.
 * - Note: If we go past the first byte, do we need to verify that
 * subsequent bytes were actually there, rather than off the last page?
 * Probably overkill.  We don't verify that they specified the first byte
 * of the instruction, either.
 * - Be clearer about which instructions we'll never probe.
 */

/*
 * opcodes we'll probably never support:
 * 63 - arpl
 * 6c-6d, e4-e5, ec-ed - in
 * 6e-6f, e6-e7, ee-ef - out
 * cc, cd - int3, int
 * cf - iret
 * d6 - illegal instruction
 * f1 - int1/icebp
 * f4 - hlt
 * fa, fb - cli, sti
 *
 * opcodes we may need to refine support for:
 * 66 - data16 prefix
 * 8f - Group 1 - only reg = 0 is OK
 * c6-c7 - Group 11 - only reg = 0 is OK
 * d9-df - fpu insns with some illegal encodings
 * f2, f3 - repnz, repz prefixes.  These are also the first byte for
 * certain floating-point instructions, such as addsd.
 * fe - Group 4 - only reg = 0 or 1 is OK
 * ff - Group 5 - only reg = 0-6 is OK
 *
 * others -- Do we need to support these?
 * 07, 17, 1f - pop es, pop ss, pop ds
 * 26, 2e, 36, 3e, - es:, cs:, ss:, ds: segment prefixes --
 *	but 64 and 65 (fs: and gs:) seems to be used, so we support them.
 * 67 - addr16 prefix
 * ce - into
 * f0 - lock prefix
 */

/*
 * Return 1 if this is a legacy instruction prefix we support, -1 if
 * it's one we don't support, or 0 if it's not a prefix at all.
 */
static inline int check_legacy_prefix(u8 byte)
{
	switch (byte) {
	case 0x26:
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0xf0:
		return -1;
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
	case 0xf2:
	case 0xf3:
		return 1;
	default:
		return 0;
	}
}

static void report_bad_1byte_opcode(uprobe_opcode_t op)
{
	printk(KERN_ERR "uprobes does not currently support probing "
		"instructions whose first byte is 0x%2.2x\n", op);
}

static void report_bad_2byte_opcode(uprobe_opcode_t op)
{
	printk(KERN_ERR "uprobes does not currently support probing "
		"instructions with the 2-byte opcode 0x0f 0x%2.2x\n", op);
}

static void report_bad_opcode_prefix(uprobe_opcode_t op, uprobe_opcode_t prefix)
{
	printk(KERN_ERR "uprobes does not currently support probing "
		"instructions whose first byte is 0x%2.2x "
		"with a prefix 0x%2.2x\n", op, prefix);
}

/* Figure out how uprobe_post_ssout should perform ip fixup. */
static int setup_uprobe_post_ssout(struct uprobe_probept *ppt,
		uprobe_opcode_t *insn)
{
	/*
	 * Some of these require special treatment, but we don't know what to
	 * do with arbitrary prefixes, so we refuse to probe them.
	 */
	int prefix_ok = 0;
	switch (*insn) {
	case 0xc3:		/* ret */
		if ((insn - ppt->insn == 1) &&
		    (*ppt->insn == 0xf3 || *ppt->insn == 0xf2))
			/*
			 * "rep ret" is an AMD kludge that's used by GCC,
			 * so we need to treat it like a normal ret.
			 */
			prefix_ok = 1;
	case 0xcb:		/* more ret/lret */
	case 0xc2:
	case 0xca:
		/* eip is correct */
		ppt->arch_info.flags |= UPFIX_ABS_IP;
		break;
	case 0xe8:		/* call relative - Fix return addr */
		ppt->arch_info.flags |= UPFIX_RETURN;
		break;
	case 0x9a:		/* call absolute - Fix return addr */
		ppt->arch_info.flags |= UPFIX_RETURN | UPFIX_ABS_IP;
		break;
	case 0xff:
		if ((insn[1] & 0x30) == 0x10) {
			/* call absolute, indirect */
			/* Fix return addr; eip is correct. */
			ppt->arch_info.flags |= UPFIX_ABS_IP | UPFIX_RETURN;
		} else if ((insn[1] & 0x31) == 0x20 ||	/* jmp near, absolute indirect */
			   (insn[1] & 0x31) == 0x21) {	/* jmp far, absolute indirect */
			/* eip is correct. */
			ppt->arch_info.flags |= UPFIX_ABS_IP;
		}
		break;
	case 0xea:		/* jmp absolute -- eip is correct */
		ppt->arch_info.flags |= UPFIX_ABS_IP;
		break;
	default:
		/* Assuming that normal ip-fixup is ok for other prefixed opcodes. */
		prefix_ok = 1;
		break;
	}

	if (!prefix_ok && insn != ppt->insn) {
		report_bad_opcode_prefix(*insn, *ppt->insn);
		return -EPERM;
	}

	return 0;
}

static
int arch_validate_probed_insn(struct uprobe_probept *ppt,
						struct task_struct *tsk)
{
	uprobe_opcode_t *insn = ppt->insn;
	int pfx, ret;

	ppt->arch_info.flags = 0x0;

	/* Skip good instruction prefixes; reject "bad" ones. */
	while ((pfx = check_legacy_prefix(insn[0])) == 1)
		insn++;
	if (pfx < 0) {
		report_bad_1byte_opcode(insn[0]);
		return -EPERM;
	}
	if ((ret = setup_uprobe_post_ssout(ppt, insn)) != 0)
		return ret;
	if (test_bit(insn[0], good_insns))
		return 0;
	if (insn[0] == 0x0f) {
		if (test_bit(insn[1], good_2byte_insns))
			return 0;
		report_bad_2byte_opcode(insn[1]);
	} else
		report_bad_1byte_opcode(insn[0]);
	return -EPERM;
}

/*
 * Get an instruction slot from the process's SSOL area, containing the
 * instruction at ppt's probepoint.  Point the eip at that slot, in
 * preparation for single-stepping out of line.
 */
static
void uprobe_pre_ssout(struct uprobe_task *utask, struct uprobe_probept *ppt,
		struct pt_regs *regs)
{
	struct uprobe_ssol_slot *slot;

	slot = uprobe_get_insn_slot(ppt);
	if (!slot) {
		utask->doomed = 1;
		return;
	}
	regs->eip = (long)slot->insn;
	utask->singlestep_addr = regs->eip;
}

/*
 * Called by uprobe_post_ssout() to adjust the return address
 * pushed by a call instruction executed out-of-line.
 */
static void adjust_ret_addr(long esp, long correction,
		struct uprobe_task *utask)
{
	int nleft;
	long ra;

	nleft = copy_from_user(&ra, (const void __user *) esp, 4);
	if (unlikely(nleft != 0))
		goto fail;
	ra +=  correction;
	nleft = copy_to_user((void __user *) esp, &ra, 4);
	if (unlikely(nleft != 0))
		goto fail;
	return;

fail:
	printk(KERN_ERR
		"uprobes: Failed to adjust return address after"
		" single-stepping call instruction;"
		" pid=%d, esp=%#lx\n", current->pid, esp);
	utask->doomed = 1;
}

/*
 * Called after single-stepping.  ppt->vaddr is the address of the
 * instruction whose first byte has been replaced by the "int3"
 * instruction.  To avoid the SMP problems that can occur when we
 * temporarily put back the original opcode to single-step, we
 * single-stepped a copy of the instruction.  The address of this
 * copy is utask->singlestep_addr.
 *
 * This function prepares to return from the post-single-step
 * interrupt.  We have to fix up the stack as follows:
 *
 * 0) Typically, the new eip is relative to the copied instruction.  We
 * need to make it relative to the original instruction.  Exceptions are
 * return instructions and absolute or indirect jump or call instructions.
 *
 * 1) If the single-stepped instruction was a call, the return address
 * that is atop the stack is the address following the copied instruction.
 * We need to make it the address following the original instruction.
 */
static
void uprobe_post_ssout(struct uprobe_task *utask, struct uprobe_probept *ppt,
		struct pt_regs *regs)
{
	long copy_eip = utask->singlestep_addr;
	long orig_eip = ppt->vaddr;
	unsigned long flags = ppt->arch_info.flags;

	up_read(&ppt->slot->rwsem);

	if (flags & UPFIX_RETURN)
		adjust_ret_addr(regs->esp, (orig_eip - copy_eip), utask);

	if (!(flags & UPFIX_ABS_IP))
		regs->eip = orig_eip + (regs->eip - copy_eip);
}

/*
 * Replace the return address with the trampoline address.  Returns
 * the original return address.
 */
static
unsigned long arch_hijack_uret_addr(unsigned long trampoline_address,
		struct pt_regs *regs, struct uprobe_task *utask)
{
	int nleft;
	unsigned long orig_ret_addr;
#define RASIZE (sizeof(unsigned long))

	nleft = copy_from_user(&orig_ret_addr,
		       (const void __user *)regs->esp, RASIZE);
	if (unlikely(nleft != 0))
		return 0;

	if (orig_ret_addr == trampoline_address)
		/*
		 * There's another uretprobe on this function, and it was
		 * processed first, so the return address has already
		 * been hijacked.
		 */
		return orig_ret_addr;

	nleft = copy_to_user((void __user *)regs->esp,
		       &trampoline_address, RASIZE);
	if (unlikely(nleft != 0)) {
		if (nleft != RASIZE) {
			printk(KERN_ERR "uretprobe_entry_handler: "
					"return address partially clobbered -- "
					"pid=%d, %%esp=%#lx, %%eip=%#lx\n",
					current->pid, regs->esp, regs->eip);
			utask->doomed = 1;
		} /* else nothing written, so no harm */
		return 0;
	}
	return orig_ret_addr;
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

static
unsigned long arch_predict_sp_at_ret(struct pt_regs *regs,
		struct task_struct *tsk)
{
	return (unsigned long) (regs->esp + 4 + STRUCT_RETURN_SLOP);
}

/* Check if instruction is nop and return true. */
static int uprobe_emulate_insn(struct pt_regs *regs,
						struct uprobe_probept *ppt)
{
	uprobe_opcode_t *insn = ppt->insn;

	if (insn[0] == 0x90)
		/* regs->ip already points to the insn after the nop/int3. */
		return 1;

	/* TODO: add multibyte nop instructions */
	/* For multibyte nop instructions, we need to set ip accordingly. */
	return 0;
}
