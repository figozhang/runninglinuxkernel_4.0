/*
 *  Userspace Probes (UProbes)
 *  arch/s390/uprobes/uprobes_s390.c
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

/* adapted from s390/kernel/kprobes.c is_prohibited_opcode() */
/* TODO More instructions?? Should floating point inst be added?? */
static int prohibited_opcode(uprobe_opcode_t *instruction)
{
        switch (*(__u8 *) instruction) {
        case 0x0c:      /* bassm */
        case 0x0b:      /* bsm   */
        case 0x83:      /* diag  */
        case 0x44:      /* ex    */
                return -EINVAL;
        }
        switch (*(__u16 *) instruction) {
        case 0x0101:    /* pr    */
        case 0xb25a:    /* bsa   */
        case 0xb240:    /* bakr  */
        case 0xb258:    /* bsg   */
        case 0xb218:    /* pc    */
        case 0xb228:    /* pt    */
                return -EINVAL;
        }
        return 0;
}

static
int arch_validate_probed_insn(struct uprobe_probept *ppt,
						struct task_struct *tsk)
{
	if (ppt->vaddr & 0x01) {
		printk("Attempt to register uprobe at an unaligned address\n");
		return -EPERM;
	}

	/* Make sure the probe isn't going on a difficult instruction */
        if (prohibited_opcode((uprobe_opcode_t *) ppt->insn))
                return -EPERM;

	return 0;
}

/*
 * Get an instruction slot from the process's SSOL area, containing the
 * instruction at ppt's probepoint.  Point the psw.addr at that slot, in
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
	regs->psw.addr = (long)slot->insn;
	utask->singlestep_addr = regs->psw.addr;
}

static
void uprobe_post_ssout(struct uprobe_task *utask, struct uprobe_probept *ppt,
			struct pt_regs *regs)
{
	int ilen, fixup, reg;
	unsigned long copy_ins_addr = utask->singlestep_addr;
	unsigned long orig_ins_addr = ppt->vaddr;

	up_read(&ppt->slot->rwsem);

	/* default fixup method */
	fixup = FIXUP_PSW_NORMAL;;

	/* get r1 operand */
	reg = (*ppt->insn & 0xf0) >> 4;

	/* save the instruction length (pop 5-5) in bytes */
	switch (*(__u8 *) (ppt->insn) >> 6) {
	case 0:
		ilen = 2;
		break;
	case 1:
	case 2:
		ilen = 4;
		break;
	case 3:
		ilen = 6;
		break;
	default:
		ilen = 0;
		BUG();
	}


	switch (*(__u8 *) ppt->insn) {
	case 0x05:	/* balr */
	case 0x0d:	/* basr */
		fixup = FIXUP_RETURN_REGISTER;
		/* if r2 = 0, no branch will be taken */
		if ((*ppt->insn & 0x0f) == 0)
			fixup |= FIXUP_BRANCH_NOT_TAKEN;
		break;
	case 0x06:	/* bctr */
	case 0x07:	/* bcr  */
		fixup = FIXUP_BRANCH_NOT_TAKEN;
		break;
	case 0x45:	/* bal  */
	case 0x4d:	/* bas  */
		fixup = FIXUP_RETURN_REGISTER;
		break;
	case 0x47:	/* bc   */
	case 0x46:	/* bct  */
	case 0x86:	/* bxh  */
	case 0x87:	/* bxle */
		fixup = FIXUP_BRANCH_NOT_TAKEN;
		break;
	case 0x82:	/* lpsw */
		fixup = FIXUP_NOT_REQUIRED;
		break;
	case 0xb2:	/* lpswe */
		if (*(((__u8 *) ppt->insn) + 1) == 0xb2) {
			fixup = FIXUP_NOT_REQUIRED;
		}
		break;
	case 0xa7:	/* bras */
		if ((*ppt->insn & 0x0f) == 0x05) {
			fixup |= FIXUP_RETURN_REGISTER;
		}
		break;
	case 0xc0:
		if ((*ppt->insn & 0x0f) == 0x00  /* larl  */
			|| (*ppt->insn & 0x0f) == 0x05) /* brasl */
		fixup |= FIXUP_RETURN_REGISTER;
		break;
	case 0xeb:
		if (*(((__u8 *) ppt->insn) + 5 ) == 0x44 ||   /* bxhg  */
			*(((__u8 *) ppt->insn) + 5) == 0x45) {/* bxleg */
			fixup = FIXUP_BRANCH_NOT_TAKEN;
		}
		break;
	case 0xe3:	/* bctg */
		if (*(((__u8 *) ppt->insn) + 5) == 0x46) {
			fixup = FIXUP_BRANCH_NOT_TAKEN;
		}
		break;
        }

	/* do the fixup and adjust psw as needed */
	regs->psw.addr &= PSW_ADDR_INSN;

	if (fixup & FIXUP_PSW_NORMAL)
		regs->psw.addr = orig_ins_addr + regs->psw.addr -
						 copy_ins_addr;

	if (fixup & FIXUP_BRANCH_NOT_TAKEN)
                if (regs->psw.addr - copy_ins_addr == ilen)
                        regs->psw.addr = orig_ins_addr + ilen;

	if (fixup & FIXUP_RETURN_REGISTER)
                regs->gprs[reg] = (orig_ins_addr + (regs->gprs[reg] -
				 copy_ins_addr)) | PSW_ADDR_AMODE;

	regs->psw.addr |= PSW_ADDR_AMODE;
}


/*
 * Replace the return address with the trampoline address.  Returns
 * the original return address.
 */
static
unsigned long arch_hijack_uret_addr(unsigned long trampoline_address,
                struct pt_regs *regs, struct uprobe_task *utask)
{
	unsigned long orig_ret_addr;
#ifdef CONFIG_COMPAT
	if (test_tsk_thread_flag(utask->tsk, TIF_31BIT))
		orig_ret_addr = regs->gprs[14]&0x7FFFFFFFUL;
	else
#endif
		orig_ret_addr = regs->gprs[14];
	regs->gprs[14] = trampoline_address;
	return orig_ret_addr;
}


/* Check if instruction is nop and return true. */
static int uprobe_emulate_insn(struct pt_regs *regs,
						struct uprobe_probept *ppt)
{
	unsigned int insn = *ppt->insn;
	if (insn == 0x47000000)
		/* ip already points to the insn after the nop/bkpt insn. */
		return 1;

	return 0;
}
