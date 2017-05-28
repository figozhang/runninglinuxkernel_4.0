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
/*
 * In versions of uprobes built in the SystemTap runtime, this file
 * is #included at the end of uprobes.c.
 */

/* copied from arch/powerpc/lib/sstep.c */
#ifdef CONFIG_PPC64
/* Bits in SRR1 that are copied from MSR */
#define MSR_MASK	0xffffffff87c0ffffUL
#else
#define MSR_MASK	0x87c0ffff
#endif

/*
 * Replace the return address with the trampoline address.  Returns
 * the original return address.
 */
static
unsigned long arch_hijack_uret_addr(unsigned long trampoline_address,
		struct pt_regs *regs, struct uprobe_task *utask)
{
	unsigned long orig_ret_addr = regs->link;

	regs->link = trampoline_address;
	return orig_ret_addr;
}

/*
 * Get an instruction slot from the process's SSOL area, containing the
 * instruction at ppt's probepoint.  Point the eip at that slot, in preparation
 * for single-stepping out of line.
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
	regs->nip = (long)slot->insn;
}


static inline void calc_offset(struct uprobe_probept *ppt,
	       struct pt_regs *regs)
{
	int offset = 0;
	unsigned int opcode = 0;
	unsigned int insn = *ppt->insn;

	opcode = insn >> 26;
	switch (opcode) {
	case 16:	/* bc */
		if ((insn & 2) == 0) {
			offset = (signed short)(insn & 0xfffc);
			regs->nip = ppt->vaddr + offset;
		}
		if (insn & 1)
			regs->link = ppt->vaddr + MAX_UINSN_BYTES;
		break;
	case 17:	/* sc */
		/* Do we need to do anything */
		break;
	case 18:	/* b */
		if ((insn & 2) == 0) {
			offset = insn & 0x03fffffc;
			if (offset & 0x02000000)
				offset -= 0x04000000;
			regs->nip = ppt->vaddr + offset;
		}
		if (insn & 1)
			regs->link = ppt->vaddr + MAX_UINSN_BYTES;
		break;
	}
#ifdef UPROBES_DEBUG
	printk (KERN_ERR "ppt->vaddr=%p, regs->nip=%p, offset=%ld\n",
                (void*)(long)ppt->vaddr, (void*)(long)regs->nip, (long)offset);
	if (insn & 1)
          printk (KERN_ERR "regs->link=%p \n", (void*)(long)regs->link);
#endif
	return;
}

/*
 * Called after single-stepping.  ppt->vaddr is the address of the
 * instruction which was replaced by a breakpoint instruction.  To avoid
 * the SMP problems that can occur when we temporarily put back the
 * original opcode to single-step, we single-stepped a copy of the
 * instruction.
 *
 * This function prepares to return from the post-single-step
 * interrupt.
 *
 * 1) Typically, the new nip is relative to the copied instruction.  We
 * need to make it relative to the original instruction.  Exceptions are
 * branch instructions.
 *
 * 2) For branch instructions, update the nip if the branch uses
 * relative addressing.  Update the link instruction to the instruction
 * following the original instruction address.
 */

static
void uprobe_post_ssout(struct uprobe_task *utask, struct uprobe_probept *ppt,
		struct pt_regs *regs)
{
	unsigned long copy_nip;

	copy_nip = (unsigned long) ppt->slot->insn;
	up_read(&ppt->slot->rwsem);

	/*
	 * If the single stepped instruction is non-branch instruction
	 * then update the IP to be relative to probepoint.
	 */
	if (regs->nip == copy_nip + MAX_UINSN_BYTES)
		regs->nip = ppt->vaddr + MAX_UINSN_BYTES;
	else
		calc_offset(ppt,regs);
}

static
int arch_validate_probed_insn(struct uprobe_probept *ppt,
		 struct task_struct *tsk)
{
	if ((unsigned long)ppt->vaddr & 0x03) {
		printk(KERN_WARNING
			"Attempt to register uprobe at an unaligned addr\n");
		return -EINVAL;
	}
	return 0;
}

/*
 * Determine whether a conditional branch instruction would branch.
 * copied from arch/powerpc/lib/sstep.c
 */
static int branch_taken(unsigned int instr, struct pt_regs *regs)
{
	unsigned int bo = (instr >> 21) & 0x1f;
	unsigned int bi;

	if ((bo & 4) == 0) {
		/* decrement counter */
		--regs->ctr;
		if (((bo >> 1) & 1) ^ (regs->ctr == 0))
			return 0;
	}
	if ((bo & 0x10) == 0) {
		/* check bit from CR */
		bi = (instr >> 16) & 0x1f;
		if (((regs->ccr >> (31 - bi)) & 1) != ((bo >> 3) & 1))
			return 0;
	}
	return 1;
}

/*
 * Emulate instructions that cause a transfer of control.
 * Returns 1 if the step was emulated, 0 if not,
 * or -1 if the instruction is one that should not be stepped,
 * such as an rfid, or a mtmsrd that would clear MSR_RI.
 * copied/modified from arch/powerpc/lib/step.c;
 */
static int emulate_step(struct pt_regs *regs, unsigned int instr)
{
	unsigned int opcode, rs, rb, rd, spr;
	unsigned long int imm;

	/* ori 0,0,0 is a nop. Emulate that too */
	if (instr == 0x60000000) {
		regs->nip += 4;
		return 1;
	}

	opcode = instr >> 26;
	switch (opcode) {
	case 16:	/* bc */
		imm = (signed short)(instr & 0xfffc);
		if ((instr & 2) == 0)
			imm += regs->nip;
		regs->nip += 4;
		if ((regs->msr & MSR_SF) == 0)
			regs->nip &= 0xffffffffUL;
		if (instr & 1)
			regs->link = regs->nip;
		if (branch_taken(instr, regs))
			regs->nip = imm;
		return 1;
	case 18:	/* b */
		imm = instr & 0x03fffffc;
		if (imm & 0x02000000)
			imm -= 0x04000000;
		if ((instr & 2) == 0)
			imm += regs->nip;
		if (instr & 1) {
			regs->link = regs->nip + 4;
			if ((regs->msr & MSR_SF) == 0)
				regs->link &= 0xffffffffUL;
		}
		if ((regs->msr & MSR_SF) == 0)
			imm &= 0xffffffffUL;
		regs->nip = imm;
		return 1;
	case 19:
		switch (instr & 0x7fe) {
		case 0x20:	/* bclr */
		case 0x420:	/* bcctr */
			imm = (instr & 0x400) ? regs->ctr : regs->link;
			regs->nip += 4;
			if ((regs->msr & MSR_SF) == 0) {
				regs->nip &= 0xffffffffUL;
				imm &= 0xffffffffUL;
			}
			if (instr & 1)
				regs->link = regs->nip;
			if (branch_taken(instr, regs))
				regs->nip = imm;
			return 1;
		case 0x24:	/* rfid, scary */
			return -1;
		}
		break;
	case 31:
		rd = (instr >> 21) & 0x1f;
		switch (instr & 0x7fe) {
#if 0 // MSR opcodes are privileged, and must not be emulated for uprobes
		case 0xa6:	/* mfmsr */
			regs->gpr[rd] = regs->msr & MSR_MASK;
			regs->nip += 4;
			if ((regs->msr & MSR_SF) == 0)
				regs->nip &= 0xffffffffUL;
			return 1;
		case 0x124:	/* mtmsr */
			imm = regs->gpr[rd];
			if ((imm & MSR_RI) == 0)
				/* can't step mtmsr that would clear MSR_RI */
				return -1;
			regs->msr = imm;
			regs->nip += 4;
			return 1;
#ifdef CONFIG_PPC64
		case 0x164:	/* mtmsrd */
			/* only MSR_EE and MSR_RI get changed if bit 15 set */
			/* mtmsrd doesn't change MSR_HV and MSR_ME */
			imm = (instr & 0x10000) ? 0x8002
						: 0xefffffffffffefffUL;
			imm = (regs->msr & MSR_MASK & ~imm)
				| (regs->gpr[rd] & imm);
			if ((imm & MSR_RI) == 0)
				/* can't step mtmsrd that would clear MSR_RI */
				return -1;
			regs->msr = imm;
			regs->nip += 4;
			if ((imm & MSR_SF) == 0)
				regs->nip &= 0xffffffffUL;
			return 1;
#endif
#endif
		case 0x26:	/* mfcr */
			regs->gpr[rd] = regs->ccr;
			regs->gpr[rd] &= 0xffffffffUL;
			goto mtspr_out;
		case 0x2a6:	/* mfspr */
			spr = (instr >> 11) & 0x3ff;
			switch (spr) {
			case 0x20:	/* mfxer */
				regs->gpr[rd] = regs->xer;
				regs->gpr[rd] &= 0xffffffffUL;
				goto mtspr_out;
			case 0x100:	/* mflr */
				regs->gpr[rd] = regs->link;
				goto mtspr_out;
			case 0x120:	/* mfctr */
				regs->gpr[rd] = regs->ctr;
				goto mtspr_out;
			}
			break;
		case 0x378:	/* orx */
			if (instr & 1)
				break;
			rs = (instr >> 21) & 0x1f;
			rb = (instr >> 11) & 0x1f;
			if (rs == rb) {		/* mr */
				rd = (instr >> 16) & 0x1f;
				regs->gpr[rd] = regs->gpr[rs];
				goto mtspr_out;
			}
			break;
		case 0x3a6:	/* mtspr */
			spr = (instr >> 11) & 0x3ff;
			switch (spr) {
			case 0x20:	/* mtxer */
				regs->xer = (regs->gpr[rd] & 0xffffffffUL);
				goto mtspr_out;
			case 0x100:	/* mtlr */
				regs->link = regs->gpr[rd];
				goto mtspr_out;
			case 0x120:	/* mtctr */
				regs->ctr = regs->gpr[rd];
mtspr_out:
				regs->nip += 4;
				return 1;
			}
		}
	}
	return 0;
}

/* Check if instruction can be emulated and return 1 if emulated. */
static int uprobe_emulate_insn(struct pt_regs *regs,
						struct uprobe_probept *ppt)
{
	unsigned int insn = *ppt->insn;

	return emulate_step(regs, insn) > 0;
}
