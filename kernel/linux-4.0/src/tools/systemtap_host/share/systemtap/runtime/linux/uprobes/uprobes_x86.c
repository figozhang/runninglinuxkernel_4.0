/*
 *  Userspace Probes (UProbes)
 *  uprobes.c
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
 * Copyright (C) IBM Corporation, 2006-2008
 */

#ifdef CONFIG_X86_32
#define is_32bit_app(tsk) 1
#else
#define is_32bit_app(tsk) (test_tsk_thread_flag(tsk, TIF_IA32))
#endif

/* Adapted from arch/x86_64/kprobes.c */
#undef W
#define W(row,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf)		      \
	(((b0##ULL << 0x0)|(b1##ULL << 0x1)|(b2##ULL << 0x2)|(b3##ULL << 0x3) |   \
	  (b4##ULL << 0x4)|(b5##ULL << 0x5)|(b6##ULL << 0x6)|(b7##ULL << 0x7) |   \
	  (b8##ULL << 0x8)|(b9##ULL << 0x9)|(ba##ULL << 0xa)|(bb##ULL << 0xb) |   \
	  (bc##ULL << 0xc)|(bd##ULL << 0xd)|(be##ULL << 0xe)|(bf##ULL << 0xf))    \
	 << (row % 64))

static const volatile unsigned long long good_insns_64[256 / 64] = {
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	/*      -------------------------------         */
	W(0x00, 1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,0)| /* 00 */
	W(0x10, 1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,0)| /* 10 */
	W(0x20, 1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,0)| /* 20 */
	W(0x30, 1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,0), /* 30 */
	W(0x40, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)| /* 40 */
	W(0x50, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 50 */
	W(0x60, 0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,0)| /* 60 */
	W(0x70, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* 70 */
	W(0x80, 1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 80 */
	W(0x90, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 90 */
	W(0xa0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* a0 */
	W(0xb0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* b0 */
	W(0xc0, 1,1,1,1,0,0,1,1,1,1,1,1,0,0,0,0)| /* c0 */
	W(0xd0, 1,1,1,1,0,0,0,1,1,1,1,1,1,1,1,1)| /* d0 */
	W(0xe0, 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0)| /* e0 */
	W(0xf0, 0,0,1,1,0,1,1,1,1,1,0,0,1,1,1,1)  /* f0 */
	/*      -------------------------------         */
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
};

/* Good-instruction tables for 32-bit apps -- copied from i386 uprobes */

static const volatile unsigned long long good_insns_32[256 / 64] = {
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	/*      -------------------------------         */
	W(0x00, 1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,0)| /* 00 */
	W(0x10, 1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,0)| /* 10 */
	W(0x20, 1,1,1,1,1,1,0,1,1,1,1,1,1,1,0,1)| /* 20 */
	W(0x30, 1,1,1,1,1,1,0,1,1,1,1,1,1,1,0,1), /* 30 */
	W(0x40, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 40 */
	W(0x50, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 50 */
	W(0x60, 1,1,1,0,1,1,0,0,1,1,1,1,0,0,0,0)| /* 60 */
	W(0x70, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* 70 */
	W(0x80, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 80 */
	W(0x90, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 90 */
	W(0xa0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* a0 */
	W(0xb0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1), /* b0 */
	W(0xc0, 1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0)| /* c0 */
	W(0xd0, 1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1)| /* d0 */
	W(0xe0, 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0)| /* e0 */
	W(0xf0, 0,0,1,1,0,1,1,1,1,1,0,0,1,1,1,1)  /* f0 */
	/*      -------------------------------         */
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
};

/* Using this for both 64-bit and 32-bit apps */
static const volatile unsigned long long good_2byte_insns[256 / 64] = {
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	/*      -------------------------------         */
	W(0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1)| /* 00 */
	W(0x10, 1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1)| /* 10 */
	W(0x20, 1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1)| /* 20 */
	W(0x30, 0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0), /* 30 */
	W(0x40, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 40 */
	W(0x50, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 50 */
	W(0x60, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 60 */
	W(0x70, 1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1), /* 70 */
	W(0x80, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 80 */
	W(0x90, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 90 */
	W(0xa0, 1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1)| /* a0 */
	W(0xb0, 1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1), /* b0 */
	W(0xc0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* c0 */
	W(0xd0, 0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* d0 */
	W(0xe0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* e0 */
	W(0xf0, 0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0)  /* f0 */
	/*      -------------------------------         */
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
};

/*
 * opcodes we'll probably never support:
 * 6c-6d, e4-e5, ec-ed - in
 * 6e-6f, e6-e7, ee-ef - out
 * cc, cd - int3, int
 * cf - iret
 * d6 - illegal instruction
 * f1 - int1/icebp
 * f4 - hlt
 * fa, fb - cli, sti
 * 0f - lar, lsl, syscall, clts, sysret, sysenter, sysexit, invd, wbinvd, ud2
 *
 * invalid opcodes in 64-bit mode:
 * 06, 0e, 16, 1e, 27, 2f, 37, 3f, 60-62, 82, c4-c5, d4-d5
 *
 * 63 - we support this opcode in x86_64 but not in i386.
 * opcodes we may need to refine support for:
 * 0f - 2-byte instructions: For many of these instructions, the validity
 * depends on the prefix and/or the reg field.  On such instructions, we
 * just consider the opcode combination valid if it corresponds to any
 * valid instruction.
 * 8f - Group 1 - only reg = 0 is OK
 * c6-c7 - Group 11 - only reg = 0 is OK
 * d9-df - fpu insns with some illegal encodings
 * f2, f3 - repnz, repz prefixes.  These are also the first byte for
 * certain floating-point instructions, such as addsd.
 * fe - Group 4 - only reg = 0 or 1 is OK
 * ff - Group 5 - only reg = 0-6 is OK
 *
 * others -- Do we need to support these?
 * 0f - (floating-point?) prefetch instructions
 * 07, 17, 1f - pop es, pop ss, pop ds
 * 26, 2e, 36, 3e - es:, cs:, ss:, ds: segment prefixes --
 *	but 64 and 65 (fs: and gs:) seems to be used, so we support them.
 * 67 - addr16 prefix
 * ce - into
 * f0 - lock prefix
 */

/*
 * TODO:
 * - Where necessary, examine the modrm byte and allow only valid instructions
 * in the different Groups and fpu instructions.
 * - Note: If we go past the first byte, do we need to verify that
 * subsequent bytes were actually there, rather than off the last page?
 * - Be clearer about which instructions we'll never probe.
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

static void report_bad_1byte_opcode(int mode, uprobe_opcode_t op)
{
	printk(KERN_ERR "In %d-bit apps, "
		"uprobes does not currently support probing "
		"instructions whose first byte is 0x%2.2x\n", mode, op);
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
		/* rip is correct */
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
			/* Fix return addr; rip is correct. */
			ppt->arch_info.flags |= UPFIX_ABS_IP | UPFIX_RETURN;
		} else if ((insn[1] & 0x31) == 0x20 ||	/* jmp near, absolute indirect */
			   (insn[1] & 0x31) == 0x21) {	/* jmp far, absolute indirect */
			/* rip is correct. */
			ppt->arch_info.flags |= UPFIX_ABS_IP;
		}
		break;
	case 0xea:		/* jmp absolute -- rip is correct */
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

static int validate_insn_32bits(struct uprobe_probept *ppt)
{
	uprobe_opcode_t *insn = ppt->insn;
	int pfx, ret;

	/* Skip good instruction prefixes; reject "bad" ones. */
	while ((pfx = check_legacy_prefix(insn[0])) == 1)
		insn++;
	if (pfx < 0) {
		report_bad_1byte_opcode(32, insn[0]);
		return -EPERM;
	}
	if ((ret = setup_uprobe_post_ssout(ppt, insn)) != 0)
		return ret;
	if (test_bit(insn[0], (unsigned long*)good_insns_32))
		return 0;
	if (insn[0] == 0x0f) {
		if (test_bit(insn[1], (unsigned long*)good_2byte_insns))
			return 0;
		report_bad_2byte_opcode(insn[1]);
	} else
		report_bad_1byte_opcode(32, insn[0]);
	return -EPERM;
}

static int validate_insn_64bits(struct uprobe_probept *ppt)
{
	uprobe_opcode_t *insn = ppt->insn;
	int pfx, ret;

	/* Skip good instruction prefixes; reject "bad" ones. */
	while ((pfx = check_legacy_prefix(insn[0])) == 1)
		insn++;
	if (pfx < 0) {
		report_bad_1byte_opcode(64, insn[0]);
		return -EPERM;
	}
	/* Skip REX prefix. */
	if ((insn[0] & 0xf0) == 0x40)
		insn++;
	if ((ret = setup_uprobe_post_ssout(ppt, insn)) != 0)
		return ret;
	if (test_bit(insn[0], (unsigned long*)good_insns_64))
		return 0;
	if (insn[0] == 0x0f) {
		if (test_bit(insn[1], (unsigned long*)good_2byte_insns))
			return 0;
		report_bad_2byte_opcode(insn[1]);
	} else
		report_bad_1byte_opcode(64, insn[0]);
	return -EPERM;
}

#ifdef CONFIG_X86_64
static int handle_riprel_insn(struct uprobe_probept *ppt);
#endif

static
int arch_validate_probed_insn(struct uprobe_probept *ppt,
						struct task_struct *tsk)
{
	int ret;

	ppt->arch_info.flags = 0x0;
#ifdef CONFIG_X86_64
	ppt->arch_info.rip_target_address = 0x0;
#endif

	if (is_32bit_app(tsk))
		return validate_insn_32bits(ppt);
	if ((ret = validate_insn_64bits(ppt)) != 0)
		return ret;
#ifdef CONFIG_X86_64
	(void) handle_riprel_insn(ppt);
#endif
	return 0;
}

#ifdef CONFIG_X86_64
/*
 * Returns 0 if the indicated instruction has no immediate operand
 * and/or can't use rip-relative addressing.  Otherwise returns
 * the size of the immediate operand in the instruction.  (Note that
 * for instructions such as "movq $7,xxxx(%rip)" the immediate-operand
 * field is 4 bytes, even though 8 bytes are stored.)
 */
static int immediate_operand_size(u8 opcode1, u8 opcode2, u8 reg,
						int operand_size_prefix)
{
	switch (opcode1) {
	case 0x6b:	/* imul immed,mem,reg */
	case 0x80:	/* Group 1 */
	case 0x83:	/* Group 1 */
	case 0xc0:	/* Group 2 */
	case 0xc1:	/* Group 2 */
	case 0xc6:	/* Group 11 */
		return 1;
	case 0x69:	/* imul immed,mem,reg */
	case 0x81:	/* Group 1 */
	case 0xc7:	/* Group 11 */
		return (operand_size_prefix ? 2 : 4);
	case 0xf6:	/* Group 3, reg field == 0 or 1 */
		return (reg > 1 ? 0 : 1);
	case 0xf7:	/* Group 3, reg field == 0 or 1 */
		if (reg > 1)
			return 0;
		return (operand_size_prefix ? 2 : 4);
	case 0x0f:
		/* 2-byte opcodes */
		switch (opcode2) {
		/*
		 * Note: 0x71-73 (Groups 12-14) have immediate operands,
		 * but not memory operands.
		 */
		case 0x70:	/* pshuf* immed,mem,reg */
		case 0xa4:	/* shld immed,reg,mem */
		case 0xac:	/* shrd immed,reg,mem */
		case 0xc2:	/* cmpps or cmppd */
		case 0xc4:	/* pinsrw */
		case 0xc5:	/* pextrw */
		case 0xc6:	/* shufps or shufpd */
		case 0x0f:	/* 3DNow extensions */
			return 1;
		default:
			return 0;
		}
	}
	return 0;
}

/*
 * TODO: These tables are common for kprobes and uprobes and can be moved
 * to a common place.
 */
static const volatile u64 onebyte_has_modrm[256 / 64] = {
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	/*      -------------------------------         */
	W(0x00, 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0)| /* 00 */
	W(0x10, 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0)| /* 10 */
	W(0x20, 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0)| /* 20 */
	W(0x30, 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0), /* 30 */
	W(0x40, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)| /* 40 */
	W(0x50, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)| /* 50 */
	W(0x60, 0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,0)| /* 60 */
	W(0x70, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), /* 70 */
	W(0x80, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 80 */
	W(0x90, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)| /* 90 */
	W(0xa0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)| /* a0 */
	W(0xb0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), /* b0 */
	W(0xc0, 1,1,0,0,1,1,1,1,0,0,0,0,0,0,0,0)| /* c0 */
	W(0xd0, 1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1)| /* d0 */
	W(0xe0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)| /* e0 */
	W(0xf0, 0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,1)  /* f0 */
	/*      -------------------------------         */
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
};
static const volatile u64 twobyte_has_modrm[256 / 64] = {
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	/*      -------------------------------         */
	W(0x00, 1,1,1,1,0,0,0,0,0,0,0,0,0,1,0,1)| /* 0f */
	W(0x10, 1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0)| /* 1f */
	W(0x20, 1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1)| /* 2f */
	W(0x30, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), /* 3f */
	W(0x40, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 4f */
	W(0x50, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 5f */
	W(0x60, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 6f */
	W(0x70, 1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1), /* 7f */
	W(0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)| /* 8f */
	W(0x90, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* 9f */
	W(0xa0, 0,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1)| /* af */
	W(0xb0, 1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1), /* bf */
	W(0xc0, 1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0)| /* cf */
	W(0xd0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* df */
	W(0xe0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)| /* ef */
	W(0xf0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0)  /* ff */
	/*      -------------------------------         */
	/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
};

/*
 * If pp->insn doesn't use rip-relative addressing, return 0.  Otherwise,
 * rewrite the instruction so that it accesses its memory operand
 * indirectly through a scratch register.  Set flags and rip_target_address
 * in ppt->arch_info accordingly.  (The contents of the scratch register
 * will be saved before we single-step the modified instruction, and
 * restored afterward.)  Return 1.
 *
 * We do this because a rip-relative instruction can access only a
 * relatively small area (+/- 2 GB from the instruction), and the SSOL
 * area typically lies beyond that area.  At least for instructions
 * that store to memory, we can't single-step the original instruction
 * and "fix things up" later, because the misdirected store could be
 * disastrous.
 *
 * Some useful facts about rip-relative instructions:
 * - There's always a modrm byte.
 * - There's never a SIB byte.
 * - The offset is always 4 bytes.
 */
static int handle_riprel_insn(struct uprobe_probept *ppt)
{
	u8 *insn = (u8*) ppt->insn;
	u8 opcode1, opcode2, modrm, reg;
	int need_modrm;
	int operand_size_prefix = 0;
	int immed_size, instruction_size;

	/*
	 * Skip legacy instruction prefixes.  Some of these we don't
	 * support (yet), but here we pretend to support all of them.
	 * Skip the REX prefix, if any.
	 */
	while (check_legacy_prefix(*insn)) {
		if (*insn == 0x66)
			operand_size_prefix = 1;
		insn++;
	}
	if ((*insn & 0xf0) == 0x40)
		insn++;

	opcode1 = *insn;
	if (opcode1 == 0x0f) {	/* Two-byte opcode.  */
		opcode2 = *++insn;
		need_modrm = test_bit(opcode2, twobyte_has_modrm);
	} else {		/* One-byte opcode.  */
		opcode2 = 0x0;
		need_modrm = test_bit(opcode1, onebyte_has_modrm);
	}

	if (!need_modrm)
		return 0;

	modrm = *++insn;
	/*
	 * For rip-relative instructions, the mod field (top 2 bits)
	 * is zero and the r/m field (bottom 3 bits) is 0x5.
	 */
	if ((modrm & 0xc7) != 0x5)
		return 0;

	/*
	 * We have a rip-relative instruction.  insn points at the
	 * modrm byte.  The next 4 bytes are the offset. Beyond the
	 * offset, for some instructions, is the immediate operand.
	 */
	reg = (modrm >> 3) & 0x7;
	immed_size = immediate_operand_size(opcode1, opcode2, reg,
						operand_size_prefix);
	instruction_size =
		(insn - (u8*) ppt->insn)	/* prefixes + opcodes */
		+ 1			/* modrm byte */
		+ 4			/* offset */
		+ immed_size;		/* immediate field */
#ifdef DEBUG_UPROBES_RIP
{
	int i;
	BUG_ON(instruction_size > 15);
	printk(KERN_INFO "Munging rip-relative insn:");
	for (i = 0; i < instruction_size; i++)
		printk(" %2.2x", ppt->insn[i]);
	printk("\n");
}
#endif

	/*
	 * Convert from rip-relative addressing to indirect addressing
	 * via a scratch register.  Change the r/m field from 0x5 (%rip)
	 * to 0x0 (%rax) or 0x1 (%rcx), and squeeze out the offset field.
	 */
	if (reg == 0) {
		/*
		 * The register operand (if any) is either the A register
		 * (%rax, %eax, etc.) or (if the 0x4 bit is set in the
		 * REX prefix) %r8.  In any case, we know the C register
		 * is NOT the register operand, so we use %rcx (register
		 * #1) for the scratch register.
		 */
		ppt->arch_info.flags |= UPFIX_RIP_RCX;
		/* Change modrm from 00 000 101 to 00 000 001. */
		*insn = 0x1;
	} else {
		/* Use %rax (register #0) for the scratch register. */
		ppt->arch_info.flags |= UPFIX_RIP_RAX;
		/* Change modrm from 00 xxx 101 to 00 xxx 000 */
		*insn = (reg << 3);
	}

	/* Target address = address of next instruction + (signed) offset */
	insn++;
	ppt->arch_info.rip_target_address =
			(long) ppt->vaddr + instruction_size + *((s32*)insn);
	if (immed_size)
		memmove(insn, insn+4, immed_size);
#ifdef DEBUG_UPROBES_RIP
{
	int i;
	printk(KERN_INFO "Munged rip-relative insn: ");
	for (i = 0; i < instruction_size-4; i++)
		printk(" %2.2x", ppt->insn[i]);
	printk("\n");
	printk(KERN_INFO "Target address = %#lx\n",
				ppt->arch_info.rip_target_address);
}
#endif
	return 1;
}
#endif

/*
 * Get an instruction slot from the process's SSOL area, containing the
 * instruction at ppt's probepoint.  Point the rip at that slot, in
 * preparation for single-stepping out of line.
 *
 * If we're emulating a rip-relative instruction, save the contents
 * of the scratch register and store the target address in that register.
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

	REGS_IP = (long)slot->insn;
	utask->singlestep_addr = REGS_IP;
#ifdef CONFIG_X86_64
	if (ppt->arch_info.flags & UPFIX_RIP_RAX) {
		utask->arch_info.saved_scratch_register = REGS_AX;
		REGS_AX = ppt->arch_info.rip_target_address;
	} else if (ppt->arch_info.flags & UPFIX_RIP_RCX) {
		utask->arch_info.saved_scratch_register = REGS_CX;
		REGS_CX = ppt->arch_info.rip_target_address;
	}
#endif
}

/*
 * Called by uprobe_post_ssout() to adjust the return address
 * pushed by a call instruction executed out of line.
 */
static void adjust_ret_addr(unsigned long rsp, long correction,
					struct uprobe_task *utask)
{
	unsigned long nleft;
	if (is_32bit_app(current)) {
		s32 ra;
		nleft = copy_from_user(&ra, (const void __user *) rsp, 4);
		if (unlikely(nleft != 0))
			goto fail;
		ra += (s32) correction;
		nleft = copy_to_user((void __user *) rsp, &ra, 4);
		if (unlikely(nleft != 0))
			goto fail;
	} else {
		s64 ra;
		nleft = copy_from_user(&ra, (const void __user *) rsp, 8);
		if (unlikely(nleft != 0))
			goto fail;
		ra += correction;
		nleft = copy_to_user((void __user *) rsp, &ra, 8);
		if (unlikely(nleft != 0))
			goto fail;
	}
	return;

fail:
	printk(KERN_ERR
		"uprobes: Failed to adjust return address after"
		" single-stepping call instruction;"
		" pid=%d, rsp=%#lx\n", current->pid, rsp);
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
 * trap.  We have to fix things up as follows:
 *
 * 0) Typically, the new rip is relative to the copied instruction.  We
 * need to make it relative to the original instruction.  Exceptions are
 * return instructions and absolute or indirect jump or call instructions.
 *
 * 1) If the single-stepped instruction was a call, the return address
 * that is atop the stack is the address following the copied instruction.
 * We need to make it the address following the original instruction.
 *
 * 2) If the original instruction was a rip-relative instruction such as
 * "movl %edx,0xnnnn(%rip)", we have instead executed an equivalent
 * instruction using a scratch register -- e.g., "movl %edx,(%rax)".
 * We need to restore the contents of the scratch register and adjust
 * the rip, keeping in mind that the instruction we executed is 4 bytes
 * shorter than the original instruction (since we squeezed out the offset
 * field).
 */
static
void uprobe_post_ssout(struct uprobe_task *utask, struct uprobe_probept *ppt,
		struct pt_regs *regs)
{
	unsigned long copy_rip = utask->singlestep_addr;
	unsigned long orig_rip = ppt->vaddr;
	long correction = (long) (orig_rip - copy_rip);
	unsigned long flags = ppt->arch_info.flags;

	up_read(&ppt->slot->rwsem);

#ifdef CONFIG_X86_64
	if (flags & (UPFIX_RIP_RAX | UPFIX_RIP_RCX)) {
		if (flags & UPFIX_RIP_RAX)
			REGS_AX = utask->arch_info.saved_scratch_register;
		else
			REGS_CX = utask->arch_info.saved_scratch_register;
		/*
		 * The original instruction includes a displacement, and so
		 * is 4 bytes longer than what we've just single-stepped.
		 * Fall through to handle stuff like "jmpq *...(%rip)" and
		 * "callq *...(%rip)".
		 */
		correction += 4;
	}
#endif

	if (flags & UPFIX_RETURN)
		adjust_ret_addr(REGS_SP, correction, utask);

	if (!(flags & UPFIX_ABS_IP))
		REGS_IP += correction;
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
	unsigned long orig_ret_addr = 0;  /* clear high bits for 32-bit apps */
	size_t rasize;

	if (is_32bit_app(current))
		rasize = 4;
	else
		rasize = 8;
	nleft = copy_from_user(&orig_ret_addr, (const void __user *) REGS_SP,
		rasize);
	if (unlikely(nleft != 0))
		return 0;
	if (orig_ret_addr == trampoline_address)
		/*
		 * There's another uretprobe on this function, and it was
		 * processed first, so the return address has already
		 * been hijacked.
		 */
		return orig_ret_addr;

	nleft = copy_to_user((void __user *) REGS_SP, &trampoline_address,
		rasize);
	if (unlikely(nleft != 0)) {
		if (nleft != rasize) {
			printk(KERN_ERR "uretprobe_entry_handler: "
				"return address partially clobbered -- "
				"pid=%d, %%sp=%#lx, %%ip=%#lx\n",
				current->pid, REGS_SP, REGS_IP);
			utask->doomed = 1;
		} // else nothing written, so no harm
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
	if (test_tsk_thread_flag(tsk, TIF_IA32))
		return (unsigned long) (REGS_SP + 4 + STRUCT_RETURN_SLOP);
	else
		return (unsigned long) (REGS_SP + 8);
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
