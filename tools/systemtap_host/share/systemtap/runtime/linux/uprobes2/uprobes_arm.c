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
 * Copyright (C) 2011 Mentor Graphics Corporation
 *
 * Instruction validation and emulation code is based on
 * ARM kprobes which is
 * Copyright (C) 2011 Jon Medhurst <tixy@yxit.co.uk>.
 * Copyright (C) 2006, 2007 Motorola Inc.
 */
/*
 * In versions of uprobes built in the SystemTap runtime, this file
 * is #included at the end of uprobes.c.
 */

/*
 * We do not have hardware single-stepping on ARM, This
 * effort is further complicated by the ARM not having a
 * "next PC" register.  Instructions that change the PC
 * can't be safely single-stepped in a MP environment, so
 * we have a lot of work to do:
 *
 * In the prepare phase:
 *   *) If it is an instruction that does anything
 *      with the CPU mode, we reject it for a uprobe.
 *      (This is out of laziness rather than need.  The
 *      instructions could be simulated.)
 *
 *   *) Otherwise, decode the instruction rewriting its
 *      registers to take fixed, ordered registers and
 *      setting a handler for it to run the instruction.
 *
 * In the execution phase by an instruction's handler:
 *
 *   *) If the PC is written to by the instruction, the
 *      instruction must be fully simulated in software.
 *
 *   *) Otherwise, a modified form of the instruction is
 *      directly executed.  Its handler calls the
 *      instruction in insn[0].  In insn[1] is a
 *      "mov pc, lr" to return.
 *
 *      Before calling, load up the reordered registers
 *      from the original instruction's registers.  If one
 *      of the original input registers is the PC, compute
 *      and adjust the appropriate input register.
 *
 *	After call completes, copy the output registers to
 *      the original instruction's original registers.
 *
 * We don't use a real breakpoint instruction since that
 * would have us in the kernel go from SVC mode to SVC
 * mode losing the link register.  Instead we use an
 * undefined instruction.  To simplify processing, the
 * undefined instruction used for uprobes must be reserved
 * exclusively for uprobes use.
 *
 * TODO: ifdef out some instruction decoding based on architecture.
 */

#define APSR_MASK       0xf80f0000      /* N, Z, C, V, Q and GE flags */

int cpu_architecture(void)
{
	int cpu_arch;

	if ((read_cpuid_id() & 0x0008f000) == 0) {
		cpu_arch = CPU_ARCH_UNKNOWN;
	} else if ((read_cpuid_id() & 0x0008f000) == 0x00007000) {
		cpu_arch = (read_cpuid_id() & (1 << 23)) ? CPU_ARCH_ARMv4T : CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x00080000) == 0x00000000) {
		cpu_arch = (read_cpuid_id() >> 16) & 7;
		if (cpu_arch)
			cpu_arch += CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x000f0000) == 0x000f0000) {
		unsigned int mmfr0;

		/* Revised CPUID format. Read the Memory Model Feature
		 * Register 0 and check for VMSAv7 or PMSAv7 */
		asm("mrc	p15, 0, %0, c0, c1, 4"
		    : "=r" (mmfr0));
		if ((mmfr0 & 0x0000000f) >= 0x00000003 ||
		    (mmfr0 & 0x000000f0) >= 0x00000030)
			cpu_arch = CPU_ARCH_ARMv7;
		else if ((mmfr0 & 0x0000000f) == 0x00000002 ||
			 (mmfr0 & 0x000000f0) == 0x00000020)
			cpu_arch = CPU_ARCH_ARMv6;
		else
			cpu_arch = CPU_ARCH_UNKNOWN;
	} else
		cpu_arch = CPU_ARCH_UNKNOWN;

	return cpu_arch;
}

#if __LINUX_ARM_ARCH__ >= 7

/* str_pc_offset is architecturally defined from ARMv7 onwards */
#define str_pc_offset 8
#define find_str_pc_offset()

#else /* __LINUX_ARM_ARCH__ < 7 */

/* We need a run-time check to determine str_pc_offset */
extern int str_pc_offset;
void find_str_pc_offset(void);

#endif

static inline void bx_write_pc(long pcv, struct pt_regs *regs)
{
	long cpsr = regs->ARM_cpsr;
	if (pcv & 0x1) {
		cpsr |= PSR_T_BIT;
		pcv &= ~0x1;
	} else {
		cpsr &= ~PSR_T_BIT;
		pcv &= ~0x2;    /* Avoid UNPREDICTABLE address allignment */
	}
	regs->ARM_cpsr = cpsr;
	regs->ARM_pc = pcv;
}

#if __LINUX_ARM_ARCH__ >= 6

/* Kernels built for >= ARMv6 should never run on <= ARMv5 hardware, so... */
#define load_write_pc_interworks true
#define test_load_write_pc_interworking()

#else /* __LINUX_ARM_ARCH__ < 6 */

/* We need run-time testing to determine if load_write_pc() should interwork.
 * */
extern bool load_write_pc_interworks;
void test_load_write_pc_interworking(void);

#endif

static inline void load_write_pc(long pcv, struct pt_regs *regs)
{
	if (load_write_pc_interworks)
		bx_write_pc(pcv, regs);
	else
		regs->ARM_pc = pcv;
}

#if __LINUX_ARM_ARCH__ >= 7

#define alu_write_pc_interworks true
#define test_alu_write_pc_interworking()

#elif __LINUX_ARM_ARCH__ <= 5

/* Kernels built for <= ARMv5 should never run on >= ARMv6 hardware, so... */
#define alu_write_pc_interworks false
#define test_alu_write_pc_interworking()

#else /* __LINUX_ARM_ARCH__ == 6 */

/* We could be an ARMv6 binary on ARMv7 hardware so we need a run-time check.
 * */
extern bool alu_write_pc_interworks;
void test_alu_write_pc_interworking(void);

#endif /* __LINUX_ARM_ARCH__ == 6 */

static inline void alu_write_pc(long pcv, struct pt_regs *regs)
{
	if (alu_write_pc_interworks)
		bx_write_pc(pcv, regs);
	else
		regs->ARM_pc = pcv;
}

enum uprobe_insn {
	INSN_REJECTED,
	INSN_GOOD,
	INSN_GOOD_NO_SLOT
};

typedef enum uprobe_insn (uprobe_decode_insn_t)(uprobe_opcode_t,
		struct uprobe_probept_arch_info *);

/*
 * Test if load/store instructions writeback the address register.
 * if P (bit 24) == 0 or W (bit 21) == 1
 */
#define is_writeback(insn) ((insn ^ 0x01000000) & 0x01200000)

/*
 * The following definitions and macros are used to build instruction
 * decoding tables for use by uprobe_decode_insn.
 *
 * These tables are a concatenation of entries each of which consist of one of
 * the decode_* structs. All of the fields in every type of decode structure
 * are of the union type decode_item, therefore the entire decode table can be
 * viewed as an array of these and declared like:
 *
 *	static const union decode_item table_name[] = {};
 *
 * In order to construct each entry in the table, macros are used to
 * initialise a number of sequential decode_item values in a layout which
 * matches the relevant struct. E.g. DECODE_SIMULATE initialise a struct
 * decode_simulate by initialising four decode_item objects like this...
 *
 *	{.bits = _type},
 *	{.bits = _mask},
 *	{.bits = _value},
 *	{.handler = _handler},
 *
 * Initialising a specified member of the union means that the compiler
 * will produce a warning if the argument is of an incorrect type.
 *
 * Below is a list of each of the macros used to initialise entries and a
 * description of the action performed when that entry is matched to an
 * instruction. A match is found when (instruction & mask) == value.
 *
 * DECODE_TABLE(mask, value, table)
 *	Instruction decoding jumps to parsing the new sub-table 'table'.
 *
 * DECODE_CUSTOM(mask, value, decoder)
 *	The custom function 'decoder' is called to the complete decoding
 *	of an instruction.
 *
 * DECODE_SIMULATE(mask, value, handler)
 *	Set the probes instruction handler to 'handler', this will be used
 *	to simulate the instruction when the probe is hit. Decoding returns
 *	with INSN_GOOD_NO_SLOT.
 *
 * DECODE_EMULATE(mask, value, handler)
 *	Set the probes instruction handler to 'handler', this will be used
 *	to emulate the instruction when the probe is hit. The modified
 *	instruction (see below) is placed in the probes instruction slot so it
 *	may be called by the emulation code. Decoding returns with INSN_GOOD.
 *
 * DECODE_REJECT(mask, value)
 *	Instruction decoding fails with INSN_REJECTED
 *
 * DECODE_OR(mask, value)
 *	This allows the mask/value test of multiple table entries to be
 *	logically ORed. Once an 'or' entry is matched the decoding action to
 *	be performed is that of the next entry which isn't an 'or'. E.g.
 *
 *		DECODE_OR	(mask1, value1)
 *		DECODE_OR	(mask2, value2)
 *		DECODE_SIMULATE	(mask3, value3, simulation_handler)
 *
 *	This means that if any of the three mask/value pairs match the
 *	instruction being decoded, then 'simulation_handler' will be used
 *	for it.
 *
 * Both the SIMULATE and EMULATE macros have a second form which take an
 * additional 'regs' argument.
 *
 *	DECODE_SIMULATEX(mask, value, handler, regs)
 *	DECODE_EMULATEX	(mask, value, handler, regs)
 *
 * These are used to specify what kind of CPU register is encoded in each of the
 * least significant 5 nibbles of the instruction being decoded. The regs value
 * is specified using the REGS macro, this takes any of the REG_TYPE_* values
 * from enum decode_reg_type as arguments; only the '*' part of the name is
 * given. E.g.
 *
 *	REGS(0, ANY, NOPC, 0, ANY)
 *
 * This indicates an instruction is encoded like:
 *
 *	bits 19..16	ignore
 *	bits 15..12	any register allowed here
 *	bits 11.. 8	any register except PC allowed here
 *	bits  7.. 4	ignore
 *	bits  3.. 0	any register allowed here
 *
 * This register specification is checked after a decode table entry is found to
 * match an instruction (through the mask/value test). Any invalid register then
 * found in the instruction will cause decoding to fail with INSN_REJECTED. In
 * the above example this would happen if bits 11..8 of the instruction were
 * 1111, indicating R15 or PC.
 *
 * As well as checking for legal combinations of registers, this data is also
 * used to modify the registers encoded in the instructions so that an
 * emulation routines can use it. (See decode_regs() and INSN_NEW_BITS.)
 *
 * Here is a real example which matches ARM instructions of the form
 * "AND <Rd>,<Rn>,<Rm>,<shift> <Rs>"
 *
 *	DECODE_EMULATEX	(0x0e000090, 0x00000010, emulate_rd12rn16rm0rs8_rwflags,
 *						 REGS(ANY, ANY, NOPC, 0, ANY)),
 *						      ^    ^    ^        ^
 *						      Rn   Rd   Rs       Rm
 *
 * Decoding the instruction "AND R4, R5, R6, ASL R15" will be rejected because
 * Rs == R15
 *
 * Decoding the instruction "AND R4, R5, R6, ASL R7" will be accepted and the
 * instruction will be modified to "AND R0, R2, R3, ASL R1" and then placed into
 * the uprobes instruction slot. This can then be called later by the handler
 * function emulate_rd12rn16rm0rs8_rwflags in order to simulate the instruction.
 */

enum decode_type {
	DECODE_TYPE_END,
	DECODE_TYPE_TABLE,
	DECODE_TYPE_CUSTOM,
	DECODE_TYPE_SIMULATE,
	DECODE_TYPE_EMULATE,
	DECODE_TYPE_OR,
	DECODE_TYPE_REJECT,
	NUM_DECODE_TYPES /* Must be last enum */
};

#define DECODE_TYPE_BITS	4
#define DECODE_TYPE_MASK	((1 << DECODE_TYPE_BITS) - 1)

enum decode_reg_type {
	REG_TYPE_NONE = 0, /* Not a register, ignore */
	REG_TYPE_ANY,	   /* Any register allowed */
	REG_TYPE_SAMEAS16, /* Register should be same as that at bits 19..16 */
	REG_TYPE_SP,	   /* Register must be SP */
	REG_TYPE_PC,	   /* Register must be PC */
	REG_TYPE_NOSP,	   /* Register must not be SP */
	REG_TYPE_NOSPPC,   /* Register must not be SP or PC */
	REG_TYPE_NOPC,	   /* Register must not be PC */
	REG_TYPE_NOPCWB,   /* No PC if load/store write-back flag also set */

	/* The following types are used when the encoding for PC indicates
	 * another instruction form. This distiction only matters for test
	 * case coverage checks.
	 */
	REG_TYPE_NOPCX,	   /* Register must not be PC */
	REG_TYPE_NOSPPCX,  /* Register must not be SP or PC */

	/* Alias to allow '0' arg to be used in REGS macro. */
	REG_TYPE_0 = REG_TYPE_NONE
};

#define REGS(r16, r12, r8, r4, r0)	\
	((REG_TYPE_##r16) << 16) +	\
	((REG_TYPE_##r12) << 12) +	\
	((REG_TYPE_##r8) << 8) +	\
	((REG_TYPE_##r4) << 4) +	\
	(REG_TYPE_##r0)

union decode_item {
	u32			bits;
	const union decode_item	*table;
	uprobe_insn_handler_t	*handler;
	uprobe_decode_insn_t	*decoder;
};


#define DECODE_END			\
	{.bits = DECODE_TYPE_END}


struct decode_header {
	union decode_item	type_regs;
	union decode_item	mask;
	union decode_item	value;
};

#define DECODE_HEADER(_type, _mask, _value, _regs)		\
	{.bits = (_type) | ((_regs) << DECODE_TYPE_BITS)},	\
	{.bits = (_mask)},					\
	{.bits = (_value)}


struct decode_table {
	struct decode_header	header;
	union decode_item	table;
};

#define DECODE_TABLE(_mask, _value, _table)			\
	DECODE_HEADER(DECODE_TYPE_TABLE, _mask, _value, 0),	\
	{.table = (_table)}


struct decode_custom {
	struct decode_header	header;
	union decode_item	decoder;
};

#define DECODE_CUSTOM(_mask, _value, _decoder)			\
	DECODE_HEADER(DECODE_TYPE_CUSTOM, _mask, _value, 0),	\
	{.decoder = (_decoder)}


struct decode_simulate {
	struct decode_header	header;
	union decode_item	handler;
};

#define DECODE_SIMULATEX(_mask, _value, _handler, _regs)		\
	DECODE_HEADER(DECODE_TYPE_SIMULATE, _mask, _value, _regs),	\
	{.handler = (_handler)}

#define DECODE_SIMULATE(_mask, _value, _handler)	\
	DECODE_SIMULATEX(_mask, _value, _handler, 0)


struct decode_emulate {
	struct decode_header	header;
	union decode_item	handler;
};

#define DECODE_EMULATEX(_mask, _value, _handler, _regs)			\
	DECODE_HEADER(DECODE_TYPE_EMULATE, _mask, _value, _regs),	\
	{.handler = (_handler)}

#define DECODE_EMULATE(_mask, _value, _handler)		\
	DECODE_EMULATEX(_mask, _value, _handler, 0)


struct decode_or {
	struct decode_header	header;
};

#define DECODE_OR(_mask, _value)				\
	DECODE_HEADER(DECODE_TYPE_OR, _mask, _value, 0)


struct decode_reject {
	struct decode_header	header;
};

#define DECODE_REJECT(_mask, _value)				\
	DECODE_HEADER(DECODE_TYPE_REJECT, _mask, _value, 0)

#define sign_extend(x, signbit) ((x) | (0 - ((x) & (1 << (signbit)))))

#define branch_displacement(insn) sign_extend(((insn) & 0xffffff) << 2, 25)

#if  __LINUX_ARM_ARCH__ >= 6
#define BLX(reg)	"blx	"reg"		\n\t"
#else
#define BLX(reg)	"mov	lr, pc		\n\t"	\
			"mov	pc, "reg"	\n\t"
#endif

#ifndef find_str_pc_offset

/*
 * For STR and STM instructions, an ARM core may choose to use either
 * a +8 or a +12 displacement from the current instruction's address.
 * Whichever value is chosen for a given core, it must be the same for
 * both instructions and may not change.  This function measures it.
 */

int str_pc_offset;

void find_str_pc_offset(void)
{
	int addr, scratch, ret;

	__asm__ (
		"sub	%[ret], pc, #4		\n\t"
		"str	pc, %[addr]		\n\t"
		"ldr	%[scr], %[addr]		\n\t"
		"sub	%[ret], %[scr], %[ret]	\n\t"
		: [ret] "=r" (ret), [scr] "=r" (scratch), [addr] "+m" (addr));

	str_pc_offset = ret;
}

#endif /* !find_str_pc_offset */


#ifndef test_load_write_pc_interworking

bool load_write_pc_interworks;

void test_load_write_pc_interworking(void)
{
	int arch = cpu_architecture();
	BUG_ON(arch == CPU_ARCH_UNKNOWN);
	load_write_pc_interworks = arch >= CPU_ARCH_ARMv5T;
}

#endif /* !test_load_write_pc_interworking */


#ifndef test_alu_write_pc_interworking

bool alu_write_pc_interworks;

void test_alu_write_pc_interworking(void)
{
	int arch = cpu_architecture();
	BUG_ON(arch == CPU_ARCH_UNKNOWN);
	alu_write_pc_interworks = arch >= CPU_ARCH_ARMv7;
}

#endif /* !test_alu_write_pc_interworking */


void arm_uprobe_decode_init(void)
{
	find_str_pc_offset();
	test_load_write_pc_interworking();
	test_alu_write_pc_interworking();
}


static unsigned long __check_eq(unsigned long cpsr)
{
	return cpsr & PSR_Z_BIT;
}

static unsigned long __check_ne(unsigned long cpsr)
{
	return (~cpsr) & PSR_Z_BIT;
}

static unsigned long __check_cs(unsigned long cpsr)
{
	return cpsr & PSR_C_BIT;
}

static unsigned long __check_cc(unsigned long cpsr)
{
	return (~cpsr) & PSR_C_BIT;
}

static unsigned long __check_mi(unsigned long cpsr)
{
	return cpsr & PSR_N_BIT;
}

static unsigned long __check_pl(unsigned long cpsr)
{
	return (~cpsr) & PSR_N_BIT;
}

static unsigned long __check_vs(unsigned long cpsr)
{
	return cpsr & PSR_V_BIT;
}

static unsigned long __check_vc(unsigned long cpsr)
{
	return (~cpsr) & PSR_V_BIT;
}

static unsigned long __check_hi(unsigned long cpsr)
{
	cpsr &= ~(cpsr >> 1); /* PSR_C_BIT &= ~PSR_Z_BIT */
	return cpsr & PSR_C_BIT;
}

static unsigned long __check_ls(unsigned long cpsr)
{
	cpsr &= ~(cpsr >> 1); /* PSR_C_BIT &= ~PSR_Z_BIT */
	return (~cpsr) & PSR_C_BIT;
}

static unsigned long __check_ge(unsigned long cpsr)
{
	cpsr ^= (cpsr << 3); /* PSR_N_BIT ^= PSR_V_BIT */
	return (~cpsr) & PSR_N_BIT;
}

static unsigned long __check_lt(unsigned long cpsr)
{
	cpsr ^= (cpsr << 3); /* PSR_N_BIT ^= PSR_V_BIT */
	return cpsr & PSR_N_BIT;
}

static unsigned long __check_gt(unsigned long cpsr)
{
	unsigned long temp = cpsr ^ (cpsr << 3); /* PSR_N_BIT ^= PSR_V_BIT */
	temp |= (cpsr << 1);			 /* PSR_N_BIT |= PSR_Z_BIT */
	return (~temp) & PSR_N_BIT;
}

static unsigned long __check_le(unsigned long cpsr)
{
	unsigned long temp = cpsr ^ (cpsr << 3); /* PSR_N_BIT ^= PSR_V_BIT */
	temp |= (cpsr << 1);			 /* PSR_N_BIT |= PSR_Z_BIT */
	return temp & PSR_N_BIT;
}

static unsigned long __check_al(unsigned long cpsr)
{
	return true;
}

uprobe_check_cc * const uprobe_condition_checks[16] = {
	&__check_eq, &__check_ne, &__check_cs, &__check_cc,
	&__check_mi, &__check_pl, &__check_vs, &__check_vc,
	&__check_hi, &__check_ls, &__check_ge, &__check_lt,
	&__check_gt, &__check_le, &__check_al, &__check_al
};

/*
 * To avoid the complications of mimicing single-stepping on a
 * processor without a Next-PC or a single-step mode, and to
 * avoid having to deal with the side-effects of boosting, we
 * simulate or emulate (almost) all ARM instructions.
 *
 * "Simulation" is where the instruction's behavior is duplicated in
 * C code.  "Emulation" is where the original instruction is rewritten
 * and executed, often by altering its registers.
 *
 * By having all behavior of the uprobe'd instruction completed before
 * returning from the uprobe_handler(), all locks (scheduler and
 * interrupt) can safely be released.  There is no need for secondary
 * breakpoints, no race with MP or preemptable kernels, nor having to
 * clean up resources counts at a later time impacting overall system
 * performance.  By rewriting the instruction, only the minimum registers
 * need to be loaded and saved back optimizing performance.
 *
 * Calling the insnslot_*_rwflags version of a function doesn't hurt
 * anything even when the CPSR flags aren't updated by the
 * instruction.  It's just a little slower in return for saving
 * a little space by not having a duplicate function that doesn't
 * update the flags.  (The same optimization can be said for
 * instructions that do or don't perform register writeback)
 * Also, instructions can either read the flags, only write the
 * flags, or read and write the flags.  To save combinations
 * rather than for sheer performance, flag functions just assume
 * read and write of flags.
 */

void uprobe_simulate_nop(struct uprobe_probept *p, struct pt_regs *regs)
{
}

void uprobe_emulate_none(struct uprobe_probept *p, struct pt_regs *regs)
{
	p->arch_info.insn_fn();
}

static void simulate_ldm1stm1(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	int rn = (insn >> 16) & 0xf;
	int lbit = insn & (1 << 20);
	int wbit = insn & (1 << 21);
	int ubit = insn & (1 << 23);
	int pbit = insn & (1 << 24);
	long *addr = (long *)regs->uregs[rn];
	int reg_bit_vector;
	int reg_count;

	reg_count = 0;
	reg_bit_vector = insn & 0xffff;
	while (reg_bit_vector) {
		reg_bit_vector &= (reg_bit_vector - 1);
		++reg_count;
	}

	if (!ubit)
		addr -= reg_count;
	addr += (!pbit == !ubit);

	reg_bit_vector = insn & 0xffff;
	while (reg_bit_vector) {
		int reg = __ffs(reg_bit_vector);
		reg_bit_vector &= (reg_bit_vector - 1);
		if (lbit)
			regs->uregs[reg] = *addr++;
		else
			*addr++ = regs->uregs[reg];
	}

	if (wbit) {
		if (!ubit)
			addr -= reg_count;
		addr -= (!pbit == !ubit);
		regs->uregs[rn] = (long)addr;
	}
}

static void simulate_stm1_pc(struct uprobe_probept *p, struct pt_regs *regs)
{
	regs->ARM_pc = (long)p->vaddr + str_pc_offset;
	simulate_ldm1stm1(p, regs);
	regs->ARM_pc = (long)p->vaddr + 4;
}

static void simulate_ldm1_pc(struct uprobe_probept *p, struct pt_regs *regs)
{
	simulate_ldm1stm1(p, regs);
	load_write_pc(regs->ARM_pc, regs);
}

static void
emulate_generic_r0_12_noflags(struct uprobe_probept *p, struct pt_regs *regs)
{
	register void *rregs asm("r1") = regs;
	register void *rfn asm("lr") = p->arch_info.insn_fn;

	__asm__ __volatile__ (
		"stmdb	sp!, {%[regs], r11}	\n\t"
		"ldmia	%[regs], {r0-r12}	\n\t"
#if __LINUX_ARM_ARCH__ >= 6
		"blx	%[fn]			\n\t"
#else
		"str	%[fn], [sp, #-4]!	\n\t"
		"adr	lr, 1f			\n\t"
		"ldr	pc, [sp], #4		\n\t"
		"1:				\n\t"
#endif
		"ldr	lr, [sp], #4		\n\t" /* lr = regs */
		"stmia	lr, {r0-r12}		\n\t"
		"ldr	r11, [sp], #4		\n\t"
		: [regs] "=r" (rregs), [fn] "=r" (rfn)
		: "0" (rregs), "1" (rfn)
		: "r0", "r2", "r3", "r4", "r5", "r6", "r7",
		  "r8", "r9", "r10", "r12", "memory", "cc"
		);
}

static void
emulate_generic_r2_14_noflags(struct uprobe_probept *p, struct pt_regs *regs)
{
	emulate_generic_r0_12_noflags(p, (struct pt_regs *)(regs->uregs+2));
}

static void
emulate_ldm_r3_15(struct uprobe_probept *p, struct pt_regs *regs)
{
	emulate_generic_r0_12_noflags(p, (struct pt_regs *)(regs->uregs+3));
	load_write_pc(regs->ARM_pc, regs);
}

enum uprobe_insn
uprobe_decode_ldmstm(uprobe_opcode_t insn, struct uprobe_probept_arch_info *ai)
{
	uprobe_insn_handler_t *handler = 0;
	unsigned reglist = insn & 0xffff;
	int is_ldm = insn & 0x100000;
	int rn = (insn >> 16) & 0xf;

	if (rn <= 12 && (reglist & 0xe000) == 0) {
		/* Instruction only uses registers in the range R0..R12 */
		handler = emulate_generic_r0_12_noflags;

	} else if (rn >= 2 && (reglist & 0x8003) == 0) {
		/* Instruction only uses registers in the range R2..R14 */
		rn -= 2;
		reglist >>= 2;
		handler = emulate_generic_r2_14_noflags;

	} else if (rn >= 3 && (reglist & 0x0007) == 0) {
		/* Instruction only uses registers in the range R3..R15 */
		if (is_ldm && (reglist & 0x8000)) {
			rn -= 3;
			reglist >>= 3;
			handler = emulate_ldm_r3_15;
		}
	}

	if (handler) {
		/* We can emulate the instruction in (possibly) modified form */
		ai->insn[0] = (insn & 0xfff00000) | (rn << 16) | reglist;
		ai->insn_handler = handler;
		return INSN_GOOD;
	}

	/* Fallback to slower simulation... */
	if (reglist & 0x8000)
		handler = is_ldm ? simulate_ldm1_pc : simulate_stm1_pc;
	else
		handler = simulate_ldm1stm1;
	ai->insn_handler = handler;
	return INSN_GOOD_NO_SLOT;
}

static void simulate_bbl(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	long iaddr = (long)p->vaddr;
	int disp  = branch_displacement(insn);

	if (insn & (1 << 24))
		regs->ARM_lr = iaddr + 4;

	regs->ARM_pc = iaddr + 8 + disp;
}

static void simulate_blx1(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	long iaddr = (long)p->vaddr;
	int disp = branch_displacement(insn);

	regs->ARM_lr = iaddr + 4;
	regs->ARM_pc = iaddr + 8 + disp + ((insn >> 23) & 0x2);
	regs->ARM_cpsr |= PSR_T_BIT;
}

static void simulate_blx2bx(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	int rm = insn & 0xf;
	long rmv = regs->uregs[rm];

	if (insn & (1 << 5))
		regs->ARM_lr = (long)p->vaddr + 4;

	regs->ARM_pc = rmv & ~0x1;
	regs->ARM_cpsr &= ~PSR_T_BIT;
	if (rmv & 0x1)
		regs->ARM_cpsr |= PSR_T_BIT;
}

static void simulate_mrs(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	int rd = (insn >> 12) & 0xf;
	unsigned long mask = 0xf8ff03df; /* Mask out execution state */
	regs->uregs[rd] = regs->ARM_cpsr & mask;
}

static void simulate_mov_ipsp(struct uprobe_probept *p, struct pt_regs *regs)
{
	regs->uregs[12] = regs->uregs[13];
}

static void
emulate_ldrdstrd(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	unsigned long pc = (unsigned long)p->vaddr + 8;
	int rt = (insn >> 12) & 0xf;
	int rn = (insn >> 16) & 0xf;
	int rm = insn & 0xf;

	register unsigned long rtv asm("r0") = regs->uregs[rt];
	register unsigned long rt2v asm("r1") = regs->uregs[rt+1];
	register unsigned long rnv asm("r2") = (rn == 15) ? pc
							  : regs->uregs[rn];
	register unsigned long rmv asm("r3") = regs->uregs[rm];

	__asm__ __volatile__ (
		BLX("%[fn]")
		: "=r" (rtv), "=r" (rt2v), "=r" (rnv)
		: "0" (rtv), "1" (rt2v), "2" (rnv), "r" (rmv),
		  [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	regs->uregs[rt] = rtv;
	regs->uregs[rt+1] = rt2v;
	if (is_writeback(insn))
		regs->uregs[rn] = rnv;
}

static void
emulate_ldr(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	unsigned long pc = (unsigned long)p->vaddr + 8;
	int rt = (insn >> 12) & 0xf;
	int rn = (insn >> 16) & 0xf;
	int rm = insn & 0xf;

	register unsigned long rtv asm("r0");
	register unsigned long rnv asm("r2") = (rn == 15) ? pc
							  : regs->uregs[rn];
	register unsigned long rmv asm("r3") = regs->uregs[rm];

	__asm__ __volatile__ (
		BLX("%[fn]")
		: "=r" (rtv), "=r" (rnv)
		: "1" (rnv), "r" (rmv), [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	if (rt == 15)
		load_write_pc(rtv, regs);
	else
		regs->uregs[rt] = rtv;

	if (is_writeback(insn))
		regs->uregs[rn] = rnv;
}

static void
emulate_str(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	unsigned long rtpc = (unsigned long)p->vaddr + str_pc_offset;
	unsigned long rnpc = (unsigned long)p->vaddr + 8;
	int rt = (insn >> 12) & 0xf;
	int rn = (insn >> 16) & 0xf;
	int rm = insn & 0xf;

	register unsigned long rtv asm("r0") = (rt == 15) ? rtpc
							  : regs->uregs[rt];
	register unsigned long rnv asm("r2") = (rn == 15) ? rnpc
							  : regs->uregs[rn];
	register unsigned long rmv asm("r3") = regs->uregs[rm];

	__asm__ __volatile__ (
		BLX("%[fn]")
		: "=r" (rnv)
		: "r" (rtv), "0" (rnv), "r" (rmv), [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	if (is_writeback(insn))
		regs->uregs[rn] = rnv;
}

static void
emulate_rd12rn16rm0rs8_rwflags(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	unsigned long pc = (unsigned long)p->vaddr + 8;
	int rd = (insn >> 12) & 0xf;
	int rn = (insn >> 16) & 0xf;
	int rm = insn & 0xf;
	int rs = (insn >> 8) & 0xf;

	register unsigned long rdv asm("r0") = regs->uregs[rd];
	register unsigned long rnv asm("r2") = (rn == 15) ? pc
							  : regs->uregs[rn];
	register unsigned long rmv asm("r3") = (rm == 15) ? pc
							  : regs->uregs[rm];
	register unsigned long rsv asm("r1") = regs->uregs[rs];
	unsigned long cpsr = regs->ARM_cpsr;

	__asm__ __volatile__ (
		"msr	cpsr_fs, %[cpsr]	\n\t"
		BLX("%[fn]")
		"mrs	%[cpsr], cpsr		\n\t"
		: "=r" (rdv), [cpsr] "=r" (cpsr)
		: "0" (rdv), "r" (rnv), "r" (rmv), "r" (rsv),
		  "1" (cpsr), [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	if (rd == 15)
		alu_write_pc(rdv, regs);
	else
		regs->uregs[rd] = rdv;
	regs->ARM_cpsr = (regs->ARM_cpsr & ~APSR_MASK) | (cpsr & APSR_MASK);
}

static void
emulate_rd12rn16rm0_rwflags_nopc(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	int rd = (insn >> 12) & 0xf;
	int rn = (insn >> 16) & 0xf;
	int rm = insn & 0xf;

	register unsigned long rdv asm("r0") = regs->uregs[rd];
	register unsigned long rnv asm("r2") = regs->uregs[rn];
	register unsigned long rmv asm("r3") = regs->uregs[rm];
	unsigned long cpsr = regs->ARM_cpsr;

	__asm__ __volatile__ (
		"msr	cpsr_fs, %[cpsr]	\n\t"
		BLX("%[fn]")
		"mrs	%[cpsr], cpsr		\n\t"
		: "=r" (rdv), [cpsr] "=r" (cpsr)
		: "0" (rdv), "r" (rnv), "r" (rmv),
		  "1" (cpsr), [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	regs->uregs[rd] = rdv;
	regs->ARM_cpsr = (regs->ARM_cpsr & ~APSR_MASK) | (cpsr & APSR_MASK);
}

static void
emulate_rd16rn12rm0rs8_rwflags_nopc(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	int rd = (insn >> 16) & 0xf;
	int rn = (insn >> 12) & 0xf;
	int rm = insn & 0xf;
	int rs = (insn >> 8) & 0xf;

	register unsigned long rdv asm("r2") = regs->uregs[rd];
	register unsigned long rnv asm("r0") = regs->uregs[rn];
	register unsigned long rmv asm("r3") = regs->uregs[rm];
	register unsigned long rsv asm("r1") = regs->uregs[rs];
	unsigned long cpsr = regs->ARM_cpsr;

	__asm__ __volatile__ (
		"msr	cpsr_fs, %[cpsr]	\n\t"
		BLX("%[fn]")
		"mrs	%[cpsr], cpsr		\n\t"
		: "=r" (rdv), [cpsr] "=r" (cpsr)
		: "0" (rdv), "r" (rnv), "r" (rmv), "r" (rsv),
		  "1" (cpsr), [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	regs->uregs[rd] = rdv;
	regs->ARM_cpsr = (regs->ARM_cpsr & ~APSR_MASK) | (cpsr & APSR_MASK);
}

static void
emulate_rd12rm0_noflags_nopc(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	int rd = (insn >> 12) & 0xf;
	int rm = insn & 0xf;

	register unsigned long rdv asm("r0") = regs->uregs[rd];
	register unsigned long rmv asm("r3") = regs->uregs[rm];

	__asm__ __volatile__ (
		BLX("%[fn]")
		: "=r" (rdv)
		: "0" (rdv), "r" (rmv), [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	regs->uregs[rd] = rdv;
}

static void
emulate_rdlo12rdhi16rn0rm8_rwflags_nopc(struct uprobe_probept *p, struct pt_regs *regs)
{
	uprobe_opcode_t insn = p->opcode;
	int rdlo = (insn >> 12) & 0xf;
	int rdhi = (insn >> 16) & 0xf;
	int rn = insn & 0xf;
	int rm = (insn >> 8) & 0xf;

	register unsigned long rdlov asm("r0") = regs->uregs[rdlo];
	register unsigned long rdhiv asm("r2") = regs->uregs[rdhi];
	register unsigned long rnv asm("r3") = regs->uregs[rn];
	register unsigned long rmv asm("r1") = regs->uregs[rm];
	unsigned long cpsr = regs->ARM_cpsr;

	__asm__ __volatile__ (
		"msr	cpsr_fs, %[cpsr]	\n\t"
		BLX("%[fn]")
		"mrs	%[cpsr], cpsr		\n\t"
		: "=r" (rdlov), "=r" (rdhiv), [cpsr] "=r" (cpsr)
		: "0" (rdlov), "1" (rdhiv), "r" (rnv), "r" (rmv),
		  "2" (cpsr), [fn] "r" (p->arch_info.insn_fn)
		: "lr", "memory", "cc"
	);

	regs->uregs[rdlo] = rdlov;
	regs->uregs[rdhi] = rdhiv;
	regs->ARM_cpsr = (regs->ARM_cpsr & ~APSR_MASK) | (cpsr & APSR_MASK);
}

/*
 * For the instruction masking and comparisons in all the "space_*"
 * functions below, Do _not_ rearrange the order of tests unless
 * you're very, very sure of what you are doing.  For the sake of
 * efficiency, the masks for some tests sometimes assume other test
 * have been done prior to them so the number of patterns to test
 * for an instruction set can be as broad as possible to reduce the
 * number of tests needed.
 */

static const union decode_item arm_1111_table[] = {
	/* Unconditional instructions					*/

	/* memory hint		1111 0100 x001 xxxx xxxx xxxx xxxx xxxx */
	/* PLDI (immediate)	1111 0100 x101 xxxx xxxx xxxx xxxx xxxx */
	/* PLDW (immediate)	1111 0101 x001 xxxx xxxx xxxx xxxx xxxx */
	/* PLD (immediate)	1111 0101 x101 xxxx xxxx xxxx xxxx xxxx */
	DECODE_SIMULATE	(0xfe300000, 0xf4100000, uprobe_simulate_nop),

	/* memory hint		1111 0110 x001 xxxx xxxx xxxx xxx0 xxxx */
	/* PLDI (register)	1111 0110 x101 xxxx xxxx xxxx xxx0 xxxx */
	/* PLDW (register)	1111 0111 x001 xxxx xxxx xxxx xxx0 xxxx */
	/* PLD (register)	1111 0111 x101 xxxx xxxx xxxx xxx0 xxxx */
	DECODE_SIMULATE	(0xfe300010, 0xf6100000, uprobe_simulate_nop),

	/* BLX (immediate)	1111 101x xxxx xxxx xxxx xxxx xxxx xxxx */
	DECODE_SIMULATE	(0xfe000000, 0xfa000000, simulate_blx1),

	/* CPS			1111 0001 0000 xxx0 xxxx xxxx xx0x xxxx */
	/* SETEND		1111 0001 0000 0001 xxxx xxxx 0000 xxxx */
	/* SRS			1111 100x x1x0 xxxx xxxx xxxx xxxx xxxx */
	/* RFE			1111 100x x0x1 xxxx xxxx xxxx xxxx xxxx */

	/* Coprocessor instructions... */
	/* MCRR2		1111 1100 0100 xxxx xxxx xxxx xxxx xxxx */
	/* MRRC2		1111 1100 0101 xxxx xxxx xxxx xxxx xxxx */
	/* LDC2			1111 110x xxx1 xxxx xxxx xxxx xxxx xxxx */
	/* STC2			1111 110x xxx0 xxxx xxxx xxxx xxxx xxxx */
	/* CDP2			1111 1110 xxxx xxxx xxxx xxxx xxx0 xxxx */
	/* MCR2			1111 1110 xxx0 xxxx xxxx xxxx xxx1 xxxx */
	/* MRC2			1111 1110 xxx1 xxxx xxxx xxxx xxx1 xxxx */

	/* Other unallocated instructions...				*/
	DECODE_END
};

static const union decode_item arm_cccc_0001_0xx0____0xxx_table[] = {
	/* Miscellaneous instructions					*/

	/* MRS cpsr		cccc 0001 0000 xxxx xxxx xxxx 0000 xxxx */
	DECODE_SIMULATEX(0x0ff000f0, 0x01000000, simulate_mrs,
						 REGS(0, NOPC, 0, 0, 0)),

	/* BX			cccc 0001 0010 xxxx xxxx xxxx 0001 xxxx */
	DECODE_SIMULATE	(0x0ff000f0, 0x01200010, simulate_blx2bx),

	/* BLX (register)	cccc 0001 0010 xxxx xxxx xxxx 0011 xxxx */
	DECODE_SIMULATEX(0x0ff000f0, 0x01200030, simulate_blx2bx,
						 REGS(0, 0, 0, 0, NOPC)),

	/* CLZ			cccc 0001 0110 xxxx xxxx xxxx 0001 xxxx */
	DECODE_EMULATEX	(0x0ff000f0, 0x01600010, emulate_rd12rm0_noflags_nopc,
						 REGS(0, NOPC, 0, 0, NOPC)),

	/* QADD			cccc 0001 0000 xxxx xxxx xxxx 0101 xxxx */
	/* QSUB			cccc 0001 0010 xxxx xxxx xxxx 0101 xxxx */
	/* QDADD		cccc 0001 0100 xxxx xxxx xxxx 0101 xxxx */
	/* QDSUB		cccc 0001 0110 xxxx xxxx xxxx 0101 xxxx */
	DECODE_EMULATEX	(0x0f9000f0, 0x01000050, emulate_rd12rn16rm0_rwflags_nopc,
						 REGS(NOPC, NOPC, 0, 0, NOPC)),

	/* BXJ			cccc 0001 0010 xxxx xxxx xxxx 0010 xxxx */
	/* MSR			cccc 0001 0x10 xxxx xxxx xxxx 0000 xxxx */
	/* MRS spsr		cccc 0001 0100 xxxx xxxx xxxx 0000 xxxx */
	/* BKPT			1110 0001 0010 xxxx xxxx xxxx 0111 xxxx */
	/* SMC			cccc 0001 0110 xxxx xxxx xxxx 0111 xxxx */
	/* And unallocated instructions...				*/
	DECODE_END
};

static const union decode_item arm_cccc_0001_0xx0____1xx0_table[] = {
	/* Halfword multiply and multiply-accumulate			*/

	/* SMLALxy		cccc 0001 0100 xxxx xxxx xxxx 1xx0 xxxx */
	DECODE_EMULATEX	(0x0ff00090, 0x01400080, emulate_rdlo12rdhi16rn0rm8_rwflags_nopc,
						 REGS(NOPC, NOPC, NOPC, 0, NOPC)),

	/* SMULWy		cccc 0001 0010 xxxx xxxx xxxx 1x10 xxxx */
	DECODE_OR	(0x0ff000b0, 0x012000a0),
	/* SMULxy		cccc 0001 0110 xxxx xxxx xxxx 1xx0 xxxx */
	DECODE_EMULATEX	(0x0ff00090, 0x01600080, emulate_rd16rn12rm0rs8_rwflags_nopc,
						 REGS(NOPC, 0, NOPC, 0, NOPC)),

	/* SMLAxy		cccc 0001 0000 xxxx xxxx xxxx 1xx0 xxxx */
	DECODE_OR	(0x0ff00090, 0x01000080),
	/* SMLAWy		cccc 0001 0010 xxxx xxxx xxxx 1x00 xxxx */
	DECODE_EMULATEX	(0x0ff000b0, 0x01200080, emulate_rd16rn12rm0rs8_rwflags_nopc,
						 REGS(NOPC, NOPC, NOPC, 0, NOPC)),

	DECODE_END
};

static const union decode_item arm_cccc_0000_____1001_table[] = {
	/* Multiply and multiply-accumulate				*/

	/* MUL			cccc 0000 0000 xxxx xxxx xxxx 1001 xxxx */
	/* MULS			cccc 0000 0001 xxxx xxxx xxxx 1001 xxxx */
	DECODE_EMULATEX	(0x0fe000f0, 0x00000090, emulate_rd16rn12rm0rs8_rwflags_nopc,
						 REGS(NOPC, 0, NOPC, 0, NOPC)),

	/* MLA			cccc 0000 0010 xxxx xxxx xxxx 1001 xxxx */
	/* MLAS			cccc 0000 0011 xxxx xxxx xxxx 1001 xxxx */
	DECODE_OR	(0x0fe000f0, 0x00200090),
	/* MLS			cccc 0000 0110 xxxx xxxx xxxx 1001 xxxx */
	DECODE_EMULATEX	(0x0ff000f0, 0x00600090, emulate_rd16rn12rm0rs8_rwflags_nopc,
						 REGS(NOPC, NOPC, NOPC, 0, NOPC)),

	/* UMAAL		cccc 0000 0100 xxxx xxxx xxxx 1001 xxxx */
	DECODE_OR	(0x0ff000f0, 0x00400090),
	/* UMULL		cccc 0000 1000 xxxx xxxx xxxx 1001 xxxx */
	/* UMULLS		cccc 0000 1001 xxxx xxxx xxxx 1001 xxxx */
	/* UMLAL		cccc 0000 1010 xxxx xxxx xxxx 1001 xxxx */
	/* UMLALS		cccc 0000 1011 xxxx xxxx xxxx 1001 xxxx */
	/* SMULL		cccc 0000 1100 xxxx xxxx xxxx 1001 xxxx */
	/* SMULLS		cccc 0000 1101 xxxx xxxx xxxx 1001 xxxx */
	/* SMLAL		cccc 0000 1110 xxxx xxxx xxxx 1001 xxxx */
	/* SMLALS		cccc 0000 1111 xxxx xxxx xxxx 1001 xxxx */
	DECODE_EMULATEX	(0x0f8000f0, 0x00800090, emulate_rdlo12rdhi16rn0rm8_rwflags_nopc,
						 REGS(NOPC, NOPC, NOPC, 0, NOPC)),

	DECODE_END
};

static const union decode_item arm_cccc_0001_____1001_table[] = {
	/* Synchronization primitives					*/

	/* SMP/SWPB		cccc 0001 0x00 xxxx xxxx xxxx 1001 xxxx */
	DECODE_EMULATEX	(0x0fb000f0, 0x01000090, emulate_rd12rn16rm0_rwflags_nopc,
						 REGS(NOPC, NOPC, 0, 0, NOPC)),

	/* LDREX/STREX{,D,B,H}	cccc 0001 1xxx xxxx xxxx xxxx 1001 xxxx */
	/* And unallocated instructions...				*/
	DECODE_END
};

static const union decode_item arm_cccc_000x_____1xx1_table[] = {
	/* Extra load/store instructions				*/

	/* STRHT		cccc 0000 xx10 xxxx xxxx xxxx 1011 xxxx */
	/* ???			cccc 0000 xx10 xxxx xxxx xxxx 11x1 xxxx */
	/* LDRHT		cccc 0000 xx11 xxxx xxxx xxxx 1011 xxxx */
	/* LDRSBT		cccc 0000 xx11 xxxx xxxx xxxx 1101 xxxx */
	/* LDRSHT		cccc 0000 xx11 xxxx xxxx xxxx 1111 xxxx */
	DECODE_REJECT	(0x0f200090, 0x00200090),

	/* LDRD/STRD lr,pc,{...	cccc 000x x0x0 xxxx 111x xxxx 1101 xxxx */
	DECODE_REJECT	(0x0e10e0d0, 0x0000e0d0),

	/* LDRD (register)	cccc 000x x0x0 xxxx xxxx xxxx 1101 xxxx */
	/* STRD (register)	cccc 000x x0x0 xxxx xxxx xxxx 1111 xxxx */
	DECODE_EMULATEX	(0x0e5000d0, 0x000000d0, emulate_ldrdstrd,
						 REGS(NOPCWB, NOPCX, 0, 0, NOPC)),

	/* LDRD (immediate)	cccc 000x x1x0 xxxx xxxx xxxx 1101 xxxx */
	/* STRD (immediate)	cccc 000x x1x0 xxxx xxxx xxxx 1111 xxxx */
	DECODE_EMULATEX	(0x0e5000d0, 0x004000d0, emulate_ldrdstrd,
						 REGS(NOPCWB, NOPCX, 0, 0, 0)),

	/* STRH (register)	cccc 000x x0x0 xxxx xxxx xxxx 1011 xxxx */
	DECODE_EMULATEX	(0x0e5000f0, 0x000000b0, emulate_str,
						 REGS(NOPCWB, NOPC, 0, 0, NOPC)),

	/* LDRH (register)	cccc 000x x0x1 xxxx xxxx xxxx 1011 xxxx */
	/* LDRSB (register)	cccc 000x x0x1 xxxx xxxx xxxx 1101 xxxx */
	/* LDRSH (register)	cccc 000x x0x1 xxxx xxxx xxxx 1111 xxxx */
	DECODE_EMULATEX	(0x0e500090, 0x00100090, emulate_ldr,
						 REGS(NOPCWB, NOPC, 0, 0, NOPC)),

	/* STRH (immediate)	cccc 000x x1x0 xxxx xxxx xxxx 1011 xxxx */
	DECODE_EMULATEX	(0x0e5000f0, 0x004000b0, emulate_str,
						 REGS(NOPCWB, NOPC, 0, 0, 0)),

	/* LDRH (immediate)	cccc 000x x1x1 xxxx xxxx xxxx 1011 xxxx */
	/* LDRSB (immediate)	cccc 000x x1x1 xxxx xxxx xxxx 1101 xxxx */
	/* LDRSH (immediate)	cccc 000x x1x1 xxxx xxxx xxxx 1111 xxxx */
	DECODE_EMULATEX	(0x0e500090, 0x00500090, emulate_ldr,
						 REGS(NOPCWB, NOPC, 0, 0, 0)),

	DECODE_END
};

static const union decode_item arm_cccc_000x_table[] = {
	/* Data-processing (register)					*/

	/* <op>S PC, ...	cccc 000x xxx1 xxxx 1111 xxxx xxxx xxxx */
	DECODE_REJECT	(0x0e10f000, 0x0010f000),

	/* MOV IP, SP		1110 0001 1010 0000 1100 0000 0000 1101 */
	DECODE_SIMULATE	(0xffffffff, 0xe1a0c00d, simulate_mov_ipsp),

	/* TST (register)	cccc 0001 0001 xxxx xxxx xxxx xxx0 xxxx */
	/* TEQ (register)	cccc 0001 0011 xxxx xxxx xxxx xxx0 xxxx */
	/* CMP (register)	cccc 0001 0101 xxxx xxxx xxxx xxx0 xxxx */
	/* CMN (register)	cccc 0001 0111 xxxx xxxx xxxx xxx0 xxxx */
	DECODE_EMULATEX	(0x0f900010, 0x01100000, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(ANY, 0, 0, 0, ANY)),

	/* MOV (register)	cccc 0001 101x xxxx xxxx xxxx xxx0 xxxx */
	/* MVN (register)	cccc 0001 111x xxxx xxxx xxxx xxx0 xxxx */
	DECODE_EMULATEX	(0x0fa00010, 0x01a00000, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(0, ANY, 0, 0, ANY)),

	/* AND (register)	cccc 0000 000x xxxx xxxx xxxx xxx0 xxxx */
	/* EOR (register)	cccc 0000 001x xxxx xxxx xxxx xxx0 xxxx */
	/* SUB (register)	cccc 0000 010x xxxx xxxx xxxx xxx0 xxxx */
	/* RSB (register)	cccc 0000 011x xxxx xxxx xxxx xxx0 xxxx */
	/* ADD (register)	cccc 0000 100x xxxx xxxx xxxx xxx0 xxxx */
	/* ADC (register)	cccc 0000 101x xxxx xxxx xxxx xxx0 xxxx */
	/* SBC (register)	cccc 0000 110x xxxx xxxx xxxx xxx0 xxxx */
	/* RSC (register)	cccc 0000 111x xxxx xxxx xxxx xxx0 xxxx */
	/* ORR (register)	cccc 0001 100x xxxx xxxx xxxx xxx0 xxxx */
	/* BIC (register)	cccc 0001 110x xxxx xxxx xxxx xxx0 xxxx */
	DECODE_EMULATEX	(0x0e000010, 0x00000000, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(ANY, ANY, 0, 0, ANY)),

	/* TST (reg-shift reg)	cccc 0001 0001 xxxx xxxx xxxx 0xx1 xxxx */
	/* TEQ (reg-shift reg)	cccc 0001 0011 xxxx xxxx xxxx 0xx1 xxxx */
	/* CMP (reg-shift reg)	cccc 0001 0101 xxxx xxxx xxxx 0xx1 xxxx */
	/* CMN (reg-shift reg)	cccc 0001 0111 xxxx xxxx xxxx 0xx1 xxxx */
	DECODE_EMULATEX	(0x0f900090, 0x01100010, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(ANY, 0, NOPC, 0, ANY)),

	/* MOV (reg-shift reg)	cccc 0001 101x xxxx xxxx xxxx 0xx1 xxxx */
	/* MVN (reg-shift reg)	cccc 0001 111x xxxx xxxx xxxx 0xx1 xxxx */
	DECODE_EMULATEX	(0x0fa00090, 0x01a00010, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(0, ANY, NOPC, 0, ANY)),

	/* AND (reg-shift reg)	cccc 0000 000x xxxx xxxx xxxx 0xx1 xxxx */
	/* EOR (reg-shift reg)	cccc 0000 001x xxxx xxxx xxxx 0xx1 xxxx */
	/* SUB (reg-shift reg)	cccc 0000 010x xxxx xxxx xxxx 0xx1 xxxx */
	/* RSB (reg-shift reg)	cccc 0000 011x xxxx xxxx xxxx 0xx1 xxxx */
	/* ADD (reg-shift reg)	cccc 0000 100x xxxx xxxx xxxx 0xx1 xxxx */
	/* ADC (reg-shift reg)	cccc 0000 101x xxxx xxxx xxxx 0xx1 xxxx */
	/* SBC (reg-shift reg)	cccc 0000 110x xxxx xxxx xxxx 0xx1 xxxx */
	/* RSC (reg-shift reg)	cccc 0000 111x xxxx xxxx xxxx 0xx1 xxxx */
	/* ORR (reg-shift reg)	cccc 0001 100x xxxx xxxx xxxx 0xx1 xxxx */
	/* BIC (reg-shift reg)	cccc 0001 110x xxxx xxxx xxxx 0xx1 xxxx */
	DECODE_EMULATEX	(0x0e000090, 0x00000010, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(ANY, ANY, NOPC, 0, ANY)),

	DECODE_END
};

static const union decode_item arm_cccc_001x_table[] = {
	/* Data-processing (immediate)					*/

	/* MOVW			cccc 0011 0000 xxxx xxxx xxxx xxxx xxxx */
	/* MOVT			cccc 0011 0100 xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0fb00000, 0x03000000, emulate_rd12rm0_noflags_nopc,
						 REGS(0, NOPC, 0, 0, 0)),

	/* YIELD		cccc 0011 0010 0000 xxxx xxxx 0000 0001 */
	DECODE_OR	(0x0fff00ff, 0x03200001),
	/* SEV			cccc 0011 0010 0000 xxxx xxxx 0000 0100 */
	DECODE_EMULATE	(0x0fff00ff, 0x03200004, uprobe_emulate_none),
	/* NOP			cccc 0011 0010 0000 xxxx xxxx 0000 0000 */
	/* WFE			cccc 0011 0010 0000 xxxx xxxx 0000 0010 */
	/* WFI			cccc 0011 0010 0000 xxxx xxxx 0000 0011 */
	DECODE_SIMULATE	(0x0fff00fc, 0x03200000, uprobe_simulate_nop),
	/* DBG			cccc 0011 0010 0000 xxxx xxxx ffff xxxx */
	/* unallocated hints	cccc 0011 0010 0000 xxxx xxxx xxxx xxxx */
	/* MSR (immediate)	cccc 0011 0x10 xxxx xxxx xxxx xxxx xxxx */
	DECODE_REJECT	(0x0fb00000, 0x03200000),

	/* <op>S PC, ...	cccc 001x xxx1 xxxx 1111 xxxx xxxx xxxx */
	DECODE_REJECT	(0x0e10f000, 0x0210f000),

	/* TST (immediate)	cccc 0011 0001 xxxx xxxx xxxx xxxx xxxx */
	/* TEQ (immediate)	cccc 0011 0011 xxxx xxxx xxxx xxxx xxxx */
	/* CMP (immediate)	cccc 0011 0101 xxxx xxxx xxxx xxxx xxxx */
	/* CMN (immediate)	cccc 0011 0111 xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0f900000, 0x03100000, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(ANY, 0, 0, 0, 0)),

	/* MOV (immediate)	cccc 0011 101x xxxx xxxx xxxx xxxx xxxx */
	/* MVN (immediate)	cccc 0011 111x xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0fa00000, 0x03a00000, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(0, ANY, 0, 0, 0)),

	/* AND (immediate)	cccc 0010 000x xxxx xxxx xxxx xxxx xxxx */
	/* EOR (immediate)	cccc 0010 001x xxxx xxxx xxxx xxxx xxxx */
	/* SUB (immediate)	cccc 0010 010x xxxx xxxx xxxx xxxx xxxx */
	/* RSB (immediate)	cccc 0010 011x xxxx xxxx xxxx xxxx xxxx */
	/* ADD (immediate)	cccc 0010 100x xxxx xxxx xxxx xxxx xxxx */
	/* ADC (immediate)	cccc 0010 101x xxxx xxxx xxxx xxxx xxxx */
	/* SBC (immediate)	cccc 0010 110x xxxx xxxx xxxx xxxx xxxx */
	/* RSC (immediate)	cccc 0010 111x xxxx xxxx xxxx xxxx xxxx */
	/* ORR (immediate)	cccc 0011 100x xxxx xxxx xxxx xxxx xxxx */
	/* BIC (immediate)	cccc 0011 110x xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0e000000, 0x02000000, emulate_rd12rn16rm0rs8_rwflags,
						 REGS(ANY, ANY, 0, 0, 0)),

	DECODE_END
};

static const union decode_item arm_cccc_0110_____xxx1_table[] = {
	/* Media instructions						*/

	/* SEL			cccc 0110 1000 xxxx xxxx xxxx 1011 xxxx */
	DECODE_EMULATEX	(0x0ff000f0, 0x068000b0, emulate_rd12rn16rm0_rwflags_nopc,
						 REGS(NOPC, NOPC, 0, 0, NOPC)),

	/* SSAT			cccc 0110 101x xxxx xxxx xxxx xx01 xxxx */
	/* USAT			cccc 0110 111x xxxx xxxx xxxx xx01 xxxx */
	DECODE_OR(0x0fa00030, 0x06a00010),
	/* SSAT16		cccc 0110 1010 xxxx xxxx xxxx 0011 xxxx */
	/* USAT16		cccc 0110 1110 xxxx xxxx xxxx 0011 xxxx */
	DECODE_EMULATEX	(0x0fb000f0, 0x06a00030, emulate_rd12rn16rm0_rwflags_nopc,
						 REGS(0, NOPC, 0, 0, NOPC)),

	/* REV			cccc 0110 1011 xxxx xxxx xxxx 0011 xxxx */
	/* REV16		cccc 0110 1011 xxxx xxxx xxxx 1011 xxxx */
	/* RBIT			cccc 0110 1111 xxxx xxxx xxxx 0011 xxxx */
	/* REVSH		cccc 0110 1111 xxxx xxxx xxxx 1011 xxxx */
	DECODE_EMULATEX	(0x0fb00070, 0x06b00030, emulate_rd12rm0_noflags_nopc,
						 REGS(0, NOPC, 0, 0, NOPC)),

	/* ???			cccc 0110 0x00 xxxx xxxx xxxx xxx1 xxxx */
	DECODE_REJECT	(0x0fb00010, 0x06000010),
	/* ???			cccc 0110 0xxx xxxx xxxx xxxx 1011 xxxx */
	DECODE_REJECT	(0x0f8000f0, 0x060000b0),
	/* ???			cccc 0110 0xxx xxxx xxxx xxxx 1101 xxxx */
	DECODE_REJECT	(0x0f8000f0, 0x060000d0),
	/* SADD16		cccc 0110 0001 xxxx xxxx xxxx 0001 xxxx */
	/* SADDSUBX		cccc 0110 0001 xxxx xxxx xxxx 0011 xxxx */
	/* SSUBADDX		cccc 0110 0001 xxxx xxxx xxxx 0101 xxxx */
	/* SSUB16		cccc 0110 0001 xxxx xxxx xxxx 0111 xxxx */
	/* SADD8		cccc 0110 0001 xxxx xxxx xxxx 1001 xxxx */
	/* SSUB8		cccc 0110 0001 xxxx xxxx xxxx 1111 xxxx */
	/* QADD16		cccc 0110 0010 xxxx xxxx xxxx 0001 xxxx */
	/* QADDSUBX		cccc 0110 0010 xxxx xxxx xxxx 0011 xxxx */
	/* QSUBADDX		cccc 0110 0010 xxxx xxxx xxxx 0101 xxxx */
	/* QSUB16		cccc 0110 0010 xxxx xxxx xxxx 0111 xxxx */
	/* QADD8		cccc 0110 0010 xxxx xxxx xxxx 1001 xxxx */
	/* QSUB8		cccc 0110 0010 xxxx xxxx xxxx 1111 xxxx */
	/* SHADD16		cccc 0110 0011 xxxx xxxx xxxx 0001 xxxx */
	/* SHADDSUBX		cccc 0110 0011 xxxx xxxx xxxx 0011 xxxx */
	/* SHSUBADDX		cccc 0110 0011 xxxx xxxx xxxx 0101 xxxx */
	/* SHSUB16		cccc 0110 0011 xxxx xxxx xxxx 0111 xxxx */
	/* SHADD8		cccc 0110 0011 xxxx xxxx xxxx 1001 xxxx */
	/* SHSUB8		cccc 0110 0011 xxxx xxxx xxxx 1111 xxxx */
	/* UADD16		cccc 0110 0101 xxxx xxxx xxxx 0001 xxxx */
	/* UADDSUBX		cccc 0110 0101 xxxx xxxx xxxx 0011 xxxx */
	/* USUBADDX		cccc 0110 0101 xxxx xxxx xxxx 0101 xxxx */
	/* USUB16		cccc 0110 0101 xxxx xxxx xxxx 0111 xxxx */
	/* UADD8		cccc 0110 0101 xxxx xxxx xxxx 1001 xxxx */
	/* USUB8		cccc 0110 0101 xxxx xxxx xxxx 1111 xxxx */
	/* UQADD16		cccc 0110 0110 xxxx xxxx xxxx 0001 xxxx */
	/* UQADDSUBX		cccc 0110 0110 xxxx xxxx xxxx 0011 xxxx */
	/* UQSUBADDX		cccc 0110 0110 xxxx xxxx xxxx 0101 xxxx */
	/* UQSUB16		cccc 0110 0110 xxxx xxxx xxxx 0111 xxxx */
	/* UQADD8		cccc 0110 0110 xxxx xxxx xxxx 1001 xxxx */
	/* UQSUB8		cccc 0110 0110 xxxx xxxx xxxx 1111 xxxx */
	/* UHADD16		cccc 0110 0111 xxxx xxxx xxxx 0001 xxxx */
	/* UHADDSUBX		cccc 0110 0111 xxxx xxxx xxxx 0011 xxxx */
	/* UHSUBADDX		cccc 0110 0111 xxxx xxxx xxxx 0101 xxxx */
	/* UHSUB16		cccc 0110 0111 xxxx xxxx xxxx 0111 xxxx */
	/* UHADD8		cccc 0110 0111 xxxx xxxx xxxx 1001 xxxx */
	/* UHSUB8		cccc 0110 0111 xxxx xxxx xxxx 1111 xxxx */
	DECODE_EMULATEX	(0x0f800010, 0x06000010, emulate_rd12rn16rm0_rwflags_nopc,
						 REGS(NOPC, NOPC, 0, 0, NOPC)),

	/* PKHBT		cccc 0110 1000 xxxx xxxx xxxx x001 xxxx */
	/* PKHTB		cccc 0110 1000 xxxx xxxx xxxx x101 xxxx */
	DECODE_EMULATEX	(0x0ff00030, 0x06800010, emulate_rd12rn16rm0_rwflags_nopc,
						 REGS(NOPC, NOPC, 0, 0, NOPC)),

	/* ???			cccc 0110 1001 xxxx xxxx xxxx 0111 xxxx */
	/* ???			cccc 0110 1101 xxxx xxxx xxxx 0111 xxxx */
	DECODE_REJECT	(0x0fb000f0, 0x06900070),

	/* SXTB16		cccc 0110 1000 1111 xxxx xxxx 0111 xxxx */
	/* SXTB			cccc 0110 1010 1111 xxxx xxxx 0111 xxxx */
	/* SXTH			cccc 0110 1011 1111 xxxx xxxx 0111 xxxx */
	/* UXTB16		cccc 0110 1100 1111 xxxx xxxx 0111 xxxx */
	/* UXTB			cccc 0110 1110 1111 xxxx xxxx 0111 xxxx */
	/* UXTH			cccc 0110 1111 1111 xxxx xxxx 0111 xxxx */
	DECODE_EMULATEX	(0x0f8f00f0, 0x068f0070, emulate_rd12rm0_noflags_nopc,
						 REGS(0, NOPC, 0, 0, NOPC)),

	/* SXTAB16		cccc 0110 1000 xxxx xxxx xxxx 0111 xxxx */
	/* SXTAB		cccc 0110 1010 xxxx xxxx xxxx 0111 xxxx */
	/* SXTAH		cccc 0110 1011 xxxx xxxx xxxx 0111 xxxx */
	/* UXTAB16		cccc 0110 1100 xxxx xxxx xxxx 0111 xxxx */
	/* UXTAB		cccc 0110 1110 xxxx xxxx xxxx 0111 xxxx */
	/* UXTAH		cccc 0110 1111 xxxx xxxx xxxx 0111 xxxx */
	DECODE_EMULATEX	(0x0f8000f0, 0x06800070, emulate_rd12rn16rm0_rwflags_nopc,
						 REGS(NOPCX, NOPC, 0, 0, NOPC)),

	DECODE_END
};

static const union decode_item arm_cccc_0111_____xxx1_table[] = {
	/* Media instructions						*/

	/* UNDEFINED		cccc 0111 1111 xxxx xxxx xxxx 1111 xxxx */
	DECODE_REJECT	(0x0ff000f0, 0x07f000f0),

	/* SMLALD		cccc 0111 0100 xxxx xxxx xxxx 00x1 xxxx */
	/* SMLSLD		cccc 0111 0100 xxxx xxxx xxxx 01x1 xxxx */
	DECODE_EMULATEX	(0x0ff00090, 0x07400010, emulate_rdlo12rdhi16rn0rm8_rwflags_nopc,
						 REGS(NOPC, NOPC, NOPC, 0, NOPC)),

	/* SMUAD		cccc 0111 0000 xxxx 1111 xxxx 00x1 xxxx */
	/* SMUSD		cccc 0111 0000 xxxx 1111 xxxx 01x1 xxxx */
	DECODE_OR	(0x0ff0f090, 0x0700f010),
	/* SMMUL		cccc 0111 0101 xxxx 1111 xxxx 00x1 xxxx */
	DECODE_OR	(0x0ff0f0d0, 0x0750f010),
	/* USAD8		cccc 0111 1000 xxxx 1111 xxxx 0001 xxxx */
	DECODE_EMULATEX	(0x0ff0f0f0, 0x0780f010, emulate_rd16rn12rm0rs8_rwflags_nopc,
						 REGS(NOPC, 0, NOPC, 0, NOPC)),

	/* SMLAD		cccc 0111 0000 xxxx xxxx xxxx 00x1 xxxx */
	/* SMLSD		cccc 0111 0000 xxxx xxxx xxxx 01x1 xxxx */
	DECODE_OR	(0x0ff00090, 0x07000010),
	/* SMMLA		cccc 0111 0101 xxxx xxxx xxxx 00x1 xxxx */
	DECODE_OR	(0x0ff000d0, 0x07500010),
	/* USADA8		cccc 0111 1000 xxxx xxxx xxxx 0001 xxxx */
	DECODE_EMULATEX	(0x0ff000f0, 0x07800010, emulate_rd16rn12rm0rs8_rwflags_nopc,
						 REGS(NOPC, NOPCX, NOPC, 0, NOPC)),

	/* SMMLS		cccc 0111 0101 xxxx xxxx xxxx 11x1 xxxx */
	DECODE_EMULATEX	(0x0ff000d0, 0x075000d0, emulate_rd16rn12rm0rs8_rwflags_nopc,
						 REGS(NOPC, NOPC, NOPC, 0, NOPC)),

	/* SBFX			cccc 0111 101x xxxx xxxx xxxx x101 xxxx */
	/* UBFX			cccc 0111 111x xxxx xxxx xxxx x101 xxxx */
	DECODE_EMULATEX	(0x0fa00070, 0x07a00050, emulate_rd12rm0_noflags_nopc,
						 REGS(0, NOPC, 0, 0, NOPC)),

	/* BFC			cccc 0111 110x xxxx xxxx xxxx x001 1111 */
	DECODE_EMULATEX	(0x0fe0007f, 0x07c0001f, emulate_rd12rm0_noflags_nopc,
						 REGS(0, NOPC, 0, 0, 0)),

	/* BFI			cccc 0111 110x xxxx xxxx xxxx x001 xxxx */
	DECODE_EMULATEX	(0x0fe00070, 0x07c00010, emulate_rd12rm0_noflags_nopc,
						 REGS(0, NOPC, 0, 0, NOPCX)),

	DECODE_END
};

static const union decode_item arm_cccc_01xx_table[] = {
	/* Load/store word and unsigned byte				*/

	/* LDRB/STRB pc,[...]	cccc 01xx x0xx xxxx xxxx xxxx xxxx xxxx */
	DECODE_REJECT	(0x0c40f000, 0x0440f000),

	/* STRT			cccc 01x0 x010 xxxx xxxx xxxx xxxx xxxx */
	/* LDRT			cccc 01x0 x011 xxxx xxxx xxxx xxxx xxxx */
	/* STRBT		cccc 01x0 x110 xxxx xxxx xxxx xxxx xxxx */
	/* LDRBT		cccc 01x0 x111 xxxx xxxx xxxx xxxx xxxx */
	DECODE_REJECT	(0x0d200000, 0x04200000),

	/* STR (immediate)	cccc 010x x0x0 xxxx xxxx xxxx xxxx xxxx */
	/* STRB (immediate)	cccc 010x x1x0 xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0e100000, 0x04000000, emulate_str,
						 REGS(NOPCWB, ANY, 0, 0, 0)),

	/* LDR (immediate)	cccc 010x x0x1 xxxx xxxx xxxx xxxx xxxx */
	/* LDRB (immediate)	cccc 010x x1x1 xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0e100000, 0x04100000, emulate_ldr,
						 REGS(NOPCWB, ANY, 0, 0, 0)),

	/* STR (register)	cccc 011x x0x0 xxxx xxxx xxxx xxxx xxxx */
	/* STRB (register)	cccc 011x x1x0 xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0e100000, 0x06000000, emulate_str,
						 REGS(NOPCWB, ANY, 0, 0, NOPC)),

	/* LDR (register)	cccc 011x x0x1 xxxx xxxx xxxx xxxx xxxx */
	/* LDRB (register)	cccc 011x x1x1 xxxx xxxx xxxx xxxx xxxx */
	DECODE_EMULATEX	(0x0e100000, 0x06100000, emulate_ldr,
						 REGS(NOPCWB, ANY, 0, 0, NOPC)),

	DECODE_END
};

static const union decode_item arm_cccc_100x_table[] = {
	/* Block data transfer instructions				*/

	/* LDM			cccc 100x x0x1 xxxx xxxx xxxx xxxx xxxx */
	/* STM			cccc 100x x0x0 xxxx xxxx xxxx xxxx xxxx */
	DECODE_CUSTOM	(0x0e400000, 0x08000000, uprobe_decode_ldmstm),

	/* STM (user registers)	cccc 100x x1x0 xxxx xxxx xxxx xxxx xxxx */
	/* LDM (user registers)	cccc 100x x1x1 xxxx 0xxx xxxx xxxx xxxx */
	/* LDM (exception ret)	cccc 100x x1x1 xxxx 1xxx xxxx xxxx xxxx */
	DECODE_END
};

const union decode_item uprobe_decode_arm_table[] = {
	/*
	 * Unconditional instructions
	 *			1111 xxxx xxxx xxxx xxxx xxxx xxxx xxxx
	 */
	DECODE_TABLE	(0xf0000000, 0xf0000000, arm_1111_table),

	/*
	 * Miscellaneous instructions
	 *			cccc 0001 0xx0 xxxx xxxx xxxx 0xxx xxxx
	 */
	DECODE_TABLE	(0x0f900080, 0x01000000, arm_cccc_0001_0xx0____0xxx_table),

	/*
	 * Halfword multiply and multiply-accumulate
	 *			cccc 0001 0xx0 xxxx xxxx xxxx 1xx0 xxxx
	 */
	DECODE_TABLE	(0x0f900090, 0x01000080, arm_cccc_0001_0xx0____1xx0_table),

	/*
	 * Multiply and multiply-accumulate
	 *			cccc 0000 xxxx xxxx xxxx xxxx 1001 xxxx
	 */
	DECODE_TABLE	(0x0f0000f0, 0x00000090, arm_cccc_0000_____1001_table),

	/*
	 * Synchronization primitives
	 *			cccc 0001 xxxx xxxx xxxx xxxx 1001 xxxx
	 */
	DECODE_TABLE	(0x0f0000f0, 0x01000090, arm_cccc_0001_____1001_table),

	/*
	 * Extra load/store instructions
	 *			cccc 000x xxxx xxxx xxxx xxxx 1xx1 xxxx
	 */
	DECODE_TABLE	(0x0e000090, 0x00000090, arm_cccc_000x_____1xx1_table),

	/*
	 * Data-processing (register)
	 *			cccc 000x xxxx xxxx xxxx xxxx xxx0 xxxx
	 * Data-processing (register-shifted register)
	 *			cccc 000x xxxx xxxx xxxx xxxx 0xx1 xxxx
	 */
	DECODE_TABLE	(0x0e000000, 0x00000000, arm_cccc_000x_table),

	/*
	 * Data-processing (immediate)
	 *			cccc 001x xxxx xxxx xxxx xxxx xxxx xxxx
	 */
	DECODE_TABLE	(0x0e000000, 0x02000000, arm_cccc_001x_table),

	/*
	 * Media instructions
	 *			cccc 011x xxxx xxxx xxxx xxxx xxx1 xxxx
	 */
	DECODE_TABLE	(0x0f000010, 0x06000010, arm_cccc_0110_____xxx1_table),
	DECODE_TABLE	(0x0f000010, 0x07000010, arm_cccc_0111_____xxx1_table),

	/*
	 * Load/store word and unsigned byte
	 *			cccc 01xx xxxx xxxx xxxx xxxx xxxx xxxx
	 */
	DECODE_TABLE	(0x0c000000, 0x04000000, arm_cccc_01xx_table),

	/*
	 * Block data transfer instructions
	 *			cccc 100x xxxx xxxx xxxx xxxx xxxx xxxx
	 */
	DECODE_TABLE	(0x0e000000, 0x08000000, arm_cccc_100x_table),

	/* B			cccc 1010 xxxx xxxx xxxx xxxx xxxx xxxx */
	/* BL			cccc 1011 xxxx xxxx xxxx xxxx xxxx xxxx */
	DECODE_SIMULATE	(0x0e000000, 0x0a000000, simulate_bbl),

	/*
	 * Supervisor Call, and coprocessor instructions
	 */

	/* MCRR			cccc 1100 0100 xxxx xxxx xxxx xxxx xxxx */
	/* MRRC			cccc 1100 0101 xxxx xxxx xxxx xxxx xxxx */
	/* LDC			cccc 110x xxx1 xxxx xxxx xxxx xxxx xxxx */
	/* STC			cccc 110x xxx0 xxxx xxxx xxxx xxxx xxxx */
	/* CDP			cccc 1110 xxxx xxxx xxxx xxxx xxx0 xxxx */
	/* MCR			cccc 1110 xxx0 xxxx xxxx xxxx xxx1 xxxx */
	/* MRC			cccc 1110 xxx1 xxxx xxxx xxxx xxx1 xxxx */
	/* SVC			cccc 1111 xxxx xxxx xxxx xxxx xxxx xxxx */
	DECODE_REJECT	(0x0c000000, 0x0c000000),

	DECODE_END
};

/*
 * Prepare an instruction slot to receive an instruction for emulating.
 * This is done by placing a subroutine return after the location where the
 * instruction will be placed. We also modify ARM instructions to be
 * unconditional as the condition code will already be checked before any
 * emulation handler is called.
 */
static uprobe_opcode_t
prepare_emulated_insn(uprobe_opcode_t insn, struct uprobe_probept_arch_info *ai)
{
	ai->insn[1] = 0xe1a0f00e; /* mov pc, lr */

	/* Make an ARM instruction unconditional */
	if (insn < 0xe0000000)
		insn = (insn | 0xe0000000) & ~0x10000000;
	return insn;
}

/*
 * Write a (probably modified) instruction into the slot previously prepared by
 * prepare_emulated_insn
 */
static void
set_emulated_insn(uprobe_opcode_t insn, struct uprobe_probept_arch_info *ai)
{
	ai->insn[0] = insn;
}

/*
 * When we modify the register numbers encoded in an instruction to be emulated,
 * the new values come from this define. For ARM and 32-bit Thumb instructions
 * this gives...
 *
 *	bit position	  16  12   8   4   0
 *	---------------+---+---+---+---+---+
 *	register	 r2  r0  r1  --  r3
 */
#define INSN_NEW_BITS		0x00020103

/* Each nibble has same value as that at INSN_NEW_BITS bit 16 */
#define INSN_SAMEAS16_BITS	0x22222222

/*
 * Validate and modify each of the registers encoded in an instruction.
 *
 * Each nibble in regs contains a value from enum decode_reg_type. For each
 * non-zero value, the corresponding nibble in pinsn is validated and modified
 * according to the type.
 */
static bool decode_regs(uprobe_opcode_t* pinsn, u32 regs)
{
	uprobe_opcode_t insn = *pinsn;
	uprobe_opcode_t mask = 0xf; /* Start at least significant nibble */

	for (; regs != 0; regs >>= 4, mask <<= 4) {

		uprobe_opcode_t new_bits = INSN_NEW_BITS;

		switch (regs & 0xf) {

		case REG_TYPE_NONE:
			/* Nibble not a register, skip to next */
			continue;

		case REG_TYPE_ANY:
			/* Any register is allowed */
			break;

		case REG_TYPE_SAMEAS16:
			/* Replace register with same as at bit position 16 */
			new_bits = INSN_SAMEAS16_BITS;
			break;

		case REG_TYPE_SP:
			/* Only allow SP (R13) */
			if ((insn ^ 0xdddddddd) & mask)
				goto reject;
			break;

		case REG_TYPE_PC:
			/* Only allow PC (R15) */
			if ((insn ^ 0xffffffff) & mask)
				goto reject;
			break;

		case REG_TYPE_NOSP:
			/* Reject SP (R13) */
			if (((insn ^ 0xdddddddd) & mask) == 0)
				goto reject;
			break;

		case REG_TYPE_NOSPPC:
		case REG_TYPE_NOSPPCX:
			/* Reject SP and PC (R13 and R15) */
			if (((insn ^ 0xdddddddd) & 0xdddddddd & mask) == 0)
				goto reject;
			break;

		case REG_TYPE_NOPCWB:
			if (!is_writeback(insn))
				break; /* No writeback, so any register is OK */
			/* fall through... */
		case REG_TYPE_NOPC:
		case REG_TYPE_NOPCX:
			/* Reject PC (R15) */
			if (((insn ^ 0xffffffff) & mask) == 0)
				goto reject;
			break;
		}

		/* Replace value of nibble with new register number... */
		insn &= ~mask;
		insn |= new_bits & mask;
	}

	*pinsn = insn;
	return true;

reject:
	return false;
}

static const int decode_struct_sizes[NUM_DECODE_TYPES] = {
	[DECODE_TYPE_TABLE]	= sizeof(struct decode_table),
	[DECODE_TYPE_CUSTOM]	= sizeof(struct decode_custom),
	[DECODE_TYPE_SIMULATE]	= sizeof(struct decode_simulate),
	[DECODE_TYPE_EMULATE]	= sizeof(struct decode_emulate),
	[DECODE_TYPE_OR]	= sizeof(struct decode_or),
	[DECODE_TYPE_REJECT]	= sizeof(struct decode_reject)
};

/*
 * uprobe_decode_insn operates on data tables in order to decode an ARM
 * architecture instruction onto which a uprobe has been placed.
 *
 * These instruction decoding tables are a concatenation of entries each
 * of which consist of one of the following structs:
 *
 *	decode_table
 *	decode_custom
 *	decode_simulate
 *	decode_emulate
 *	decode_or
 *	decode_reject
 *
 * Each of these starts with a struct decode_header which has the following
 * fields:
 *
 *	type_regs
 *	mask
 *	value
 *
 * The least significant DECODE_TYPE_BITS of type_regs contains a value
 * from enum decode_type, this indicates which of the decode_* structs
 * the entry contains. The value DECODE_TYPE_END indicates the end of the
 * table.
 *
 * When the table is parsed, each entry is checked in turn to see if it
 * matches the instruction to be decoded using the test:
 *
 *	(insn & mask) == value
 *
 * If no match is found before the end of the table is reached then decoding
 * fails with INSN_REJECTED.
 *
 * When a match is found, decode_regs() is called to validate and modify each
 * of the registers encoded in the instruction; the data it uses to do this
 * is (type_regs >> DECODE_TYPE_BITS). A validation failure will cause decoding
 * to fail with INSN_REJECTED.
 *
 * Once the instruction has passed the above tests, further processing
 * depends on the type of the table entry's decode struct.
 *
 */
int
uprobe_decode_insn(uprobe_opcode_t insn, struct uprobe_probept_arch_info *ai,
				const union decode_item *table)
{
	const struct decode_header *h = (struct decode_header *)table;
	const struct decode_header *next;
	bool matched = false;

	insn = prepare_emulated_insn(insn, ai);

	for (;; h = next) {
		enum decode_type type = h->type_regs.bits & DECODE_TYPE_MASK;
		u32 regs = h->type_regs.bits >> DECODE_TYPE_BITS;

		if (type == DECODE_TYPE_END)
			return INSN_REJECTED;

		next = (struct decode_header *)
				((uintptr_t)h + decode_struct_sizes[type]);

		if (!matched && (insn & h->mask.bits) != h->value.bits)
			continue;

		if (!decode_regs(&insn, regs))
			return INSN_REJECTED;

		switch (type) {

		case DECODE_TYPE_TABLE: {
			struct decode_table *d = (struct decode_table *)h;
			next = (struct decode_header *)d->table.table;
			break;
		}

		case DECODE_TYPE_CUSTOM: {
			struct decode_custom *d = (struct decode_custom *)h;
			return (*d->decoder.decoder)(insn, ai);
		}

		case DECODE_TYPE_SIMULATE: {
			struct decode_simulate *d = (struct decode_simulate *)h;
			ai->insn_handler = d->handler.handler;
			return INSN_GOOD_NO_SLOT;
		}

		case DECODE_TYPE_EMULATE: {
			struct decode_emulate *d = (struct decode_emulate *)h;
			ai->insn_handler = d->handler.handler;
			set_emulated_insn(insn, ai);
			return INSN_GOOD;
		}

		case DECODE_TYPE_OR:
			matched = true;
			break;

		case DECODE_TYPE_REJECT:
		default:
			return INSN_REJECTED;
		}
		}
	}
/* Return:
 *   INSN_REJECTED     If instruction is one not allowed to uprobe,
 *   INSN_GOOD         If instruction is supported and uses instruction slot,
 *   INSN_GOOD_NO_SLOT If instruction is supported but doesn't use its slot.
 *
 * For instructions we don't want to uprobe (INSN_REJECTED return result):
 *   These are generally ones that modify the processor state making
 *   them "hard" to simulate such as switches processor modes or
 *   make accesses in alternate modes.  Any of these could be simulated
 *   if the work was put into it, but low return considering they
 *   should also be very rare.
 */
enum uprobe_insn
arm_uprobe_decode_insn(uprobe_opcode_t insn,
		struct uprobe_probept_arch_info *ai)
{
	ai->insn_check_cc = uprobe_condition_checks[insn>>28];
	return uprobe_decode_insn(insn, ai, uprobe_decode_arm_table);
}

static int arch_validate_probed_insn(struct uprobe_probept *ppt,
		struct task_struct *tsk)
{
	uprobe_opcode_t insn = *ppt->insn;

	if (ppt->vaddr & 0x3)
		return -EINVAL;

	arm_uprobe_decode_init();
	switch (arm_uprobe_decode_insn(insn, &ppt->arch_info)) {
	case INSN_REJECTED:
		return -EINVAL;

	case INSN_GOOD:
		ppt->arch_info.insn_fn = (uprobe_insn_fn_t *)
			ppt->arch_info.insn;
		flush_icache_range((unsigned long)ppt->arch_info.insn,
				   (unsigned long)ppt->arch_info.insn +
				   	sizeof(ppt->arch_info.insn[0]) *
					MAX_INSN_SIZE);
		break;

	case INSN_GOOD_NO_SLOT:
		break;
	}

	return 0;
}

static int uprobe_emulate_insn(struct pt_regs *regs,
		struct uprobe_probept *ppt)
{
	if (ppt->arch_info.insn_handler) {
		regs->ARM_pc += 4;
		ppt->arch_info.insn_handler(ppt, regs);
		return 1;
	}
	return 0;
}

