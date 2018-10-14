/* -*- linux-c -*-
 *
 * dwarf unwinder header file
 * Copyright (C) 2008-2010, 2013 Red Hat Inc.
 * Copyright (C) 2002-2006 Novell, Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_UNWIND_H_
#define _STP_UNWIND_H_

// portions of code needed by the debug_line decoder
#if defined(STP_USE_DWARF_UNWINDER) || defined(STP_NEED_LINE_DATA)

struct unwind_frame_info
{
    struct pt_regs regs;
    unsigned call_frame:1;
};

#if defined (__x86_64__)
#include "x86_64.h"
#elif  defined (__i386__)
#include "i386.h"
#elif defined (__powerpc64__)
#include "ppc64.h"
#elif defined (__s390x__)
#include "s390x.h"
#elif defined (__arm__)
#include "arm.h"
#elif defined (__aarch64__)
#include "arm64.h"
#else
#error "Unsupported dwarf unwind architecture"
#endif

#define DW_EH_PE_absptr   0x00
#define DW_EH_PE_leb128   0x01
#define DW_EH_PE_data2    0x02
#define DW_EH_PE_data4    0x03
#define DW_EH_PE_data8    0x04
#define DW_EH_PE_FORM     0x07 /* mask */
#define DW_EH_PE_signed   0x08 /* signed versions of above have this bit set */

#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_textrel  0x20
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_funcrel  0x40
#define DW_EH_PE_aligned  0x50
#define DW_EH_PE_ADJUST   0x70 /* mask */
#define DW_EH_PE_indirect 0x80
#define DW_EH_PE_omit     0xff

typedef unsigned long uleb128_t;
typedef   signed long sleb128_t;


static uleb128_t get_uleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	uleb128_t value = 0;
	unsigned shift;

	for (shift = 0; cur < end; shift += 7) {
		if (shift + 7 > 8 * sizeof(value)
		    && (*cur & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (uleb128_t)(*cur & 0x7f) << shift;
		if (!(*cur++ & 0x80))
			break;
	}
	*pcur = cur;

	return value;
}

static sleb128_t get_sleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	sleb128_t value = 0;
	unsigned shift;

	for (shift = 0; cur < end; shift += 7) {
    const u8 cur_val = *cur++;
		if (shift + 7 > 8 * sizeof(value)
		    && (cur_val & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (sleb128_t)(cur_val & 0x7f) << shift;
		if (!(cur_val & 0x80)) {
			value |= -(cur_val & 0x40) << shift;
			break;
		}
	}
	*pcur = cur;

	return value;
}

/* read an encoded pointer and increment *pLoc past the end of the
 * data read. */
static unsigned long read_ptr_sect(const u8 **pLoc, const void *end,
				   signed ptrType, unsigned long textAddr,
				   unsigned long dataAddr, int user, int compat_task, int tableSize)
{
	unsigned long value = 0;
	union {
		const u8 *p8;
		const u16 *p16u;
		const s16 *p16s;
		const u32 *p32u;
		const s32 *p32s;
		const unsigned long *pul;
		const unsigned int *pui;
	} ptr;

	if (ptrType < 0 || ptrType == DW_EH_PE_omit)
		return 0;

	ptr.p8 = *pLoc;
	switch (ptrType & DW_EH_PE_FORM) {
	case DW_EH_PE_data2:
		if (end < (const void *)(ptr.p16u + 1))
			return 0;
		if (ptrType & DW_EH_PE_signed)
			value = _stp_get_unaligned(ptr.p16s++);
		else
			value = _stp_get_unaligned(ptr.p16u++);
		break;
	case DW_EH_PE_data4:
#ifdef CONFIG_64BIT

		/* If the tableSize matches the length of data we're trying to return
		 * or if specifically set to 0 in the call it means we actually want a
		 * DW_EH_PE_data4 and not a DW_EH_PE_absptr.  If this is not the case
		 * then we want to fall through to DW_EH_PE_absptr */
		if (!compat_task || (compat_task && (tableSize == 4 || tableSize == 0)))
		{
			if (end < (const void *)(ptr.p32u + 1))
				return 0;

			if (ptrType & DW_EH_PE_signed)
				value = _stp_get_unaligned(ptr.p32s++);
			else
				value = _stp_get_unaligned(ptr.p32u++);
			break;
		}
	case DW_EH_PE_data8:
		BUILD_BUG_ON(sizeof(u64) != sizeof(value));
#else
		BUILD_BUG_ON(sizeof(u32) != sizeof(value));
#endif
	/* fallthrough, see above. */
	case DW_EH_PE_absptr:
		if (compat_task)
		{
			if (end < (const void *)(ptr.pui + 1))
				return 0;
			value = _stp_get_unaligned(ptr.pui++);
		} else {
			if (end < (const void *)(ptr.pul + 1))
				return 0;
			value = _stp_get_unaligned(ptr.pul++);
		}

		break;
	case DW_EH_PE_leb128:
		BUILD_BUG_ON(sizeof(uleb128_t) > sizeof(value));
		value = ptrType & DW_EH_PE_signed ? get_sleb128(&ptr.p8, end)
		    : get_uleb128(&ptr.p8, end);
		if ((const void *)ptr.p8 > end)
			return 0;
		break;
	default:
		return 0;
	}
	switch (ptrType & DW_EH_PE_ADJUST) {
	case DW_EH_PE_absptr:
		break;
	case DW_EH_PE_pcrel:
		value += (unsigned long)*pLoc;
		break;
	case DW_EH_PE_textrel:
		value += textAddr;
		break;
	case DW_EH_PE_datarel:
		value += dataAddr;
		break;
	default:
		return 0;
	}
	if ((ptrType & DW_EH_PE_indirect)
	    && _stp_read_address(value, (unsigned long *)value,
				 (user ? USER_DS : KERNEL_DS)))
		return 0;
	*pLoc = ptr.p8;

	return value;
}

static unsigned long read_pointer(const u8 **pLoc, const void *end, signed ptrType,
				  int user, int compat_task)
{
	return read_ptr_sect(pLoc, end, ptrType, 0, 0, user, compat_task, 0);
}

#endif /* defined(STP_USE_DWARF_UNWINDER) || defined(STP_NEED_LINE_DATA) */

#ifdef STP_USE_DWARF_UNWINDER

/* Used for DW_CFA_remember_state and DW_CFA_restore_state. */
#define STP_MAX_STACK_DEPTH 4

#ifndef BUILD_BUG_ON_ZERO
#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#endif


#define EXTRA_INFO(f) { \
		BUILD_BUG_ON_ZERO(offsetof(struct unwind_frame_info, f) \
		                  % FIELD_SIZEOF(struct unwind_frame_info, f)) \
		+ offsetof(struct unwind_frame_info, f) \
		  / FIELD_SIZEOF(struct unwind_frame_info, f), \
		FIELD_SIZEOF(struct unwind_frame_info, f) \
	}
#define PTREGS_INFO(f) EXTRA_INFO(regs.f)

static const struct {
	unsigned offs:BITS_PER_LONG / 2;
	unsigned width:BITS_PER_LONG / 2;
} reg_info[] = {
	UNW_REGISTER_INFO
};

#undef PTREGS_INFO
#undef EXTRA_INFO

/* The reg_info array assumes dwarf register numbers start at zero and
   are consecutive.  If that isn't the case for some architecture (e.g. ppc)
   then redefine to map the given dwarf register number to the actual
   reg_info index.  */
#ifndef DWARF_REG_MAP
#define DWARF_REG_MAP(r) r
#endif

/* COMPAT_REG_MAP is the mapping from 32bit to 64bit DWARF registers.  In
   the case where they're not the same (e.g. x86_64 and i386) the alternate
   mapping will be located in the 64bit header file */
#ifndef COMPAT_REG_MAP
#define COMPAT_REG_MAP(r) r
#endif

/* The number of real registers in the register map. These are all assumed
   to be the Same in the new frame. All others will be Unknown untill they
   have been explictly set. (e.g. the x86 return register). */
#ifndef UNW_NR_REAL_REGS
#define UNW_NR_REAL_REGS ARRAY_SIZE(reg_info)
#endif

#ifndef REG_INVALID
#define REG_INVALID(r) (reg_info[r].width == 0)
#endif

/* Whether the stack pointer should be set from the CFA.
   If this isn't what the architecture wants, then it should define
   this as zero.  */
#ifndef UNW_SP_FROM_CFA
#define UNW_SP_FROM_CFA 1
#endif

/* Whether the instruction pointer should be set from the return address
   column.  If this isn't what the architecture wants, then it should
   define this as zero.  */
#ifndef UNW_PC_FROM_RA
#define UNW_PC_FROM_RA 1
#endif

#define DW_CFA_nop                          0x00
#define DW_CFA_set_loc                      0x01
#define DW_CFA_advance_loc1                 0x02
#define DW_CFA_advance_loc2                 0x03
#define DW_CFA_advance_loc4                 0x04
#define DW_CFA_offset_extended              0x05
#define DW_CFA_restore_extended             0x06
#define DW_CFA_undefined                    0x07
#define DW_CFA_same_value                   0x08
#define DW_CFA_register                     0x09
#define DW_CFA_remember_state               0x0a
#define DW_CFA_restore_state                0x0b
#define DW_CFA_def_cfa                      0x0c
#define DW_CFA_def_cfa_register             0x0d
#define DW_CFA_def_cfa_offset               0x0e
#define DW_CFA_def_cfa_expression           0x0f
#define DW_CFA_expression                   0x10
#define DW_CFA_offset_extended_sf           0x11
#define DW_CFA_def_cfa_sf                   0x12
#define DW_CFA_def_cfa_offset_sf            0x13
#define DW_CFA_val_offset                   0x14
#define DW_CFA_val_offset_sf                0x15
#define DW_CFA_val_expression               0x16
#define DW_CFA_lo_user                      0x1c
#define DW_CFA_GNU_window_save              0x2d
#define DW_CFA_GNU_args_size                0x2e
#define DW_CFA_GNU_negative_offset_extended 0x2f
#define DW_CFA_hi_user                      0x3f

#define	DW_OP_addr		0x03
#define	DW_OP_deref		0x06
#define	DW_OP_const1u		0x08
#define	DW_OP_const1s		0x09
#define	DW_OP_const2u		0x0a
#define	DW_OP_const2s		0x0b
#define	DW_OP_const4u		0x0c
#define	DW_OP_const4s		0x0d
#define	DW_OP_const8u		0x0e
#define	DW_OP_const8s		0x0f
#define	DW_OP_constu		0x10
#define	DW_OP_consts		0x11
#define	DW_OP_dup		0x12
#define	DW_OP_drop		0x13
#define	DW_OP_over		0x14
#define	DW_OP_pick		0x15
#define	DW_OP_swap		0x16
#define	DW_OP_rot		0x17
#define	DW_OP_xderef		0x18
#define	DW_OP_abs		0x19
#define	DW_OP_and		0x1a
#define	DW_OP_div		0x1b
#define	DW_OP_minus		0x1c
#define	DW_OP_mod		0x1d
#define	DW_OP_mul		0x1e
#define	DW_OP_neg		0x1f
#define	DW_OP_not		0x20
#define	DW_OP_or		0x21
#define	DW_OP_plus		0x22
#define	DW_OP_plus_uconst	0x23
#define	DW_OP_shl		0x24
#define	DW_OP_shr		0x25
#define	DW_OP_shra		0x26
#define	DW_OP_xor		0x27
#define	DW_OP_bra		0x28
#define	DW_OP_eq		0x29
#define	DW_OP_ge		0x2a
#define	DW_OP_gt		0x2b
#define	DW_OP_le		0x2c
#define	DW_OP_lt		0x2d
#define	DW_OP_ne		0x2e
#define	DW_OP_skip		0x2f
#define	DW_OP_lit0		0x30
#define	DW_OP_lit1		0x31
#define	DW_OP_lit2		0x32
#define	DW_OP_lit3		0x33
#define	DW_OP_lit4		0x34
#define	DW_OP_lit5		0x35
#define	DW_OP_lit6		0x36
#define	DW_OP_lit7		0x37
#define	DW_OP_lit8		0x38
#define	DW_OP_lit9		0x39
#define	DW_OP_lit10		0x3a
#define	DW_OP_lit11		0x3b
#define	DW_OP_lit12		0x3c
#define	DW_OP_lit13		0x3d
#define	DW_OP_lit14		0x3e
#define	DW_OP_lit15		0x3f
#define	DW_OP_lit16		0x40
#define	DW_OP_lit17		0x41
#define	DW_OP_lit18		0x42
#define	DW_OP_lit19		0x43
#define	DW_OP_lit20		0x44
#define	DW_OP_lit21		0x45
#define	DW_OP_lit22		0x46
#define	DW_OP_lit23		0x47
#define	DW_OP_lit24		0x48
#define	DW_OP_lit25		0x49
#define	DW_OP_lit26		0x4a
#define	DW_OP_lit27		0x4b
#define	DW_OP_lit28		0x4c
#define	DW_OP_lit29		0x4d
#define	DW_OP_lit30		0x4e
#define	DW_OP_lit31		0x4f
#define	DW_OP_reg0		0x50
#define	DW_OP_reg1		0x51
#define	DW_OP_reg2		0x52
#define	DW_OP_reg3		0x53
#define	DW_OP_reg4		0x54
#define	DW_OP_reg5		0x55
#define	DW_OP_reg6		0x56
#define	DW_OP_reg7		0x57
#define	DW_OP_reg8		0x58
#define	DW_OP_reg9		0x59
#define	DW_OP_reg10		0x5a
#define	DW_OP_reg11		0x5b
#define	DW_OP_reg12		0x5c
#define	DW_OP_reg13		0x5d
#define	DW_OP_reg14		0x5e
#define	DW_OP_reg15		0x5f
#define	DW_OP_reg16		0x60
#define	DW_OP_reg17		0x61
#define	DW_OP_reg18		0x62
#define	DW_OP_reg19		0x63
#define	DW_OP_reg20		0x64
#define	DW_OP_reg21		0x65
#define	DW_OP_reg22		0x66
#define	DW_OP_reg23		0x67
#define	DW_OP_reg24		0x68
#define	DW_OP_reg25		0x69
#define	DW_OP_reg26		0x6a
#define	DW_OP_reg27		0x6b
#define	DW_OP_reg28		0x6c
#define	DW_OP_reg29		0x6d
#define	DW_OP_reg30		0x6e
#define	DW_OP_reg31		0x6f
#define	DW_OP_breg0		0x70
#define	DW_OP_breg1		0x71
#define	DW_OP_breg2		0x72
#define	DW_OP_breg3		0x73
#define	DW_OP_breg4		0x74
#define	DW_OP_breg5		0x75
#define	DW_OP_breg6		0x76
#define	DW_OP_breg7		0x77
#define	DW_OP_breg8		0x78
#define	DW_OP_breg9		0x79
#define	DW_OP_breg10		0x7a
#define	DW_OP_breg11		0x7b
#define	DW_OP_breg12		0x7c
#define	DW_OP_breg13		0x7d
#define	DW_OP_breg14		0x7e
#define	DW_OP_breg15		0x7f
#define	DW_OP_breg16		0x80
#define	DW_OP_breg17		0x81
#define	DW_OP_breg18		0x82
#define	DW_OP_breg19		0x83
#define	DW_OP_breg20		0x84
#define	DW_OP_breg21		0x85
#define	DW_OP_breg22		0x86
#define	DW_OP_breg23		0x87
#define	DW_OP_breg24		0x88
#define	DW_OP_breg25		0x89
#define	DW_OP_breg26		0x8a
#define	DW_OP_breg27		0x8b
#define	DW_OP_breg28		0x8c
#define	DW_OP_breg29		0x8d
#define	DW_OP_breg30		0x8e
#define	DW_OP_breg31		0x8f
#define	DW_OP_regx		0x90
#define	DW_OP_fbreg		0x91
#define	DW_OP_bregx		0x92
#define	DW_OP_deref_size	0x94
#define	DW_OP_xderef_size	0x95
#define	DW_OP_nop		0x96

struct unwind_item {
	enum item_location {
		Same,     /* no state */
		Nowhere,  /* no state */
		Memory,   /* signed offset from CFA */
		Register, /* unsigned register number */
		Value,    /* signed offset from CFA */
		Expr,     /* DWARF expression */
		ValExpr   /* DWARF expression */
	} where;
	union {
		uleb128_t reg;
		sleb128_t off;
		const u8 *expr;
	} state;
};

struct unwind_reg_state {
	union {
		struct cfa {
			uleb128_t reg;
			sleb128_t off;
		} cfa;
		const u8 *cfa_expr;
	};
	struct unwind_item regs[ARRAY_SIZE(reg_info)];
	unsigned cfa_is_expr:1;
};

struct unwind_state {
	uleb128_t loc;
	uleb128_t codeAlign;
	sleb128_t dataAlign;
	unsigned stackDepth:8;
	struct unwind_reg_state reg[STP_MAX_STACK_DEPTH];
	struct unwind_item cie_regs[ARRAY_SIZE(reg_info)];
};

struct unwind_context {
    struct unwind_frame_info info;
    struct unwind_state state;
};

static const struct cfa badCFA = { ARRAY_SIZE(reg_info), 1 };
#else  /* !STP_USE_DWARF_UNWINDER */
struct unwind_context { };
#endif /* !STP_USE_DWARF_UNWINDER */

#ifndef MAXBACKTRACE
#define MAXBACKTRACE 20
#endif

struct unwind_cache {
	enum uwcache_state {
		uwcache_uninitialized,
		uwcache_partial,
		uwcache_finished
	} state;
	unsigned depth; /* pc[0..(depth-1)] contains valid entries */
	unsigned long pc[MAXBACKTRACE];
};

#endif /*_STP_UNWIND_H_*/
