/* -*- linux-c -*-
 * kernel stack unwinding
 * Copyright (C) 2008-2011, 2014 Red Hat Inc.
 *
 * Based on old kernel code that is
 * Copyright (C) 2002-2006 Novell, Inc.
 *	Jan Beulich <jbeulich@novell.com>
 *
 * This code is released under version 2 of the GNU GPL.
 *
 * This code currently does stack unwinding in the kernel and modules.
 * It has been extended to handle userspace unwinding using systemtap
 * data structures.
 */

#include "unwind/unwind.h"

/* Whether this is a real CIE. Assumes CIE (length) sane. */
static int has_cie_id(const u32 *cie, int is_ehframe)
{
	/* CIE id for eh_frame is 0, otherwise 0xffffffff */
	if (is_ehframe && cie[1] == 0)
		return 1;
	else if (cie[1] == 0xffffffff)
		return 1;
	else
		return 0;
}

/* whether this is a real fde or not */
static int is_fde(const u32 *fde, void *table, uint32_t table_len,
			int is_ehframe)
{
	const u8 *end;

	/* check that length is proper */
	if (!*fde || (*fde & (sizeof(*fde) - 1))) {
		_stp_warn("bad fde\n");
		return 0;
	}

	if (has_cie_id(fde, is_ehframe))
		return 0;

	end = (const u8 *)(fde + 1) + *fde;

        /* end should fall within unwind table. */
        if (((void*)end) < table
            || ((void *)end) > ((void *)(table + table_len))) {
		_stp_warn("bad fde length\n");
		return 0;
	}

	return 1;
}

/* given an FDE, find its CIE and sanity check */
static const u32 *cie_for_fde(const u32 *fde, void *unwind_data,
			      uint32_t table_len, int is_ehframe)
{
	const u32 *cie;
	unsigned version;
	const u8 *end;

	/* CIE_pointer must be a proper offset */
	if ((fde[1] & (sizeof(*fde) - 1)) || fde[1] > (unsigned long)(fde + 1) - (unsigned long)unwind_data) {
		_stp_warn("invalid fde[1]=%lx fde+1=%lx, unwind_data=%lx  %lx\n",
			    (unsigned long)fde[1], (unsigned long)(fde + 1),
			    (unsigned long)unwind_data, (unsigned long)(fde + 1) - (unsigned long)unwind_data);
		return NULL;	/* this is not a valid FDE */
	}

	/* cie pointer field is different in eh_frame vs debug_frame */
	if (is_ehframe)
		cie = fde + 1 - fde[1] / sizeof(*fde);
	else
		cie = unwind_data + fde[1];

	/* Make sure address falls in the table */
	if (((void *)cie) < ((void*)unwind_data)
	    || ((void*)cie) > ((void*)(unwind_data + table_len))) {
		_stp_warn("cie address falls outside table\n");
		return NULL;
	}

	if (*cie <= sizeof(*cie) + 4 || *cie >= fde[1] - sizeof(*fde)
	    || ! has_cie_id(cie, is_ehframe)) {
		_stp_warn("cie is not valid %lx %x %x %x\n", (unsigned long)cie, *cie, fde[1], cie[1]);
		return NULL;	/* this is not a (valid) CIE */
	}

	version = *(const u8 *)(cie + 2);
	if (version != 1 && version != 3 && version != 4) {
		_stp_warn ("Unsupported CIE version: %d\n", version);
		return NULL;
	}

	end = (const u8 *)(cie + 1) + *cie;

        /* end should fall within unwind table. */
        if (((void *)end) < (void *)unwind_data
            || ((void *)end) > ((void *)(unwind_data + table_len))) {
		_stp_warn ("CIE end falls outside table\n");
		return NULL;
	}

	return cie;
}


/* Parse FDE and CIE content. Basic sanity checks should already have
   been done start/end/version/id (done by is_fde and cie_for_fde).
   Returns -1 if FDE or CIE cannot be parsed.*/
static int parse_fde_cie(const u32 *fde, const u32 *cie,
			 void *unwind_data, uint32_t table_len,
			 unsigned *ptrType, int user,
			 unsigned long *startLoc, unsigned long *locRange,
			 const u8 **fdeStart, const u8 **fdeEnd,
			 const u8 **cieStart, const u8 **cieEnd,
			 uleb128_t *codeAlign, sleb128_t *dataAlign,
			 uleb128_t *retAddrReg, unsigned *call_frame, int compat_task)
{
	const u8 *ciePtr = (const u8 *)(cie + 2);
	const u8 *fdePtr = (const u8 *)(fde + 2);
	unsigned version = *ciePtr++;
	const char *aug = (const void *)ciePtr;
	uleb128_t augLen = 0;	/* Set to non-zero if cie aug starts with z */

	*cieEnd = (const u8 *)(cie + 1) + *cie;
	*fdeEnd = (const u8 *)(fde + 1) + *fde;

	/* check if augmentation string is nul-terminated */
	if ((ciePtr = memchr(aug, 0, *cieEnd - ciePtr)) == NULL) {
		_stp_warn("Unterminated augmentation string\n");
		return -1;
	}
	ciePtr++;	/* skip aug terminator */

	*codeAlign = get_uleb128(&ciePtr, *cieEnd);
	*dataAlign = get_sleb128(&ciePtr, *cieEnd);
	dbug_unwind(2, "codeAlign=%lx, dataAlign=%lx\n",
		    *codeAlign, *dataAlign);
	if (*codeAlign == 0 || *dataAlign == 0) {
		_stp_warn("zero codeAlign or dataAlign values\n");
		return -1;
	}

	*retAddrReg = ((version <= 1)
		       ? *ciePtr++ : get_uleb128(&ciePtr, *cieEnd));
	if(compat_task){
		dbug_unwind(1, "map retAddrReg value %ld to reg_info idx %ld\n",
			    *retAddrReg, COMPAT_REG_MAP(DWARF_REG_MAP(*retAddrReg)));
		*retAddrReg = COMPAT_REG_MAP(DWARF_REG_MAP(*retAddrReg));
	} else {
		dbug_unwind(1, "map retAddrReg value %ld to reg_info idx %ld\n",
			    *retAddrReg, DWARF_REG_MAP(*retAddrReg));
		*retAddrReg = DWARF_REG_MAP(*retAddrReg);
	}

	if (*aug == 'z') {
		augLen = get_uleb128(&ciePtr, *cieEnd);
		if (augLen > (const u8 *)cie - *cieEnd
		    || ciePtr + augLen > *cieEnd) {
			_stp_warn("Bogus CIE augmentation length\n");
			return -1;
		}
	}
	*cieStart = ciePtr + augLen;

	/* Read augmentation string to determine frame_call and ptrType. */
	*call_frame = 1;
	*ptrType = DW_EH_PE_absptr;
	while (*aug) {
		if (ciePtr > *cieStart) {
			_stp_warn("Augmentation data runs past end\n");
			return -1;
		}
		switch (*aug) {
			case 'z':
				break;
			case 'L':
				ciePtr++;
				break;
			case 'P': {
				/* We are not actually interested in
				   the value, so don't try to deref.
				   Mask off DW_EH_PE_indirect. */
				signed pType = *ciePtr++ & 0x7F;
				if (!read_pointer(&ciePtr, *cieStart, pType, user, compat_task)) {
					_stp_warn("couldn't read personality routine handler\n");
					return -1;
				}
				break;
			}
			case 'R':
				*ptrType = *ciePtr++;
				break;
			case 'S':
				*call_frame = 0;
				break;
			default:
				_stp_warn("Unknown augmentation char '%c'\n", *(aug - 1));
				return -1;
		}
		aug++;
	}
	if (ciePtr != *cieStart) {
		_stp_warn("Bogus CIE augmentation data\n");
		return -1;
	}

	/* Now we finally know the type encoding and whether or not the
	   augmentation string starts with 'z' indicating the FDE might also
	   have some augmentation data, so we can parse the FDE. */
	*startLoc = read_pointer(&fdePtr, *fdeEnd, *ptrType, user, compat_task);
	*locRange = read_pointer(&fdePtr, *fdeEnd,
				 *ptrType & (DW_EH_PE_FORM | DW_EH_PE_signed),
				 user, compat_task);
	dbug_unwind(2, "startLoc: %lx, locrange: %lx\n",
		    *startLoc, *locRange);

	/* Skip FDE augmentation length (not interested in data). */
	if (augLen != 0) {
		augLen = get_uleb128(&fdePtr, *fdeEnd);
		if (augLen > (const u8 *)fde - *fdeEnd
		    || fdePtr + augLen > *fdeEnd) {
			_stp_warn("Bogus FDE augmentation length\n");
			return -1;
		}
	}
	*fdeStart = fdePtr + augLen;

	return 0;
}

#define REG_STATE state->reg[state->stackDepth]

static int advance_loc(unsigned long delta, struct unwind_state *state)
{
	state->loc += delta * state->codeAlign;
	dbug_unwind(1, "state->loc=%lx\n", state->loc);
	return delta > 0;
}

/* Set Same or Nowhere rule for register. */
static void set_no_state_rule(uleb128_t reg, enum item_location where,
                              struct unwind_state *state)
{
	dbug_unwind(1, "reg=%lx, where=%d\n", reg, where);
	if (reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = where;
	}
}

/* Memory or Value rule */
static void set_offset_rule(uleb128_t reg, enum item_location where,
                            sleb128_t svalue, struct unwind_state *state)
{
	dbug_unwind(1, "reg=%lx, where=%d, svalue=%lx\n", reg, where, svalue);
	if (reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = where;
		REG_STATE.regs[reg].state.off = svalue;
	}
}

/* Register rule. */
static void set_register_rule(uleb128_t reg, uleb128_t value,
                              struct unwind_state *state)
{
	dbug_unwind(1, "reg=%lx, value=%lx\n", reg, value);
	if (reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = Register;
		REG_STATE.regs[reg].state.reg = value;
	}
}

/* Expr or ValExpr rule. */
static void set_expr_rule(uleb128_t reg, enum item_location where,
			  const u8 **expr, const u8 *end,
			  struct unwind_state *state)
{
	const u8 *const start = *expr;
	uleb128_t len = get_uleb128(expr, end);
	dbug_unwind(1, "reg=%lx, where=%d, expr=%lu@%p\n",
		    reg, where, len, *expr);
	/* Sanity check that expr falls completely inside known data. */
	if (end - *expr >= len && reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = where;
		REG_STATE.regs[reg].state.expr = start;
		*expr += len;
	}
}

/* Limit the number of instructions we process. Arbitrary limit.
   512 should be enough for anybody... */
#define MAX_CFI 512

static int processCFI(const u8 *start, const u8 *end, unsigned long targetLoc,
		      signed ptrType, int user, struct unwind_state *state, int compat_task)
{
	union {
		const u8 *p8;
		const u16 *p16;
		const u32 *p32;
	} ptr;
	int result = 1;

	if (end - start > MAX_CFI) {
		_stp_warn("Too many CFI instuctions\n");
		return 0;
	}

	dbug_unwind(1, "targetLoc=%lx state->loc=%lx\n", targetLoc, state->loc);
	for (ptr.p8 = start; result && ptr.p8 < end;) {
		switch (*ptr.p8 >> 6) {
			uleb128_t value;
			uleb128_t value2;
			sleb128_t svalue;
		case 0:
			switch (*ptr.p8++) {
			case DW_CFA_nop:
				dbug_unwind(1, "DW_CFA_nop\n");
				break;
			case DW_CFA_set_loc:
				if ((state->loc = read_pointer(&ptr.p8, end, ptrType, user, compat_task)) == 0)
					result = 0;
				dbug_unwind(1, "DW_CFA_set_loc %lx (result=%d)\n", state->loc, result);
				break;
			case DW_CFA_advance_loc1:
				result = ptr.p8 < end && advance_loc(*ptr.p8++, state);
				dbug_unwind(1, "DW_CFA_advance_loc1 (result=%d)\n", result);
				break;
			case DW_CFA_advance_loc2:
				result = ptr.p8 <= end + 2 && advance_loc(*ptr.p16++, state);
				dbug_unwind(1, "DW_CFA_advance_loc2 (result=%d)\n", result);
				break;
			case DW_CFA_advance_loc4:
				result = ptr.p8 <= end + 4 && advance_loc(*ptr.p32++, state);
				dbug_unwind(1, "DW_CFA_advance_loc4 (result=%d)\n", result);
				break;
			case DW_CFA_offset_extended:
				value = get_uleb128(&ptr.p8, end);
				value2 = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_offset_extended value %ld to reg_info idx %ld, with offset %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), value2);
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_offset_extended value %ld to reg_info idx %ld, with offset %ld\n",
						    value, DWARF_REG_MAP(value), value2);
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Memory,
                                                value2 * state->dataAlign,
                                                state);
				break;
			case DW_CFA_val_offset:
				value = get_uleb128(&ptr.p8, end);
				value2 = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_val_offset value %ld to reg_info idx %ld\n, with offset: %ld",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), value2);
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_val_offset value %ld to reg_info idx %ld\n, with offset: %ld",
						    value, DWARF_REG_MAP(value), value2);
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Value,
                                                value2 * state->dataAlign,
                                                state);
				break;
			case DW_CFA_offset_extended_sf:
				value = get_uleb128(&ptr.p8, end);
				svalue = get_sleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_offset_extended_sf value %ld to reg_info idx %ld, with offset: %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), svalue);
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_offset_extended_sf value %ld to reg_info idx %ld, with offset: %ld\n",
						    value, DWARF_REG_MAP(value), svalue);
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Memory,
						svalue * state->dataAlign,
						state);
				break;
			case DW_CFA_val_offset_sf:
				value = get_uleb128(&ptr.p8, end);
				svalue = get_sleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_val_offset_sf value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_val_offset_sf value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Value,
						svalue * state->dataAlign,
						state);
				break;
			case DW_CFA_same_value:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_same_value value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_same_value value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_no_state_rule(value, Same, state);
				break;
			case DW_CFA_restore_extended:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_restore_extended value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_restore_extended value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				if (value < ARRAY_SIZE(REG_STATE.regs))
					memcpy(&REG_STATE.regs[value], &state->cie_regs[value], sizeof(struct unwind_item));
				break;
			case DW_CFA_undefined:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_undefined value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_undefined value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_no_state_rule(value, Nowhere, state);
				break;
			case DW_CFA_register: {
				uleb128_t reg_value;
				value = get_uleb128(&ptr.p8, end);
				reg_value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_register value %ld to reg_info idx %ld (reg_value %ld to reg_info idx %ld)\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), reg_value, COMPAT_REG_MAP(DWARF_REG_MAP(reg_value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
					reg_value = DWARF_REG_MAP(reg_value);
				} else {
					dbug_unwind(1, "map DW_CFA_register value %ld to reg_info idx %ld (reg_value %ld to reg_info idx %ld)\n",
						    value, DWARF_REG_MAP(value), reg_value, DWARF_REG_MAP(reg_value));
					value = DWARF_REG_MAP(value);
					reg_value = DWARF_REG_MAP(reg_value);
				}
				set_register_rule(value, reg_value, state);
				break;
			}
			case DW_CFA_expression:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_expression value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_expression value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_expr_rule(value, Expr, &ptr.p8, end, state);
				break;
			case DW_CFA_val_expression:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_val_expression value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_val_expression value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_expr_rule(value, ValExpr, &ptr.p8, end,
					      state);
				break;
			case DW_CFA_remember_state:
				state->stackDepth++;
				if (state->stackDepth >= STP_MAX_STACK_DEPTH) {
					_stp_warn("Too many stacked DW_CFA_remember_state\n");
					return 0;
				}
				memcpy(&REG_STATE,
				       &state->reg[state->stackDepth - 1],
				       sizeof (REG_STATE));
				dbug_unwind(1, "DW_CFA_remember_state (stackDepth=%d)\n", state->stackDepth);
				break;
			case DW_CFA_restore_state:
				if (state->stackDepth == 0) {
					_stp_warn("Unbalanced DW_CFA_restore_state\n");
					return 0;
				}
				state->stackDepth--;
				dbug_unwind(1, "DW_CFA_restore_state (stackDepth=%d)\n", state->stackDepth);
				break;
			case DW_CFA_def_cfa:
				value = get_uleb128(&ptr.p8, end);
				REG_STATE.cfa_is_expr = 0;
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_def_cfa value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					REG_STATE.cfa.reg = COMPAT_REG_MAP(value);
					dbug_unwind(1, "DW_CFA_def_cfa reg=%ld\n", COMPAT_REG_MAP(REG_STATE.cfa.reg));
				} else {
					dbug_unwind(1, "map DW_CFA_def_cfa value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					REG_STATE.cfa.reg = value;
					dbug_unwind(1, "DW_CFA_def_cfa reg=%ld\n", REG_STATE.cfa.reg);
				}
				/*nobreak */
			case DW_CFA_def_cfa_offset:
				if (REG_STATE.cfa_is_expr != 0) {
					_stp_warn("Unexpected DW_CFA_def_cfa_offset\n");
				} else {
					/* non-factored uleb128 */
					REG_STATE.cfa.off = get_uleb128(&ptr.p8, end);
					dbug_unwind(1, "DW_CFA_def_cfa_offset offs=%lx\n", REG_STATE.cfa.off);
				}
				break;
			case DW_CFA_def_cfa_sf:
				value = get_uleb128(&ptr.p8, end);
				REG_STATE.cfa_is_expr = 0;
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_def_cfa_sf value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					REG_STATE.cfa.reg = COMPAT_REG_MAP(value);
				} else {
					dbug_unwind(1, "map DW_CFA_def_cfa_sf value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					REG_STATE.cfa.reg = value;
				}
				/*nobreak */
			case DW_CFA_def_cfa_offset_sf:
				if (REG_STATE.cfa_is_expr != 0) {
					_stp_warn("Unexpected DW_CFA_def_cfa_offset_sf\n");
				} else {
					/* factored sleb128 */
					REG_STATE.cfa.off = get_sleb128(&ptr.p8, end) * state->dataAlign;
					dbug_unwind(1, "DW_CFA_def_cfa_offset_sf offs=%lx\n", REG_STATE.cfa.off);
				}
				break;
			case DW_CFA_def_cfa_register:
				if (REG_STATE.cfa_is_expr != 0) {
					_stp_warn("Unexpected DW_CFA_def_cfa_register\n");
				} else {
					value = get_uleb128(&ptr.p8, end);
					if (compat_task) {
						dbug_unwind(1, "map DW_CFA_def_cfa_register value %ld to reg_info idx %ld (%ld)\n",
							    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), DWARF_REG_MAP(value));
						REG_STATE.cfa.reg = COMPAT_REG_MAP(value);
					} else {
						dbug_unwind(1, "map DW_CFA_def_cfa_register value %ld to reg_info idx %ld (%ld)\n",
							    value, DWARF_REG_MAP(value), DWARF_REG_MAP(value));
						REG_STATE.cfa.reg = value;
					}
				}
				break;
			case DW_CFA_def_cfa_expression: {
				const u8 *cfa_expr = ptr.p8;
				value = get_uleb128(&ptr.p8, end);
				/* Sanity check that cfa_expr falls completely
				   inside known data. */
				if (ptr.p8 < end && end - ptr.p8 >= value) {
					REG_STATE.cfa_is_expr = 1;
					REG_STATE.cfa_expr = cfa_expr;
					ptr.p8 += value;
					dbug_unwind(1, "DW_CFA_def_cfa_expression %lu@%p\n", value, cfa_expr);
				}
				else
					_stp_warn("BAD DW_CFA_def_cfa_expression value %lu\n", value);
				break;
			}
			/* Size of all arguments pushed on the stack. */
			case DW_CFA_GNU_args_size:
				get_uleb128(&ptr.p8, end);
				dbug_unwind(1, "DW_CFA_GNU_args_size\n");
				break;
			/* This is only produced by GCC before 2002.
			   Like DW_CFA_offset_extended_sf but using an
			   uleb128 that is subtracted from CFA.  */
			case DW_CFA_GNU_negative_offset_extended:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_GNU_negative_offset_extended value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_GNU_negative_offset_extended value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Memory,
						(uleb128_t)0 - get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_GNU_window_save:
			default:
				_stp_warn("unimplemented call frame instruction: 0x%x\n", *(ptr.p8 - 1));
				result = 0;
				break;
			}
			break;
		case 1:
			result = advance_loc(*ptr.p8++ & 0x3f, state);
			dbug_unwind(1, "DW_CFA_advance_loc\n");
			break;
		case 2:
			value = *ptr.p8++ & 0x3f;
			if (compat_task) {
				dbug_unwind(1, "map DW_CFA_offset value %ld to reg_info idx %ld\n",
					    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
				value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
			} else {
				dbug_unwind(1, "map DW_CFA_offset value %ld to reg_info idx %ld\n",
					    value, DWARF_REG_MAP(value));
				value = DWARF_REG_MAP(value);
			}
			value2 = get_uleb128(&ptr.p8, end);
			set_offset_rule(value, Memory,
					value2 * state->dataAlign, state);
			break;
		case 3:
			value = *ptr.p8++ & 0x3f;
			if (compat_task) {
				dbug_unwind(1, "map DW_CFA_restore value %ld to reg_info idx %ld\n",
					    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
				value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
			} else {
				dbug_unwind(1, "map DW_CFA_restore value %ld to reg_info idx %ld\n",
					    value, DWARF_REG_MAP(value));
				value = DWARF_REG_MAP(value);
			}
			if (value < ARRAY_SIZE(REG_STATE.regs))
				memcpy(&REG_STATE.regs[value], &state->cie_regs[value], sizeof(struct unwind_item));
			break;
		}
		dbug_unwind(1, "targetLoc=%lx state->loc=%lx\n", targetLoc, state->loc);
		dbug_unwind(1, "result: %d\n", result);
		if (ptr.p8 > end)
			result = 0;
		if (result && targetLoc != 0 && targetLoc < state->loc)
			return 1;
	}
	return result && ptr.p8 == end;
}

#ifdef DEBUG_UNWIND
static const char *_stp_enc_hi_name[] = {
	"DW_EH_PE",
	"DW_EH_PE_pcrel",
	"DW_EH_PE_textrel",
	"DW_EH_PE_datarel",
	"DW_EH_PE_funcrel",
	"DW_EH_PE_aligned"
};
static const char *_stp_enc_lo_name[] = {
	"_absptr",
	"_uleb128",
	"_udata2",
	"_udata4",
	"_udata8",
	"_sleb128",
	"_sdata2",
	"_sdata4",
	"_sdata8"
};
static char *_stp_eh_enc_name(signed type)
{
	static char buf[64];
	int hi, low;
	if (type == DW_EH_PE_omit)
		return "DW_EH_PE_omit";

	hi = (type & DW_EH_PE_ADJUST) >> 4;
	low = type & DW_EH_PE_FORM;
	if (hi > 5 || low > 4 || (low == 0 && (type & DW_EH_PE_signed))) {
	    snprintf(buf, sizeof(buf), "ERROR:encoding=0x%x", type);
		return buf;
	}

	buf[0] = 0;
	if (type & DW_EH_PE_indirect)
		strlcpy(buf, "DW_EH_PE_indirect|", sizeof(buf));
	strlcat(buf, _stp_enc_hi_name[hi], sizeof(buf));

	if (type & DW_EH_PE_signed)
		low += 4;
	strlcat(buf, _stp_enc_lo_name[low], sizeof(buf));
	return buf;
}
#endif /* DEBUG_UNWIND */

// If this is an address inside a module, adjust for section relocation
// and the elfutils base relocation done during loading of the .dwarf_frame
// in translate.cxx.
static unsigned long
adjustStartLoc (unsigned long startLoc,
		struct _stp_module *m,
		struct _stp_section *s,
		unsigned ptrType, int is_ehframe, int user)
{
  unsigned long vm_addr = 0;

  /* If we're unwinding the current module, then the addresses
     we've got don't require adjustment, they didn't come from user
     space */
  if(strcmp(THIS_MODULE->name,m->name)==0)
      return startLoc;

  /* XXX - some, or all, of this should really be done by
     _stp_module_relocate and/or read_pointer. */
  dbug_unwind(2, "adjustStartLoc=%lx, ptrType=%s, m=%s, s=%s eh=%d\n",
	      startLoc, _stp_eh_enc_name(ptrType), m->path, s->name, is_ehframe);
  if (startLoc == 0
      || strcmp (m->name, "kernel")  == 0
      || (strcmp (s->name, ".absolute") == 0 && !is_ehframe))
    return startLoc;

  /* eh_frame data has been loaded in the kernel, so readjust offset. */
  if (is_ehframe) {
    dbug_unwind(2, "eh_frame=%lx, eh_frame_addr=%lx\n", (unsigned long) m->eh_frame, m->eh_frame_addr);
    if ((ptrType & DW_EH_PE_ADJUST) == DW_EH_PE_pcrel) {
      startLoc -= (unsigned long) m->eh_frame;
      startLoc += m->eh_frame_addr;
    }
    /* User space exec */
    if (strcmp (s->name, ".absolute") == 0)
      return startLoc;
  }

  /* User space or kernel dynamic module. */
  if (user && strcmp (s->name, ".dynamic") == 0)
    stap_find_vma_map_info_user(current->group_leader, m, &vm_addr, NULL, NULL);
  else
    vm_addr = s->static_addr;

  if (is_ehframe)
    return startLoc + vm_addr;
  else
    return startLoc + vm_addr - s->sec_load_offset;

}

/* If we previously created an unwind header, then use it now to binary search */
/* for the FDE corresponding to pc. */
static u32 *_stp_search_unwind_hdr(unsigned long pc,
				   struct _stp_module *m,
				   struct _stp_section *s,
				   int is_ehframe, int user, int compat_task)
{
	const u8 *ptr, *end, *hdr = is_ehframe ? m->unwind_hdr: s->debug_hdr;
	uint32_t hdr_len = is_ehframe ? m->unwind_hdr_len : s->debug_hdr_len;
	unsigned long startLoc;
	u32 *fde = NULL;
	unsigned num, tableSize, t2;
	unsigned long eh_hdr_addr = m->unwind_hdr_addr;

	if (hdr == NULL || hdr_len < 4 || hdr[0] != 1) {
		_stp_warn("no or bad debug frame hdr\n");
		return NULL;
	}

	dbug_unwind(1, "binary search for %lx", pc);

	/* table_enc */
	switch (hdr[3] & DW_EH_PE_FORM) {
	case DW_EH_PE_absptr:
		if (!compat_task)
			tableSize = sizeof(unsigned long);
		else
			tableSize = sizeof(unsigned int);
		break;
	case DW_EH_PE_data2:
		tableSize = 2;
		break;
	case DW_EH_PE_data4:
		tableSize = 4;
		break;
	case DW_EH_PE_data8:
		tableSize = 8;
		break;
	default:
		_stp_warn("bad unwind table encoding");
		return NULL;
	}
	ptr = hdr + 4;
	end = hdr + hdr_len;
	{
		// XXX Can the header validity be checked just once?
		unsigned long eh = read_ptr_sect(&ptr, end, hdr[1], 0,
						 eh_hdr_addr, user, compat_task, tableSize);
		if ((hdr[1] & DW_EH_PE_ADJUST) == DW_EH_PE_pcrel)
			eh = eh - (unsigned long)hdr + eh_hdr_addr;
		if ((is_ehframe && eh != (unsigned long)m->eh_frame_addr)) {
			_stp_warn("eh_frame_ptr in eh_frame_hdr 0x%lx not valid; eh_frame_addr = 0x%lx", eh, (unsigned long)m->eh_frame_addr);
			return NULL;
		}
	}
	num = read_ptr_sect(&ptr, end, hdr[2], 0, eh_hdr_addr, user, compat_task, tableSize);
	if (num == 0 || num != (end - ptr) / (2 * tableSize)
	    || (end - ptr) % (2 * tableSize)) {
		_stp_warn("unwind Bad num=%d end-ptr=%ld 2*tableSize=%d",
			    num, (long)(end - ptr), 2 * tableSize);
		return NULL;
	}

	do {
		const u8 *cur = ptr + (num / 2) * (2 * tableSize);
		startLoc = read_ptr_sect(&cur, cur + tableSize, hdr[3], 0,
					 eh_hdr_addr, user, compat_task, tableSize);
		startLoc = adjustStartLoc(startLoc, m, s, hdr[3],
					  is_ehframe, user);
		if (pc < startLoc)
			num /= 2;
		else {
			ptr = cur - tableSize;
			num = (num + 1) / 2;
		}
	} while (startLoc && num > 1);

	if (num == 1
	    && (startLoc = adjustStartLoc(read_ptr_sect(&ptr, ptr + tableSize, hdr[3], 0,
							eh_hdr_addr, user, compat_task, tableSize),
					  m, s, hdr[3], is_ehframe, user)) != 0 && pc >= startLoc) {
		unsigned long off;
		off = read_ptr_sect(&ptr, ptr + tableSize, hdr[3],
				    0, eh_hdr_addr, user, compat_task, tableSize);
		dbug_unwind(1, "fde off=%lx\n", off);
		/* For real eh_frame_hdr the actual fde address is at the
		   new eh_frame load address. For our own debug_hdr created
		   table the fde is an offset into the debug_frame table. */
		if (is_ehframe)
			fde = off - m->eh_frame_addr + m->eh_frame;
		else
			fde = m->debug_frame + off;
	}

	dbug_unwind(1, "returning fde=%lx startLoc=%lx", (unsigned long) fde, startLoc);
	return fde;
}

#define FRAME_REG(r, t) (((t *)frame)[reg_info[r].offs])

#ifndef CONFIG_64BIT
# define CASES CASE(8); CASE(16); CASE(32)
#else
# define CASES CASE(8); CASE(16); CASE(32); CASE(64)
#endif

#define MAX_EXPR_STACK	8	/* arbitrary */

static int compute_expr(const u8 *expr, struct unwind_frame_info *frame,
			unsigned long *result, int user, int compat_task)
{
	/*
	 * We previously validated the length, so we won't read off the end.
	 * See sanity checks in set_expr() and for DW_CFA_def_cfa_expression.
	 */
	uleb128_t len = get_uleb128(&expr, (const u8 *) -1UL);
	const u8 *const start = expr;
	const u8 *const end = expr + len;

	long stack[MAX_EXPR_STACK]; /* stack slots are signed */
	unsigned int sp = 0;
#define PUSH(val) do { \
		if (sp == MAX_EXPR_STACK) \
			goto overflow; \
		stack[sp++] = (val); \
	} while (0)
#define POP ({ \
		if (sp == 0) \
			goto underflow; \
		stack[--sp]; \
	})
#define NEED(n)	do { \
		if (end - expr < (n)) \
			goto truncated; \
	} while (0)

	while (expr < end) {
		uleb128_t value;
		union {
			u8 u8;
			s8 s8;
			u16 u16;
			s16 s16;
			u32 u32;
			s32 s32;
			u64 u64;
			s64 s64;
		} u;
		const u8 op = *expr++;
		dbug_unwind(3, " expr op 0x%x (%ld left)\n", op, (long)(end - expr));
		switch (op) {
		case DW_OP_nop:
			break;

		case DW_OP_bra:
			if (POP == 0)
				break;
			/* Fall through.  */
		case DW_OP_skip:
			NEED(sizeof(u.s16));
			memcpy(&u.s16, expr, sizeof(u.s16));
			expr += sizeof(u.s16);
			if (u.s16 < 0 ?
			    unlikely(expr - start < -u.s16) :
			    unlikely(end - expr < u.s16)) {
				_stp_warn("invalid skip %d in CFI expression\n", (int) u.s16);
				return 1;
			}
			/*
			 * A backward branch could lead to an infinite loop.
			 * So punt it until we find we actually need it.
			 */
			if (u.s16 < 0) {
				_stp_warn("backward branch in CFI expression not supported\n");
				return 1;
			}
			expr += u.s16;
			break;

		case DW_OP_dup:
			value = POP;
			PUSH(value);
			PUSH(value);
			break;
		case DW_OP_drop:
			POP;
			break;
		case DW_OP_swap: {
			unsigned long tos = POP;
			unsigned long nos = POP;
			PUSH(tos);
			PUSH(nos);
			break;
		};

		case DW_OP_over:
			value = 1;
			goto pick;
		case DW_OP_pick:
			NEED(1);
			value = *expr++;
		pick:
			if (value >= sp)
				goto underflow;
			value = stack[sp - value];
			PUSH(value);
			break;

#define CONSTANT(type) \
			NEED(sizeof(u.type)); \
			memcpy(&u.type, expr, sizeof(u.type)); \
			expr += sizeof(u.type); \
			value = u.type; \
			PUSH(value); \
			break

		case DW_OP_addr:
			if (sizeof(unsigned long) == 8) { /* XXX 32/64!! */
				CONSTANT(u64);
			} else {
				CONSTANT(u32);
			}
			break;

		case DW_OP_const1u: CONSTANT(u8);
		case DW_OP_const1s: CONSTANT(s8);
		case DW_OP_const2u: CONSTANT(u16);
		case DW_OP_const2s: CONSTANT(s16);
		case DW_OP_const4u: CONSTANT(u32);
		case DW_OP_const4s: CONSTANT(s32);
		case DW_OP_const8u: CONSTANT(u64);
		case DW_OP_const8s: CONSTANT(s64);

#undef	CONSTANT

		case DW_OP_constu:
			value = get_uleb128(&expr, end);
			PUSH(value);
			break;
		case DW_OP_consts:
			value = get_sleb128(&expr, end);
			PUSH(value);
			break;

		case DW_OP_lit0 ... DW_OP_lit31:
			PUSH(op - DW_OP_lit0);
			break;

		case DW_OP_plus_uconst:
			value = get_uleb128(&expr, end);
			PUSH(value + POP);
			break;

#define BINOP(name, operator)				\
			case DW_OP_##name: {		\
				long b = POP;		\
				long a = POP;		\
				PUSH(a operator b);	\
			} break

			BINOP(eq, ==);
			BINOP(ne, !=);
			BINOP(ge, >=);
			BINOP(gt, >);
			BINOP(le, <=);
			BINOP(lt, <);

			BINOP(and, &);
			BINOP(or, |);
			BINOP(xor, ^);
			BINOP(plus, +);
			BINOP(minus, -);
			BINOP(mul, *);
			BINOP(shl, <<);
			BINOP(shra, >>);
#undef	BINOP

		case DW_OP_mod: {
			unsigned long b = POP;
			unsigned long a = POP;
			if (b == 0)
				goto divzero;
			PUSH (a % b);
			break;
		}

		case DW_OP_div: {
			long b = POP;
			long a = POP;
			if (b == 0)
				goto divzero;
			PUSH (a / b);
			break;
		}

		case DW_OP_shr: {
			unsigned long b = POP;
			unsigned long a = POP;
			PUSH (a >> b);
			break;
		}

		case DW_OP_not:
			PUSH(~ POP);
			break;
		case DW_OP_neg:
			PUSH(- POP);
			break;
		case DW_OP_abs:
			value = POP;
			value = abs(value);
			PUSH(value);
			break;

		case DW_OP_bregx:
			value = get_uleb128(&expr, end);
			goto breg;
		case DW_OP_breg0 ... DW_OP_breg31:
			value = op - DW_OP_breg0;
		breg:
			if (compat_task) {
				dbug_unwind(1, "map DW_OP_breg value %ld to reg_info idx %ld\n",
					    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
				value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
			} else {
				dbug_unwind(1, "map DW_OP_breg value %ld to reg_info idx %ld\n",
					    value, DWARF_REG_MAP(value));
				value = DWARF_REG_MAP(value);
			}
			if (unlikely(value >= ARRAY_SIZE(reg_info))) {
				_stp_warn("invalid register number %lu in CFI expression\n", value);
				return 1;
			} else {
				sleb128_t offset = get_sleb128(&expr, end);
				value = FRAME_REG(value, unsigned long);
				PUSH(value + offset);
			}
			break;

		case DW_OP_deref:
			value = sizeof(long); /* XXX 32/64!! */
			goto deref;
		case DW_OP_deref_size:
			NEED(1);
			value = *expr++;
			if (unlikely(value > sizeof(stack[0]))) {
			bad_deref_size:
				_stp_warn("invalid DW_OP_deref_size %lu in CFI expression\n", value);
				return 1;
			}
		deref: {
				unsigned long addr = POP;
				switch (value) {
#define CASE(n)     		case sizeof(u##n):			\
					if (unlikely(_stp_read_address(value, (u##n *)addr, \
						                       (user ? USER_DS : KERNEL_DS)))) \
						goto copy_failed;	\
					break
					CASES;
#undef CASE
				default:
					goto bad_deref_size;
				}
			}
			break;

		case DW_OP_rot:
		default:
			_stp_warn("unimplemented CFI expression operation: 0x%x\n", op);
			return 1;
		}
	}

	*result = POP;
	return 0;

copy_failed:
	_stp_warn("_stp_read_address failed to access memory for deref\n");
	return 1;
truncated:
	_stp_warn("invalid (truncated) DWARF expression in CFI\n");
	return 1;
overflow:
	_stp_warn("DWARF expression stack overflow in CFI\n");
	return 1;
underflow:
	_stp_warn("DWARF expression stack underflow in CFI\n");
	return 1;
divzero:
	_stp_warn("DWARF expression stack divide by zero in CFI\n");
	return 1;

#undef	NEED
#undef	PUSH
#undef	POP
}

/* Unwind to previous to frame.  Returns 0 if successful, negative
 * number in case of an error.  A positive return means unwinding is finished;
 * don't try to fallback to dumping addresses on the stack. */
static int unwind_frame(struct unwind_context *context,
			struct _stp_module *m, struct _stp_section *s,
			void *table, uint32_t table_len, int is_ehframe,
			int user, int compat_task)
{
	const u32 *fde = NULL, *cie = NULL;
	/* The start and end of the CIE CFI instructions. */
	const u8 *cieStart = NULL, *cieEnd = NULL;
	/* The start and end of the FDE CFI instructions. */
	const u8 *fdeStart = NULL, *fdeEnd = NULL;
	struct unwind_frame_info *frame = &context->info;
	unsigned long pc = UNW_PC(frame) - frame->call_frame;
	unsigned long startLoc = 0, endLoc = 0, locRange = 0, cfa;
	unsigned i;
	signed ptrType = -1, call_frame = 1;
	uleb128_t retAddrReg = 0;
	struct unwind_state *state = &context->state;
	unsigned long addr;

	if (unlikely(table_len == 0)) {
		// Don't _stp_warn about this, debug_frame and/or eh_frame
		// might actually not be there.
		dbug_unwind(1, "Module %s: no unwind frame data", m->path);
		goto err;
	}
	if (unlikely(table_len & (sizeof(*fde) - 1))) {
		_stp_warn("Module %s: frame_len=%d", m->path, table_len);
		goto err;
	}

	/* Sets all rules to default Same value. */
	memset(state, 0, sizeof(*state));

	/* All "fake" dwarf registers should start out Nowhere. */
	for (i = UNW_NR_REAL_REGS; i < ARRAY_SIZE(REG_STATE.regs); ++i)
		set_no_state_rule(i, Nowhere, state);

	fde = _stp_search_unwind_hdr(pc, m, s, is_ehframe, user, compat_task);
	dbug_unwind(1, "%s: fde=%lx\n", m->path, (unsigned long) fde);

	/* found the fde, now set startLoc and endLoc */
	if (fde != NULL && is_fde(fde, table, table_len, is_ehframe)) {
		cie = cie_for_fde(fde, table, table_len, is_ehframe);
		dbug_unwind(1, "%s: cie=%lx\n", m->path, (unsigned long) cie);
		if (likely(cie != NULL)) {
			if (parse_fde_cie(fde, cie, table, table_len,
					  &ptrType, user,
					  &startLoc, &locRange,
					  &fdeStart, &fdeEnd,
					  &cieStart, &cieEnd,
					  &state->codeAlign,
					  &state->dataAlign,
					  &retAddrReg,
					  &call_frame,
					  compat_task) < 0)
				goto err;
			startLoc = adjustStartLoc(startLoc, m, s, ptrType, is_ehframe, user);
			endLoc = startLoc + locRange;
			dbug_unwind(1, "startLoc: %lx, endLoc: %lx\n", startLoc, endLoc);
			if (pc > endLoc) {
				dbug_unwind(1, "pc (%lx) > endLoc(%lx)\n", pc, endLoc);
				goto done;
			}
		} else {
			_stp_warn("fde found in header, but cie is bad!\n");
			fde = NULL;
		}
	} else if ((is_ehframe ? m->unwind_hdr: s->debug_hdr) == NULL) {
	    /* Only do a linear search if there isn't a search header.
	       There always should be one, we create it in the translator
	       if it didn't exist. These should never be missing except
	       when there are toolchain bugs. */
	    unsigned long tableSize;
	    _stp_warn("No binary search table for %s frame, doing slow linear search for %s\n", (is_ehframe ? "eh" : "debug"), m->path);
	    for (fde = table, tableSize = table_len; cie = NULL, tableSize > sizeof(*fde)
		 && tableSize - sizeof(*fde) >= *fde; tableSize -= sizeof(*fde) + *fde, fde += 1 + *fde / sizeof(*fde)) {
			dbug_unwind(3, "fde=%lx tableSize=%d\n", (long)*fde, (int)tableSize);
			if (!is_fde(fde, table, table_len, is_ehframe))
				continue;
			cie = cie_for_fde(fde, table, table_len, is_ehframe);
			if (cie == NULL
			    || parse_fde_cie(fde, cie, table, table_len,
					     &ptrType, user,
					     &startLoc, &locRange,
					     &fdeStart, &fdeEnd,
					     &cieStart, &cieEnd,
					     &state->codeAlign,
					     &state->dataAlign,
					     &retAddrReg,
					     &call_frame, compat_task) < 0)
				break;
			startLoc = adjustStartLoc(startLoc, m, s, ptrType, is_ehframe, user);
			if (!startLoc)
				continue;
			endLoc = startLoc + locRange;
// removal because this is a way of checking if the next fde is in range, if the fde's aren't sorted (which is why we're doing a linear search in the first place, than this check is bogus
                        /*if (pc > endLoc) {
                                dbug_unwind(1, "pc (%lx) > endLoc(%lx)\n", pc, endLoc);
				goto done;
				}*/
			dbug_unwind(3, "endLoc=%lx\n", endLoc);
			if (pc >= startLoc && pc < endLoc)
				break;
		}
	}

	dbug_unwind(1, "cie=%lx fde=%lx startLoc=%lx endLoc=%lx, pc=%lx\n",
                    (unsigned long) cie, (unsigned long)fde, (unsigned long) startLoc, (unsigned long) endLoc, pc);
	if (cie == NULL || fde == NULL)
		goto err;

	/* found the CIE and FDE */

	// Sanity check return address register value.
	if (retAddrReg >= ARRAY_SIZE(reg_info)
	    || REG_INVALID(retAddrReg)
	    || reg_info[retAddrReg].width != sizeof(unsigned long)) {
		_stp_warn("Bad retAddrReg value\n");
		goto err;
	}

	frame->call_frame = call_frame;
	state->stackDepth = 0;
	state->loc = startLoc;
	memcpy(&REG_STATE.cfa, &badCFA, sizeof(REG_STATE.cfa));

	/* Common Information Entry (CIE) instructions. */
	dbug_unwind (1, "processCFI for CIE\n");
	if (!processCFI(cieStart, cieEnd, 0, ptrType, user, state, compat_task))
		goto err;

	/* Store initial state registers for use with DW_CFA_restore... */
	memcpy(&state->cie_regs, &REG_STATE.regs, sizeof (REG_STATE.regs));

	/* Process Frame Description Entry (FDE) instructions. */
	dbug_unwind (1, "processCFI for FDE\n");
	if (!processCFI(fdeStart, fdeEnd, pc, ptrType, user, state, compat_task)
	    || state->loc > endLoc
	    || REG_STATE.regs[retAddrReg].where == Nowhere)
		goto err;

	/* update frame */
	if (REG_STATE.cfa_is_expr) {
		if (compute_expr(REG_STATE.cfa_expr, frame, &cfa, user, compat_task))
			goto err;
	}
	else {
		// We expect the offset to be a multiple of the address size
		if(REG_STATE.cfa.reg >= ARRAY_SIZE(reg_info)
		   || reg_info[REG_STATE.cfa.reg].width != sizeof(unsigned long)
		   || REG_STATE.cfa.off % (sizeof(unsigned long)/2))
			goto err;

		dbug_unwind(1, "cfa reg=%ld, off=%lx\n",
			    REG_STATE.cfa.reg, REG_STATE.cfa.off);
		cfa = FRAME_REG(REG_STATE.cfa.reg, unsigned long) + REG_STATE.cfa.off;
	}
	startLoc = min((unsigned long)UNW_SP(frame), cfa);
	endLoc = max((unsigned long)UNW_SP(frame), cfa);
	dbug_unwind(1, "cfa=%lx startLoc=%lx, endLoc=%lx\n", cfa, startLoc, endLoc);
	if (STACK_LIMIT(startLoc) != STACK_LIMIT(endLoc)) {
		startLoc = min(STACK_LIMIT(cfa), cfa);
		endLoc = max(STACK_LIMIT(cfa), cfa);
		dbug_unwind(1, "cfa startLoc=%lx, endLoc=%lx\n",
                            (unsigned long)startLoc, (unsigned long)endLoc);
	}
	dbug_unwind(1, "cie=%lx fde=%lx\n", (unsigned long) cie, (unsigned long) fde);
	for (i = 0; i < ARRAY_SIZE(REG_STATE.regs); ++i) {
		if (REG_INVALID(i)) {
			if (REG_STATE.regs[i].where == Nowhere)
				continue;
			_stp_warn("REG_INVALID %d\n", i);
			goto err;
		}
		dbug_unwind(2, "register %d. where=%d\n", i, REG_STATE.regs[i].where);
		switch (REG_STATE.regs[i].where) {
		default:
			break;
		case Register:
			if (REG_STATE.regs[i].state.reg >= ARRAY_SIZE(reg_info)
			    || REG_INVALID(REG_STATE.regs[i].state.reg)
			    || reg_info[i].width > reg_info[REG_STATE.regs[i].state.reg].width) {
				_stp_warn("case Register bad\n");
				goto err;
			}
			switch (reg_info[REG_STATE.regs[i].state.reg].width) {
#define CASE(n) \
			case sizeof(u##n): \
				REG_STATE.regs[i].state.reg = FRAME_REG(REG_STATE.regs[i].state.reg, \
				                                const u##n); \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register size\n");
				goto err;
			}
			break;
		}
	}
	for (i = 0; i < ARRAY_SIZE(REG_STATE.regs); ++i) {
		dbug_unwind(2, "register %d. invalid=%d\n", i, REG_INVALID(i));
		if (REG_INVALID(i))
			continue;
		dbug_unwind(2, "register %d. where=%d\n", i, REG_STATE.regs[i].where);

#if (UNW_SP_FROM_CFA == 1)
		if (i == UNW_SP_IDX) {
			UNW_SP(frame) = cfa;
			continue;
		}
#endif

#if (UNW_PC_FROM_RA == 1)
		if (i == UNW_PC_IDX) {
			UNW_PC(frame) = FRAME_REG(retAddrReg, unsigned long);
			continue;
		}
#endif

		switch (REG_STATE.regs[i].where) {
		case Same:
			/* Preserve register from current frame. */
			break;
		case Nowhere:
			switch (reg_info[i].width) {
#define CASE(n) case sizeof(u##n): \
				FRAME_REG(i, u##n) = 0; \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register size (Nowhere)\n");
				goto err;
			}
			break;
		case Register:
			switch (reg_info[i].width) {
#define CASE(n) case sizeof(u##n): \
				FRAME_REG(i, u##n) = REG_STATE.regs[i].state.reg; \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register size (Register)\n");
				goto err;
			}
			break;
		case Expr:
			if (compute_expr(REG_STATE.regs[i].state.expr, frame, &addr, user, compat_task))
				goto err;
			goto memory;
		case ValExpr:
			if (compute_expr(REG_STATE.regs[i].state.expr, frame, &addr, user, compat_task))
				goto err;
			goto value;
		case Value:
			addr = cfa + REG_STATE.regs[i].state.off;
		value:
			if (reg_info[i].width != sizeof(unsigned long)) {
				_stp_warn("bad Register width for value state\n");
				goto err;
			}
			FRAME_REG(i, unsigned long) = addr;
			break;
		case Memory:
			addr = cfa + REG_STATE.regs[i].state.off;
		memory:
			dbug_unwind(2, "addr=%lx width=%d\n", addr, reg_info[i].width);
			/* We only want the lower half of the address defined, however
			   _stp_read_address will sometimes return garbage in the top half.
			   for 32-on-64 bit unwinding we need to ensure this is 0xFFFFFFFF */
			switch (reg_info[i].width) {
#define CASE(n)     case sizeof(u##n):					\
				if (unlikely(_stp_read_address(FRAME_REG(i, u##n), (u##n *)addr, \
							       (user ? USER_DS : KERNEL_DS)))) \
					goto copy_failed;		\
				if (compat_task) FRAME_REG(i, u##n) &= 0xFFFFFFFF; \
				dbug_unwind(1, "set register %d to %lx\n", i, (long)FRAME_REG(i,u##n)); \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register width\n");
				goto err;
			}
			break;
		}
	}
	dbug_unwind(1, "returning 0 (%llx)\n",
		    (unsigned long long) UNW_PC(frame));
	return 0;

copy_failed:
	_stp_warn("_stp_read_address failed to access memory location\n");
err:
	return -EIO;

done:
	/* PC was in a range convered by a module but no unwind info */
	/* found for the specific PC. This seems to happen only for kretprobe */
	/* trampolines and at the end of interrupt backtraces. */
	return 1;
#undef CASES
#undef FRAME_REG
}

static int unwind(struct unwind_context *context, int user)
{
	struct _stp_module *m;
	struct _stp_section *s = NULL;
	struct unwind_frame_info *frame = &context->info;
	unsigned long pc = UNW_PC(frame) - frame->call_frame;
	int res;
        const char *module_name = 0;
	/* compat_task is a flag for 32bit process unwinding on a 64-bit
	   architecture.  If this flag is set, it means a mapping of
	   register numbers is required, as well as being aware of 32-bit
	   values on 64-bit registers. */
	int compat_task = _stp_is_compat_task();

	dbug_unwind(1, "pc=%lx, %llx", pc,
		    (unsigned long long) UNW_PC(frame));

	if (UNW_PC(frame) == 0)
		return -EINVAL;

	if (user)
	  {
	    m = _stp_umod_lookup (pc, current, & module_name, NULL, NULL);
	    if (m)
	      s = &m->sections[0];
	  }
	else
          {
            m = _stp_kmod_sec_lookup (pc, &s);
            if (!m) {
#ifdef STAPCONF_MODULE_TEXT_ADDRESS
                struct module *ko;
                preempt_disable();
                ko = __module_text_address (pc);
                if (ko) { module_name = ko->name; }
                else {
                  /* Possible heuristic: we could assume we're talking
                     about the kernel.  If __kernel_text_address()
                     were SYMBOL_EXPORT'd, we could call that and be
                     more sure. */
                }
                preempt_enable_no_resched();
#endif
            }
          }

	if (unlikely(m == NULL)) {
                // some heuristics for the module name; we can't call
                // kernel_text_address or friends from this context.
                if (! module_name && (unsigned long)pc > PAGE_OFFSET)
                        module_name = "kernel";
                _stp_warn ("Missing unwind data for a module, rerun with 'stap -d %s'\n",
                           module_name ?: "(unknown; retry with -DDEBUG_UNWIND)");
		// Don't _stp_warn including the pc#, since it'll defeat warning deduplicator
		dbug_unwind(1, "No module found for pc=%lx", pc);
		return -EINVAL;
	}

	dbug_unwind(1, "trying debug_frame\n");
	res = unwind_frame (context, m, s, m->debug_frame,
			    m->debug_frame_len, 0, user, compat_task);
	if (res != 0) {
	  dbug_unwind(1, "debug_frame failed: %d, trying eh_frame\n", res);
	  res = unwind_frame (context, m, s, m->eh_frame,
			      m->eh_frame_len, 1, user, compat_task);
	}

        /* This situation occurs where some unwind data was found, but
           it was lacking somehow.  */
        if (res != 0) {
                dbug_unwind (2, "unwinding failed: %d\n", res);
        }

	return res;
}
