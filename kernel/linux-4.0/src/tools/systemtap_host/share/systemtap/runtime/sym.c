/* -*- linux-c -*- 
 * Symbolic Lookup Functions
 * Copyright (C) 2005-2014 Red Hat Inc.
 * Copyright (C) 2006 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_SYM_C_
#define _STP_SYM_C_

#include "sym.h"
#include "vma.c"
#include "stp_string.c"
#ifdef STP_NEED_LINE_DATA
#include "unwind/unwind.h"
#endif
#include <asm/unaligned.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/module.h>
#ifdef STAPCONF_PROBE_KERNEL
#include <linux/uaccess.h>
#endif

/* Returns absolute address of offset into kernel module/section.
   Returns zero when module and section couldn't be found
   (aren't in memory yet). */
static unsigned long _stp_kmodule_relocate(const char *module,
					   const char *section,
					   unsigned long offset)
{
  unsigned i, j;

  dbug_sym(1, "%s, %s, %lx\n", module, section, offset);

  /* absolute, unrelocated address */
  if (!module || !strcmp(section, "")
      ||_stp_num_modules == 0) {
    return offset;
  }

  for (i = 0; i < _stp_num_modules; i++) {
    struct _stp_module *m = _stp_modules[i];
    if (strcmp(module, m->name)) /* duplication apprx. not possible for kernel */
      continue;

    for (j = 0; j < m->num_sections; j++) {
      struct _stp_section *s = &m->sections[j];
      if (!strcmp(section, s->name)) {
	/* mod and sec name match. tsk should match dynamic/static. */
	if (s->static_addr != 0) {
	  unsigned long addr = offset + s->static_addr;
	  dbug_sym(1, "address=%lx\n", addr);
	  return addr;
	} else {
	  /* static section, not in memory yet? */
	  dbug_sym(1, "section %s, not in memory yet?", s->name);
	  return 0;
	}
      }
    }
  }

  return 0;
}

static unsigned long _stp_umodule_relocate(const char *path,
					   unsigned long offset,
					   struct task_struct *tsk)
{
  unsigned i;
  unsigned long vm_start = 0;

  dbug_sym(1, "[%d] %s, %lx\n", tsk->pid, path, offset);

  for (i = 0; i < _stp_num_modules; i++) {
    struct _stp_module *m = _stp_modules[i];

    if (strcmp(path, m->path)
        || m->num_sections != 1)
      continue;

    if (!strcmp(m->sections[0].name, ".absolute"))
      return offset;
    if (strcmp(m->sections[0].name, ".dynamic"))
      continue;

    if (stap_find_vma_map_info_user(tsk->group_leader, m,
				    &vm_start, NULL, NULL) == 0) {
      offset += vm_start;
      dbug_sym(1, "address=%lx\n", offset);
      return offset;
    }
  }

  return 0;
}

/* Return (kernel) module owner and, if sec != NULL, fills in closest
   section of the address if found, return NULL otherwise. */
static struct _stp_module *_stp_kmod_sec_lookup(unsigned long addr,
						struct _stp_section **sec)
{
  unsigned midx = 0;

  for (midx = 0; midx < _stp_num_modules; midx++)
    {
      unsigned secidx;
      for (secidx = 0; secidx < _stp_modules[midx]->num_sections; secidx++)
	{
	  unsigned long sec_addr;
	  unsigned long sec_size;
	  sec_addr = _stp_modules[midx]->sections[secidx].static_addr;
	  sec_size = _stp_modules[midx]->sections[secidx].size;
	  if (addr >= sec_addr && addr < sec_addr + sec_size)
            {
	      if (sec)
		*sec = & _stp_modules[midx]->sections[secidx];
	      return _stp_modules[midx];
	    }
	}
      }
  return NULL;
}

/* Return (user) module in which the the given addr falls.  Returns
   NULL when no module can be found that contains the addr.  Fills in
   vm_start (addr where module is mapped in) and (base) name of module
   when given.  Note that user modules always have exactly one section
   (.dynamic or .absolute). */
static struct _stp_module *_stp_umod_lookup(unsigned long addr,
					    struct task_struct *task,
					    const char **name,
					    unsigned long *vm_start,
					    unsigned long *vm_end)
{
  void *user = NULL;
#ifdef CONFIG_COMPAT
        /* Handle 32bit signed values in 64bit longs, chop off top bits. */
        if (test_tsk_thread_flag(task, TIF_32BIT))
          addr &= ((compat_ulong_t) ~0);
#endif
  if (stap_find_vma_map_info(task->group_leader, addr,
			     vm_start, vm_end, name, &user) == 0)
    if (user != NULL)
      {
	struct _stp_module *m = (struct _stp_module *)user;
	dbug_sym(1, "found module %s at 0x%lx\n", m->path,
		 vm_start ? *vm_start : 0);
	return m;
      }
  return NULL;
}

static const char *_stp_kallsyms_lookup(unsigned long addr,
                                        unsigned long *symbolsize,
                                        unsigned long *offset, 
                                        const char **modname, 
                                        /* char ** secname? */
					struct task_struct *task)
{
	struct _stp_module *m = NULL;
	struct _stp_section *sec = NULL;
	struct _stp_symbol *s = NULL;
	unsigned end, begin = 0;
	unsigned long rel_addr = 0;

	if (addr == 0)
	  return NULL;

	if (task)
	  {
	    unsigned long vm_start = 0;
	    unsigned long vm_end = 0;
#ifdef CONFIG_COMPAT
        /* Handle 32bit signed values in 64bit longs, chop off top bits.
           _stp_umod_lookup does the same, but we need it here for the
           binary search on addr below. */
        if (test_tsk_thread_flag(task, TIF_32BIT))
          addr &= ((compat_ulong_t) ~0);
#endif
	    m = _stp_umod_lookup(addr, task, modname, &vm_start, &vm_end);
	    if (m)
	      {
		sec = &m->sections[0];
		/* XXX .absolute sections really shouldn't be here... */
		if (strcmp(".dynamic", m->sections[0].name) == 0)
		  rel_addr = addr - vm_start;
		else
		  rel_addr = addr;
	      }
	    if (modname && *modname)
	      {
		/* In case no symbol is found, fill in based on module. */
		if (offset)
		  *offset = addr - vm_start;
		if (symbolsize)
		  *symbolsize = vm_end - vm_start;
	      }
	  }
	else
	  {
	    m = _stp_kmod_sec_lookup(addr, &sec);
	    if (m)
	      {
	        rel_addr = addr - sec->static_addr;
		if (modname)
		  *modname = m->name;
	      }
	  }

        if (unlikely (m == NULL || sec == NULL))
          return NULL;
        
        /* NB: relativize the address to the section. */
        addr = rel_addr;
	end = sec->num_symbols;

	/* binary search for symbols within the module */
	do {
		unsigned mid = (begin + end) / 2;
		if (addr < sec->symbols[mid].addr)
			end = mid;
		else
			begin = mid;
	} while (begin + 1 < end);
	/* result index in $begin */

	s = & sec->symbols[begin];
	if (likely(addr >= s->addr)) {
		if (offset)
			*offset = addr - s->addr;
                /* We could also pass sec->name here. */
		if (symbolsize) {
			if ((begin + 1) < sec->num_symbols)
				*symbolsize = sec->symbols[begin + 1].addr - s->addr;
			else
				*symbolsize = 0;
			// NB: This is only a heuristic.  Sometimes there are large
			// gaps between text areas of modules.
		}
		return s->symbol;
	}
	return NULL;
}

#ifdef STP_NEED_LINE_DATA
static void _stp_filename_lookup(struct _stp_module *mod, char ** filename,
                                 uint8_t *dirsecp, uint8_t *enddirsecp,
                                 unsigned fileidx, int user, int compat_task)
{
  uint8_t *linep = dirsecp;
  static char fullpath [MAXSTRINGLEN];
  char *dirname_entry = NULL, *filename_entry = NULL;
  unsigned diridx = 0, i, j;

  // skip past the directory table in the debug_line info
  while (*linep != 0 && linep < enddirsecp)
    {
      char *entry = (char *) linep;
      uint8_t *endnamep = (uint8_t *) memchr (entry, '\0', (size_t) (enddirsecp-linep));
      if (endnamep == NULL || (endnamep + 1) > enddirsecp)
        return;
      linep = endnamep + 1;
    }

  if ((char) linep[0] != '\0')
    return;
  ++linep;

  // at the filename table
  for (i = 1; *linep != 0 && linep < enddirsecp; ++i)
    {
      uint8_t *endnamep = NULL;
      filename_entry = (char *) linep;
      endnamep = (uint8_t *) memchr (filename_entry, '\0', (size_t) (enddirsecp-linep));
      if (endnamep == NULL || (endnamep + 1) > enddirsecp)
        return;

      // move the line pointer past the file name. account for the null byte
      linep = endnamep + 1;

      // save the directory index
      diridx = read_pointer ((const uint8_t **) &linep, enddirsecp, DW_EH_PE_leb128, user, compat_task);

      if (linep > enddirsecp)
        return;
      if (i == fileidx)
        break;

      filename_entry = NULL;

      // modification time
      read_pointer ((const uint8_t **) &linep, enddirsecp, DW_EH_PE_leb128, user, compat_task);
      // length of a file
      read_pointer ((const uint8_t **) &linep, enddirsecp, DW_EH_PE_leb128, user, compat_task);
      // check that nothing went wrong with reading the ulebs
      if (linep > enddirsecp)
        return;
    }

  if (filename_entry == NULL)
    return; // return just the linenumber

  // if  dirid == 0, it's the compilation directory. otherwise retrieve the
  // directory path if the file path was relative
  if (diridx != 0 && filename_entry[0] != '/')
    {
      linep = dirsecp;
      for (j = 1; *linep != 0 && linep < enddirsecp; j++)
        {
          uint8_t *endnamep = NULL;
          dirname_entry = (char *) linep;
          endnamep = (uint8_t *) memchr (dirname_entry, '\0', (size_t) (enddirsecp-linep));
          if (endnamep == NULL || (endnamep + 1) > enddirsecp)
            return;

          if (j == diridx)
            break;

          dirname_entry = NULL;
          linep = endnamep + 1;
        }

      if (dirname_entry == NULL)
        return;
    }

  // bring it all together
  // the filename was the full path
  if (filename_entry[0] == '/')
    *filename = filename_entry;
  // relative filename, and the dir corresponds to the compilation dir
  else if (diridx == 0)
    {
      char *slash = strrchr (mod->path, '/');
      strlcpy(fullpath, mod->path, (size_t) (2 + slash - mod->path));
      strlcat(fullpath, filename_entry, MAXSTRINGLEN);
      *filename = fullpath;
    }
  // relative filename and a directory from the table in the debug line data
  else
    {
      strlcpy(fullpath, dirname_entry, MAXSTRINGLEN);
      strlcat(fullpath, "/", MAXSTRINGLEN);
      strlcat(fullpath, filename_entry, MAXSTRINGLEN);
      *filename = fullpath;
    }
}

#endif /* STP_NEED_LINE_DATA */

unsigned long _stp_linenumber_lookup(unsigned long addr, struct task_struct *task, char ** filename, int need_filename)
{
  struct _stp_module *m;
  struct _stp_section *sec;
  const char *modname = NULL;
  uint8_t *linep, *enddatap;
  int compat_task = _stp_is_compat_task();
  int user = (task ? 1 : 0);

// the portion below is encased in this conditional because some of the functions
// and constants needed are encased in a similar condition
#ifdef STP_NEED_LINE_DATA
  if (addr == 0)
      return 0;

  if (task)
    {
	    unsigned long vm_start = 0;
	    unsigned long vm_end = 0;
#ifdef CONFIG_COMPAT
      /* Handle 32bit signed values in 64bit longs, chop off top bits. */
      if (test_tsk_thread_flag(task, TIF_32BIT))
        addr &= ((compat_ulong_t) ~0);
#endif
	    m = _stp_umod_lookup(addr, task, &modname, &vm_start, &vm_end);
    }
  else
    m = _stp_kmod_sec_lookup(addr, &sec);

  if (m == NULL || m->debug_line == NULL)
    return 0;

  // if addr is a kernel address, it will need to be adjusted
  if (!task)
    {
      int i;
      unsigned long offset = 0;
      // have to factor in the load_offset of (specifically) the .text section
      for (i=0; i<m->num_sections; i++)
        if (!strcmp(m->sections[i].name, ".text"))
          {
            offset = (m->sections[i].static_addr - m->sections[i].sec_load_offset);
            break;
          }

      if (addr < offset)
        return 0;
      addr = addr - offset;
    }


  linep = m->debug_line;
  enddatap = m->debug_line + m->debug_line_len;

  while (linep < enddatap)
    {
      // State machine "curr" values are updated directly.
      // A "row" is committed line data that we should compare against, only
      // updated for DW_LNS_copy, DW_LNE_end_sequence, and special opcodes.
      uint64_t curr_addr = 0, row_addr = 0;
      unsigned int curr_file_idx = 1, row_file_idx = 1;
      unsigned long curr_linenum = 1, row_linenum = 1;
      unsigned int row_end_sequence = 1;

      unsigned int length = 4;
      unsigned int skip_to_seq_end = 0, op_index = 0;
      uint64_t unit_length, hdr_length;
      uint8_t *endunitp, *endhdrp, *dirsecp, *stdopcode_lens_secp;
      uint16_t version;
      uint8_t opcode_base, line_range, min_instr_len = 0, max_ops = 1;
      int8_t line_base;

      unit_length = (uint64_t) read_pointer ((const uint8_t **) &linep, enddatap, DW_EH_PE_data4, user, compat_task);
      if (unit_length == 0xffffffff)
        {
          if (unlikely (linep + 8 > enddatap))
            return 0;
          unit_length = (uint64_t) read_pointer ((const uint8_t **) &linep, enddatap, DW_EH_PE_data8, user, compat_task);
          length = 8;
        }
      if (unit_length < (length + 2) || (linep + unit_length) > enddatap)
        return 0;

      endunitp = linep + unit_length;

      version = read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_data2, user, compat_task);

      if (length == 4)
        hdr_length = (uint64_t) read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_data4, user, compat_task);
      else
        hdr_length = (uint64_t) read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_data8, user, compat_task);

      if ((linep + hdr_length) > endunitp || hdr_length < (version >= 4 ? 6 : 5))
        return 0;

      endhdrp = linep + hdr_length;

      // minimum instruction length
      min_instr_len = *linep++;
      // max operations per instruction
      if (version >= 4)
        {
          max_ops = *linep++;
          if (max_ops == 0)
              return 0; // max operations per instruction is supposed to > 0;
        }
      // default value of the is_stmt register
      ++linep;
      // line base. this is a signed value.
      line_base = *linep++;
      // line range
      line_range = *linep++;
      if (line_range == 0)
        return 0;
      // opcode base
      opcode_base = *linep++;
      // opcodes
      stdopcode_lens_secp = linep - 1;
      // need this check if the header length check covers this region?
      if ((linep + opcode_base - 1) >= endhdrp)
        return 0;
      linep += opcode_base - 1;

      // at the directory table. don't need an other information from the header
      // in order to find the desired line number, so we will save a pointer to
      // this point and skip ahead to the end of the header. this portion of the
      // header will be visited again after a line number has been found if a
      // filename is needed.
      dirsecp = linep;
      linep = endhdrp;

      // iterating through the opcodes. will deal with three defined types of
      // opcode: special, extended and standard. there is also a portion at
      // the end of this loop that will deal with unknown (standard) opcodes.
      while (linep < endunitp)
        {
          uint8_t opcode = *linep++;
          long addr_adv = 0;
          unsigned int commit_row = 0;
          unsigned int end_sequence = 0;

          if (opcode >= opcode_base) // special opcode
            {
              // line range was checked before this point. this variable is not altered after it is initialized.
              curr_linenum += (line_base + ((opcode - opcode_base) % line_range));
              addr_adv = ((opcode - opcode_base) / line_range);
              commit_row = 1;
            }

          else if (opcode == 0) // extended opcode
            {
              int len;
              uint8_t subopcode;

              if (linep + 1 > endunitp)
                return 0;

              len = *linep++;
              if (linep + len > endunitp || len < 1)
                return 0;

              subopcode = *linep++; // the sub opcode
              switch (subopcode)
                {
                  case DW_LNE_end_sequence:
                    // NB: we don't clear "curr" values until after the row is compared.
                    op_index = 0;
                    skip_to_seq_end = 0;
                    end_sequence = 1;
                    commit_row = 1;
                    break;
                  case DW_LNE_set_address:
                    if ((len - 1) == 4) // account for the opcode (the -1)
                      curr_addr = (uint64_t) read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_data4, user, compat_task);
                    else if ((len - 1) == 8)
                      curr_addr = (uint64_t) read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_data8, user, compat_task);
                    else
                      return 0;

                    // if the set address is past the address we want, iterate
                    // to the end of the sequence without doing more address
                    // and linenumber calcs than necessary
                    if (curr_addr > addr)
                      skip_to_seq_end = 1;
                    op_index = 0;
                    break;
                  default: // advance the ptr by the specified amount
                    linep += len-1;
                    break;
                }
            }
          else if (opcode <= DW_LNS_set_isa) // known standard opcode
            {
              uint8_t *linep_before = linep;
              switch (opcode)
                {
                  case DW_LNS_copy:
                    commit_row = 1;
                    break;
                  case DW_LNS_advance_pc:
                    addr_adv = read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_leb128, user, compat_task);
                    break;
                  case DW_LNS_fixed_advance_pc:
                    addr_adv = read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_data2, user, compat_task);
                    if (linep_before == linep) // the read failed
                      return 0;
                    op_index = 0;
                    break;
                  case DW_LNS_advance_line:
                    curr_linenum += read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_leb128+DW_EH_PE_signed, user, compat_task);
                    break;
                  case DW_LNS_set_file:
                    curr_file_idx = read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_leb128, user, compat_task);
                    break;
                  case DW_LNS_set_column:
                    read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_leb128, user, compat_task);
                    break;
                  case DW_LNS_const_add_pc:
                    addr_adv = ((255 - opcode_base) / line_range);
                    break;
                  case DW_LNS_set_isa:
                    read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_leb128, user, compat_task);
                    break;
                }
                if (linep > endunitp) // reading in the leb128 failed
                  return 0;
            }
          else
            {
              int i;
              for (i=stdopcode_lens_secp[opcode]; i>0; --i)
                {
                  read_pointer ((const uint8_t **) &linep, endunitp, DW_EH_PE_leb128, user, compat_task);
                  if (linep > endunitp)
                    return 0;
                }
            }

          // don't worry about doing address advances since we are waiting
          // till we hit the end of the sequence or the end of the unit at which
          // point the address and linenumber will be reset
          if (skip_to_seq_end)
            continue;

          // calculate actual address advance
          if (addr_adv != 0 && opcode != DW_LNS_fixed_advance_pc)
            {
              addr_adv = min_instr_len * (op_index + addr_adv) / max_ops;
              op_index =  (op_index + addr_adv) % max_ops;
            }
          curr_addr += addr_adv;

          if (commit_row) {
            // compare the whole range from the prior committed row
            // (except an end_sequence can't be the base)
            if (row_end_sequence == 0 && row_addr <= addr && addr < curr_addr)
              {
                if (need_filename)
                  _stp_filename_lookup(m, filename, dirsecp, endhdrp,
                                       row_file_idx, user, compat_task);
                return row_linenum;
              }

            if (end_sequence) {
              curr_addr = 0;
              curr_file_idx = 1;
              curr_linenum = 1;
            }

            row_addr = curr_addr;
            row_file_idx = curr_file_idx;
            row_linenum = curr_linenum;
            row_end_sequence = end_sequence;
          }
        }
    }
#endif /* STP_NEED_LINE_DATA */

  // no linenumber was found otherwise this function would have returned before this point
  return 0;
}

static int _stp_build_id_check (struct _stp_module *m,
				unsigned long notes_addr,
				struct task_struct *tsk)
{
  int j;

  for (j = 0; j < m->build_id_len; j++) {
    /* Use set_fs / get_user to access conceivably invalid addresses.
     * If loc2c-runtime.h were more easily usable, a deref() loop
     * could do it too. */
    mm_segment_t oldfs = get_fs();
    int rc;
    unsigned char theory, practice = 0;

#ifdef STAPCONF_PROBE_KERNEL
    if (!tsk) {
      theory = m->build_id_bits[j];
      set_fs(KERNEL_DS);
      rc = probe_kernel_read(&practice, (void*)(notes_addr + j), 1);
    }
    else
#endif
    {
      theory = m->build_id_bits[j];
      set_fs (tsk ? USER_DS : KERNEL_DS);

      /*
       * Why check CONFIG_UTRACE here? If we're using real in-kernel
       * utrace, we can always just call get_user() (since we're
       * either reading kernel memory or tsk == current).
       *
       * Since we're only reading here, we can call
       * __access_process_vm_noflush(), which only calls things that
       * are exported.
       */
#ifdef CONFIG_UTRACE
      rc = get_user(practice, ((unsigned char*)(void*)(notes_addr + j)));
#else
      if (!tsk || tsk == current) {
	rc = get_user(practice, ((unsigned char*)(void*)(notes_addr + j)));
      }
      else {
	rc = (__access_process_vm_noflush(tsk, (notes_addr + j), &practice,
					  1, 0) != 1);
      }
#endif
    }
    set_fs(oldfs);

    if (rc || (theory != practice)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
      _stp_error ("Build-id mismatch [man error::buildid]: \"%s\" byte %d (0x%02x vs 0x%02x) address %#lx rc %d\n",
		  m->path, j, theory, practice, notes_addr, rc);
      return 1;
#else
      /* This branch is a surrogate for kernels affected by Fedora bug
       * #465873. */
      _stp_warn (KERN_WARNING
		 "Build-id mismatch [man error::buildid]: \"%s\" byte %d (0x%02x vs 0x%02x) rc %d\n",
		 m->path, j, theory, practice, rc);
#endif
      break;
    } /* end mismatch */
  } /* end per-byte check loop */
  return 0;
}


/* Validate all-modules + kernel based on build-id (if present).
*  The completed case is the following combination:
*	   Debuginfo 		 Module			         Kernel	
* 			   X				X
* 	has build-id/not	unloaded		      has build-id/not	
*				loaded && (has build-id/not)  
*
*  NB: build-id exists only if ld>=2.18 and kernel>= 2.6.23
*/
static int _stp_module_check(void)
{
  struct _stp_module *m = NULL;
  unsigned long notes_addr, base_addr;
  unsigned i,j;
  int rc = 0;

#ifdef STP_NO_BUILDID_CHECK
  return 0;
#endif

  for (i = 0; i < _stp_num_modules; i++)
    {
      m = _stp_modules[i];

      if (m->build_id_len > 0 && m->notes_sect != 0) {
          dbug_sym(1, "build-id validation [%s]\n", m->name); /* kernel only */

          /* skip userspace program */
          if (m->name[0] != '/') continue;

          /* notes end address */
          if (!strcmp(m->name, "kernel")) {
              notes_addr = _stp_kmodule_relocate("kernel",
                  "_stext", m->build_id_offset);
              base_addr = _stp_kmodule_relocate("kernel",
                  "_stext", 0);
          } else {
              notes_addr = m->notes_sect + m->build_id_offset;
              base_addr = m->notes_sect;
          }

          if (notes_addr <= base_addr) { /* shouldn't happen */
              _stp_warn ("build-id address %lx <= base %lx\n",
                  notes_addr, base_addr);
              continue;
          }

          rc |=  _stp_build_id_check (m, notes_addr, NULL);
      } /* end checking */
    } /* end loop */

  return rc;
}



/* Iterate over _stp_modules, looking for a kernel module of given
   name.  Run build-id checking for it.  Return 0 on ok. */
static int _stp_kmodule_check (const char *name)
{
  struct _stp_module *m = NULL;
  unsigned long notes_addr, base_addr;
  unsigned i,j;

#ifdef STP_NO_BUILDID_CHECK
  return 0;
#endif

  WARN_ON(!name || name[0]=='/'); // non-userspace only

  for (i = 0; i < _stp_num_modules; i++)
    {
      m = _stp_modules[i];

      /* PR16406 must be unique kernel module name (non-/-prefixed path) */
      if (strcmp (name, m->name)) continue;

      if (m->build_id_len > 0 && m->notes_sect != 0) {
          dbug_sym(1, "build-id validation [%s]\n", m->name);

          /* notes end address */
          notes_addr = m->notes_sect + m->build_id_offset;
          base_addr = m->notes_sect;

          if (notes_addr <= base_addr) { /* shouldn't happen */
              _stp_warn ("build-id address %lx < base %lx\n",
                  notes_addr, base_addr);
              continue;
          }
          return _stp_build_id_check (m, notes_addr, NULL);
      } /* end checking */
    } /* end loop */

  return 0; /* not found */
}



/* Validate user module based on build-id (if present) */
static int _stp_usermodule_check(struct task_struct *tsk, const char *path_name, unsigned long addr)
{
  struct _stp_module *m = NULL;
  unsigned long notes_addr;
  unsigned i, j;
  unsigned char practice_id_bits[MAXSTRINGLEN];
  unsigned long vm_end = 0;

#ifdef STP_NO_BUILDID_CHECK
  return 0;
#endif

  WARN_ON(!path_name || path_name[0]!='/'); // user-space only

  for (i = 0; i < _stp_num_modules; i++)
    {
      m = _stp_modules[i];

      /* PR16406 must be unique userspace name (/-prefixed path); it's also in m->name */
      if (strcmp(path_name, m->path) != 0) continue;

      if (m->build_id_len > 0) {
	int ret, build_id_len;

	notes_addr = addr + m->build_id_offset /* + m->module_base */;

        dbug_sym(1, "build-id validation [%d %s] address=%#lx build_id_offset=%#lx\n",
                 tsk->pid, m->path, addr, m->build_id_offset);

	if (notes_addr <= addr) {
	  _stp_warn ("build-id address %lx < base %lx\n", notes_addr, addr);
	  continue;
	}
	return _stp_build_id_check (m, notes_addr, tsk);
      }
    }

  return 0; /* not found */
}


/** Prints an address based on the _STP_SYM flags.
 * @param address The address to lookup.
 * @param task The address to lookup (if NULL lookup kernel/module address).
 * @note Symbolic lookups should not normally be done within
 * a probe because it is too time-consuming. Use at module exit time. */
static int _stp_snprint_addr(char *str, size_t len, unsigned long address,
			     int flags, struct task_struct *task)
{
  const char *modname = NULL;
  const char *name = NULL;
  char *filename = NULL;
  unsigned long offset = 0, size = 0, linenumber = 0;
  char *exstr, *poststr, *prestr;

  prestr = (flags & _STP_SYM_PRE_SPACE) ? " " : "";
  exstr = (((flags & _STP_SYM_INEXACT) && (flags & _STP_SYM_SYMBOL))
	   ? " (inexact)" : "");
  if (flags & _STP_SYM_POST_SPACE)
    poststr = " ";
  else if (flags & _STP_SYM_NEWLINE)
    poststr = "\n";
  else
    poststr = "";

  if (flags & (_STP_SYM_SYMBOL | _STP_SYM_MODULE)) {
    name = _stp_kallsyms_lookup(address, &size, &offset, &modname, task);
    if (name && name[0] == '.')
      name++;
  }

  if (modname && (flags & _STP_SYM_MODULE_BASENAME)) {
     char *slash = strrchr (modname, '/');
     if (slash)
        modname = slash+1;
  }

  if ((flags & _STP_SYM_LINENUMBER) || (flags & _STP_SYM_FILENAME)) {
      linenumber = _stp_linenumber_lookup (address, task, &filename,
                                           (int) (flags & _STP_SYM_FILENAME));
  }

  if (name && (flags & _STP_SYM_SYMBOL)) {
    if ((flags & _STP_SYM_MODULE) && modname && *modname) {
      if (flags & _STP_SYM_OFFSET) {
	if (flags & _STP_SYM_SIZE) {
	  /* symbol, module, offset and size. */
	  if (flags & _STP_SYM_HEX_SYMBOL)
	    return _stp_snprintf(str, len, "%s%p : %s+%#lx/%#lx [%s]%s%s",
				 prestr, (int64_t) address,
				 name, offset, size, modname,
				 exstr, poststr);
	  else
	    return _stp_snprintf(str, len, "%s%s+%#lx/%#lx [%s]%s%s",
				 prestr, name, offset, size,
				 modname, exstr, poststr);
	} else {
	  /* symbol, module, offset. */
	  if (flags & _STP_SYM_HEX_SYMBOL)
	    return _stp_snprintf(str, len, "%s%p : %s+%#lx [%s]%s%s",
				 prestr, (int64_t) address,
				 name, offset, modname,
				 exstr, poststr);
	  else
	    return _stp_snprintf(str, len, "%s%s+%#lx [%s]%s%s",
				 prestr, name, offset,
				 modname, exstr, poststr);
	}
      } else {
	/* symbol plus module */
	if (flags & _STP_SYM_HEX_SYMBOL)
	  return _stp_snprintf(str, len, "%s%p : %s [%s]%s%s", prestr,
			       (int64_t) address, name, modname,
			       exstr, poststr);
	else
	  return _stp_snprintf(str, len, "%s%s [%s]%s%s", prestr, name,
			       modname, exstr, poststr);
      }
    } else if (flags & _STP_SYM_OFFSET) {
      if (flags & _STP_SYM_SIZE) {
	/* symbol name, offset + size, no module name */
	if (flags & _STP_SYM_HEX_SYMBOL)
	  return _stp_snprintf(str, len, "%s%p : %s+%#lx/%#lx%s%s", prestr,
			       (int64_t) address, name, offset,
			       size, exstr, poststr);
	else
	  return _stp_snprintf(str, len, "%s%s+%#lx/%#lx%s%s", prestr, name,
			       offset, size, exstr, poststr);
      } else {
	/* symbol name, offset, no module name */
	if (flags & _STP_SYM_HEX_SYMBOL)
	  return _stp_snprintf(str, len, "%s%p : %s+%#lx%s%s", prestr,
			       (int64_t) address, name, offset,
			       exstr, poststr);
	else
	  return _stp_snprintf(str, len, "%s%s+%#lx%s%s", prestr, name,
			       offset, exstr, poststr);
      }
    } else {
      /* symbol name only */
      if (flags & _STP_SYM_HEX_SYMBOL)
	return _stp_snprintf(str, len, "%s%p : %s%s%s", prestr,
			     (int64_t) address, name, exstr, poststr);
      else
	return _stp_snprintf(str, len, "%s%s%s%s", prestr, name,
			     exstr, poststr);
    }
  } else {
    /* no symbol name */
    if (modname && *modname && (flags & _STP_SYM_MODULE)) {
      if (flags & _STP_SYM_OFFSET) {
        if (flags & _STP_SYM_SIZE) {
          /* hex address, module name, offset + size */
          return _stp_snprintf(str, len, "%s%p [%s+%#lx/%#lx]%s%s", prestr,
			       (int64_t) address, modname, offset,
			       size, exstr, poststr);
        } else {
          /* hex address, module name, offset */
	  return _stp_snprintf(str, len, "%s%p [%s+%#lx]%s%s", prestr,
			       (int64_t) address, modname, offset,
			       exstr, poststr);
        }
      } else {
	/* hex address, module name */
        return _stp_snprintf(str, len, "%s%p [%s]%s%s", prestr,
			     (int64_t) address, modname, exstr, poststr);
      }
#ifdef STAPCONF_MODULE_TEXT_ADDRESS
    } if ((flags & _STP_SYM_MODULE) && ! task) {
      /* No symbol, nor module name, but user really wants one, do one
	 last try. */
      struct module *ko;
      preempt_disable();
      ko = __module_text_address (address);
      if (ko && ko->name)
	{
	  /* hex address, module name */
	  int ret = _stp_snprintf(str, len, "%s%p [%s]%s%s", prestr,
				  (int64_t) address, ko->name, exstr, poststr);
	  preempt_enable_no_resched();
	  return ret;
        }
      preempt_enable_no_resched();
      /* no names, hex only */
      return _stp_snprintf(str, len, "%s%p%s%s", prestr,
			   (int64_t) address, exstr, poststr);
#endif
    } else if ((flags & _STP_SYM_LINENUMBER) && linenumber) {
        if (flags & _STP_SYM_FILENAME) {
          if (filename) {
            /* filename, linenumber */
            return _stp_snprintf(str, len, "%s%s:%#lu%s%s", prestr,
                 filename,  linenumber, exstr, poststr);
          } else {
            /* filename=??, linenumber */
            return _stp_snprintf(str, len, "%s??:%#lu%s%s", prestr,
                 linenumber, exstr, poststr);
          }
        } else {
          /* linenumber */
          return _stp_snprintf(str, len, "%s%#lu%s%s", prestr,
               linenumber, exstr, poststr);
        }
    } else if ((flags & _STP_SYM_FILENAME) && filename) {
      /* filename */
      return _stp_snprintf(str, len, "%s%s%s%s", prestr,
           filename, exstr, poststr);
    }else {
      /* no names, hex only */
      return _stp_snprintf(str, len, "%s%p%s%s", prestr,
			   (int64_t) address, exstr, poststr);
    }
  }
}

static void _stp_print_addr(unsigned long address, int flags,
			    struct task_struct *task)
{
  _stp_snprint_addr(NULL, 0, address, flags, task);
}

/** @} */



/* Update the given module/section's offset value.  Assume that there
   is no need for locking or for super performance.  NB: this is only
   for kernel modules, which exist singly at run time.  User-space
   modules (executables, shared libraries) exist at different
   addresses in different processes, so are tracked in the
   _stp_tf_vma_map. */
static void _stp_kmodule_update_address(const char* module,
                                        const char* reloc, /* NULL="all" */
                                        unsigned long address)
{
  unsigned mi, si;
  for (mi=0; mi<_stp_num_modules; mi++)
    {
      const char *note_sectname = ".note.gnu.build-id";
      if (strcmp (_stp_modules[mi]->name, module))
        continue;

      if (reloc && !strcmp (note_sectname, reloc)) {
        dbug_sym(1, "module %s special section %s address %#lx\n",
                 _stp_modules[mi]->name,
                 note_sectname,
                 address);
        _stp_modules[mi]->notes_sect = address;   /* cache this particular address  */
      }

      for (si=0; si<_stp_modules[mi]->num_sections; si++)
        {
          if (reloc && strcmp (_stp_modules[mi]->sections[si].name, reloc))
            continue;
          else
            {
              dbug_sym(1, "module %s section %s address %#lx\n",
                       _stp_modules[mi]->name,
                       _stp_modules[mi]->sections[si].name,
                       address);
              _stp_modules[mi]->sections[si].static_addr = address;

              if (reloc) break;
              else continue; /* wildcarded - will have more hits */
            }
        } /* loop over sections */
    } /* loop over modules */
}


#ifndef STAPCONF_KALLSYMS
unsigned long kallsyms_lookup_name (const char *name)
{
        /* NB: PR14804: don't use _stp_error here.  It's called too
           early for the actual message buffer goo to be allocated. */
        /* Don't even printk.  A user can't do anything about it. */
        /* printk (KERN_ERR "kallsyms_lookup_name unavailable for %s\n", name); */
        return 0;
}
#endif



#endif /* _STP_SYM_C_ */
