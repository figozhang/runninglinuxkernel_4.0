/* -*- linux-c -*-
 * symbols.c - stp symbol and module functions
 *
 * Copyright (C) Red Hat Inc, 2006-2015
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_SYMBOLS_C_
#define _STP_SYMBOLS_C_
#include "../sym.h"

#ifndef KERN_CONT
#define KERN_CONT	""
#endif

static int _stp_kmodule_check (const char*);

/* PR12612: pre-commit-3abb860f values */

#define STP13_MODULE_NAME_LEN 64
#define STP13_SYMBOL_NAME_LEN 64
struct _stp13_msg_relocation {
        char module[STP13_MODULE_NAME_LEN];
        char reloc[STP13_SYMBOL_NAME_LEN];
        uint64_t address;
};

static void _stp_do_relocation(const char __user *buf, size_t count)
{
  static struct _stp_msg_relocation msg; /* by protocol, never concurrently used */
  static struct _stp13_msg_relocation msg13; /* ditto */

  /* PR12612: Let's try to be compatible with systemtap modules being
     compiled by new systemtap, but loaded (staprun'd) by an older
     systemtap runtime.  The only known incompatilibility is that we
     get an older, smaller, relocation message.  So here we accept both
     sizes. */
  if (sizeof(msg) == count) { /* systemtap 1.4+ runtime */
    if (unlikely(copy_from_user (& msg, buf, count)))
            return;
  } else if (sizeof(msg13) == count) { /* systemtap 1.3- runtime */
    if (unlikely(copy_from_user (& msg13, buf, count)))
            return;
#if STP_MODULE_NAME_LEN <= STP13_MODULE_NAME_LEN
#error "STP_MODULE_NAME_LEN should not be smaller than STP13_MODULE_NAME_LEN"
#endif
    strlcpy (msg.module, msg13.module, STP13_MODULE_NAME_LEN);
    strlcpy (msg.reloc, msg13.reloc, STP13_MODULE_NAME_LEN);
    msg.address = msg13.address;
  } else {
      errk ("STP_RELOCATE message size mismatch (%lu or %lu vs %lu)\n",
            (long unsigned) sizeof(msg), (long unsigned) sizeof (msg13), (long unsigned) count);
      return;
  }

  dbug_sym(2, "relocate (%s %s 0x%lx)\n", msg.module, msg.reloc, (unsigned long) msg.address);

  /* Detect actual kernel load address. */
  if (!strcmp ("kernel", msg.module)
      && !strcmp ("_stext", msg.reloc)) {
#ifdef CONFIG_KALLSYMS
          if (msg.address == 0)
                  msg.address = kallsyms_lookup_name("_stext");
#endif
          if (msg.address == 0)
                  _stp_warn("No load address found _stext.  Kernel probes and addresses may not be available.");
          else
                  dbug_sym(1, "found kernel _stext load address: 0x%lx\n",
                           (unsigned long) msg.address);
          if (_stp_kretprobe_trampoline != (unsigned long) -1)
                  _stp_kretprobe_trampoline += (unsigned long) msg.address;
  }

  _stp_kmodule_update_address(msg.module, msg.reloc, msg.address);
}



#if !defined(STAPCONF_MODULE_SECT_ATTRS) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
/* It would be nice if it were (still) in a header we could get to,
   like include/linux/module.h, but commit a58730c42 moved them into
   kernel/module.c. */
struct module_sect_attr
{
        struct module_attribute mattr;
        char *name;
        unsigned long address;
};

struct module_sect_attrs
{
        struct attribute_group grp;
        unsigned int nsections;
        struct module_sect_attr attrs[0];
};
#endif


#if defined(CONFIG_KALLSYMS) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
static unsigned _stp_module_nsections (struct module_sect_attrs *attrs)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
	/* We have the answer right here!  */
	return attrs->nsections;
#else
	/* Since grp.attrs is the same length and NULL-terminated,
	 * we can count the sections from that.  */
	struct attribute **gattr = &attrs->grp.attrs[0];
	while (*gattr != NULL)
		++gattr;
	return gattr - &attrs->grp.attrs[0];
#endif
}
#endif


static int _stp_module_notifier (struct notifier_block * nb,
                                 unsigned long val, void *data)
{
        struct module *mod = data;
        struct module_sect_attrs *attrs;
        unsigned i, nsections;

        (void) attrs;
        (void) i;
        (void) nsections;

        if (!mod) { // so as to avoid null pointer checks later
                WARN_ON (!mod);
                return NOTIFY_DONE;
        }

        dbug_sym(1, "module notify %lu %s attrs %p\n",
                 val, mod->name, mod->sect_attrs);

        /* Prior to 2.6.11, struct module contained a module_sections
           attribute vector rather than module_sect_attrs.  Prior to
           2.6.19, module_sect_attrs lacked a number-of-sections
           field.  Past 3.8, MODULE_STATE_COMING is sent too early to
           let us probe module init functions.

           Without CONFIG_KALLSYMS, we don't get any of the
           related fields at all in struct module.  XXX: autoconf for
           that directly? */

#if defined(CONFIG_KALLSYMS)
	// After kernel commit 4982223e51, module notifiers are being
	// called too early to get module section info. So, we have to
	// switch to using symbol+offset probing for modules.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	// The module refresh code (in systemtap_module_refresh)
	// assumes the 1st call is on module load and the 2nd is on
	// module unload. So, we can't call systemtap_module_refresh()
	// twice for module load (once for MODULE_STATE_COMING and
	// once for MODULE_STATE_LIVE). In the MODULE_STATE_COMING
	// state, the module's init function hasn't fired yet and we
	// can register symbol+offset probes. In the MODULE_STATE_LIVE
	// state, the module's init function has already been run (and
	// the init section has been discarded). So, we'll ignore
	// MODULE_STATE_LIVE.
        if (val == MODULE_STATE_COMING) {
		/* Verify build-id. */
		_stp_kmodule_check (mod->name);
        }
        else if (val != MODULE_STATE_GOING) {
		return NOTIFY_DONE;
        }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
        if (val == MODULE_STATE_COMING ||
            val == MODULE_STATE_LIVE) {
                /* A module is arriving or has arrived.  Register all
                   of its section addresses, as though staprun sent us
                   a bunch of STP_RELOCATE messages.  Now ... where
                   did the fishie go? */

                attrs = mod->sect_attrs;
                dbug_sym(1, "module_sect_attrs: %p\n", attrs);
                if (attrs == NULL) // until add_sect_attrs(), may be zero
                        return NOTIFY_DONE; // remain ignorant

                nsections = _stp_module_nsections(attrs);
                for (i=0; i<nsections; i++) {
                        int init_p = (strstr(attrs->attrs[i].name, "init.") != NULL);
                        int init_gone_p = (val == MODULE_STATE_LIVE); // likely already unloaded

                        _stp_kmodule_update_address(mod->name,
                                                    attrs->attrs[i].name,
                                                    ((init_p && init_gone_p) ? 0 : attrs->attrs[i].address));
                }

                /* Verify build-id. */
                if (_stp_kmodule_check (mod->name))
                   _stp_kmodule_update_address(mod->name, NULL, 0); /* Pretend it was never here. */
        }
        else if (val == MODULE_STATE_GOING) {
                /* Unregister all sections. */
                _stp_kmodule_update_address(mod->name, NULL, 0);
        }
	else
		return NOTIFY_DONE;
#endif

        /* Give the probes a chance to update themselves. */
        /* Proper kprobes support for this appears to be relatively
           recent.  Example prerequisite commits: 0deddf436a f24659d9 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        systemtap_module_refresh(mod->name);
#endif

#endif /* skipped for ancient or kallsyms-free kernels */

        return NOTIFY_DONE;
}

static int _stp_module_update_self (void)
{
	/* Only bother if we need unwinding and have module_sect_attrs.  */
  /* Or if we need to figure out the addr->file:line mapping */
#if (defined(STP_USE_DWARF_UNWINDER) && defined(STP_NEED_UNWIND_DATA)) \
    || defined(STP_NEED_LINE_DATA)
#if defined(CONFIG_KALLSYMS)  && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)

	bool found_eh_frame = false;
	struct module *mod = THIS_MODULE;
	struct module_sect_attrs *attrs = mod->sect_attrs;
	unsigned i, nsections = _stp_module_nsections(attrs);

	/* We've already been inserted at this point, so the path variable will
	 * still be unique.  */
	_stp_module_self.name = mod->name;
	_stp_module_self.path = mod->name;

	for (i=0; i<nsections; i++) {
		struct module_sect_attr *attr = &attrs->attrs[i];
		if (!attr->name)
			continue;

		if(!strcmp(".note.gnu.build-id",attr->name)) {
			_stp_module_self.notes_sect = attr->address;
		}
		else if (!strcmp(".eh_frame", attr->name)) {
			_stp_module_self.eh_frame = (void*)attr->address;
			_stp_module_self.eh_frame_len = 0;
			found_eh_frame = true;
		}
		else if (!strcmp(".symtab", attr->name)) {
#ifdef STAPCONF_MOD_KALLSYMS
			struct mod_kallsyms *kallsyms = rcu_dereference_sched(mod->kallsyms);
			if (attr->address == (unsigned long) kallsyms->symtab)
				_stp_module_self.sections[0].size =
					kallsyms->num_symtab * sizeof(kallsyms->symtab[0]);
#else
			if (attr->address == (unsigned long) mod->symtab)
				_stp_module_self.sections[0].size =
					mod->num_symtab * sizeof(mod->symtab[0]);
#endif
			_stp_module_self.sections[0].static_addr = attr->address;
		}
		else if (!strcmp(".text", attr->name)) {
			_stp_module_self.sections[1].static_addr = attr->address;
#ifdef STAPCONF_MODULE_LAYOUT
			_stp_module_self.sections[1].size = mod->core_layout.text_size;
#elif defined(STAPCONF_GRSECURITY)
                        _stp_module_self.sections[1].size = mod->core_size_rx;
#else
			_stp_module_self.sections[1].size = mod->core_text_size;
#endif
		}
	}

	if (found_eh_frame) {
		/* Scan again for an upper bound on eh_frame_len, deduced from
		 * the position of the next closest section.  (if any!)  */
		const unsigned long base = (unsigned long) _stp_module_self.eh_frame;
		unsigned long maxlen = 0, len = 0;
		for (i=0; i<nsections; i++) {
			unsigned long address = attrs->attrs[i].address;
			if (base < address && (maxlen == 0 || address < base + maxlen))
				maxlen = address - base;
		}

		/* The length could be smaller, especially if the next section
		 * has alignment padding.  Walking the fde determines the real
		 * eh_frame length.  There should be a 0x00000000 terminator
		 * word added by translate.cxx's T_800 auxiliary file, but
		 * check our maxlen bound just in case.  */
		while (len + sizeof(u32) <= maxlen) {
			unsigned long offset = get_unaligned((u32*)(base + len));
			if (offset == 0 || offset > maxlen - len - sizeof(u32))
				break; /* 0-terminator, or out of bounds */
			len += sizeof(u32) + offset;
		}
		_stp_module_self.eh_frame_len = len;
	}

#endif /* defined(CONFIG_KALLSYMS) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11) */
#endif /* (defined(STP_USE_DWARF_UNWINDER) && defined(STP_NEED_UNWIND_DATA))
          || defined(STP_NEED_LINE_DATA) */

	return 0;
}

#if STP_TRANSPORT_VERSION == 2
/* Notification function to call on a kernel panic */
static int _stp_module_panic_notifier (struct notifier_block *nb, unsigned long val, void *data)
{
        int i;

        /* Loop over each cpu buffer */
        for_each_possible_cpu(i)
        {
                int j=0;
                struct rchan_buf * sub_buf;
                char *subbuf_start;
                char *previous;
                char *next;
                size_t bytes_passed;
                int printed;
                int first_iteration;

                sub_buf = _stp_relay_data.rchan->buf[i];

                /* Set our pointer to the beginning of the channel buffer */
                subbuf_start = (char *)sub_buf->start;

                /* Loop over each sub buffer */
                for (j=0; j< sub_buf->chan->n_subbufs; j++)
                {
                        /* Ensure our start is not NULL */
                        if(subbuf_start == NULL)
                        {
                                printk(KERN_EMERG "Current buffer is NULL\n");
                                return NOTIFY_DONE;
                        }

                        bytes_passed = 0; /* Keep track of the number of bytes already passed */
                        first_iteration = 1; /* Flag for keeping track of the 1st itteration*/
                        printed = 0; /* Flag for keeping track of when we've already printed the
                                      * message about what info might be new */

                        previous = subbuf_start;
                        next = strchr(previous, '\n');
                        bytes_passed+= (next - previous);

                        /* Loop over the whole buffer, printing line by line */
                        while (next != NULL && bytes_passed < sub_buf->chan->subbuf_size)
                        {

                                if(first_iteration)
                                {
                                        printk(KERN_CONT "%s trace buffer for processor %d sub-buffer %d:\n",
                                               THIS_MODULE->name, i, j);
                                }

                                /* Once we reach the number of bytes consumed on the last
                                 * sub-buffer filled, print a message saying that everything
                                 * from then on might not have made it to the display before
                                 * the kernel panic */
                                if(subbuf_start == sub_buf->data
                                   && bytes_passed >= sub_buf->bytes_consumed
                                   && !printed)
                                {
                                        printk(KERN_CONT
                                               "The following may not have been sent to the display:\n");
                                        printed = 1;
                                }

                                /* Print the line. Other than the first itteration, we need to print everything
                                 * except the first '\n' character.*/
                                if(first_iteration)
                                {
                                        printk(KERN_CONT "%.*s\n", (int)(next - previous), previous);
                                        first_iteration = 0;
                                }
                                else
                                {
                                        printk(KERN_CONT "%.*s\n", (int)(next - previous)-1, previous+1);
                                }

                                /* Get the next token */
                                previous = next;
                                next = strchr(next + 1, '\n');
                                if(next != NULL)
                                {
                                        bytes_passed+= (next - previous);
                                }
                        }

                        /* Move on to the next sub-buffer */
                        subbuf_start = subbuf_start + sub_buf->chan->subbuf_size;
                }
        }
        return NOTIFY_DONE;
}
#endif
#endif /* _STP_SYMBOLS_C_ */
