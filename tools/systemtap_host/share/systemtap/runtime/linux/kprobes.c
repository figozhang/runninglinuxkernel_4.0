/* -*- linux-c -*-
 * Common functions for using kprobes
 * Copyright (C) 2014-2015 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _KPROBES_C_
#define _KPROBES_C_

// Warn of misconfigured kernels
#if !defined(CONFIG_KPROBES)
#error "Need CONFIG_KPROBES!"
#endif

#include <linux/kprobes.h>
#include <linux/module.h>

#ifdef DEBUG_KPROBES
#define dbug_stapkp(args...) do {					\
		_stp_dbug(__FUNCTION__, __LINE__, args);		\
	} while (0)
#define dbug_stapkp_cond(cond, args...) do {				\
		if (cond)						\
			dbug_stapkp(args);				\
	} while (0)
#else
#define dbug_stapkp(args...) do { } while (0)
#define dbug_stapkp_cond(cond, args...)  do { } while (0)
#endif

#ifndef KRETACTIVE
#define KRETACTIVE (max(15, 6 * (int)num_possible_cpus()))
#endif

// This shouldn't happen, but check as a precaution. If we're on kver >= 2.6.30,
// then we must also have STP_ON_THE_FLY_TIMER_ENABLE (which is turned on for
// kver >= 2.6.17, see translate_pass()). This indicates that the background
// timer is available and thus that kprobes can be armed/disarmed on-the-fly.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30) \
      && !defined(STP_ON_THE_FLY_TIMER_ENABLE)
#error "STP_ON_THE_FLY_TIMER_ENABLE undefined"
#endif

// NB: this struct is set up by the stapkp_prepare_* functions prior to
// registering and zero'ed out again after each unregister
struct stap_kprobe {
   union { struct kprobe kp; struct kretprobe krp; } u;
   #ifdef __ia64__
   // PR6028: We register a second dummy probe at the same address so that the
   // kernel uses aggr_kprobe. This is needed ensure that the bspcache is always
   // valid.
   struct kprobe dummy;
   #endif
};


struct stap_kprobe_probe {
   const unsigned return_p:1;
   const unsigned maxactive_p:1;
   const unsigned optional_p:1;
   unsigned registered_p:1;
   const unsigned short maxactive_val;

   // data saved in the kretprobe_instance packet
   const unsigned short saved_longs;
   const unsigned short saved_strings;

   // These macros declare the module and section strings as either const char[]
   // or const char * const. Their actual types are determined at translate-time
   // in dwarf_derived_probe_group::emit_module_decls().
   STAP_KPROBE_PROBE_STR_module;
   STAP_KPROBE_PROBE_STR_section;

   // For the majority of dwarf-based kprobes, we'll use address-based
   // probing. But, for dwarf-based kprobes in modules, we need to
   // switch to using symbol_name+offset (on kernels that support
   // symbol_name+offset probing).
   const unsigned long address;

   // Note we can't really check for STAPCONF_KPROBE_SYMBOL_NAME here,
   // since that complicates the init logic too much.
   const char *symbol_name;
   unsigned int offset;

   const struct stap_probe * const probe;
   const struct stap_probe * const entry_probe;
   struct stap_kprobe * const kprobe;
};


// Forward declare the master entry functions (stap-generated)
static int
enter_kprobe_probe(struct kprobe *inst,
                   struct pt_regs *regs);
static int
enter_kretprobe_common(struct kretprobe_instance *inst,
                       struct pt_regs *regs, int entry);

// Helper entry functions for kretprobes
static int
enter_kretprobe_probe(struct kretprobe_instance *inst,
                      struct pt_regs *regs)
{
   return enter_kretprobe_common(inst, regs, 0);
}

static int
enter_kretprobe_entry_probe(struct kretprobe_instance *inst,
                            struct pt_regs *regs)
{
   return enter_kretprobe_common(inst, regs, 1);
}


static unsigned long
stapkp_relocate_addr(struct stap_kprobe_probe *skp)
{
   return _stp_kmodule_relocate(skp->module, skp->section, skp->address);
}


static int
stapkp_prepare_kprobe(struct stap_kprobe_probe *skp)
{
   struct kprobe *kp = &skp->kprobe->u.kp;
   unsigned long addr = 0;

   if (! skp->symbol_name) {
      addr = stapkp_relocate_addr(skp);
      if (addr == 0)
	 return 1;
      kp->addr = (void *) addr;
   }
   else {
#ifdef STAPCONF_KALLSYMS_ON_EACH_SYMBOL
      // If we're doing symbolic name + offset probing (that gets
      // converted to an address), it doesn't really matter if the
      // symbol is in a module and the module isn't loaded right
      // now. The registration will fail, but will get tried again
      // when the module is loaded.
      if (kp->addr == 0)
	 return 1;
#else
      // If we don't have kallsyms_on_each_symbol(), we'll use
      // symbol_name+offset probing and let
      // register_kprobe()/register_kretprobe() call
      // kallsyms_lookup_name() for us. However, on kernels < 3.11,
      // module_kallsyms_lookup_name() (called from
      // kallsyms_lookup_name()) has a bug where it modifies its
      // argument. So, for those kernels we'll workaround the bug by
      // duplicating the string (so we go from read-only memory in the
      // initialized struct data to read-write allocated memory). The
      // memory gets freed when the probe is unregistered.
      //
      // This bug was fixed in kernel 3.11+ by the following commit:
      //
      //   commit 4f6de4d51f4a3ab06a85e91e708cc89a513ef30c
      //      Author: Mathias Krause <minipli@googlemail.com>
      //      Date:   Tue Jul 2 15:35:11 2013 +0930
      //
      //      module: don't modify argument of module_kallsyms_lookup_name()
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
      if (kp->symbol_name == NULL)
	 kp->symbol_name = kstrdup(skp->symbol_name, STP_ALLOC_FLAGS);
#else
      kp->symbol_name = (typeof(kp->symbol_name))skp->symbol_name;
#endif
      kp->offset = skp->offset;
#endif
   }

   kp->pre_handler = &enter_kprobe_probe;

#ifdef __ia64__ // PR6028
   skp->kprobe->dummy.addr = kp->addr;
   skp->kprobe->dummy.pre_handler = NULL;
   skp->kprobe->dummy.symbol_name = kp->symbol_name;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
   if (!skp->probe->cond_enabled) {
      kp->flags |= KPROBE_FLAG_DISABLED;
      dbug_otf("registering as disabled (kprobe) pidx %zu\n",
               skp->probe->index);
   }
#endif

   return 0;
}


static int
stapkp_arch_register_kprobe(struct stap_kprobe_probe *skp)
{
   int ret = 0;
   struct kprobe *kp = &skp->kprobe->u.kp;

#ifndef __ia64__
   ret = register_kprobe(kp);
   if (ret == 0) {
      if (skp->symbol_name)
	 dbug_stapkp("+kprobe %s+%u\n", kp->symbol_name, kp->offset);
      else
	 dbug_stapkp("+kprobe %p\n", kp->addr);
   }
#else // PR6028
   ret = register_kprobe(&skp->kprobe->dummy);
   if (ret == 0) {
      ret = register_kprobe(kp);
      if (ret != 0)
         unregister_kprobe(&skp->kprobe->dummy);
   }
   dbug_stapkp_cond(ret == 0, "+kprobe %p\n", skp->kprobe->dummy.addr);
   dbug_stapkp_cond(ret == 0, "+kprobe %p\n", kp->addr);
#endif

   skp->registered_p = (ret ? 0 : 1);

   return ret;
}


static int
stapkp_register_kprobe(struct stap_kprobe_probe *skp)
{
   int ret = stapkp_prepare_kprobe(skp);
   if (ret == 0)
      ret = stapkp_arch_register_kprobe(skp);
   return ret;
}


static int
stapkp_prepare_kretprobe(struct stap_kprobe_probe *skp)
{
   struct kretprobe *krp = &skp->kprobe->u.krp;
   unsigned long addr = 0;

   if (! skp->symbol_name) {
      addr = stapkp_relocate_addr(skp);
      if (addr == 0)
	 return 1;
      krp->kp.addr = (void *) addr;
   }
   else {
#ifdef STAPCONF_KALLSYMS_ON_EACH_SYMBOL
      if (krp->kp.addr == 0)
	 return 1;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
      if (krp->kp.symbol_name == NULL)
	 krp->kp.symbol_name = kstrdup(skp->symbol_name, STP_ALLOC_FLAGS);
#else
      krp->kp.symbol_name = (typeof(krp->kp.symbol_name))skp->symbol_name;
#endif
      krp->kp.offset = skp->offset;
#endif
   }

   if (skp->maxactive_p)
      krp->maxactive = skp->maxactive_val;
   else
      krp->maxactive = KRETACTIVE;

   krp->handler = &enter_kretprobe_probe;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
   if (skp->entry_probe) {
      krp->entry_handler = &enter_kretprobe_entry_probe;
      krp->data_size = skp->saved_longs * sizeof(int64_t) +
                       skp->saved_strings * MAXSTRINGLEN;
   }
#endif

#ifdef __ia64__ // PR6028
   skp->kprobe->dummy.addr = krp->kp.addr;
   skp->kprobe->dummy.pre_handler = NULL;
   skp->kprobe->dummy.symbol_name = krp->kp.symbol_name;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
   if (!skp->probe->cond_enabled) {
      krp->kp.flags |= KPROBE_FLAG_DISABLED;
      dbug_otf("registering as disabled (kretprobe) pidx %zu\n",
               skp->probe->index);
   }
#endif

   return 0;
}


static int
stapkp_arch_register_kretprobe(struct stap_kprobe_probe *skp)
{
   int ret = 0;
   struct kretprobe *krp = &skp->kprobe->u.krp;

#ifndef __ia64__
   ret = register_kretprobe(krp);
   dbug_stapkp_cond(ret == 0, "+kretprobe %p\n", krp->kp.addr);
#else // PR6028
   ret = register_kprobe(&skp->kprobe->dummy);
   if (ret == 0) {
      ret = register_kretprobe(krp);
      if (ret != 0)
         unregister_kprobe(&skp->kprobe->dummy);
   }
   dbug_stapkp_cond(ret == 0, "+kprobe %p\n", skp->kprobe->dummy.addr);
   dbug_stapkp_cond(ret == 0, "+kretprobe %p\n", krp->kp.addr);
#endif

   skp->registered_p = (ret ? 0 : 1);

   return ret;
}


static int
stapkp_register_kretprobe(struct stap_kprobe_probe *skp)
{
   int ret = stapkp_prepare_kretprobe(skp);
   if (ret == 0)
      ret = stapkp_arch_register_kretprobe(skp);
   return ret;
}


static int
stapkp_register_probe(struct stap_kprobe_probe *skp)
{
   if (skp->registered_p)
      return 0;

   return skp->return_p ? stapkp_register_kretprobe(skp)
                        : stapkp_register_kprobe(skp);
}


static void
stapkp_add_missed(struct stap_kprobe_probe *skp)
{
   if (skp->return_p) {

      struct kretprobe *krp = &skp->kprobe->u.krp;

      atomic_add(krp->nmissed, skipped_count());
#ifdef STP_TIMING
      if (krp->nmissed)
         _stp_warn ("Skipped due to missed kretprobe/1 on '%s': %d\n",
                    skp->probe->pp, krp->nmissed);
#endif

      atomic_add(krp->kp.nmissed, skipped_count());
#ifdef STP_TIMING
      if (krp->kp.nmissed)
         _stp_warn ("Skipped due to missed kretprobe/2 on '%s': %lu\n",
                    skp->probe->pp, krp->kp.nmissed);
#endif

   } else {

      struct kprobe *kp = &skp->kprobe->u.kp;

      atomic_add (kp->nmissed, skipped_count());
#ifdef STP_TIMING
      if (kp->nmissed)
         _stp_warn ("Skipped due to missed kprobe on '%s': %lu\n",
                    skp->probe->pp, kp->nmissed);
#endif
   }
}


static void
stapkp_unregister_probe(struct stap_kprobe_probe *skp)
{
   struct stap_kprobe *sk = skp->kprobe;

   if (!skp->registered_p)
      return;

   if (skp->return_p) {
      unregister_kretprobe (&sk->u.krp);
      if (skp->symbol_name)
	 dbug_stapkp("-kretprobe %s:%d\n", sk->u.krp.kp.symbol_name,
		     sk->u.krp.kp.offset);
      else
	 dbug_stapkp("-kretprobe %p\n", sk->u.krp.kp.addr);
   } else {
      unregister_kprobe (&sk->u.kp);
      if (skp->symbol_name)
	 dbug_stapkp("-kprobe %s:%u\n", sk->u.kp.symbol_name,
		     sk->u.kp.offset);
      else
	 dbug_stapkp("-kprobe %p\n", sk->u.kp.addr);
   }

#if defined(__ia64__)
   unregister_kprobe (&sk->dummy);
   dbug_stapkp("-kprobe %p\n", sk->dummy.addr);
#endif

   skp->registered_p = 0;

   stapkp_add_missed(skp);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
   if (skp->symbol_name != NULL) {
      if (skp->return_p) {
	 if (sk->u.krp.kp.symbol_name != NULL)
	    kfree(sk->u.krp.kp.symbol_name);
      }
      else {
	 if (sk->u.kp.symbol_name != NULL)
	    kfree(sk->u.kp.symbol_name);
      }
   }
#endif

   // PR16861: kprobes may have left some things in the k[ret]probe struct.
   // Let's reset it to be sure it's safe for re-use.
   memset(sk, 0, sizeof(struct stap_kprobe));
}


#if defined(STAPCONF_UNREGISTER_KPROBES)

// The actual size is set later on in
// generic_kprobe_derived_probe_group::emit_module_decls().
static void * stap_unreg_kprobes[];

enum collect_type {
   COLLECT_KPROBES,
#if defined(__ia64__)
   COLLECT_DUMMYS,
#endif
   COLLECT_KRETPROBES
};

static size_t
stapkp_collect_registered_probes(struct stap_kprobe_probe *probes,
                                 size_t nprobes, enum collect_type type)
{
   size_t i, j;

   j = 0;
   for (i = 0; i < nprobes; i++) {

      struct stap_kprobe_probe *skp = &probes[i];
      struct stap_kprobe *sk = skp->kprobe;

      if (!skp->registered_p)
         continue;

      if (type == COLLECT_KPROBES && !skp->return_p)
         stap_unreg_kprobes[j++] = &sk->u.kp;
      else if (type == COLLECT_KRETPROBES && skp->return_p)
         stap_unreg_kprobes[j++] = &sk->u.krp;
#if defined(__ia64__)
      else if (type == COLLECT_DUMMYS)
         stap_unreg_kprobes[j++] = &sk->dummy;
#endif
   }

   return j;
}

static void
stapkp_batch_unregister_probes(struct stap_kprobe_probe *probes,
                               size_t nprobes)
{
   size_t i, n;

   n = stapkp_collect_registered_probes(probes,
                                        nprobes, COLLECT_KPROBES);
   unregister_kprobes((struct kprobe **)stap_unreg_kprobes, n);
   dbug_stapkp_cond(n > 0, "-kprobe * %zd\n", n);

   n = stapkp_collect_registered_probes(probes,
                                        nprobes, COLLECT_KRETPROBES);
   unregister_kretprobes((struct kretprobe **)stap_unreg_kprobes, n);
   dbug_stapkp_cond(n > 0, "-kretprobe * %zd\n", n);

#ifdef __ia64__
   n = stapkp_collect_registered_probes(probes,
                                        nprobes, COLLECT_DUMMYS);
   unregister_kprobes((struct kprobe **)stap_unreg_kprobes, n);
   dbug_stapkp_cond(n > 0, "-kprobe * %zd\n", n);
#endif

   // Now for all of those we just unregistered, we need to update registered_p
   // and account for (and possibly report) missed hits.
   for (i = 0; i < nprobes; i++) {

      struct stap_kprobe_probe *skp = &probes[i];

      if (!skp->registered_p)
         continue;

      skp->registered_p = 0;

      stapkp_add_missed(skp);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
      if (skp->symbol_name != NULL) {
	 if (skp->return_p) {
	    if (skp->kprobe->u.krp.kp.symbol_name != NULL)
	       kfree(skp->kprobe->u.krp.kp.symbol_name);
	 }
	 else {
	    if (skp->kprobe->u.kp.symbol_name != NULL)
	       kfree(skp->kprobe->u.kp.symbol_name);
	 }
      }
#endif

      // PR16861: kprobes may have left some things in the k[ret]probe struct.
      // Let's reset it to be sure it's safe for re-use.
      memset(skp->kprobe, 0, sizeof(struct stap_kprobe));
   }
}

#endif /* STAPCONF_UNREGISTER_KPROBES */


static void
stapkp_unregister_probes(struct stap_kprobe_probe *probes,
                         size_t nprobes)
{
#if defined(STAPCONF_UNREGISTER_KPROBES)

   // Unregister using batch mode
   stapkp_batch_unregister_probes(probes, nprobes);

#else

   // We'll have to unregister them one by one
   size_t i;
   for (i = 0; i < nprobes; i++) {

      struct stap_kprobe_probe *skp = &probes[i];

      if (!skp->registered_p)
         continue;

      stapkp_unregister_probe(skp);
   }

#endif
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)

static int
stapkp_enabled(struct stap_kprobe_probe *skp)
{
   if (!skp->registered_p)
      return 0;

   return skp->return_p ? !kprobe_disabled(&skp->kprobe->u.krp.kp)
                        : !kprobe_disabled(&skp->kprobe->u.kp);
}


static int
stapkp_should_enable_probe(struct stap_kprobe_probe *skp)
{
   return  skp->registered_p
       && !stapkp_enabled(skp)
       &&  skp->probe->cond_enabled;
}


static int
stapkp_enable_probe(struct stap_kprobe_probe *skp)
{
   int ret = 0;

   dbug_otf("enabling (k%sprobe) pidx %zu\n",
            skp->return_p ? "ret" : "", skp->probe->index);

   ret = skp->return_p ? enable_kretprobe(&skp->kprobe->u.krp)
                       : enable_kprobe(&skp->kprobe->u.kp);

   if (ret != 0) {
      stapkp_unregister_probe(skp);
      dbug_otf("failed to enable (k%sprobe) pidx %zu (rc %d)\n",
               skp->return_p ? "ret" : "", skp->probe->index, ret);
   }

   return ret;
}


static int
stapkp_should_disable_probe(struct stap_kprobe_probe *skp)
{
   return  skp->registered_p
       &&  stapkp_enabled(skp)
       && !skp->probe->cond_enabled;
}


static int
stapkp_disable_probe(struct stap_kprobe_probe *skp)
{
   int ret = 0;

   dbug_otf("disabling (k%sprobe) pidx %zu\n",
            skp->return_p ? "ret" : "", skp->probe->index);

   ret = skp->return_p ? disable_kretprobe(&skp->kprobe->u.krp)
                       : disable_kprobe(&skp->kprobe->u.kp);

   if (ret != 0) {
      stapkp_unregister_probe(skp);
      dbug_otf("failed to disable (k%sprobe) pidx %zu (rc %d)\n",
               skp->return_p ? "ret" : "", skp->probe->index, ret);
   }

   return ret;
}


static int
stapkp_refresh_probe(struct stap_kprobe_probe *skp)
{
   if (stapkp_should_enable_probe(skp))
      return stapkp_enable_probe(skp);
   if (stapkp_should_disable_probe(skp))
      return stapkp_disable_probe(skp);
   return 0;
}

#endif /* LINUX_VERSION_CODE >= 2.6.30 */


#ifdef STAPCONF_KALLSYMS_ON_EACH_SYMBOL
struct stapkp_symbol_data {
   struct stap_kprobe_probe *probes;
   size_t nprobes;			/* number of probes in "probes" */
   size_t probe_max;			/* number of probes to process */
   const char *modname;
};


static int
stapkp_symbol_callback(void *data, const char *name,
		       struct module *mod, unsigned long addr)
{
   struct stapkp_symbol_data *sd = data;
   size_t i;

   if ((mod && sd->modname && strcmp(mod->name, sd->modname) != 0)
       || (!mod && sd->modname))
      return 0;

   for (i = 0; i < sd->nprobes; i++) {
      struct stap_kprobe_probe *skp = &sd->probes[i];
      int update_addr = 0;

      if (! skp->symbol_name)
	 continue;

      // If (1) We're probing a module symbol and we're in that module
      // and the names match; or (2) we're probing a symbol in the
      // kernel and the names match, then update the k[ret]probe
      // address.
      if (mod && skp->module && strcmp(mod->name, skp->module) == 0) {
	 char *colon = strchr(skp->symbol_name, ':');

	 if (colon != NULL && strcmp(name, colon+1) == 0)
	    update_addr = 1;
      }
      else if (!mod && (skp->module == NULL || skp->module[0] == '\0')
	       && strcmp(name, skp->symbol_name) == 0)
	 update_addr = 1;
      if (update_addr) {

	 if (skp->return_p)
	    skp->kprobe->u.krp.kp.addr = (void *)(addr + skp->offset);
	 else
	    skp->kprobe->u.kp.addr = (void *)(addr + skp->offset);
	 // Note that we could have more than 1 probe at the same
	 // symbol (with the same or differing offsets), so we can't
	 // return here.
	 //
	 // But we can quit if we've processed all the needed probes.
	 --sd->probe_max;
	 if (sd->probe_max == 0)
	    return -1;
      }
   }
   return 0;
}
#endif


static int
stapkp_init(struct stap_kprobe_probe *probes,
            size_t nprobes)
{
   size_t i;

#ifdef STAPCONF_KALLSYMS_ON_EACH_SYMBOL
   // If we have any symbol_name+offset probes, we need to try to
   // convert those into address-based probes.
   size_t probe_max = 0;
   for (i = 0; i < nprobes; i++) {
      struct stap_kprobe_probe *skp = &probes[i];

      if (! skp->symbol_name)
	 continue;
      ++probe_max;
   }
   if (probe_max > 0) {
      // Here we're going to try to convert any symbol_name+offset
      // probes into address probes.
      struct stapkp_symbol_data sd;
      dbug_stapkp("looking up %lu probes\n", probe_max);
      sd.probes = probes;
      sd.nprobes = nprobes;
      sd.probe_max = probe_max;
      sd.modname = NULL;
      mutex_lock(&module_mutex);
      kallsyms_on_each_symbol(stapkp_symbol_callback, &sd);
      mutex_unlock(&module_mutex);
      dbug_stapkp("found %lu probes\n", sd.probe_max);
   }
#endif

   for (i = 0; i < nprobes; i++) {
      struct stap_kprobe_probe *skp = &probes[i];
      int rc = 0;

      rc = stapkp_register_probe(skp);
      if (rc == 1) // failed to relocate addr?
         continue; // don't fuss about it, module probably not loaded

      // NB: We keep going even if a probe failed to register (PR6749). We only
      // warn about it if it wasn't optional and isn't in a module.
      if (rc && !skp->optional_p
	  && ((skp->module == NULL) || skp->module[0] == '\0'
	      || strcmp(skp->module, "kernel") == 0)) {
	 if (skp->symbol_name)
	    _stp_warn("probe %s (%s+%u) registration error (rc %d)",
		      skp->probe->pp, skp->symbol_name, skp->offset, rc);
	 else
	    _stp_warn("probe %s (address 0x%lx) registration error (rc %d)",
		      skp->probe->pp, stapkp_relocate_addr(skp), rc);
      }
   }

   return 0;
}


/* stapkp_refresh is called for two reasons: either a kprobe needs to be
 * enabled/disabled (modname is NULL), or a module has been loaded/unloaded and
 * kprobes need to be registered/unregistered (modname is !NULL). */
static void
stapkp_refresh(const char *modname,
               struct stap_kprobe_probe *probes,
               size_t nprobes)
{
   size_t i;

   dbug_stapkp("refresh %lu probes with module %s\n", nprobes, modname ?: "?");

#ifdef STAPCONF_KALLSYMS_ON_EACH_SYMBOL
   if (modname) {
      size_t probe_max = 0;
      for (i = 0; i < nprobes; i++) {
	 struct stap_kprobe_probe *skp = &probes[i];

	 // If this probe is in the same module that is being
	 // loaded/unloaded and the probe is symbol_name+offset based
	 // and it isn't registered (so the module must be loaded),
	 // try to convert all probes in the same module to
	 // address-based probes.
	 if (skp->module && strcmp(modname, skp->module) == 0
	     && skp->symbol_name && skp->registered_p == 0)
	    ++probe_max;
      }
      if (probe_max > 0) {
	 struct stapkp_symbol_data sd;
	 sd.probes = probes;
	 sd.nprobes = nprobes;
	 sd.probe_max = probe_max;
	 sd.modname = modname;
	 mutex_lock(&module_mutex);
	 kallsyms_on_each_symbol(stapkp_symbol_callback, &sd);
	 mutex_unlock(&module_mutex);
      }
   }
#endif

   for (i = 0; i < nprobes; i++) {

      struct stap_kprobe_probe *skp = &probes[i];

      // was this probe's target module loaded/unloaded
      if (modname && skp->module
            && strcmp(modname, skp->module) == 0) {
         int rc;
         unsigned long addr = (! skp->symbol_name
			       ? stapkp_relocate_addr(skp) : 0);

         // module being loaded?
         if (skp->registered_p == 0 && (addr != 0 || skp->symbol_name))
            stapkp_register_probe(skp);
         // module/section being unloaded?
         else if (skp->registered_p == 1 && addr == 0)
            stapkp_unregister_probe(skp);

      }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
      else if (stapkp_should_enable_probe(skp)
              || stapkp_should_disable_probe(skp)) {
         stapkp_refresh_probe(skp);
      }
#endif
   }
}


static void
stapkp_exit(struct stap_kprobe_probe *probes,
            size_t nprobes)
{
   stapkp_unregister_probes(probes, nprobes);
}


#endif /* _KPROBES_C_ */
