/* -*- linux-c -*- 
 * uprobe Functions
 * Copyright (C) 2014 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _UPROBE_COMMON_C_
#define _UPROBE_COMMON_C_

/* NB: Because these utrace callbacks only occur before / after
   userspace instructions run, there is no concurrency control issue
   between active uprobe callbacks and these registration /
   unregistration pieces.

   We protect the stap_uprobe->spec_index (which also serves as a
   free/busy flag) value with the outer protective stap_probes_lock
   spinlock, to protect it against concurrent registration /
   unregistration.
*/

static int stap_uprobe_change_plus (struct task_struct *tsk, unsigned long relocation, unsigned long length, const struct stap_uprobe_tf *stf, unsigned long offset, unsigned long vm_flags) {
  int tfi = (stf - stap_uprobe_finders);
  int spec_index;
  /* iterate over stap_uprobe_spec[] that use this same stap_uprobe_tf */
  for (spec_index=0; spec_index<sizeof(stap_uprobe_specs)/sizeof(stap_uprobe_specs[0]); spec_index++) {
    int handled_p = 0;
    int slotted_p = 0;
    const struct stap_uprobe_spec *sups = &stap_uprobe_specs [spec_index];
    struct stap_uprobe *sup;
    pid_t sdt_sem_pid;
    int rc = 0;
    int i;
    int pci;
    
    if (likely(sups->tfi != tfi)) continue;
    /* skip probes with an address beyond this map event; should not 
       happen unless a shlib/exec got mmapped in weirdly piecemeal */
    if (likely((vm_flags & VM_EXEC) && sups->address >= length)) continue;

    /* Found a uprobe_spec for this stap_uprobe_tf.  Need to lock the
       stap_uprobes[] array to allocate a free spot, but then we can
       unlock and do the register_*probe subsequently. */

    mutex_lock (& stap_uprobes_lock);
    for (i=0; i<MAXUPROBES; i++) { /* XXX: slow linear search */
      sup = & stap_uprobes[i];

      /* register new uprobe
	 We make two passes for semaphores;
	 see stap_uprobe_change_semaphore_plus */
 
      if (sup->spec_index < 0 || (sups->sdt_sem_offset && vm_flags & VM_WRITE && sup->spec_index == spec_index)) {
        #if (UPROBES_API_VERSION < 2)
	/* See PR6829 comment. */
        if (sup->spec_index == -1 && sup->up.kdata != NULL) continue;
        else if (sup->spec_index == -2 && sup->urp.u.kdata != NULL) continue;
        #endif
        sup->spec_index = spec_index;
        slotted_p = 1;
        break;
      }
    }
    mutex_unlock (& stap_uprobes_lock);
    #ifdef DEBUG_UPROBES
    _stp_dbug(__FUNCTION__,__LINE__, "+uprobe spec %d idx %d process %s[%d] addr %p pp %s\n", spec_index, (slotted_p ? i : -1), tsk->comm, tsk->tgid, (void*)(relocation+sups->address), sups->probe->pp);
    #endif

    /* NB: check for user-module build-id only if we have a pathname
       at all; for a process(PID#).* probe, we may not.  If at some
       point we map process(PID#) to process("/proc/PID#/exe"), we'll
       get a pathname. */
    if (stf->pathname)
            if ((rc = _stp_usermodule_check(tsk, stf->pathname, relocation)))
                    return rc;

    /* Here, slotted_p implies that `i' points to the single
       stap_uprobes[] element that has been slotted in for registration
       or unregistration processing.  !slotted_p implies that the table
       was full (registration; MAXUPROBES) or that no matching entry was
       found (unregistration; should not happen). */

    sdt_sem_pid = (sups->return_p ? sup->urp.u.pid : sup->up.pid);
    if (sups->sdt_sem_offset && (sdt_sem_pid != tsk->tgid || sup->sdt_sem_address == 0)) {
      /* If the probe is in an ET_EXEC binary, then the sdt_sem_offset already
       * is a real address.  But stap_uprobe_process_found calls us in this
       * case with relocation=offset=0, so we don't have to worry about it.  */
      sup->sdt_sem_address = (relocation - offset) + sups->sdt_sem_offset;
    } /* sdt_sem_offset */

    for (pci=0; pci < sups->perf_counters_dim; pci++) {
	if ((sups->perf_counters)[pci] > -1)
	  _stp_perf_read_init ((sups->perf_counters)[pci], tsk);
      }

    if (slotted_p) {
      struct stap_uprobe *sup = & stap_uprobes[i];
      if (sups->return_p) {
        sup->urp.u.pid = tsk->tgid;
        sup->urp.u.vaddr = relocation + sups->address;
        sup->urp.handler = &enter_uretprobe_probe;
        rc = register_uretprobe (& sup->urp);
      } else {
        sup->up.pid = tsk->tgid;
        sup->up.vaddr = relocation + sups->address;
        sup->up.handler = &enter_uprobe_probe;
        rc = register_uprobe (& sup->up);
      }

      /* The u*probe failed to register.  However, if we got EEXIST,
       * that means that the u*probe is already there, so just ignore
       * the error.  This could happen if CLONE_THREAD or CLONE_VM was
       * used. */
      if (rc != 0 && rc != -EEXIST) {
        _stp_warn ("u*probe failed %s[%d] '%s' addr %p rc %d\n", tsk->comm, tsk->tgid, sups->probe->pp, (void*)(relocation + sups->address), rc);
	/* NB: we need to release this slot,
	   so we need to borrow the mutex temporarily. */
        mutex_lock (& stap_uprobes_lock);
        sup->spec_index = -1;
	sup->sdt_sem_address = 0;
        mutex_unlock (& stap_uprobes_lock);
      } else {
        handled_p = 1;
      }
    }
    /* NB: handled_p implies slotted_p */
    if (unlikely (! handled_p)) {
      #ifdef STP_TIMING
      atomic_inc (skipped_count_uprobe_reg());
      #endif
      /* NB: duplicates common_entryfn_epilogue,
	 but then this is not a probe entry fn epilogue. */
#ifndef STAP_SUPPRESS_HANDLER_ERRORS
      if (unlikely (atomic_inc_return (skipped_count()) > MAXSKIPPED)) {
        if (unlikely (pseudo_atomic_cmpxchg(session_state(), STAP_SESSION_RUNNING, STAP_SESSION_ERROR) == STAP_SESSION_RUNNING))
          _stp_error ("Skipped too many probes, check MAXSKIPPED or try again with stap -t for more details.");
      }
#endif
    }
  }  /* close iteration over stap_uprobe_spec[] */
  return 0; /* XXX: or rc? */
}

static int stap_uprobe_change_semaphore_plus (struct task_struct *tsk, unsigned long relocation, unsigned long length, const struct stap_uprobe_tf *stf) {
  int tfi = (stf - stap_uprobe_finders);
  int spec_index;
  int rc = 0;
  struct stap_uprobe *sup;
  int i;

  /* We make two passes for semaphores.
     The first pass, stap_uprobe_change_plus, calculates the address of the   
     semaphore.  If the probe is in a .so, we calculate the 
     address when the initial mmap maps the entire solib, e.g.
     7f089885a000-7f089885b000  rw-p-  libtcl.so
     A subsequent mmap maps in the writable segment where the 
     semaphore control variable lives, e.g.
     7f089850d000-7f0898647000  r-xp-  libtcl.so
     7f0898647000-7f0898846000  ---p   libtcl.so
     7f0898846000-7f089885b000  rw-p-  libtcl.so
     The second pass, stap_uprobe_change_semaphore_plus, sets the semaphore.
     If the probe is in a .so this will be when the writable segment of the .so
     is mapped in.  If the task changes, then recalculate the address.
  */

  for (i=0; i<MAXUPROBES; i++) {  /* XXX: slow linear search */
    sup = & stap_uprobes[i];
    if (sup->spec_index == -1) continue;
    if (sup->sdt_sem_address != 0 && !(sup->up.pid == tsk->tgid && sup->sdt_sem_address >= relocation && sup->sdt_sem_address < relocation+length)) continue;
    if (sup->sdt_sem_address) {
      unsigned short sdt_semaphore = 0; /* NB: fixed size */
      if ((rc = get_user (sdt_semaphore, (unsigned short __user*) sup->sdt_sem_address)) == 0) {
        sdt_semaphore ++;
        #ifdef DEBUG_UPROBES
        {
          const struct stap_uprobe_spec *sups = &stap_uprobe_specs [sup->spec_index];
          _stp_dbug(__FUNCTION__,__LINE__, "+semaphore %#x @ %#lx spec %d idx %d task %d\n", sdt_semaphore, sup->sdt_sem_address, sup->spec_index, i, tsk->tgid);
        }
        #endif
	rc = put_user (sdt_semaphore, (unsigned short __user*) sup->sdt_sem_address);
	/* XXX: need to analyze possibility of race condition */
      }
    }
  }
  return rc;
}

/* Removing/unmapping a uprobe is simpler than adding one (in the
  _plus function above).  We need not care about stap_uprobe_finders
  or anything, we just scan through stap_uprobes[] for a live probe
  within the given address range, and kill it.  */
static int stap_uprobe_change_minus (struct task_struct *tsk, unsigned long relocation, unsigned long length, const struct stap_uprobe_tf *stf) {
  int i;

  /* NB: it's not an error for us not to find a live uprobe within the
     given range.  We might have received a callback for a part of a
     shlib that was unmapped and unprobed. */

  for (i=0; i<MAXUPROBES; i++) { /* XXX: slow linear search */
    struct stap_uprobe *sup = & stap_uprobes[i];
    struct stap_uprobe_spec *sups;
    if (sup->spec_index < 0) continue; /* skip free uprobes slot */
    sups = (struct stap_uprobe_spec*) & stap_uprobe_specs[sup->spec_index];
    mutex_lock (& stap_uprobes_lock);

    /* PR6829, PR9940:
       Here we're unregistering for one of two reasons:
       1. the process image is going away (or gone) due to exit or exec; or
       2. the vma containing the probepoint has been unmapped.
       In case 1, it's sort of a nop, because uprobes will notice the event
       and dispose of the probes eventually, if it hasn't already.  But by
       calling unmap_u[ret]probe() ourselves, we free up sup right away.
       
       In both cases, we must use unmap_u[ret]probe instead of
       unregister_u[ret]probe, so uprobes knows not to try to restore the
       original opcode.
    */

    /* URETPROBE */
    if (sups->return_p && sup->urp.u.pid == tsk->tgid && sup->urp.u.vaddr >= relocation && sup->urp.u.vaddr < relocation+length) { /* in range */
      
      #ifdef DEBUG_UPROBES
      _stp_dbug (__FUNCTION__,__LINE__, "-uretprobe spec %d idx %d process %s[%d] addr %p pp %s\n", sup->spec_index, i, tsk->comm, tsk->tgid, (void*) sup->urp.u.vaddr, sups->probe->pp);
      #endif
      #if (UPROBES_API_VERSION >= 2)
      unmap_uretprobe (& sup->urp);
      sup->spec_index = -1;
      sup->sdt_sem_address = 0;
      #else
      /* Uprobes lacks unmap_uretprobe.  Before reusing sup, we must wait
	 until uprobes turns loose of the uretprobe on its own, as indicated
	 by uretprobe.kdata = NULL. */
      sup->spec_index = -2;
      #endif
      /* UPROBE */
    } else if (!sups->return_p && sup->up.pid == tsk->tgid && sup->up.vaddr >= relocation && sup->up.vaddr < relocation+length) { /* in range */
      
      #ifdef DEBUG_UPROBES
      _stp_dbug (__FUNCTION__,__LINE__, "-uprobe spec %d idx %d process %s[%d] reloc %p pp %s\n", sup->spec_index, i, tsk->comm, tsk->tgid, (void*) sup->up.vaddr, sups->probe->pp);
      #endif
      #if (UPROBES_API_VERSION >= 2)
      unmap_uprobe (& sup->up);
      sup->spec_index = -1;
      sup->sdt_sem_address = 0;
      #else
      /* Uprobes lacks unmap_uprobe.  Before reusing sup, we must wait
	 until uprobes turns loose of the uprobe on its own, as indicated
	 by uprobe.kdata = NULL. */
      sup->spec_index = -1;
      sup->sdt_sem_address = 0;
      #endif
      /* PR10655: we don't need to fidget with the ENABLED semaphore either,
	 as the process is gone, buh-bye, toodaloo, au revoir, see ya later! */
    }
    mutex_unlock (& stap_uprobes_lock);
  }  /* close iteration over stap_uprobes[] */
  return 0; /* XXX: or !handled_p */
}

/* The task_finder_callback we use for ET_EXEC targets.
   We used to perform uprobe insertion/removal here, but not any more.
   (PR10524) */
static int stap_uprobe_process_found (struct stap_task_finder_target *tgt, struct task_struct *tsk, int register_p, int process_p) {
  const struct stap_uprobe_tf *stf = container_of(tgt, struct stap_uprobe_tf, finder);
  if (! process_p) return 0; /* ignore threads */
  dbug_task_vma(1, "%cproc pid %d stf %p %p path %s\n", register_p?'+':'-', tsk->tgid, tgt, stf, stf->pathname);
  /* ET_EXEC events are like shlib events, but with 0 relocation bases */
  if (register_p) {
    int rc = stap_uprobe_change_plus (tsk, 0, TASK_SIZE, stf, 0, 0);
    stap_uprobe_change_semaphore_plus (tsk, 0, TASK_SIZE, stf);
    return rc;
  } else
    return stap_uprobe_change_minus (tsk, 0, TASK_SIZE, stf);
}

/* The task_finder_mmap_callback */
static int
stap_uprobe_mmap_found (struct stap_task_finder_target *tgt,
                        struct task_struct *tsk, char *path,
                        struct dentry *dentry, unsigned long addr,
                        unsigned long length, unsigned long offset,
                        unsigned long vm_flags)
{
  int rc = 0;
  const struct stap_uprobe_tf *stf = container_of(tgt, struct stap_uprobe_tf, finder);
  /* 1 - shared libraries' executable segments load from offset 0
   *   - ld.so convention offset != 0 is now allowed
   *     so stap_uprobe_change_plus can set a semaphore,
   *     i.e. a static extern, in a shared object
   * 2 - the shared library we're interested in
   * 3 - mapping should be executable or writable (for semaphore in .so)
   *     NB: or both, on kernels that lack noexec mapping
   */
  if (path == NULL || strcmp (path, stf->pathname))
    return 0;

  /* Check non-writable, executable sections for probes. */
  if ((vm_flags & VM_EXEC) && !(vm_flags & VM_WRITE)) {
    dbug_task_vma (1,
               "+mmap X pid %d path %s addr %p length %u offset %p stf %p %p path %s\n",
               tsk->tgid, path, (void *) addr, (unsigned)length, (void*) offset,
               tgt, stf, stf->pathname);
    rc = stap_uprobe_change_plus (tsk, addr, length, stf, offset, vm_flags);
  }

  /* Check writable sections for semaphores.
   * NB: They may have also been executable for the check above, if we're
   *     running a kernel that lacks noexec mappings.  So long as there's
   *     no error (rc == 0), we need to look for semaphores too.
   */
  if ((rc == 0) && (vm_flags & VM_WRITE)) {
    dbug_task_vma (1,
               "+mmap W pid %d path %s addr %p length %u offset %p stf %p %p path %s\n",
               tsk->tgid, path, (void *) addr, (unsigned)length, (void*) offset,
               tgt, stf, stf->pathname);
    rc = stap_uprobe_change_semaphore_plus (tsk, addr, length, stf);
  }

  return rc;
}

/* The task_finder_munmap_callback */
static int stap_uprobe_munmap_found (struct stap_task_finder_target *tgt, struct task_struct *tsk, unsigned long addr, unsigned long length) {
  const struct stap_uprobe_tf *stf = container_of(tgt, struct stap_uprobe_tf, finder);
  dbug_task_vma (1, "-mmap pid %d addr %p length %lu stf %p %p path %s\n", tsk->tgid, (void *) addr, length, tgt, stf, stf->pathname);
  return stap_uprobe_change_minus (tsk, addr, length, stf);
}

/* The task_finder_callback we use for ET_DYN targets.
   This just forces an unmap of everything as the process exits.
   (PR11151) */
static int stap_uprobe_process_munmap (struct stap_task_finder_target *tgt, struct task_struct *tsk, int register_p, int process_p) {
  const struct stap_uprobe_tf *stf = container_of(tgt, struct stap_uprobe_tf, finder);
  if (! process_p) return 0; /* ignore threads */
  dbug_task_vma (1, "%cproc pid %d stf %p %p path %s\n", register_p?'+':'-', tsk->tgid, tgt, stf, stf->pathname);
  /* Covering 0->TASK_SIZE means "unmap everything" */
  if (!register_p)
    return stap_uprobe_change_minus (tsk, 0, TASK_SIZE, stf);
  return 0;
}

#endif /* _UPROBE_COMMON_C_ */
