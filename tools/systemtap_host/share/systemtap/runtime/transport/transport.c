/* -*- linux-c -*- 
 * transport.c - stp transport functions
 *
 * Copyright (C) IBM Corporation, 2005
 * Copyright (C) Red Hat Inc, 2005-2014
 * Copyright (C) Intel Corporation, 2006
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _TRANSPORT_TRANSPORT_C_
#define _TRANSPORT_TRANSPORT_C_

#include "transport.h"
#include "control.h"
#include <linux/debugfs.h>
#include <linux/namei.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include "../uidgid_compatibility.h"

static int _stp_exit_flag = 0;

static uid_t _stp_uid = 0;
static gid_t _stp_gid = 0;
static int _stp_pid = 0;
static int _stp_namespaces_pid = 0;
static int _stp_remote_id = -1;
static char _stp_remote_uri[MAXSTRINGLEN];

static atomic_t _stp_ctl_attached = ATOMIC_INIT(0);

static pid_t _stp_target = 0;
static int _stp_probes_started = 0;

/* _stp_transport_mutext guards _stp_start_called and _stp_exit_called.
   We only want to do the startup and exit sequences once.  Note that
   these indicate the respective process starting, not their conclusion. */
static int _stp_start_called = 0;
static int _stp_exit_called = 0;
static DEFINE_MUTEX(_stp_transport_mutex);

#ifndef STP_CTL_TIMER_INTERVAL
/* ctl timer interval in jiffies (default 20 ms) */
#define STP_CTL_TIMER_INTERVAL		((HZ+49)/50)
#endif


// For now, disable transport version 3 (unless STP_USE_RING_BUFFER is
// defined).
#if STP_TRANSPORT_VERSION == 3 && !defined(STP_USE_RING_BUFFER)
#undef STP_TRANSPORT_VERSION
#define STP_TRANSPORT_VERSION 2
#endif

#include "control.h"
#if STP_TRANSPORT_VERSION == 1
#include "relayfs.c"
#elif STP_TRANSPORT_VERSION == 2
#include "relay_v2.c"
#include "debugfs.c"
#elif STP_TRANSPORT_VERSION == 3
#include "ring_buffer.c"
#include "debugfs.c"
#else
#error "Unknown STP_TRANSPORT_VERSION"
#endif
#include "control.c"

static unsigned _stp_nsubbufs = 8;
static unsigned _stp_subbuf_size = 65536*4;

/* module parameters */
static int _stp_bufsize;
module_param(_stp_bufsize, int, 0);
MODULE_PARM_DESC(_stp_bufsize, "buffer size");

/* forward declarations */
static void systemtap_module_exit(void);
static int systemtap_module_init(void);

static int _stp_module_notifier_active = 0;
static int _stp_module_notifier (struct notifier_block * nb,
                                 unsigned long val, void *data);
static struct notifier_block _stp_module_notifier_nb = {
        .notifier_call = _stp_module_notifier,
        // We used to have this set to 1 before since that is also what
        // kernel/trace/trace_kprobe.c does as well. The idea was that we should
        // be notified _after_ the kprobe infrastruture itself is notified.
        // However, that was the exact opposite of what was happening (we were
        // called _before_ kprobes). In the end, we do not have a hard
        // requirement as to being called before or after kprobes itself, so
        // just leave the default of 0. (See also PR16861).
        .priority = 0
};

#if STP_TRANSPORT_VERSION == 2
static int _stp_module_panic_notifier (struct notifier_block * nb,
                                 unsigned long val, void *data);
static struct notifier_block _stp_module_panic_notifier_nb = {
        .notifier_call = _stp_module_panic_notifier,
        .priority = INT_MAX
};
#endif

static struct timer_list _stp_ctl_work_timer;

/*
 *	_stp_handle_start - handle STP_START
 */

// PR17232: This might be called more than once, but not concurrently
// or reentrantly with itself, or with _stp_cleanup_and_exit.  (The
// latter case is not obvious: _stp_cleanup_and_exit could be called
// from the mutex-protected ctl message handler, so that's fine; or
// it could be called from the module cleanup function, by which time
// we know there is no ctl connection and thus no messages.  So again
// no concurrency.

static void _stp_handle_start(struct _stp_msg_start *st)
{
	int handle_startup;
#if defined(CONFIG_USER_NS)
	struct pid *_upid = NULL;
	struct task_struct *_utask = NULL;
#endif

        // protect against excessive or premature startup
	handle_startup = (! _stp_start_called && ! _stp_exit_called);
	_stp_start_called = 1;
	
	if (handle_startup) {
		dbug_trans(1, "stp_handle_start\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) // linux commit #5f4352fb
#if LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,29) // linux commit #9be260a6
#ifdef STAPCONF_VM_AREA
		{ /* PR9740: workaround for kernel valloc bug. */
                  /* PR14611: not required except within above kernel range. */
			void *dummy;
#ifdef STAPCONF_VM_AREA_PTE
			dummy = alloc_vm_area (PAGE_SIZE, NULL);
#else
			dummy = alloc_vm_area (PAGE_SIZE);
#endif
			free_vm_area (dummy);
		}
#endif
#endif
#endif

		_stp_target = st->target;

#if defined(CONFIG_USER_NS)
                rcu_read_lock();
                _upid = find_vpid(_stp_target);
                if (_upid)
                {
                    _utask = pid_task(_upid, PIDTYPE_PID);
                    if (_utask)
                    {
                        #ifdef DEBUG_UPROBES
                        _stp_dbug(__FUNCTION__,__LINE__, "translating vpid %d to pid %d\n", _stp_target, _utask->pid);
                        #endif
                        _stp_target = _utask->pid;
                    }
                }

                #ifdef DEBUG_UPROBES
                if (!_upid || !_utask)
                    _stp_dbug(__FUNCTION__,__LINE__, "cannot map pid %d to host namespace pid\n", _stp_target);
                #endif

                rcu_read_unlock();
#endif

		st->res = systemtap_module_init();
		if (st->res == 0) {
			_stp_probes_started = 1;

                        /* Register the module notifier ... */
                        /* NB: but not if the module_init stuff
                           failed: something nasty has happened, and
                           we want no further probing started.  PR16766 */
                        if (!_stp_module_notifier_active) {
                                int rc = register_module_notifier(& _stp_module_notifier_nb);
                                if (rc == 0)
                                        _stp_module_notifier_active = 1;
                                else
                                        _stp_warn ("Cannot register module notifier (%d)\n", rc);
                        }
                }

		/* Called from the user context in response to a proc
		   file write (in _stp_ctl_write_cmd), so may notify
		   the reader directly. */
		_stp_ctl_send_notify(STP_START, st, sizeof(*st));

		/* Register the panic notifier. */
#if STP_TRANSPORT_VERSION == 2
		atomic_notifier_chain_register(&panic_notifier_list, &_stp_module_panic_notifier_nb);
#endif
	}
}


// _stp_cleanup_and_exit: handle STP_EXIT and cleanup_module
//
/* We need to call it both times because we want to clean up properly */
/* when someone does /sbin/rmmod on a loaded systemtap module. */
static void _stp_cleanup_and_exit(int send_exit)
{
	int handle_exit;

        // protect against excessive or premature cleanup
	handle_exit = (_stp_start_called && ! _stp_exit_called);
	_stp_exit_called = 1;

	if (handle_exit) {
		int failures;

                dbug_trans(1, "cleanup_and_exit (%d)\n", send_exit);

	        /* Unregister the module notifier. */
	        if (_stp_module_notifier_active) {
                        int rc = unregister_module_notifier(& _stp_module_notifier_nb);
                        if (rc)
                                _stp_warn("module_notifier unregister error %d", rc);
	                _stp_module_notifier_active = 0;
                        stp_synchronize_sched(); // paranoia: try to ensure no further calls in progress
	        }

		_stp_exit_flag = 1;

		if (_stp_probes_started) {
			dbug_trans(1, "calling systemtap_module_exit\n");
			/* tell the stap-generated code to unload its probes, etc */
			systemtap_module_exit();
			dbug_trans(1, "done with systemtap_module_exit\n");
		}

		failures = atomic_read(&_stp_transport_failures);
		if (failures)
			_stp_warn("There were %d transport failures.\n", failures);

		dbug_trans(1, "*** calling _stp_transport_data_fs_stop ***\n");
		_stp_transport_data_fs_stop();

		dbug_trans(1, "ctl_send STP_EXIT\n");
		if (send_exit) {
			/* send_exit is only set to one if called from
			   _stp_ctl_write_cmd() in response to a write
			   to the proc cmd file, so in user context. It
			   is safe to immediately notify the reader.  */
			_stp_ctl_send_notify(STP_EXIT, NULL, 0);
		}
		dbug_trans(1, "done with ctl_send STP_EXIT\n");

		/* Unregister the panic notifier. */
#if STP_TRANSPORT_VERSION == 2
		atomic_notifier_chain_unregister(&panic_notifier_list, &_stp_module_panic_notifier_nb);
#endif
	}
}


// Coming from script type sources, e.g. the exit() tapset function:
// consists of sending a message to staprun/stapio, and definitely
// NOT calling _stp_cleanup_and_exit(), since that function requires
// a more user context to run from.
static void _stp_request_exit(void)
{
	static int called = 0;
	if (!called) {
		/* we only want to do this once; XXX: why? what's the harm? */
		called = 1;
		dbug_trans(1, "ctl_send STP_REQUEST_EXIT\n");
		/* Called from the timer when _stp_exit_flag has been
		   been set. So safe to immediately notify any readers. */
		_stp_ctl_send_notify(STP_REQUEST_EXIT, NULL, 0);
		dbug_trans(1, "done with ctl_send STP_REQUEST_EXIT\n");
	}
}

/*
 * Called when stapio closes the control channel.
 */
static void _stp_detach(void)
{
	dbug_trans(1, "detach\n");
	_stp_pid = 0;
  _stp_namespaces_pid = 0;

	if (!_stp_exit_flag)
		_stp_transport_data_fs_overwrite(1);

        del_timer_sync(&_stp_ctl_work_timer);
	wake_up_interruptible(&_stp_ctl_wq);
}


static void _stp_ctl_work_callback(unsigned long val);

/*
 * Called when stapio opens the control channel.
 */
static void _stp_attach(void)
{
	dbug_trans(1, "attach\n");
	_stp_pid = current->pid;
  if (_stp_namespaces_pid < 1)
    _stp_namespaces_pid = _stp_pid;
	_stp_transport_data_fs_overwrite(0);
	init_timer(&_stp_ctl_work_timer);
	_stp_ctl_work_timer.expires = jiffies + STP_CTL_TIMER_INTERVAL;
	_stp_ctl_work_timer.function = _stp_ctl_work_callback;
	_stp_ctl_work_timer.data= 0;
	add_timer(&_stp_ctl_work_timer);
}

/*
 *	_stp_ctl_work_callback - periodically check for IO or exit
 *	This IO comes from control messages like system(), warn(),
 *	that could potentially have been send from krpobe context,
 *	so they don't immediately trigger a wake_up of _stp_ctl_wq.
 *	This is run by a kernel thread and may NOT sleep, but it
 *	may call wake_up_interruptible on _stp_ctl_wq to notify
 *	any readers, or send messages itself that are immediately
 *	notified. Reschedules itself if someone is still attached
 *	to the cmd channel.
 */
static void _stp_ctl_work_callback(unsigned long val)
{
	int do_io = 0;
	unsigned long flags;
	struct context* __restrict__ c = NULL;

	/* Prevent probe reentrancy while grabbing probe-used locks.  */
	c = _stp_runtime_entryfn_get_context();

	spin_lock_irqsave(&_stp_ctl_ready_lock, flags);
	if (!list_empty(&_stp_ctl_ready_q))
		do_io = 1;
	spin_unlock_irqrestore(&_stp_ctl_ready_lock, flags);

	_stp_runtime_entryfn_put_context(c);

	if (do_io)
		wake_up_interruptible(&_stp_ctl_wq);

	/* if exit flag is set AND we have finished with systemtap_module_init() */
	if (unlikely(_stp_exit_flag && _stp_probes_started))
		_stp_request_exit();
	if (atomic_read(& _stp_ctl_attached))
                mod_timer (&_stp_ctl_work_timer, jiffies + STP_CTL_TIMER_INTERVAL);
}

/**
 *	_stp_transport_close - close ctl and relayfs channels
 *
 *	This is called automatically when the module is unloaded.
 *     
 */
static void _stp_transport_close(void)
{
	dbug_trans(1, "%d: ************** transport_close *************\n",
		   current->pid);
	_stp_cleanup_and_exit(0);
	_stp_unregister_ctl_channel();
	_stp_transport_fs_close();
	_stp_print_cleanup();	/* free print buffers */
	_stp_mem_debug_done();

	dbug_trans(1, "---- CLOSED ----\n");
}

/**
 * _stp_transport_init() is called from the module initialization.
 *   It does the bare minimum to exchange commands with staprun 
 */
static int _stp_transport_init(void)
{
	dbug_trans(1, "transport_init\n");
#ifdef STAPCONF_TASK_UID
	_stp_uid = current->uid;
	_stp_gid = current->gid;
#else
#if defined(CONFIG_USER_NS) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	_stp_uid = from_kuid_munged(current_user_ns(), current_uid());
	_stp_gid = from_kgid_munged(current_user_ns(), current_gid());
#else
	_stp_uid = current_uid();
	_stp_gid = current_gid();
#endif
#endif

/* PR13489, missing inode-uprobes symbol-export workaround */
#if !defined(STAPCONF_TASK_USER_REGSET_VIEW_EXPORTED) && !defined(STAPCONF_UTRACE_REGSET) /* RHEL5 era utrace */
        kallsyms_task_user_regset_view = (void*) kallsyms_lookup_name ("task_user_regset_view");
        /* There exist interesting kernel versions without task_user_regset_view(), like ARM before 3.0.
           For these kernels, uprobes etc. are out of the question, but plain kernel stap works fine.
           All we have to accomplish is have the loc2c runtime code compile.  For that, it's enough
           to leave this pointer zero. */
        if (kallsyms_task_user_regset_view == NULL) {
                ;
        }
#endif
#if defined(CONFIG_UPROBES) // i.e., kernel-embedded uprobes
#if !defined(STAPCONF_UPROBE_REGISTER_EXPORTED)
        kallsyms_uprobe_register = (void*) kallsyms_lookup_name ("uprobe_register");
        if (kallsyms_uprobe_register == NULL) {
		kallsyms_uprobe_register = (void*) kallsyms_lookup_name ("register_uprobe");
        }
        if (kallsyms_uprobe_register == NULL) {
                printk(KERN_ERR "%s can't resolve uprobe_register!", THIS_MODULE->name);
                goto err0;
        }
#endif
#if !defined(STAPCONF_UPROBE_UNREGISTER_EXPORTED)
        kallsyms_uprobe_unregister = (void*) kallsyms_lookup_name ("uprobe_unregister");
        if (kallsyms_uprobe_unregister == NULL) {
		kallsyms_uprobe_unregister = (void*) kallsyms_lookup_name ("unregister_uprobe");
        }
        if (kallsyms_uprobe_unregister == NULL) {
                printk(KERN_ERR "%s can't resolve uprobe_unregister!", THIS_MODULE->name);
                goto err0;
        }
#endif
#if !defined(STAPCONF_UPROBE_GET_SWBP_ADDR_EXPORTED)
        kallsyms_uprobe_get_swbp_addr = (void*) kallsyms_lookup_name ("uprobe_get_swbp_addr");
        if (kallsyms_uprobe_get_swbp_addr == NULL) {
                printk(KERN_ERR "%s can't resolve uprobe_get_swbp_addr!", THIS_MODULE->name);
                goto err0;
        }
#endif
#endif

	if (_stp_bufsize) {
		unsigned size = _stp_bufsize * 1024 * 1024;
		_stp_subbuf_size = 65536;
		while (size / _stp_subbuf_size > 64 &&
		       _stp_subbuf_size < 1024 * 1024) {
			_stp_subbuf_size <<= 1;
		}
		_stp_nsubbufs = size / _stp_subbuf_size;
		dbug_trans(1, "Using %d subbufs of size %d\n", _stp_nsubbufs, _stp_subbuf_size);
	}

	if (_stp_transport_fs_init(THIS_MODULE->name) != 0)
		goto err0;

	/* create control channel */
	if (_stp_register_ctl_channel() < 0)
		goto err1;

	/* create print buffers */
	if (_stp_print_init() < 0)
		goto err2;

	/* set _stp_module_self dynamic info */
	if (_stp_module_update_self() < 0)
		goto err3;

	/* start transport */
	_stp_transport_data_fs_start();

        /* Signal stapio to send us STP_START back.
           This is an historic convention. This was called
	   STP_TRANSPORT_INFO and had a payload that described the
	   transport buffering, this is no longer the case.
	   Called during module initialization time, so safe to immediately
	   notify reader we are ready.  */
	_stp_ctl_send_notify(STP_TRANSPORT, NULL, 0);

	dbug_trans(1, "returning 0...\n");
	return 0;

err3:
	_stp_print_cleanup();
err2:
	_stp_unregister_ctl_channel();
err1:
	_stp_transport_fs_close();
err0:
	return -1;
}

static inline void _stp_lock_inode(struct inode *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
	mutex_lock(&inode->i_mutex);
#else
	down(&inode->i_sem);
#endif
}

static inline void _stp_unlock_inode(struct inode *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
	mutex_unlock(&inode->i_mutex);
#else
	up(&inode->i_sem);
#endif
}

static struct dentry *_stp_lockfile = NULL;

static int _stp_lock_transport_dir(void)
{
	int numtries = 0;

#if STP_TRANSPORT_VERSION == 1
	while ((_stp_lockfile = relayfs_create_dir("systemtap_lock", NULL)) == NULL) {
#else
	while ((_stp_lockfile = debugfs_create_dir("systemtap_lock", NULL)) == NULL) {
#endif
		if (numtries++ >= 50)
			return 0;
		msleep(50);
	}
	return 1;
}

static void _stp_unlock_transport_dir(void)
{
	if (_stp_lockfile) {
#if STP_TRANSPORT_VERSION == 1
		relayfs_remove_dir(_stp_lockfile);
#else
		debugfs_remove(_stp_lockfile);
#endif
		_stp_lockfile = NULL;
	}
}

static struct dentry *__stp_root_dir = NULL;

/* _stp_get_root_dir() - creates root directory or returns
 * a pointer to it if it already exists.
 *
 * The caller *must* lock the transport directory.
 */

static struct dentry *_stp_get_root_dir(void)
{
	struct file_system_type *fs;
	struct super_block *sb;
	const char *name = "systemtap";

	if (__stp_root_dir != NULL) {
		return __stp_root_dir;
	}

#if STP_TRANSPORT_VERSION == 1
	fs = get_fs_type("relayfs");
	if (!fs) {
		errk("Couldn't find relayfs filesystem.\n");
		return NULL;
	}
#else
	fs = get_fs_type("debugfs");
	if (!fs) {
		errk("Couldn't find debugfs filesystem.\n");
		return NULL;
	}
#endif

#if STP_TRANSPORT_VERSION == 1
	__stp_root_dir = relayfs_create_dir(name, NULL);
#else
	__stp_root_dir = debugfs_create_dir(name, NULL);
#endif
	if (!__stp_root_dir) {
		/* Couldn't create it because it is already there, so
		 * find it. */
#ifdef STAPCONF_FS_SUPERS_HLIST
		sb = hlist_entry(fs->fs_supers.first, struct super_block,
	 			 s_instances);
#else
		sb = list_entry(fs->fs_supers.next, struct super_block,
				s_instances);
#endif
		_stp_lock_inode(sb->s_root->d_inode);
		__stp_root_dir = lookup_one_len(name, sb->s_root,
						strlen(name));
		_stp_unlock_inode(sb->s_root->d_inode);
		if (!IS_ERR(__stp_root_dir))
			dput(__stp_root_dir);
		else {
			__stp_root_dir = NULL;
			errk("Could not create or find transport directory.\n");
		}
	}
	else if (IS_ERR(__stp_root_dir)) {
	    __stp_root_dir = NULL;
	    errk("Could not create root directory \"%s\", error %ld\n", name,
		 -PTR_ERR(__stp_root_dir));
	}

	return __stp_root_dir;
}

/* _stp_remove_root_dir() - removes root directory (if empty)
 *
 * The caller *must* lock the transport directory.
 */

static void _stp_remove_root_dir(void)
{
	if (__stp_root_dir) {
		if (simple_empty(__stp_root_dir)) {
#if STP_TRANSPORT_VERSION == 1
			relayfs_remove_dir(__stp_root_dir);
#else
			debugfs_remove(__stp_root_dir);
#endif
		}
		__stp_root_dir = NULL;
	}
}

static struct dentry *__stp_module_dir = NULL;

static struct dentry *_stp_get_module_dir(void)
{
	return __stp_module_dir;
}

static int _stp_transport_fs_init(const char *module_name)
{
	struct dentry *root_dir;
    
	dbug_trans(1, "entry\n");
	if (module_name == NULL)
		return -1;

	if (!_stp_lock_transport_dir()) {
		errk("Couldn't lock transport directory.\n");
		return -1;
	}

	root_dir = _stp_get_root_dir();
	if (root_dir == NULL) {
		_stp_unlock_transport_dir();
		return -1;
	}

#if STP_TRANSPORT_VERSION == 1
        __stp_module_dir = relayfs_create_dir(module_name, root_dir);
#else
        __stp_module_dir = debugfs_create_dir(module_name, root_dir);
#endif
        if (!__stp_module_dir) {
		errk("Could not create module directory \"%s\"\n",
		     module_name);
		_stp_remove_root_dir();
		_stp_unlock_transport_dir();
		return -1;
	}
	else if (IS_ERR(__stp_module_dir)) {
		errk("Could not create module directory \"%s\", error %ld\n",
		     module_name, -PTR_ERR(__stp_module_dir));
		_stp_remove_root_dir();
		_stp_unlock_transport_dir();
		return -1;
	}

	if (_stp_transport_data_fs_init() != 0) {
#if STP_TRANSPORT_VERSION == 1
		relayfs_remove_dir(__stp_module_dir);
#else
		debugfs_remove(__stp_module_dir);
#endif
		__stp_module_dir = NULL;
		_stp_remove_root_dir();
		_stp_unlock_transport_dir();
		return -1;
	}
	_stp_unlock_transport_dir();
	dbug_trans(1, "returning 0\n");
	return 0;
}

static void _stp_transport_fs_close(void)
{
	dbug_trans(1, "stp_transport_fs_close\n");

	_stp_transport_data_fs_close();

	if (__stp_module_dir) {
		if (!_stp_lock_transport_dir()) {
			errk("Couldn't lock transport directory.\n");
			return;
		}

#if STP_TRANSPORT_VERSION == 1
		relayfs_remove_dir(__stp_module_dir);
#else
		debugfs_remove(__stp_module_dir);
#endif
		__stp_module_dir = NULL;

		_stp_remove_root_dir();
		_stp_unlock_transport_dir();
	}
}


/* NB: Accessed from tzinfo.stp tapset */
static uint64_t tz_gmtoff;
static char tz_name[MAXSTRINGLEN];

static void _stp_handle_tzinfo (struct _stp_msg_tzinfo* tzi)
{
        tz_gmtoff = tzi->tz_gmtoff;
        strlcpy (tz_name, tzi->tz_name, MAXSTRINGLEN);
        /* We may silently truncate the incoming string,
         * for example if MAXSTRINGLEN < STP_TZ_NAME_LEN-1 */
}


static int32_t _stp_privilege_credentials = 0;

static void _stp_handle_privilege_credentials (struct _stp_msg_privilege_credentials* pc)
{
  _stp_privilege_credentials = pc->pc_group_mask;
}

static void _stp_handle_remote_id (struct _stp_msg_remote_id* rem)
{
  _stp_remote_id = (int64_t) rem->remote_id;
  strlcpy(_stp_remote_uri, rem->remote_uri, min(STP_REMOTE_URI_LEN,MAXSTRINGLEN));
}

static void _stp_handle_namespaces_pid (struct _stp_msg_ns_pid *nspid)
{
  if (nspid->target > 0)
    _stp_namespaces_pid = (int) nspid->target;
}



#endif /* _TRANSPORT_C_ */
