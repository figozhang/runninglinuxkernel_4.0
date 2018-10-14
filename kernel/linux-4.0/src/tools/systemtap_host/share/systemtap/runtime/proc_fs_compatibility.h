/* -*- linux-c -*-
 *
 * procfs compatibility defines and functions
 * Copyright (C) 2013 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_PROC_FS_COMPATIBILITY_H_
#define _STP_PROC_FS_COMPATIBILITY_H_

#include <linux/proc_fs.h>

/* If STAPCONF_PDE_DATA isn't defined, we're using the original /proc
 * interface (where 'struct proc_dir_entry' isn't opaque). Provide
 * some of the new interface's functions. */
#ifndef STAPCONF_PDE_DATA

#ifndef STAPCONF_LINUX_UIDGID_H
static void proc_set_user(struct proc_dir_entry *de, uid_t uid, gid_t gid)
{
	de->uid = uid;
	de->gid = gid;
}
#else
static void proc_set_user(struct proc_dir_entry *de, kuid_t uid, kgid_t gid)
{
	de->uid = __kuid_val(uid);
	de->gid = __kgid_val(gid);
}
#endif

// 2.6.24 fixed proc_dir_entry refcounting.
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define LAST_ENTRY_COUNT 0
#else
#define LAST_ENTRY_COUNT 1
#endif

/* Notice that this proc_remove() compatibility function isn't
 * exactly like the original, since it can remove entire
 * subtrees. Since we don't call proc_remove() to remove subtrees,
 * this is OK. */
static void proc_remove(struct proc_dir_entry *de)
{
	if (de && de->subdir == NULL) {
		if (atomic_read(&de->count) != LAST_ENTRY_COUNT)
			printk(KERN_ERR "Removal of %s from /proc"
			       " is deferred until it is no longer in use.\n"
			       "Systemtap module removal will block.\n",
			       de->name);
		remove_proc_entry(de->name, de->parent);
	}
}

/* The 'proc_create_data()' function was present before the new /proc
 * interface make 'struct proc_dir_entry' opaque. */
#ifndef STAPCONF_PROC_CREATE_DATA
static struct proc_dir_entry *
proc_create_data(const char *name, umode_t mode,
		 struct proc_dir_entry *parent,
		 const struct file_operations *proc_fops, void *data)
{
	struct proc_dir_entry *de;
	de = proc_create(name, mode, parent, proc_fops);
	if (de)
		de->data = data;
	return de;
}
#endif  /* STAPCONF_PROC_CREATE_DATA */

#define PDE_DATA(inode) (PDE(inode)->data)

#endif  /* STAPCONF_PDE_DATA */

#endif	/* _STP_PROC_FS_COMPATIBILITY_H_ */
