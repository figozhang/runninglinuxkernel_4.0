/* -*- linux-c -*-
 *
 * /proc command channels
 * Copyright (C) 2007-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_PROCFS_C_
#define _STP_PROCFS_C_

#if (!defined(STAPCONF_PATH_LOOKUP) && !defined(STAPCONF_KERN_PATH_PARENT) \
     && !defined(STAPCONF_VFS_PATH_LOOKUP) && !defined(STAPCONF_KERN_PATH))
#error "Either path_lookup(), kern_path_parent(), vfs_path_lookup(), or kern_path() must be exported by the kernel."
#endif

#ifdef STAPCONF_KERN_PATH
#include <linux/namei.h>
#endif
#ifdef STAPCONF_VFS_PATH_LOOKUP
#include <linux/mount.h>
#include <linux/pid_namespace.h>
#endif
#include "proc_fs_compatibility.h"
#include "uidgid_compatibility.h"

#if defined(STAPCONF_PATH_LOOKUP) && !defined(STAPCONF_KERN_PATH_PARENT)
#define kern_path_parent(name, nameidata) \
	path_lookup(name, LOOKUP_PARENT, nameidata)
#endif

/* If STAPCONF_PDE_DATA isn't defined, we're using the original /proc
 * interface (where 'struct proc_dir_entry' isn't opaque). In this
 * case allow the (undocumented) feature of slashes
 * (i.e. subdirectories) in paths. */
#ifndef STAPCONF_PDE_DATA
#define _STP_ALLOW_PROCFS_PATH_SUBDIRS
#endif

/* The maximum number of files AND directories that can be opened.
 * It would be great if the translator would emit this based on the actual
 * number of needed files.
 */
#ifndef STP_MAX_PROCFS_FILES
#define STP_MAX_PROCFS_FILES 16
#endif

static int _stp_num_pde = 0;
static struct proc_dir_entry *_stp_pde[STP_MAX_PROCFS_FILES];

/* _stp_proc_root is the '/proc/systemtap/{module_name}' directory. */
static struct proc_dir_entry *_stp_proc_root = NULL;

static void _stp_close_procfs(void);


/*
 * Removes '/proc/systemtap/{module_name}'. Notice we're leaving
 * '/proc/systemtap' behind.  There is no way on newer kernels to know
 * if a procfs directory is empty.
 *
 * NB: this is suitable to call late in the module cleanup function,
 * and does not rely on any other facilities in the runtime.  PR19833.
 * See also PR15408.
 */
static void _stp_rmdir_proc_module(void)
{
	if (_stp_proc_root) {
		proc_remove(_stp_proc_root);
		_stp_proc_root = NULL;
	}
}


/*
 * Safely creates '/proc/systemtap' (if necessary) and
 * '/proc/systemtap/{module_name}'.
 *
 * NB: this function is suitable to call from early in the the
 * module-init function, and doesn't rely on any other facilities
 * in our runtime.  PR19833.  See also PR15408.
 */
static int _stp_mkdir_proc_module(void)
{	
	int found = 0;
	static char proc_root_name[STP_MODULE_NAME_LEN + sizeof("systemtap/")];
#if defined(STAPCONF_PATH_LOOKUP) || defined(STAPCONF_KERN_PATH_PARENT)
	struct nameidata nd;
#else  /* STAPCONF_VFS_PATH_LOOKUP or STAPCONF_KERN_PATH */
	struct path path;
#if defined(STAPCONF_VFS_PATH_LOOKUP)
	struct vfsmount *mnt;
#endif
	int rc;
#endif	/* STAPCONF_VFS_PATH_LOOKUP or STAPCONF_KERN_PATH */

        if (_stp_proc_root != NULL)
		return 0;

#if defined(STAPCONF_PATH_LOOKUP) || defined(STAPCONF_KERN_PATH_PARENT)
	/* Why "/proc/systemtap/foo"?  kern_path_parent() is basically
	 * the same thing as calling the old path_lookup() with flags
	 * set to LOOKUP_PARENT, which means to look up the parent of
	 * the path, which in this case is "/proc/systemtap". */
	if (! kern_path_parent("/proc/systemtap/foo", &nd)) {
		found = 1;
#ifdef STAPCONF_NAMEIDATA_CLEANUP
		path_put(&nd.path);
#else  /* !STAPCONF_NAMEIDATA_CLEANUP */
		path_release(&nd);
#endif	/* !STAPCONF_NAMEIDATA_CLEANUP */
	}

#elif defined(STAPCONF_KERN_PATH)
	/* Prefer kern_path() over vfs_path_lookup(), since on some
	 * kernels the declaration for vfs_path_lookup() was moved to
	 * a private header. */

	/* See if '/proc/systemtap' exists. */
	rc = kern_path("/proc/systemtap", 0, &path);
	if (rc == 0) {
		found = 1;
		path_put (&path);
	}

#else  /* STAPCONF_VFS_PATH_LOOKUP */
	/* See if '/proc/systemtap' exists. */
	if (! init_pid_ns.proc_mnt) {
		errk("Unable to create '/proc/systemap':"
		     " '/proc' doesn't exist.\n");
		goto done;
	}
	mnt = init_pid_ns.proc_mnt;
	rc = vfs_path_lookup(mnt->mnt_root, mnt, "systemtap", 0, &path);
	if (rc == 0) {
		found = 1;
		path_put (&path);
	}
#endif	/* STAPCONF_VFS_PATH_LOOKUP */

	/* If we couldn't find "/proc/systemtap", create it. */
	if (!found) {
		struct proc_dir_entry *de;

		de = proc_mkdir ("systemtap", NULL);
		if (de == NULL) {
			errk("Unable to create '/proc/systemap':"
			     " proc_mkdir failed.\n");
			goto done;
 		}
	}

	/* Create the "systemtap/{module_name} directory in procfs. */
	strlcpy(proc_root_name, "systemtap/", sizeof(proc_root_name));
	strlcat(proc_root_name, THIS_MODULE->name, sizeof(proc_root_name));
	_stp_proc_root = proc_mkdir(proc_root_name, NULL);
#ifdef STAPCONF_PROCFS_OWNER
	if (_stp_proc_root != NULL)
		_stp_proc_root->owner = THIS_MODULE;
#endif
	if (_stp_proc_root == NULL)
		errk("Unable to create '/proc/systemap/%s':"
		     " proc_mkdir failed.\n", THIS_MODULE->name);

done:
	return (_stp_proc_root) ? 0 : -EINVAL;
}

#ifdef _STP_ALLOW_PROCFS_PATH_SUBDIRS
/*
 * This checks our local cache to see if we already made the dir.
 */
static struct proc_dir_entry *_stp_procfs_lookup(const char *dir, struct proc_dir_entry *parent)
{
	int i;
	for (i = 0; i <_stp_num_pde; i++) {
		struct proc_dir_entry *pde = _stp_pde[i];
		if (pde->parent == parent && !strcmp(dir, pde->name))
			return pde;
	}
	return NULL;
}
#endif	/* _STP_ALLOW_PROCFS_PATH_SUBDIRS */


static int _stp_create_procfs(const char *path, int num,
			      const struct file_operations *fops, int perm,
			      void *data) 
{  
	const char *p; char *next;
	struct proc_dir_entry *last_dir, *de;

	if (num >= STP_MAX_PROCFS_FILES) {
		_stp_error("Requested file number %d is larger than max (%d)\n", 
			   num, STP_MAX_PROCFS_FILES);
		return -1;
	}

	last_dir = _stp_proc_root;

	/* if no path, use default one */
	if (strlen(path) == 0)
		p = "command";
	else
		p = path;
	
#ifdef _STP_ALLOW_PROCFS_PATH_SUBDIRS
	while ((next = strchr(p, '/'))) {
		if (_stp_num_pde == STP_MAX_PROCFS_FILES)
			goto too_many;
		*next = 0;
		de = _stp_procfs_lookup(p, last_dir);
		if (de == NULL) {
			last_dir = proc_mkdir(p, last_dir);
			if (!last_dir) {
				_stp_error("Could not create directory \"%s\"\n", p);
				goto err;
			}
			_stp_pde[_stp_num_pde++] = last_dir;
#ifdef STAPCONF_PROCFS_OWNER
			last_dir->owner = THIS_MODULE;
#endif
			proc_set_user(last_dir, KUIDT_INIT(_stp_uid),
				      KGIDT_INIT(_stp_gid));
		}
		else {
			last_dir = de;
		}
		p = next + 1;
	}
#else  /* !_STP_ALLOW_PROCFS_PATH_SUBDIRS */
	if (strchr(p, '/') != NULL) {
		_stp_error("Could not create path \"%s\","
			   " contains subdirectories\n", p);
		goto err;
	}
#endif	/* !_STP_ALLOW_PROCFS_PATH_SUBDIRS */
	
	if (_stp_num_pde == STP_MAX_PROCFS_FILES)
		goto too_many;
	
	de = proc_create_data(p, perm, last_dir, fops, data);
	if (de == NULL) {
		_stp_error("Could not create file \"%s\" in path \"%s\"\n",
			   p, path);
		goto err;
	}
#ifdef STAPCONF_PROCFS_OWNER
	de->owner = THIS_MODULE;
#endif
	proc_set_user(de, KUIDT_INIT(_stp_uid), KGIDT_INIT(_stp_gid));
	_stp_pde[_stp_num_pde++] = de;
	return 0;
	
too_many:
	_stp_error("Attempted to open too many procfs files. Maximum is %d\n",
		   STP_MAX_PROCFS_FILES);
err:
	_stp_close_procfs();
	return -1;
}

static void _stp_close_procfs(void)
{
	int i;
	for (i = _stp_num_pde-1; i >= 0; i--) {
		struct proc_dir_entry *pde = _stp_pde[i];
		proc_remove(pde);
	}
	_stp_num_pde = 0;
}

#endif	/* _STP_PROCFS_C_ */
