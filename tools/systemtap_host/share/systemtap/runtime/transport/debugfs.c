/* -*- linux-c -*-
 *
 * debugfs functions
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#include <linux/debugfs.h>
#include "transport.h"
#include "../uidgid_compatibility.h"

/* Defines the number of buffers allocated in control.c (which #includes
   this file) for the _stp_pool_q.  This is the number of .cmd messages
   the module can store before they have to be read by stapio.
   40 is somewhat arbitrary, 8 pre-allocated messages, 32 dynamic.  */
#define STP_DEFAULT_BUFFERS 40

/* Always returns zero, we just push all messages on the _stp_ctl_ready_q.  */
inline static int _stp_ctl_write_fs(int type, void *data, unsigned len)
{
	return 0;
}

static struct dentry *_stp_cmd_file = NULL;

static int _stp_register_ctl_channel_fs(void)
{
	struct dentry *module_dir = _stp_get_module_dir();
	if (module_dir == NULL) {
		errk("no module directory found.\n");
		return -1;
	}

	/* create [debugfs]/systemtap/module_name/.cmd  */
	_stp_cmd_file = debugfs_create_file(".cmd", 0600, module_dir,
					    NULL, &_stp_ctl_fops_cmd);
	if (_stp_cmd_file == NULL) {
		errk("Error creating systemtap debugfs entries.\n");
		return -1;
	}
	else if (IS_ERR(_stp_cmd_file)) {
		_stp_cmd_file = NULL;
		errk("Error creating systemtap debugfs entries: %ld\n",
		     -PTR_ERR(_stp_cmd_file));
		return -1;
	}

	_stp_cmd_file->d_inode->i_uid = KUIDT_INIT(_stp_uid);
	_stp_cmd_file->d_inode->i_gid = KGIDT_INIT(_stp_gid);

	return 0;
}

static void _stp_unregister_ctl_channel_fs(void)
{
	if (_stp_cmd_file)
		debugfs_remove(_stp_cmd_file);
}
