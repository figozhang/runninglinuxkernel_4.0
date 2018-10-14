/* -*- linux-c -*-
 *
 * control channel header
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _CONTROL_H_
#define _CONTROL_H_

#include <linux/spinlock.h>
#include <linux/list.h>

static struct list_head _stp_ctl_ready_q;
static spinlock_t _stp_ctl_ready_lock;
static wait_queue_head_t _stp_ctl_wq;

struct _stp_buffer {
	struct list_head list;
	int len;
	int type;
	char buf[STP_CTL_BUFFER_SIZE];
};

static struct file_operations _stp_ctl_fops_cmd;

static int _stp_ctl_send(int type, void *data, unsigned len);
static int _stp_ctl_send_notify(int type, void *data, unsigned len);

static int _stp_ctl_write_fs(int type, void *data, unsigned len);

static int _stp_register_ctl_channel(void);
static void _stp_unregister_ctl_channel(void);

static int _stp_register_ctl_channel_fs(void);
static void _stp_unregister_ctl_channel_fs(void);

#endif /* _CONTROL_H_ */
