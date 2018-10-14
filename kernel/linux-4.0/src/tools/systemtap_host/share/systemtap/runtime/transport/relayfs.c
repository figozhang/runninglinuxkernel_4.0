/* -*- linux-c -*- 
 * relayfs.c - relayfs transport functions
 *
 * Copyright (C) IBM Corporation, 2005, 2006
 * Copyright (C) 2005-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/* This file is only for older kernels that have no debugfs. */

/* relayfs is required! */
#if !defined (CONFIG_RELAYFS_FS) && !defined (CONFIG_RELAYFS_FS_MODULE)
#error "RelayFS does not appear to be in this kernel!"
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/relayfs_fs.h>
#include <linux/namei.h>

/* Note: if struct _stp_relay_data_type changes, staplog.c might need
 * to be changed. */
struct _stp_relay_data_type {
	struct rchan *rchan;
	enum _stp_transport_state transport_state;
	int flushing;
};
struct _stp_relay_data_type _stp_relay_data;

/* We need to include procfs.c here so that it can see the
 * _stp_relay_data_type definition. */
#include "procfs.c"

/**
 *	__stp_relay_subbuf_start_callback - subbuf_start() relayfs
 *	callback implementation
 */
static int
__stp_relay_subbuf_start_callback(struct rchan_buf *buf,
				  void *subbuf,
				  unsigned prev_subbuf_idx,
				  void *prev_subbuf)
{
	unsigned padding = buf->padding[prev_subbuf_idx];
	if (prev_subbuf)
		*((unsigned *)prev_subbuf) = padding;

	return sizeof(padding); /* reserve space for padding */
}

/**
 *	__stp_relay_buf_full_callback - buf_full() relayfs callback
 *	implementation
 */
static void __stp_relay_buf_full_callback(struct rchan_buf *buf,
					  unsigned subbuf_idx,
					  void *subbuf)
{
	unsigned padding = buf->padding[subbuf_idx];
	*((unsigned *)subbuf) = padding;
}

static struct rchan_callbacks stp_rchan_callbacks =
{
	.subbuf_start = __stp_relay_subbuf_start_callback,
	.buf_full = __stp_relay_buf_full_callback,
};

static void _stp_transport_data_fs_start(void)
{
	if (_stp_relay_data.transport_state == STP_TRANSPORT_INITIALIZED)
		_stp_relay_data.transport_state = STP_TRANSPORT_RUNNING;
}

static void _stp_transport_data_fs_stop(void)
{
	if (_stp_relay_data.transport_state == STP_TRANSPORT_RUNNING) {
		_stp_relay_data.transport_state = STP_TRANSPORT_STOPPED;
		_stp_relay_data.flushing = 1;
		if (_stp_relay_data.rchan)
			relay_flush(_stp_relay_data.rchan);
	}
}

static void _stp_transport_data_fs_close(void)
{
	_stp_transport_data_fs_stop();
	if (_stp_relay_data.rchan) {
		relay_close(_stp_relay_data.rchan);
		_stp_relay_data.rchan = NULL;
	}
}

static int _stp_transport_data_fs_init(void)
{
	int rc = 0;
	int i;

	dbug_trans(1, "relay_open %d %d\n", _stp_subbuf_size, _stp_nsubbufs);
	_stp_relay_data.transport_state = STP_TRANSPORT_STOPPED;
	_stp_relay_data.flushing = 0;

	/* Create "trace" file. */
	_stp_relay_data.rchan = relay_open("trace", _stp_get_module_dir(),
					   _stp_subbuf_size, _stp_nsubbufs,
					   0, &stp_rchan_callbacks);
	if (!_stp_relay_data.rchan) {
		rc = -ENOENT;
		goto err;
	}
        {
                u64 relay_mem;
                relay_mem = _stp_subbuf_size * _stp_nsubbufs;
#ifdef STP_BULKMODE
                relay_mem *= num_online_cpus();
#endif
                _stp_allocated_net_memory += relay_mem;
                _stp_allocated_memory += relay_mem;
        }

	/* now set ownership */
	for_each_online_cpu(i) {
		_stp_relay_data.rchan->buf[i]->dentry->d_inode->i_uid
			= _stp_uid;
		_stp_relay_data.rchan->buf[i]->dentry->d_inode->i_gid
			= _stp_gid;
	}

	/* We're initialized. */
	_stp_relay_data.transport_state = STP_TRANSPORT_INITIALIZED;
	return rc;

err:
	errk("couldn't create relay channel.\n");
	_stp_transport_data_fs_close();
	return rc;
}

static enum _stp_transport_state _stp_transport_get_state(void)
{
	return _stp_relay_data.transport_state;
}

static void _stp_transport_data_fs_overwrite(int overwrite)
{
	_stp_relay_data.rchan->overwrite = overwrite;
}

/**
 *      _stp_data_write_reserve - try to reserve size_request bytes
 *      @size_request: number of bytes to attempt to reserve
 *      @entry: entry is returned here
 *
 *      Returns number of bytes reserved, 0 if full.  On return, entry
 *      will point to allocated opaque pointer.  Use
 *      _stp_data_entry_data() to get pointer to copy data into.
 *
 *	(For this code's purposes, entry is filled in with the actual
 *	data pointer, but the caller doesn't know that.)
 */
static size_t
_stp_data_write_reserve(size_t size_request, void **entry)
{
	if (entry == NULL)
		return -EINVAL;

	*entry = relay_reserve(_stp_relay_data.rchan, size_request);
	if (*entry == NULL)
		return 0;
	return size_request;
}

static unsigned char *_stp_data_entry_data(void *entry)
{
	/* Nothing to do here. */
	return entry;
}

static int _stp_data_write_commit(void *entry)
{
	/* Nothing to do here. */
	return 0;
}
