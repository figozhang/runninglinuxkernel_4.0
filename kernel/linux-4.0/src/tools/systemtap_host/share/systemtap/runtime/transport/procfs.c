/* -*- linux-c -*-
 *
 * /proc transport and control
 * Copyright (C) 2005-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#include "../procfs.c"		   // for _stp_mkdir_proc_module()

#define STP_DEFAULT_BUFFERS 256

#ifdef STP_BULKMODE
/* handle the per-cpu subbuf info read for relayfs */
static ssize_t _stp_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int num;
	struct _stp_buf_info out;

	int cpu = *(int *)(PDE(file->f_dentry->d_inode)->data);

	if (!_stp_relay_data.rchan)
		return -EINVAL;

	out.cpu = cpu;
	out.produced = atomic_read(&_stp_relay_data.rchan->buf[cpu]->subbufs_produced);
	out.consumed = atomic_read(&_stp_relay_data.rchan->buf[cpu]->subbufs_consumed);
	out.flushing = _stp_relay_data.flushing;

	num = sizeof(out);
	if (copy_to_user(buf, &out, num))
		return -EFAULT;

	return num;
}

/* handle the per-cpu subbuf info write for relayfs */
static ssize_t _stp_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct _stp_consumed_info info;
	int cpu = *(int *)(PDE(file->f_dentry->d_inode)->data);
	if (copy_from_user(&info, buf, count))
		return -EFAULT;

	relay_subbufs_consumed(_stp_relay_data.rchan, cpu, info.consumed);
	return count;
}

static struct file_operations _stp_proc_fops = {
	.owner = THIS_MODULE,
	.read = _stp_proc_read,
	.write = _stp_proc_write,
};
#endif /* STP_BULKMODE */

inline static int _stp_ctl_write_fs(int type, void *data, unsigned len)
{
	struct _stp_buffer *bptr;
	unsigned long flags;

#define WRITE_AGG
#ifdef WRITE_AGG
	spin_lock_irqsave(&_stp_ctl_ready_lock, flags);
	if (!list_empty(&_stp_ctl_ready_q)) {
		bptr = (struct _stp_buffer *)_stp_ctl_ready_q.prev;
		if ((bptr->len + len) <= STP_CTL_BUFFER_SIZE
		    && type == STP_REALTIME_DATA
		    && bptr->type == STP_REALTIME_DATA) {
			memcpy(bptr->buf + bptr->len, data, len);
			bptr->len += len;
			spin_unlock_irqrestore(&_stp_ctl_ready_lock, flags);
			return len;
		}
	}
	spin_unlock_irqrestore(&_stp_ctl_ready_lock, flags);
#endif
	return 0;
}

static int _stp_ctl_read_bufsize(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len = sprintf(page, "%d,%d\n", _stp_nsubbufs, _stp_subbuf_size);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}

static int _stp_register_ctl_channel_fs(void)
{
#ifdef STP_BULKMODE
	int i;
	int j;
	char buf[32];
	struct proc_dir_entry *bs = NULL;
#endif
	struct proc_dir_entry *de;

	if (_stp_mkdir_proc_module())
		goto err0;

#ifdef STP_BULKMODE
	/* now for each cpu "n", create /proc/systemtap/module_name/n  */
	for_each_possible_cpu(i) {
		snprintf(buf, sizeof(buf), "%d", i);
		de = create_proc_entry(buf, 0600, _stp_proc_root);
		if (de == NULL)
			goto err1;
		de->uid = _stp_uid;
		de->gid = _stp_gid;
		de->proc_fops = &_stp_proc_fops;
		de->data = _stp_kmalloc(sizeof(int));
		if (de->data == NULL) {
			remove_proc_entry(buf, _stp_proc_root);
			goto err1;
		}
		*(int *)de->data = i;
	}
	bs = create_proc_read_entry("bufsize", 0, _stp_proc_root, _stp_ctl_read_bufsize, NULL);
#endif /* STP_BULKMODE */

	/* create /proc/systemtap/module_name/.cmd  */
	de = create_proc_entry(".cmd", 0600, _stp_proc_root);
	if (de == NULL)
		goto err1;
	de->uid = _stp_uid;
	de->gid = _stp_gid;
	de->proc_fops = &_stp_ctl_fops_cmd;

	return 0;

err1:
#ifdef STP_BULKMODE
	for (de = _stp_proc_root->subdir; de; de = de->next)
		_stp_kfree(de->data);
	for_each_possible_cpu(j) {
		if (j == i)
			break;
		snprintf(buf, sizeof(buf), "%d", j);
		remove_proc_entry(buf, _stp_proc_root);

	}
	if (bs)
		remove_proc_entry("bufsize", _stp_proc_root);
#endif /* STP_BULKMODE */
	_stp_rmdir_proc_module();
err0:
	return -1;
}

static void _stp_unregister_ctl_channel_fs(void)
{
#ifdef STP_BULKMODE
	char buf[32];
	int i;
	struct proc_dir_entry *de;

	dbug_trans(1, "unregistering procfs\n");
	for (de = _stp_proc_root->subdir; de; de = de->next)
		_stp_kfree(de->data);

	for_each_possible_cpu(i) {
		snprintf(buf, sizeof(buf), "%d", i);
		remove_proc_entry(buf, _stp_proc_root);
	}
	remove_proc_entry("bufsize", _stp_proc_root);
#endif /* STP_BULKMODE */

	remove_proc_entry(".cmd", _stp_proc_root);
	_stp_rmdir_proc_module();
}
