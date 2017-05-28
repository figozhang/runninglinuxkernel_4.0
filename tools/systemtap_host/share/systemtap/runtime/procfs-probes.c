#ifndef _STP_PROCFS_PROBES_C_
#define _STP_PROCFS_PROBES_C_

#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/sched.h>

#if 0
// Currently we have to output _stp_procfs_data early in the
// translation process.  It really should go here.
struct _stp_procfs_data {
	char *buffer;
	size_t bufsize;
	size_t count;
};
#endif

struct stap_procfs_probe {
	const char *path;
	const struct stap_probe * const read_probe;
	const struct stap_probe * const write_probe;

	char *buffer;
	const size_t bufsize;
	size_t count;
	int needs_fill;
	const int permissions;

	struct mutex lock;
	int opencount;
	wait_queue_head_t waitq;
};

static inline void _spp_init(struct stap_procfs_probe *spp)
{
	init_waitqueue_head(&spp->waitq);
	spp->opencount = 0;
	mutex_init(&spp->lock);
}
#define _spp_lock(spp)		mutex_lock(&(spp)->lock)
#define _spp_unlock(spp)	mutex_unlock(&(spp)->lock)
#define _spp_shutdown(spp)	mutex_destroy(&(spp)->lock)

static int _stp_proc_fill_read_buffer(struct stap_procfs_probe *spp);

static int _stp_process_write_buffer(struct stap_procfs_probe *spp,
				     const char __user *buf, size_t count);

static int
_stp_proc_open_file(struct inode *inode, struct file *filp)
{
	struct stap_procfs_probe *spp;
	int res;

	spp = (struct stap_procfs_probe *)PDE_DATA(inode);
	if (spp == NULL) {
		return -EINVAL;
	}

	res = generic_file_open(inode, filp);
	if (res)
		return res;

	/* To avoid concurrency problems, we only allow 1 open at a
	 * time. */

	_spp_lock(spp);

	/* If the file isn't open yet, ... */
	if (spp->opencount == 0) {
		res = 0;
	}
	/* If open() was called with O_NONBLOCK, don't block, just
	 * return EAGAIN. */
	else if (filp->f_flags & O_NONBLOCK) {
		res = -EAGAIN;
	}
	/* The file is already open, so wait. */
	else {
		for (res = 0;;) {
			if (spp->opencount == 0) {
				res = 0;
				break;
			}
			_spp_unlock(spp);
			res = wait_event_interruptible(spp->waitq,
						       spp->opencount == 0);
			_spp_lock(spp);
			if (res < 0)
				break;
		}
	}
	if (likely(res == 0)) {
		spp->opencount++;
		filp->private_data = spp;
		if ((filp->f_flags & O_ACCMODE) == O_RDONLY) {
			spp->buffer[0] = '\0';
			spp->count = 0;
			spp->needs_fill = 1;
		}
	}

	_spp_unlock(spp);
	return 0;
}

static int
_stp_proc_release_file(struct inode *inode, struct file *filp)
{
	struct stap_procfs_probe *spp;

	spp = (struct stap_procfs_probe *)filp->private_data;
	if (spp != NULL) {
		/* Decrement the open count. */
		_spp_lock(spp);
		spp->opencount--;
		_spp_unlock(spp);

		/* Wake up any tasks waiting to open the file. */
		wake_up(&spp->waitq);
	}
	return 0;
}

static ssize_t
_stp_proc_read_file(struct file *file, char __user *buf, size_t count,
		    loff_t *ppos) 
{
	struct stap_procfs_probe *spp = file->private_data;
	ssize_t retval = 0;

	/* If we don't have a probe read function, just return 0 to
	 * indicate there isn't any data here. */
	if (spp == NULL || spp->read_probe == NULL) {
		goto out;
	}

	/* If needed, fill up the buffer.*/
	if (spp->needs_fill) {
		if ((retval = _stp_proc_fill_read_buffer(spp))) {
			goto out;
		}
	}

	/* Return bytes from the buffer. */
	retval = simple_read_from_buffer(buf, count, ppos, spp->buffer,
					 spp->count);
out:
	return retval;
}

static ssize_t
_stp_proc_write_file(struct file *file, const char __user *buf, size_t count,
		     loff_t *ppos) 
{
	struct stap_procfs_probe *spp = file->private_data;
	struct _stp_procfs_data pdata;
	ssize_t len;

	/* If we don't have a write probe, return EIO. */
	if (spp->write_probe == NULL) {
		len = -EIO;
		goto out;
	}

	/* Handle the input buffer. */
	len = _stp_process_write_buffer(spp, buf, count);
	if (len > 0) {
		*ppos += len;
	}

out:
	return len;
}

static struct file_operations _stp_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= _stp_proc_open_file,
	.read		= _stp_proc_read_file,
	.write		= _stp_proc_write_file,
	.llseek		= generic_file_llseek,
	.release	= _stp_proc_release_file,
};

#endif /* _STP_PROCFS_PROBES_C_ */
