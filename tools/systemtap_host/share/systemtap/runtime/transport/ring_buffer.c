#include <linux/types.h>
#include <linux/ring_buffer.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/cpumask.h>
#include <asm/local.h>

static DEFINE_PER_CPU(local_t, _stp_cpu_disabled);

static inline void _stp_ring_buffer_disable_cpu(void)
{
	preempt_disable();
	local_inc(&__get_cpu_var(_stp_cpu_disabled));
}

static inline void _stp_ring_buffer_enable_cpu(void)
{
	local_dec(&__get_cpu_var(_stp_cpu_disabled));
	preempt_enable();
}

static inline int _stp_ring_buffer_cpu_disabled(void)
{
    return local_read(&__get_cpu_var(_stp_cpu_disabled));
}

#ifndef STP_RELAY_TIMER_INTERVAL
/* Wakeup timer interval in jiffies (default 10 ms) */
#define STP_RELAY_TIMER_INTERVAL		((HZ + 99) / 100)
#endif

struct _stp_data_entry {
	size_t			len;
	unsigned char		buf[];
};

/*
 * Trace iterator - used by printout routines who present trace
 * results to users and which routines might sleep, etc:
 */
struct _stp_iterator {
	int			cpu_file;
	struct ring_buffer_iter	*buffer_iter[NR_CPUS];
	int			cpu;
	u64			ts;
	atomic_t		nr_events;
};

/* In bulk mode, we need 1 'struct _stp_iterator' for each cpu.  In
 * 'normal' mode, we only need 1 'struct _stp_iterator' (since all
 * output is sent through 1 file). */
#ifdef STP_BULKMODE
#define NR_ITERS NR_CPUS
#else
#define NR_ITERS 1
#endif

struct _stp_relay_data_type {
        atomic_t /* enum _stp_transport_state */ transport_state;
	struct ring_buffer *rb;
	struct _stp_iterator iter[NR_ITERS];
	cpumask_var_t trace_reader_cpumask;
	struct timer_list timer;
	int overwrite_flag;
};
static struct _stp_relay_data_type _stp_relay_data;

/* _stp_poll_wait is a waitqueue for tasks blocked on
 * _stp_data_poll_trace() */
static DECLARE_WAIT_QUEUE_HEAD(_stp_poll_wait);

static void __stp_free_ring_buffer(void)
{
	free_cpumask_var(_stp_relay_data.trace_reader_cpumask);
	if (_stp_relay_data.rb)
		ring_buffer_free(_stp_relay_data.rb);
	_stp_relay_data.rb = NULL;
}

static int __stp_alloc_ring_buffer(void)
{
	int i;
	unsigned long buffer_size = _stp_bufsize * 1024 * 1024;

	if (!alloc_cpumask_var(&_stp_relay_data.trace_reader_cpumask,
			       (GFP_KERNEL & ~__GFP_WAIT)))
		goto fail;
	cpumask_clear(_stp_relay_data.trace_reader_cpumask);

	if (buffer_size == 0) {
		dbug_trans(1, "using default buffer size...\n");
		buffer_size = _stp_nsubbufs * _stp_subbuf_size;
	}
        dbug_trans(1, "using buffer size %lu...\n", buffer_size);

	/* The number passed to ring_buffer_alloc() is per cpu.  Our
	 * 'buffer_size' is a total number of bytes to allocate.  So,
	 * we need to divide buffer_size by the number of cpus. */
	buffer_size /= num_online_cpus();
	dbug_trans(1, "%lu\n", buffer_size);
	_stp_relay_data.rb = ring_buffer_alloc(buffer_size, 0);
	if (!_stp_relay_data.rb)
		goto fail;

        /* Increment _stp_allocated_memory and
           _stp_allocated_net_memory to approximately account for
           buffers allocated by ring_buffer_alloc. */
        {
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif
                u64 relay_pages;
                relay_pages = DIV_ROUND_UP (buffer_size, PAGE_SIZE);
                if (relay_pages < 2) relay_pages = 2;
                relay_pages *= num_online_cpus();
                _stp_allocated_net_memory += relay_pages * PAGE_SIZE;
                _stp_allocated_memory += relay_pages * PAGE_SIZE;
        }

	dbug_trans(0, "size = %lu\n", ring_buffer_size(_stp_relay_data.rb));
	return 0;

fail:
	__stp_free_ring_buffer();
	return -ENOMEM;
}

static int _stp_data_open_trace(struct inode *inode, struct file *file)
{
	struct _stp_iterator *iter = inode->i_private;
#ifdef STP_BULKMODE
	int cpu_file = iter->cpu_file;
#endif

	/* We only allow for one reader per cpu */
	dbug_trans(1, "trace attach\n");
#ifdef STP_BULKMODE
	if (!cpumask_test_cpu(cpu_file, _stp_relay_data.trace_reader_cpumask))
		cpumask_set_cpu(cpu_file, _stp_relay_data.trace_reader_cpumask);
	else {
		dbug_trans(1, "returning EBUSY\n");
		return -EBUSY;
	}
#else
	if (!cpumask_empty(_stp_relay_data.trace_reader_cpumask)) {
		dbug_trans(1, "returning EBUSY\n");
		return -EBUSY;
	}
	cpumask_setall(_stp_relay_data.trace_reader_cpumask);
#endif
	file->private_data = inode->i_private;
	return 0;
}

static int _stp_data_release_trace(struct inode *inode, struct file *file)
{
	struct _stp_iterator *iter = inode->i_private;

	dbug_trans(1, "trace detach\n");
#ifdef STP_BULKMODE
	cpumask_clear_cpu(iter->cpu_file, _stp_relay_data.trace_reader_cpumask);
#else
	cpumask_clear(_stp_relay_data.trace_reader_cpumask);
#endif
	return 0;
}

size_t
_stp_event_to_user(struct ring_buffer_event *event, char __user *ubuf,
		   size_t cnt)
{
	int ret;
	struct _stp_data_entry *entry;

	dbug_trans(1, "event(%p), ubuf(%p), cnt(%lu)\n", event, ubuf, cnt);
	if (event == NULL || ubuf == NULL) {
		dbug_trans(1, "returning -EFAULT(1)\n");
		return -EFAULT;
	}

	entry = ring_buffer_event_data(event);
	if (entry == NULL) {
		dbug_trans(1, "returning -EFAULT(2)\n");
		return -EFAULT;
	}

	/* We don't do partial entries - just fail. */
	if (entry->len > cnt) {
		dbug_trans(1, "returning -EBUSY\n");
		return -EBUSY;
	}

#if defined(DEBUG_TRANS) && (DEBUG_TRANS >= 2)
	{
		char *last = entry->buf + (entry->len - 5);
		dbug_trans2("copying %.5s...%.5s\n", entry->buf, last);
	}
#endif

	if (cnt > entry->len)
		cnt = entry->len;
	ret = copy_to_user(ubuf, entry->buf, cnt);
	if (ret) {
		dbug_trans(1, "returning -EFAULT(3)\n");
		return -EFAULT;
	}

	return cnt;
}

static int _stp_ring_buffer_empty_cpu(struct _stp_iterator *iter)
{
	int cpu;

#ifdef STP_BULKMODE
	cpu = iter->cpu_file;
	if (iter->buffer_iter[cpu]) {
		if (ring_buffer_iter_empty(iter->buffer_iter[cpu]))
			return 1;
	}
	else {
		if (atomic_read(&iter->nr_events) == 0)
			return 1;
	}
	return 0;
#else
	for_each_online_cpu(cpu) {
		if (iter->buffer_iter[cpu]) {
			if (!ring_buffer_iter_empty(iter->buffer_iter[cpu]))
				return 0;
		}
		else {
			if (atomic_read(&iter->nr_events) != 0)
				return 0;
		}
	}
	return 1;
#endif
}

static int _stp_ring_buffer_empty(void)
{
	struct _stp_iterator *iter;
#ifdef STP_BULKMODE
	int cpu;

	for_each_possible_cpu(cpu) {
		iter = &_stp_relay_data.iter[cpu];
		if (! _stp_ring_buffer_empty_cpu(iter))
			return 0;
	}
	return 1;
#else
	iter = &_stp_relay_data.iter[0];
	return _stp_ring_buffer_empty_cpu(iter);
#endif
}

static void _stp_ring_buffer_iterator_increment(struct _stp_iterator *iter)
{
	if (iter->buffer_iter[iter->cpu]) {
		_stp_ring_buffer_disable_cpu();
		ring_buffer_read(iter->buffer_iter[iter->cpu], NULL);
		_stp_ring_buffer_enable_cpu();
	}
}

static void _stp_ring_buffer_consume(struct _stp_iterator *iter)
{
	_stp_ring_buffer_iterator_increment(iter);
	_stp_ring_buffer_disable_cpu();
#ifdef STAPCONF_RING_BUFFER_LOST_EVENTS
	ring_buffer_consume(_stp_relay_data.rb, iter->cpu, &iter->ts, NULL);
#else
	ring_buffer_consume(_stp_relay_data.rb, iter->cpu, &iter->ts);
#endif
	_stp_ring_buffer_enable_cpu();
	atomic_dec(&iter->nr_events);
}

static ssize_t _stp_tracing_wait_pipe(struct file *filp)
{
	struct _stp_iterator *iter = filp->private_data;

	if (atomic_read(&iter->nr_events) == 0) {
		if ((filp->f_flags & O_NONBLOCK)) {
			dbug_trans(1, "returning -EAGAIN\n");
			return -EAGAIN;
		}

		if (signal_pending(current)) {
			dbug_trans(1, "returning -EINTR\n");
			return -EINTR;
		}
		dbug_trans(1, "returning 0\n");
		return 0;
	}

	dbug_trans(1, "returning 1\n");
	return 1;
}

static struct ring_buffer_event *
_stp_peek_next_event(struct _stp_iterator *iter, int cpu, u64 *ts)
{
	struct ring_buffer_event *event;

	_stp_ring_buffer_disable_cpu();
	if (iter->buffer_iter[cpu])
		event = ring_buffer_iter_peek(iter->buffer_iter[cpu], ts);
	else
#ifdef STAPCONF_RING_BUFFER_LOST_EVENTS
		event = ring_buffer_peek(_stp_relay_data.rb, cpu, ts, NULL);
#else
		event = ring_buffer_peek(_stp_relay_data.rb, cpu, ts);
#endif
	_stp_ring_buffer_enable_cpu();
	return event;
}

/* Find the next real event */
static struct ring_buffer_event *
_stp_find_next_event(struct _stp_iterator *iter)
{
	struct ring_buffer_event *event;

#ifdef STP_BULKMODE
	int cpu_file = iter->cpu_file;

	/*
	 * If we are in a per_cpu trace file, don't bother by iterating over
	 * all cpus and peek directly.
	 */
	if (iter->buffer_iter[cpu_file] == NULL ) {
		if (atomic_read(&iter->nr_events) == 0)
			return NULL;
	}
	else {
		if (ring_buffer_iter_empty(iter->buffer_iter[cpu_file]))
			return NULL;
	}
	event = _stp_peek_next_event(iter, cpu_file, &iter->ts);

	return event;
#else
	struct ring_buffer_event *next = NULL;
	u64 next_ts = 0, ts;
	int next_cpu = -1;
	int cpu;

	for_each_online_cpu(cpu) {
		if (iter->buffer_iter[cpu] == NULL ) {
			if (atomic_read(&iter->nr_events) == 0)
				continue;
		}
		else {
			if (ring_buffer_iter_empty(iter->buffer_iter[cpu]))
				continue;
		}

		event = _stp_peek_next_event(iter, cpu, &ts);

		/*
		 * Pick the event with the smallest timestamp:
		 */
		if (event && (!next || ts < next_ts)) {
			next = event;
			next_cpu = cpu;
			next_ts = ts;
		}
	}

	iter->cpu = next_cpu;
	iter->ts = next_ts;
	return next;
#endif
}


static void
_stp_buffer_iter_finish(struct _stp_iterator *iter)
{
#ifdef STP_BULKMODE
	int cpu_file = iter->cpu_file;

	if (iter->buffer_iter[cpu_file]) {
		ring_buffer_read_finish(iter->buffer_iter[cpu_file]);
		iter->buffer_iter[cpu_file] = NULL;
	}
#else
	int cpu;

	for_each_possible_cpu(cpu) {
		if (iter->buffer_iter[cpu]) {
			ring_buffer_read_finish(iter->buffer_iter[cpu]);
			iter->buffer_iter[cpu] = NULL;
		}
	}
#endif
	dbug_trans(0, "iterator(s) finished\n");
}


static int
_stp_buffer_iter_start(struct _stp_iterator *iter)
{
#ifdef STP_BULKMODE
	int cpu_file = iter->cpu_file;

	iter->buffer_iter[cpu_file]
#ifdef STAPCONF_RING_BUFFER_READ_PREPARE
	    = ring_buffer_read_prepare(_stp_relay_data.rb, cpu_file);
#else
	    = ring_buffer_read_start(_stp_relay_data.rb, cpu_file);
#endif
	if (iter->buffer_iter[cpu_file] == NULL) {
		dbug_trans(0, "buffer_iter[%d] was NULL\n", cpu_file);
		return 1;
	}
#ifdef STAPCONF_RING_BUFFER_READ_PREPARE
	ring_buffer_read_prepare_sync();
	ring_buffer_read_start(iter->buffer_iter[cpu_file]);
#endif
	dbug_trans(0, "iterator(s) started\n");
	return 0;
#else
	int cpu;

	for_each_online_cpu(cpu) {
		iter->buffer_iter[cpu]
#ifdef STAPCONF_RING_BUFFER_READ_PREPARE
		    = ring_buffer_read_prepare(_stp_relay_data.rb, cpu);
#else
		    = ring_buffer_read_start(_stp_relay_data.rb, cpu);
#endif
		if (iter->buffer_iter[cpu] == NULL) {
			dbug_trans(0, "buffer_iter[%d] was NULL\n", cpu);
			_stp_buffer_iter_finish(iter);
			return 1;
		}
	}
#ifdef STAPCONF_RING_BUFFER_READ_PREPARE
	ring_buffer_read_prepare_sync();
	for_each_online_cpu(cpu) {
		ring_buffer_read_start(iter->buffer_iter[cpu]);
	}
#endif
	dbug_trans(0, "iterator(s) started\n");
	return 0;
#endif
}


/*
 * Consumer reader.
 */
static ssize_t
_stp_data_read_trace(struct file *filp, char __user *ubuf,
		     size_t cnt, loff_t *ppos)
{
	ssize_t sret = 0;
	struct ring_buffer_event *event;
	struct _stp_iterator *iter = filp->private_data;
#ifdef STP_BULKMODE
	int cpu_file = iter->cpu_file;
#else
	int cpu;
#endif

	dbug_trans(1, "%lu\n", (unsigned long)cnt);
	sret = _stp_tracing_wait_pipe(filp);
	dbug_trans(1, "_stp_tracing_wait_pipe returned %ld\n", sret);
	if (sret <= 0)
		goto out;

	if (cnt >= PAGE_SIZE)
		cnt = PAGE_SIZE - 1;

	dbug_trans(1, "sret = %lu\n", (unsigned long)sret);
	sret = 0;
	iter->ts = 0;
#ifdef USE_ITERS
	if (_stp_buffer_iter_start(iter))
		goto out;
#endif
	while ((event = _stp_find_next_event(iter)) != NULL) {
		ssize_t len;

#ifdef USE_ITERS
		_stp_buffer_iter_finish(iter);
#endif
		len = _stp_event_to_user(event, ubuf, cnt);
		if (len <= 0)
			break;

		_stp_ring_buffer_consume(iter);
		dbug_trans(1, "event consumed\n");
		ubuf += len;
		cnt -= len;
		sret += len;
		if (cnt <= 0)
			break;
#ifdef USE_ITERS
		if (_stp_buffer_iter_start(iter))
			break;
#endif
	}

#ifdef USE_ITERS
	_stp_buffer_iter_finish(iter);
#endif
out:
	return sret;
}


static unsigned int
_stp_data_poll_trace(struct file *filp, poll_table *poll_table)
{
	struct _stp_iterator *iter = filp->private_data;

	dbug_trans(1, "entry\n");
	if (! _stp_ring_buffer_empty_cpu(iter))
		return POLLIN | POLLRDNORM;
	poll_wait(filp, &_stp_poll_wait, poll_table);
	if (! _stp_ring_buffer_empty_cpu(iter))
		return POLLIN | POLLRDNORM;

	dbug_trans(1, "exit\n");
	return 0;
}

static struct file_operations __stp_data_fops = {
	.owner		= THIS_MODULE,
	.open		= _stp_data_open_trace,
	.release	= _stp_data_release_trace,
	.poll		= _stp_data_poll_trace,
	.read		= _stp_data_read_trace,
};

static struct _stp_iterator *_stp_get_iterator(void)
{
#ifdef STP_BULKMODE
	int cpu = raw_smp_processor_id();
	return &_stp_relay_data.iter[cpu];
#else
	return &_stp_relay_data.iter[0];
#endif
}

/*
 * Here's how __STP_MAX_RESERVE_SIZE is figured.  The value of
 * BUF_PAGE_SIZE was gotten from the kernel's ring_buffer code.  It
 * is divided by 4, so we waste a maximum of 1/4 of the buffer (in
 * the case of a small reservation).
 */
#define __STP_MAX_RESERVE_SIZE ((/*BUF_PAGE_SIZE*/ 4080 / 4)	\
				- sizeof(struct _stp_data_entry) \
				- sizeof(struct ring_buffer_event))

/*
 * This function prepares the cpu buffer to write a sample.
 *
 * Struct op_entry is used during operations on the ring buffer while
 * struct op_sample contains the data that is stored in the ring
 * buffer. Struct entry can be uninitialized. The function reserves a
 * data array that is specified by size. Use
 * op_cpu_buffer_write_commit() after preparing the sample. In case of
 * errors a null pointer is returned, otherwise the pointer to the
 * sample.
 *
 */
static size_t
_stp_data_write_reserve(size_t size_request, void **entry)
{
	struct ring_buffer_event *event;
	struct _stp_data_entry *sde;
	struct _stp_iterator *iter = _stp_get_iterator();

	if (entry == NULL)
		return -EINVAL;

	if (size_request > __STP_MAX_RESERVE_SIZE) {
		size_request = __STP_MAX_RESERVE_SIZE;
	}

	if (_stp_ring_buffer_cpu_disabled()) {
		dbug_trans(0, "cpu disabled\n");
		entry = NULL;
		return 0;
	}

#ifdef STAPCONF_RING_BUFFER_FLAGS
	event = ring_buffer_lock_reserve(_stp_relay_data.rb,
					 (sizeof(struct _stp_data_entry)
					  + size_request), 0);
#else
	event = ring_buffer_lock_reserve(_stp_relay_data.rb,
					 (sizeof(struct _stp_data_entry)
					  + size_request));
#endif

	if (unlikely(! event)) {
		dbug_trans(0, "event = NULL (%p)?\n", event);
		if (! _stp_relay_data.overwrite_flag) {
			entry = NULL;
			return 0;
		}

		if (_stp_buffer_iter_start(iter)) {
			entry = NULL;
			return 0;
		}

		/* If we're in overwrite mode and all the buffers are
		 * full, take a event out of the buffer and consume it
		 * (throw it away).  This should make room for the new
		 * data. */
		event = _stp_find_next_event(iter);
		if (event) {
			ssize_t len;

			sde = ring_buffer_event_data(event);
			if (sde->len < size_request)
				size_request = sde->len;
			_stp_ring_buffer_consume(iter);
			_stp_buffer_iter_finish(iter);

			/* Try to reserve again. */
#ifdef STAPCONF_RING_BUFFER_FLAGS
			event = ring_buffer_lock_reserve(_stp_relay_data.rb,
							 sizeof(struct _stp_data_entry) + size_request,
							 0);
#else
			event = ring_buffer_lock_reserve(_stp_relay_data.rb,
							 sizeof(struct _stp_data_entry) + size_request);
#endif
			dbug_trans(0, "overwritten event = 0x%p\n", event);
		}
		else {
			_stp_buffer_iter_finish(iter);
		}

		if (unlikely(! event)) {
			entry = NULL;
			return 0;
		}
	}

	sde = ring_buffer_event_data(event);
	sde->len = size_request;
	
	*entry = event;
	return size_request;
}

static unsigned char *_stp_data_entry_data(void *entry)
{
	struct ring_buffer_event *event = entry;
	struct _stp_data_entry *sde;

	if (event == NULL)
		return NULL;

	sde = ring_buffer_event_data(event);
	return sde->buf;
}

static int _stp_data_write_commit(void *entry)
{
	struct ring_buffer_event *event = (struct ring_buffer_event *)entry;

	if (unlikely(! entry)) {
		dbug_trans(1, "entry = NULL, returning -EINVAL\n");
		return -EINVAL;
	}

#if defined(DEBUG_TRANS) && (DEBUG_TRANS >= 2)
	{
		struct _stp_data_entry *sde = ring_buffer_event_data(event);
		char *last = sde->buf + (sde->len - 5);
		dbug_trans2("committing %.5s...%.5s\n", sde->buf, last);
	}
#endif
	atomic_inc(&(_stp_get_iterator()->nr_events));

#ifdef STAPCONF_RING_BUFFER_FLAGS
	return ring_buffer_unlock_commit(_stp_relay_data.rb, event, 0);
#else
	return ring_buffer_unlock_commit(_stp_relay_data.rb, event);
#endif
}

static void __stp_relay_wakeup_timer(unsigned long val)
{
	if (waitqueue_active(&_stp_poll_wait) && ! _stp_ring_buffer_empty())
		wake_up_interruptible(&_stp_poll_wait);
	if (atomic_read(&_stp_relay_data.transport_state) == STP_TRANSPORT_RUNNING)
        	mod_timer(&_stp_relay_data.timer, jiffies + STP_RELAY_TIMER_INTERVAL);
        else
		dbug_trans(0, "ring_buffer wakeup timer expiry\n");
}

static void __stp_relay_timer_start(void)
{
	init_timer(&_stp_relay_data.timer);
	_stp_relay_data.timer.expires = jiffies + STP_RELAY_TIMER_INTERVAL;
	_stp_relay_data.timer.function = __stp_relay_wakeup_timer;
	_stp_relay_data.timer.data = 0;
	add_timer(&_stp_relay_data.timer);
	smp_mb();
}

static void __stp_relay_timer_stop(void)
{
	del_timer_sync(&_stp_relay_data.timer);
}

static struct dentry *__stp_entry[NR_CPUS] = { NULL };

static int _stp_transport_data_fs_init(void)
{
	int rc;
	int cpu, cpu2;

	atomic_set (&_stp_relay_data.transport_state, STP_TRANSPORT_STOPPED);
	_stp_relay_data.rb = NULL;

	// allocate buffer
	dbug_trans(1, "entry...\n");
	rc = __stp_alloc_ring_buffer();
	if (rc != 0)
		return rc;

	// create file(s)
	for_each_online_cpu(cpu) {
		char cpu_file[9];	/* 5(trace) + 3(XXX) + 1(\0) = 9 */

		if (cpu > 999 || cpu < 0) {
			_stp_transport_data_fs_close();
			return -EINVAL;
		}
		snprintf(cpu_file, sizeof(cpu_file), "trace%d", cpu);
		__stp_entry[cpu] = debugfs_create_file(cpu_file, 0600,
						       _stp_get_module_dir(),
						       (void *)(long)cpu,
						       &__stp_data_fops);

		if (!__stp_entry[cpu]) {
			pr_warning("Could not create debugfs 'trace' entry\n");
			__stp_free_ring_buffer();
			return -ENOENT;
		}
		else if (IS_ERR(__stp_entry[cpu])) {
			rc = PTR_ERR(__stp_entry[cpu]);
			pr_warning("Could not create debugfs 'trace' entry\n");
			__stp_free_ring_buffer();
			return rc;
		}

		__stp_entry[cpu]->d_inode->i_uid = KUIDT_INIT(_stp_uid);
		__stp_entry[cpu]->d_inode->i_gid = KGIDT_INIT(_stp_gid);
		__stp_entry[cpu]->d_inode->i_private = &_stp_relay_data.iter[cpu];

#ifndef STP_BULKMODE
		break;
#endif
	}

	for_each_possible_cpu(cpu) {
#ifdef STP_BULKMODE
		_stp_relay_data.iter[cpu].cpu_file = cpu;
		_stp_relay_data.iter[cpu].cpu = cpu;
#endif
		for_each_possible_cpu(cpu2) {
			_stp_relay_data.iter[cpu].buffer_iter[cpu2] = NULL;
		}

		atomic_set(&_stp_relay_data.iter[cpu].nr_events, 0);

#ifndef STP_BULKMODE
		break;
#endif
	}

	dbug_trans(1, "returning 0...\n");
	atomic_set (&_stp_relay_data.transport_state, STP_TRANSPORT_INITIALIZED);
	return 0;
}

static void _stp_transport_data_fs_start(void)
{
	if (atomic_read(&_stp_relay_data.transport_state) == STP_TRANSPORT_INITIALIZED) {
        	atomic_set(&_stp_relay_data.transport_state, STP_TRANSPORT_RUNNING);
                __stp_relay_timer_start();
	}
}

static void _stp_transport_data_fs_stop(void)
{
	if (atomic_read(&_stp_relay_data.transport_state) == STP_TRANSPORT_RUNNING) {
        	atomic_set(&_stp_relay_data.transport_state, STP_TRANSPORT_STOPPED);
                __stp_relay_timer_stop();
	}
}

static void _stp_transport_data_fs_close(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (__stp_entry[cpu])
			debugfs_remove(__stp_entry[cpu]);
		__stp_entry[cpu] = NULL;
	}

	__stp_free_ring_buffer();
}

static enum _stp_transport_state _stp_transport_get_state(void)
{
	return atomic_read (&_stp_relay_data.transport_state);
}

static void _stp_transport_data_fs_overwrite(int overwrite)
{
	dbug_trans(0, "setting ovewrite to %d\n", overwrite);
	_stp_relay_data.overwrite_flag = overwrite;
}
