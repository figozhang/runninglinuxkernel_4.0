/*  -*- linux-c -*-
 * Preallocated memory pools
 * Copyright (C) 2008-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_MEMPOOL_C_
#define _STP_MEMPOOL_C_

/* An opaque struct identifying the memory pool. */
typedef struct {
	struct list_head free_list;
	unsigned num;
	unsigned size;
	spinlock_t lock;
} _stp_mempool_t;

/* for internal use only */
struct _stp_mem_buffer {
	struct list_head list;
	_stp_mempool_t *pool;
	void *buf;
};

/* Delete a memory pool */
static void _stp_mempool_destroy(_stp_mempool_t *pool)
{
	struct list_head *p, *tmp;
	if (pool) {
		list_for_each_safe(p, tmp, &pool->free_list) {
			list_del(p);
			_stp_kfree(p);
		}
		_stp_kfree(pool);
	}
}

/* Create a new memory pool */
static _stp_mempool_t *_stp_mempool_init(size_t size, size_t num)
{
	int i, alloc_size;
	struct _stp_mem_buffer *m;

	_stp_mempool_t *pool = (_stp_mempool_t *)_stp_kmalloc(sizeof(_stp_mempool_t));
	if (unlikely(pool == NULL)) {
		errk("Memory allocation failed.\n");
		return NULL;
	}

	INIT_LIST_HEAD(&pool->free_list);
	spin_lock_init(&pool->lock);

	alloc_size = size + sizeof(struct _stp_mem_buffer) - sizeof(void *);

	for (i = 0; i < num; i++) {
		m = (struct _stp_mem_buffer *)_stp_kmalloc(alloc_size);
		if (unlikely(m == NULL))
			goto err;
		m->pool = pool;
		list_add((struct list_head *)m, &pool->free_list);
	}
	pool->num = num;
	pool->size = alloc_size;
	return pool;

err:
	_stp_mempool_destroy(pool);
	return NULL;
}

/* allocate a buffer from a memory pool */
static void *_stp_mempool_alloc(_stp_mempool_t *pool)
{
	unsigned long flags;
	struct _stp_mem_buffer *ptr = NULL;
        /* PR14804: tolerate accidental early call, before pool is
         actually initialized. */
        if (pool == NULL)
                return NULL;
	spin_lock_irqsave(&pool->lock, flags);
	if (likely(!list_empty(&pool->free_list))) {
		ptr = (struct _stp_mem_buffer *)pool->free_list.next;
		list_del_init(&ptr->list);
		spin_unlock_irqrestore(&pool->lock, flags);
		return &ptr->buf;
	}
	spin_unlock_irqrestore(&pool->lock, flags);
	return NULL;
}

/* return a buffer to its memory pool */
static void _stp_mempool_free(void *buf)
{
	unsigned long flags;
	struct _stp_mem_buffer *m = container_of(buf, struct _stp_mem_buffer, buf);
	spin_lock_irqsave(&m->pool->lock, flags);
	list_add(&m->list, &m->pool->free_list);
	spin_unlock_irqrestore(&m->pool->lock, flags);
}
#endif /* _STP_MEMPOOL_C_ */
