/* -*- linux-c -*- 
 * Memory allocation functions
 * Copyright (C) 2005-2008 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STAPLINUX_ALLOC_C_
#define _STAPLINUX_ALLOC_C_

#include <linux/percpu.h>

static int _stp_allocated_net_memory = 0;
/* Default, and should be "safe" from anywhere. */
#define STP_ALLOC_FLAGS ((GFP_KERNEL | __GFP_NORETRY | __GFP_NOWARN) \
			 & ~__GFP_WAIT)
/* May only be used in context that can sleep. __GFP_NORETRY is to
   suppress the oom-killer from kicking in. */
#define STP_ALLOC_SLEEP_FLAGS (GFP_KERNEL | __GFP_NORETRY)

/* #define DEBUG_MEM */
/*
 * If DEBUG_MEM is defined (stap -DDEBUG_MEM ...) then full memory
 * tracking is used. Each allocation is recorded and matched with 
 * a free. Also a fence is set around the allocated memory so overflows
 * and underflows can be detected. Errors are written to the system log
 * with printk.
 *
 * NOTE: if youy system is slow or your script makes a very large number
 * of allocations, you may get a warning in the system log:
 * BUG: soft lockup - CPU#1 stuck for 11s! [staprun:28269]
 * This is an expected side-effect of the overhead of tracking, especially
 * with a simple linked list of allocations. Optimization
 * would be nice, but DEBUG_MEM is only for testing.
 */

static int _stp_allocated_memory = 0;

#ifdef DEBUG_MEM
static DEFINE_SPINLOCK(_stp_mem_lock);

#define MEM_MAGIC 0xc11cf77f
#define MEM_FENCE_SIZE 32

enum _stp_memtype { MEM_KMALLOC, MEM_VMALLOC, MEM_PERCPU };

typedef struct {
	char *alloc;
	char *free;
} _stp_malloc_type;

static const _stp_malloc_type const _stp_malloc_types[] = {
	{"kmalloc", "kfree"},
	{"vmalloc", "vfree"},
	{"alloc_percpu", "free_percpu"}
};

struct _stp_mem_entry {
	struct list_head list;
	int32_t magic;
	enum _stp_memtype type;
	size_t len;
	void *addr;
};

#define MEM_DEBUG_SIZE (2*MEM_FENCE_SIZE+sizeof(struct _stp_mem_entry))

static LIST_HEAD(_stp_mem_list);

static void _stp_check_mem_fence (char *addr, int size)
{
	char *ptr;
	int i;

	ptr = addr - MEM_FENCE_SIZE;
	while (ptr < addr) {
		if (*ptr != 0x55) {
			printk("SYSTEMTAP ERROR: Memory fence corrupted before allocated memory\n");
			printk("at addr %p. (Allocation starts at %p)", ptr, addr);
			return;
		}
		ptr++;
	}
	ptr = addr + size;
	while (ptr < addr + size + MEM_FENCE_SIZE) {
		if (*ptr != 0x55) {
			printk("SYSTEMTAP ERROR: Memory fence corrupted after allocated memory\n");
			printk("at addr %p. (Allocation ends at %p)", ptr, addr + size - 1);
			return;
		}
		ptr++;
	}
}

static void *_stp_mem_debug_setup(void *addr, size_t size, enum _stp_memtype type)
{
	struct list_head *p;
	struct _stp_mem_entry *m;
	memset(addr, 0x55, MEM_FENCE_SIZE);
	addr += MEM_FENCE_SIZE;
	memset(addr + size, 0x55, MEM_FENCE_SIZE);
	p = (struct list_head *)(addr + size + MEM_FENCE_SIZE);
	m = (struct _stp_mem_entry *)p;
	m->magic = MEM_MAGIC;
	m->type = type;
	m->len = size;
	m->addr = addr;
	spin_lock(&_stp_mem_lock);
	list_add(p, &_stp_mem_list); 
	spin_unlock(&_stp_mem_lock);
	return addr;
}

/* Percpu allocations don't have the fence. Implementing it is problematic. */
static void _stp_mem_debug_percpu(struct _stp_mem_entry *m, void *addr, size_t size)
{
	struct list_head *p = (struct list_head *)m;
	m->magic = MEM_MAGIC;
	m->type = MEM_PERCPU;
	m->len = size;
	m->addr = addr;
	spin_lock(&_stp_mem_lock);
	list_add(p, &_stp_mem_list);
	spin_unlock(&_stp_mem_lock);	
}

static void _stp_mem_debug_free(void *addr, enum _stp_memtype type)
{
	int found = 0;
	struct list_head *p, *tmp;
	struct _stp_mem_entry *m = NULL;

	spin_lock(&_stp_mem_lock);
	list_for_each_safe(p, tmp, &_stp_mem_list) {
		m = list_entry(p, struct _stp_mem_entry, list);
		if (m->addr == addr) {
			list_del(p);
			found = 1;
			break;
		}
	}
	spin_unlock(&_stp_mem_lock);
	if (!found) {
		printk("SYSTEMTAP ERROR: Free of unallocated memory %p type=%s\n", 
		       addr, _stp_malloc_types[type].free);
		return;
	}
	if (m->magic != MEM_MAGIC) {
		printk("SYSTEMTAP ERROR: Memory at %p corrupted!!\n", addr);
		return;
	}
	if (m->type != type) {
		printk("SYSTEMTAP ERROR: Memory allocated with %s and freed with %s\n",
		       _stp_malloc_types[m->type].alloc, 		       
		       _stp_malloc_types[type].free);
	}
	
	switch (m->type) {
	case MEM_KMALLOC:
		_stp_check_mem_fence(addr, m->len);
		kfree(addr - MEM_FENCE_SIZE);
		break;
	case MEM_PERCPU:
		free_percpu(addr);
		kfree(p);
		break;
	case MEM_VMALLOC:
		_stp_check_mem_fence(addr, m->len);
		vfree(addr - MEM_FENCE_SIZE);		
		break;
	default:
		printk("SYSTEMTAP ERROR: Attempted to free memory at addr %p len=%d with unknown allocation type.\n", addr, (int)m->len);
	}

	return;
}

static void _stp_mem_debug_validate(void *addr)
{
	int found = 0;
	struct list_head *p, *tmp;
	struct _stp_mem_entry *m = NULL;

	spin_lock(&_stp_mem_lock);
	list_for_each_safe(p, tmp, &_stp_mem_list) {
		m = list_entry(p, struct _stp_mem_entry, list);
		if (m->addr == addr) {
			found = 1;
			break;
		}
	}
	spin_unlock(&_stp_mem_lock);
	if (!found) {
		printk("SYSTEMTAP ERROR: Couldn't validate memory %p\n", 
		       addr);
		return;
	}
	if (m->magic != MEM_MAGIC) {
		printk("SYSTEMTAP ERROR: Memory at %p corrupted!!\n", addr);
		return;
	}
	
	switch (m->type) {
	case MEM_KMALLOC:
		_stp_check_mem_fence(addr, m->len);
		break;
	case MEM_PERCPU:
		/* do nothing */
		break;
	case MEM_VMALLOC:
		_stp_check_mem_fence(addr, m->len);
		break;
	default:
		printk("SYSTEMTAP ERROR: Attempted to validate memory at addr %p len=%d with unknown allocation type.\n", addr, (int)m->len);
	}

	return;
}
#endif

/* #define STP_MAXMEMORY 8192 */
/*
 * If STP_MAXMEMORY is defined to a value (stap -DSTP_MAXMEMORY=8192
 * ...) then every memory allocation is checked to make sure the
 * systemtap module doesn't use more than STP_MAXMEMORY of memory.
 * STP_MAXMEMORY is specified in kilobytes, so, for example, '8192'
 * means that the systemtap module won't use more than 8 megabytes of
 * memory.
 *
 * Note 1: This size does include the size of the module itself, plus
 * any additional allocations.
 *
 * Note 2: Since we can't be ensured that the module transport is set
 * up when a memory allocation problem happens, this code can't
 * directly report an error back to a user (so instead it uses
 * 'printk').  If the modules transport has been set up, the code that
 * calls the memory allocation functions
 * (_stp_kmalloc/_stp_kzalloc/etc.) should report an error directly to
 * the user.
 *
 * Note 3: This only tracks direct allocations by the systemtap
 * runtime.  This does not track indirect allocations (such as done by
 * kprobes/uprobes/etc. internals).
 */

#ifdef STP_MAXMEMORY
#ifdef STAPCONF_MODULE_LAYOUT
#define _STP_MODULE_CORE_SIZE (THIS_MODULE->core_layout.size)
#elif defined(STAPCONF_GRSECURITY)
#define _STP_MODULE_CORE_SIZE (THIS_MODULE->core_size_rw)
#else
#define _STP_MODULE_CORE_SIZE (THIS_MODULE->core_size)
#endif
#endif

static void *_stp_kmalloc_gfp(size_t size, gfp_t gfp_mask)
{
	void *ret;
#ifdef STP_MAXMEMORY
	if ((_STP_MODULE_CORE_SIZE + _stp_allocated_memory + size)
	    > (STP_MAXMEMORY * 1024)) {
		return NULL;
	}
#endif
#ifdef DEBUG_MEM
	ret = kmalloc(size + MEM_DEBUG_SIZE, gfp_mask);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
		ret = _stp_mem_debug_setup(ret, size, MEM_KMALLOC);
	}
#else
	ret = kmalloc(size, gfp_mask);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
	}
#endif
	return ret;
}

static void *_stp_kmalloc(size_t size)
{
	return _stp_kmalloc_gfp(size, STP_ALLOC_FLAGS);
}

static void *_stp_kzalloc_gfp(size_t size, gfp_t gfp_mask)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
{
	void *ret;
#ifdef STP_MAXMEMORY
	if ((_STP_MODULE_CORE_SIZE + _stp_allocated_memory + size)
	    > (STP_MAXMEMORY * 1024)) {
		return NULL;
	}
#endif
#ifdef DEBUG_MEM
	ret = kmalloc(size + MEM_DEBUG_SIZE, gfp_mask);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
		ret = _stp_mem_debug_setup(ret, size, MEM_KMALLOC);
		memset (ret, 0, size);
	}
#else
	ret = kmalloc(size, gfp_mask);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
		memset (ret, 0, size);
	}
#endif /* DEBUG_MEM */
	return ret;
}
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) */
{
	void *ret;
#ifdef STP_MAXMEMORY
	if ((_STP_MODULE_CORE_SIZE + _stp_allocated_memory + size)
	    > (STP_MAXMEMORY * 1024)) {
		return NULL;
	}
#endif
#ifdef DEBUG_MEM
	ret = kzalloc(size + MEM_DEBUG_SIZE, gfp_mask);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
		ret = _stp_mem_debug_setup(ret, size, MEM_KMALLOC);
	}
#else
	ret = kzalloc(size, gfp_mask);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
	}
#endif
	return ret;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15) */

static void *_stp_kzalloc(size_t size)
{
  return _stp_kzalloc_gfp(size, STP_ALLOC_FLAGS);
}

#ifndef STAPCONF_VZALLOC
static void *vzalloc(unsigned long size)
{
	void *ret = vmalloc(size);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

static void *_stp_vzalloc(size_t size)
{
	void *ret;
#ifdef STP_MAXMEMORY
	if ((_STP_MODULE_CORE_SIZE + _stp_allocated_memory + size)
	    > (STP_MAXMEMORY * 1024)) {
		return NULL;
	}
#endif
#ifdef DEBUG_MEM
	ret = vzalloc(size + MEM_DEBUG_SIZE);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
		ret = _stp_mem_debug_setup(ret, size, MEM_VMALLOC);
	}
#else
	ret = vzalloc(size);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
	}
#endif
	return ret;
}


#ifndef STAPCONF_VMALLOC_NODE
static void *vmalloc_node(unsigned long size, int node __attribute__((unused)))
{
	return vmalloc(size);
}
#endif

#ifndef STAPCONF_VZALLOC_NODE
static void *vzalloc_node(unsigned long size, int node)
{
	void *ret = vmalloc_node(size, node);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

static void *_stp_vzalloc_node(size_t size, int node)
{
	void *ret;

#ifdef STP_MAXMEMORY
	if ((_STP_MODULE_CORE_SIZE + _stp_allocated_memory + size)
	    > (STP_MAXMEMORY * 1024)) {
		return NULL;
	}
#endif
#ifdef DEBUG_MEM
	ret = vzalloc_node(size + MEM_DEBUG_SIZE, node);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
		ret = _stp_mem_debug_setup(ret, size, MEM_VMALLOC);
	}
#else
	ret = vzalloc_node(size, node);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
	}
#endif
	return ret;
}

#ifdef PCPU_MIN_UNIT_SIZE
#define _STP_MAX_PERCPU_SIZE PCPU_MIN_UNIT_SIZE
#else
#define _STP_MAX_PERCPU_SIZE 131072
#endif

/* Note, calls __alloc_percpu which may sleep and always uses GFP_KERNEL. */
static void *_stp_alloc_percpu(size_t size)
{
	void *ret;

	if (size > _STP_MAX_PERCPU_SIZE)
		return NULL;

#ifdef STP_MAXMEMORY
	if ((_STP_MODULE_CORE_SIZE + _stp_allocated_memory
	     + (size * num_online_cpus()))
	    > (STP_MAXMEMORY * 1024)) {
		return NULL;
	}
#endif

#ifdef STAPCONF_ALLOC_PERCPU_ALIGN
	ret = __alloc_percpu(size, 8);
#else
	ret = __alloc_percpu(size);
#endif
#ifdef DEBUG_MEM
	if (likely(ret)) {
		struct _stp_mem_entry *m = kmalloc(sizeof(struct _stp_mem_entry), GFP_KERNEL);
		if (unlikely(m == NULL)) {
			free_percpu(ret);
			return NULL;
		}
	        _stp_allocated_memory += size * num_online_cpus();
		_stp_mem_debug_percpu(m, ret, size);
	}
#else
	if (likely(ret)) {
	        _stp_allocated_memory += size * num_online_cpus();
	}
#endif
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
#define _stp_kmalloc_node(size,node) _stp_kmalloc(size)
#define _stp_kmalloc_node_gfp(size,node,gfp) _stp_kmalloc_gfp(size,gfp)
#define _stp_kzalloc_node(size,node) _stp_kzalloc(size)
#define _stp_kzalloc_node_gfp(size,node,gfp) _stp_kzalloc_gfp(size,gfp)
#else
static void *_stp_kmalloc_node_gfp(size_t size, int node, gfp_t gfp_mask)
{
	void *ret;
#ifdef STP_MAXMEMORY
	if ((_STP_MODULE_CORE_SIZE + _stp_allocated_memory + size)
	    > (STP_MAXMEMORY * 1024)) {
		return NULL;
	}
#endif
#ifdef DEBUG_MEM
	ret = kmalloc_node(size + MEM_DEBUG_SIZE, gfp_mask, node);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
		ret = _stp_mem_debug_setup(ret, size, MEM_KMALLOC);
	}
#else
	ret = kmalloc_node(size, gfp_mask, node);
	if (likely(ret)) {
	        _stp_allocated_memory += size;
	}
#endif
	return ret;
}
static void *_stp_kzalloc_node_gfp(size_t size, int node, gfp_t gfp_mask)
{
	/* This used to be simply:
	 *   return _stp_kmalloc_node_gfp(size, node, gfp_mask | __GFP_ZERO);
	 * but rhel5-era kernels BUG out on that flag. (PR14957)
	 *
	 * We could make a big #if-alternation for kernels which have support
	 * for kzalloc_node (kernel commit 979b0fea), as in _stp_kzalloc_gfp,
	 * but IMO that's needlessly complex.
	 *
	 * So for now, just malloc and zero it manually.
	 */
	void *ret = _stp_kmalloc_node_gfp(size, node, gfp_mask);
	if (likely(ret)) {
		memset (ret, 0, size);
	}
	return ret;
}
static void *_stp_kmalloc_node(size_t size, int node)
{
	return _stp_kmalloc_node_gfp(size, node, STP_ALLOC_FLAGS);
}
static void *_stp_kzalloc_node(size_t size, int node)
{
	return _stp_kzalloc_node_gfp(size, node, STP_ALLOC_FLAGS);
}
#endif /* LINUX_VERSION_CODE */

static void _stp_kfree(void *addr)
{
#ifdef DEBUG_MEM
	_stp_mem_debug_free(addr, MEM_KMALLOC);
#else
	kfree(addr);
#endif
}

static void _stp_vfree(void *addr)
{
#ifdef DEBUG_MEM
	_stp_mem_debug_free(addr, MEM_VMALLOC);
#else
	vfree(addr);
#endif
}

static void _stp_free_percpu(void *addr)
{
#ifdef DEBUG_MEM
	_stp_mem_debug_free(addr, MEM_PERCPU);
#else
	free_percpu(addr);
#endif
}

static void _stp_mem_debug_done(void)
{
#ifdef DEBUG_MEM
	struct list_head *p, *tmp;
	struct _stp_mem_entry *m;

	spin_lock(&_stp_mem_lock);
	list_for_each_safe(p, tmp, &_stp_mem_list) {
		m = list_entry(p, struct _stp_mem_entry, list);
		list_del(p);

		printk("SYSTEMTAP ERROR: Memory %p len=%d allocation type: %s. Not freed.\n", 
		       m->addr, (int)m->len, _stp_malloc_types[m->type].alloc);

		if (m->magic != MEM_MAGIC) {
			printk("SYSTEMTAP ERROR: Memory at %p len=%d corrupted!!\n", m->addr, (int)m->len);
			/* Don't free. Too dangerous */
			goto done;
		}

		switch (m->type) {
		case MEM_KMALLOC:
			_stp_check_mem_fence(m->addr, m->len);
			kfree(m->addr - MEM_FENCE_SIZE);
			break;
		case MEM_PERCPU:
			free_percpu(m->addr);
			kfree(p);
			break;
		case MEM_VMALLOC:
			_stp_check_mem_fence(m->addr, m->len);
			vfree(m->addr - MEM_FENCE_SIZE);		
			break;
		default:
			printk("SYSTEMTAP ERROR: Attempted to free memory at addr %p len=%d with unknown allocation type.\n", m->addr, (int)m->len);
		}
	}
done:
	spin_unlock(&_stp_mem_lock);

	return;

#endif
}
#endif /* _STAPLINUX_ALLOC_C_ */
