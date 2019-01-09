/* -*- linux-c -*- 
 * Map Runtime Functions
 * Copyright (C) 2012-2016 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_MAP_RUNTIME_H_
#define _LINUX_MAP_RUNTIME_H_

/* get/put_cpu wrappers.  Unnecessary if caller is already atomic. */
#define MAP_GET_CPU()	smp_processor_id()
#define MAP_PUT_CPU()	do {} while (0)


struct pmap {
	MAP agg;	/* aggregation map */
	MAP map[];	/* per-cpu maps */
};

static inline MAP _stp_pmap_get_agg(PMAP p)
{
	return p->agg;
}

static inline void _stp_pmap_set_agg(PMAP p, MAP agg)
{
	p->agg = agg;
}

static inline MAP _stp_pmap_get_map(PMAP p, unsigned cpu)
{
	if (cpu >= NR_CPUS)
		cpu = 0;
	return p->map[cpu];
}

static inline void _stp_pmap_set_map(PMAP p, MAP m, unsigned cpu)
{
	if (cpu >= NR_CPUS)
		cpu = 0;
	p->map[cpu] = m;
}


/** Deletes a map.
 * Deletes a map, freeing all memory in all elements.
 * Normally done only when the module exits.
 * @param map
 */

static void _stp_map_del(MAP map)
{
	if (map == NULL)
		return;

	if (map->node_mem)
		_stp_vfree(map->node_mem);

	_stp_vfree(map);
}

static void _stp_pmap_del(PMAP pmap)
{
	int i;

	if (pmap == NULL)
		return;

	for_each_possible_cpu(i) {
		MAP m = _stp_pmap_get_map (pmap, i);
		_stp_map_del(m);
	}

	/* free agg map elements */
	_stp_map_del(_stp_pmap_get_agg(pmap));
	_stp_vfree(pmap);
}


static void*
_stp_map_vzalloc(size_t size, int cpu)
{
	/* Called from module_init, so user context, may sleep alloc. */
	if (cpu < 0)
		return _stp_vzalloc(size);
	return _stp_vzalloc_node(size, cpu_to_node(cpu));
}


static int
_stp_map_init(MAP m, unsigned max_entries, unsigned hash_table_mask,
              int wrap, int node_size, int cpu)
{
	unsigned i;

	INIT_MLIST_HEAD(&m->pool);
	INIT_MLIST_HEAD(&m->head);

        m->hash_table_mask = hash_table_mask;
	for (i = 0; i <= hash_table_mask; i++)
		INIT_MHLIST_HEAD(&m->hashes[i]);

	m->maxnum = max_entries;
	m->wrap = wrap;

	/* Since we're using _stp_map_vzalloc(), we can afford to
	 * allocate the nodes in one big chunk. */
	m->node_mem = _stp_map_vzalloc(node_size * max_entries, cpu);
	if (m->node_mem == NULL)
		return -1;

	for (i = 0; i < max_entries; i++) {
		struct map_node *node = m->node_mem + i * node_size;
		mlist_add(&node->lnode, &m->pool);
		INIT_MHLIST_NODE(&node->hnode);
	}

	return 0;
}


/** Create a new map.
 * Maps must be created at module initialization time.
 * @param max_entries The maximum number of entries allowed. Currently that
 * number will be preallocated.If more entries are required, the oldest ones
 * will be deleted. This makes it effectively a circular buffer.
 * @return A MAP on success or NULL on failure.
 * @ingroup map_create
 */

static MAP
_stp_map_new(unsigned max_entries, int wrap, int node_size, int cpu)
{
	MAP m;
        unsigned hash_table_mask = HASHTABLESIZE(max_entries)-1; /* usable as bitmask */
	m = _stp_map_vzalloc(sizeof(struct map_root) +
                             sizeof(struct mhlist_head) * (hash_table_mask+1),
                             cpu);
	if (m == NULL)
		return NULL;

	if (_stp_map_init(m, max_entries, hash_table_mask, wrap, node_size, cpu)) {
		_stp_map_del(m);
		return NULL;
	}
	return m;
}

static PMAP
_stp_pmap_new(unsigned max_entries, int wrap, int node_size)
{
	int i;
	MAP m;

	PMAP pmap = _stp_map_vzalloc(sizeof(struct pmap)
				     + NR_CPUS * sizeof(MAP), -1);
	if (pmap == NULL)
		return NULL;

	/* Allocate the per-cpu maps.  */
	for_each_possible_cpu(i) {
		m = _stp_map_new(max_entries, wrap, node_size, i);
		if (m == NULL)
			goto err1;
                _stp_pmap_set_map(pmap, m, i);
	}

	/* Allocate the aggregate map.  */
	m = _stp_map_new(max_entries, wrap, node_size, -1);
	if (m == NULL)
		goto err1;
        _stp_pmap_set_agg(pmap, m);

	return pmap;

err1:
	for_each_possible_cpu(i) {
		m = _stp_pmap_get_map (pmap, i);
		_stp_map_del(m);
	}
	_stp_vfree(pmap);
	return NULL;
}

#endif /* _LINUX_MAP_RUNTIME_H_ */
