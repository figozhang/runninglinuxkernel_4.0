/* -*- linux-c -*- 
 * pmap API generator
 * Copyright (C) 2005-2016 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/** @file pmap-gen.c
 * @brief Pmap function generator
 * This file is a template designed to be included as many times as
 * needed to generate the necessary pmap functions.  It is only included
 * indirectly by map-gen.c, so all the shared #defines are in place.
 */


/* returns 1 on match, 0 otherwise */
static int KEYSYM(pmap_key_cmp) (struct map_node *m1, struct map_node *m2)
{
	struct KEYSYM(map_node) *n1 = KEYSYM(get_map_node)(m1);
	struct KEYSYM(map_node) *n2 = KEYSYM(get_map_node)(m2);
		if (KEY1_EQ_P(n1->key1, n2->key1)
#if KEY_ARITY > 1
		    && KEY2_EQ_P(n1->key2, n2->key2)
#if KEY_ARITY > 2
		    && KEY3_EQ_P(n1->key3, n2->key3)
#if KEY_ARITY > 3
		    && KEY4_EQ_P(n1->key4, n2->key4)
#if KEY_ARITY > 4
		    && KEY5_EQ_P(n1->key5, n2->key5)
#if KEY_ARITY > 5
		    && KEY6_EQ_P(n1->key6, n2->key6)
#if KEY_ARITY > 6
		    && KEY7_EQ_P(n1->key7, n2->key7)
#if KEY_ARITY > 7
		    && KEY8_EQ_P(n1->key8, n2->key8)
#if KEY_ARITY > 8
		    && KEY9_EQ_P(n1->key9, n2->key9)
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
			)
			return 1;
		else
			return 0;
}

/* copy keys for m2 -> m1 */
static void KEYSYM(pmap_copy_keys) (struct map_node *m1, struct map_node *m2)
{
	struct KEYSYM(map_node) *dst = KEYSYM(get_map_node)(m1);
	struct KEYSYM(map_node) *src = KEYSYM(get_map_node)(m2);
#if KEY1_TYPE == STRING
	str_copy (dst->key1, src->key1); 
#else
	dst->key1 = src->key1;
#endif
#if KEY_ARITY > 1
#if KEY2_TYPE == STRING
	str_copy (dst->key2, src->key2); 
#else
	dst->key2 = src->key2;
#endif
#if KEY_ARITY > 2
#if KEY3_TYPE == STRING
	str_copy (dst->key3, src->key3); 
#else
	dst->key3 = src->key3;
#endif
#if KEY_ARITY > 3
#if KEY4_TYPE == STRING
	str_copy (dst->key4, src->key4); 
#else
	dst->key4 = src->key4;
#endif
#if KEY_ARITY > 4
#if KEY5_TYPE == STRING
	str_copy (dst->key5, src->key5); 
#else
	dst->key5 = src->key5;
#endif
#if KEY_ARITY > 5
#if KEY6_TYPE == STRING
	str_copy (dst->key6, src->key6); 
#else
	dst->key6 = src->key6;
#endif
#if KEY_ARITY > 6
#if KEY7_TYPE == STRING
	str_copy (dst->key7, src->key7); 
#else
	dst->key7 = src->key7;
#endif
#if KEY_ARITY > 7
#if KEY8_TYPE == STRING
	str_copy (dst->key8, src->key8); 
#else
	dst->key8 = src->key8;
#endif
#if KEY_ARITY > 8
#if KEY9_TYPE == STRING
	str_copy (dst->key9, src->key9); 
#else
	dst->key9 = src->key9;
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
}

/* update the keys and value of a map_node */
static void KEYSYM(pmap_update_node) (MAP m, struct map_node *m1, struct map_node *m2, int add)
{
	struct KEYSYM(map_node) *src, * dst = KEYSYM(get_map_node)(m1);

	if (!m2) {
		MAP_COPY_VAL(m, dst, NULLRET, 0);
		return;
	}

	src = KEYSYM(get_map_node)(m2);
	if (!add)
		KEYSYM(pmap_copy_keys)(m1, m2);
	MAP_COPY_VAL(m, dst, MAP_GET_VAL(src), add);
}

#if VALUE_TYPE == INT64 || VALUE_TYPE == STRING
static PMAP KEYSYM(_stp_pmap_new) (unsigned max_entries, int wrap)
{
	PMAP pmap = _stp_pmap_new (max_entries, wrap,
				   sizeof(struct KEYSYM(map_node)));
	return pmap;
}
#else
/*
 * _stp_pmap_new_key1_key2...val (num, wrap, HIST_LINEAR, start, end, interval) 
 * _stp_pmap_new_key1_key2...val (num, wrap, HIST_LOG)
 */
static PMAP
KEYSYM(_stp_pmap_new) (unsigned max_entries, int wrap, int htype, ...)
{
	int start=0, stop=0, interval=0;
	PMAP pmap;

	if (htype == HIST_LINEAR) {
		va_list ap;
		va_start (ap, htype);
		start = va_arg(ap, int);
		stop = va_arg(ap, int);
		interval = va_arg(ap, int);
		va_end (ap);
	}

	switch (htype) {
	case HIST_NONE:
		pmap = _stp_pmap_new_hstat (max_entries, wrap,
					    sizeof(struct KEYSYM(map_node)));
		break;
	case HIST_LOG:
		pmap = _stp_pmap_new_hstat_log (max_entries, wrap,
						sizeof(struct KEYSYM(map_node)));
		break;
	case HIST_LINEAR:
		pmap = _stp_pmap_new_hstat_linear (max_entries, wrap,
						   sizeof(struct KEYSYM(map_node)),
						   start, stop, interval);
		break;
	default:
		_stp_warn ("Unknown histogram type %d\n", htype);
		pmap = NULL;
	}

	return pmap;
}

#endif /* VALUE_TYPE */

static int KEYSYM(_stp_pmap_set) (PMAP pmap, ALLKEYSD(key), VSTYPE val)
{
	int res;
	MAP m = _stp_pmap_get_map (pmap, MAP_GET_CPU());
	res = KEYSYM(__stp_map_set) (m, ALLKEYS(key), val, 0);
        MAP_PUT_CPU();
	return res;
}

static int KEYSYM(_stp_pmap_add) (PMAP pmap, ALLKEYSD(key), VSTYPE val)
{
	int res;
	MAP m = _stp_pmap_get_map (pmap, MAP_GET_CPU());
	res = KEYSYM(__stp_map_set) (m, ALLKEYS(key), val, 1);
        MAP_PUT_CPU();
	return res;
}


static VALTYPE KEYSYM(_stp_pmap_get_cpu) (PMAP pmap, ALLKEYSD(key))
{
	unsigned int hv;
	struct mhlist_head *head;
	struct mhlist_node *e;
	struct KEYSYM(map_node) *n;
	VALTYPE res;
	MAP map;

	map = _stp_pmap_get_map (pmap, MAP_GET_CPU());
	hv = KEYSYM(hash) (ALLKEYS(key)) & map->hash_table_mask;
	head = &map->hashes[hv];
	mhlist_for_each_entry(n, e, head, node.hnode) {
		if (KEY_EQ_P(n)) {
			res = MAP_GET_VAL(n);
			MAP_PUT_CPU();
			return res;
		}
	}
	/* key not found */
        MAP_PUT_CPU();
	return NULLRET;
}

static VALTYPE KEYSYM(_stp_pmap_get) (PMAP pmap, ALLKEYSD(key))
{
	unsigned int hv;
	int cpu, clear_agg = 0;
	struct mhlist_head *head, *ahead;
	struct mhlist_node *e;
	struct KEYSYM(map_node) *n;
	struct map_node *anode = NULL;
	MAP map, agg;

	hv = KEYSYM(hash) (ALLKEYS(key));

	/* first look it up in the aggregation map */
	agg = _stp_pmap_get_agg(pmap);
	ahead = &agg->hashes[hv & agg->hash_table_mask];
	mhlist_for_each_entry(n, e, ahead, node.hnode) {
		if (KEY_EQ_P(n)) {
			anode = &n->node;
			clear_agg = 1;
			break;
		}
	}

	/* now total each cpu */
	for_each_possible_cpu(cpu) {
		map = _stp_pmap_get_map (pmap, cpu);
		head = &map->hashes[hv & map->hash_table_mask];
		mhlist_for_each_entry(n, e, head, node.hnode) {
			if (KEY_EQ_P(n)) {
				if (anode == NULL) {
					anode = _stp_new_agg(agg, ahead, &n->node,
							     KEYSYM(pmap_update_node));
				} else {
					if (clear_agg) {
						KEYSYM(pmap_update_node)(agg, anode, NULL, 0);
						clear_agg = 0;
					}
					KEYSYM(pmap_update_node)(agg, anode, &n->node, 1);
				}
			}
		}
	}
	if (anode && !clear_agg) 
		return MAP_GET_VAL(KEYSYM(get_map_node)(anode));

	/* key not found */
	return NULLRET;
}

static MAP KEYSYM(_stp_pmap_agg) (PMAP pmap)
{
	return _stp_pmap_agg(pmap, KEYSYM(pmap_update_node),
			     KEYSYM(pmap_key_cmp));
}

static int KEYSYM(_stp_pmap_del) (PMAP pmap, ALLKEYSD(key))
{
	unsigned int hv;
	int cpu;
	MAP m;

	/* Get the key's hash */
	if (KEYSYM(keycheck) (ALLKEYS(key)) == 0)
		return -1;
	hv = KEYSYM(hash) (ALLKEYS(key));

	/* Delete in each cpu's map */
	for_each_possible_cpu(cpu) {
		m = _stp_pmap_get_map (pmap, cpu);
		(void)KEYSYM(_stp_map_del_hash) (m, hv & m->hash_table_mask,
                                                 ALLKEYS(key));
	}

	/* Note that we don't need to delete the aggregate's value,
	 * since it isn't "live" between statements. */
	return 1;
}

