/* -*- linux-c -*- 
 * Map Functions
 * Copyright (C) 2005-2016 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _MAP_C_
#define _MAP_C_

/** @file map.c
 * @brief Implements maps (associative arrays) and lists
 */

#include "stat-common.c"
#include "map-stat.c"

static int int64_eq_p (int64_t key1, int64_t key2)
{
	return key1 == key2;
}

static void str_copy(char *dest, char *src)
{
	if (src)
		strlcpy(dest, src, MAP_STRING_LENGTH);
	else
		*dest = 0;
}

static void str_add(void *dest, char *val)
{
	char *dst = (char *)dest;
	strlcat(dst, val, MAP_STRING_LENGTH);
}

static int str_eq_p (char *key1, char *key2)
{
	return strncmp(key1, key2, MAP_STRING_LENGTH - 1) == 0;
}


/** @addtogroup maps 
 * Implements maps (associative arrays) and lists
 * @{ 
 */


/** Get the first element in a map.
 * @param map 
 * @returns a pointer to the first element.
 * This is typically used with _stp_map_iter().  See the foreach() macro
 * for typical usage.  It probably does what you want anyway.
 * @sa foreach
 */

static struct map_node *_stp_map_start(MAP map)
{
	//dbug ("%lx\n", (long)mlist_next(&map->head));

	if (mlist_empty(&map->head))
		return NULL;

	return mlist_map_node(mlist_next(&map->head));
}

/** Get the next element in a map.
 * @param map 
 * @param m a pointer to the current element, returned from _stp_map_start()
 * or _stp_map_iter().
 * @returns a pointer to the next element.
 * This is typically used with _stp_map_start().  See the foreach() macro
 * for typical usage.  It probably does what you want anyway.
 * @sa foreach
 */

static struct map_node *_stp_map_iter(MAP map, struct map_node *m)
{
	if (mlist_next(&m->lnode) == &map->head)
		return NULL;

	return mlist_map_node(mlist_next(&m->lnode));
}

static struct map_node *_stp_map_iterdel(MAP map, struct map_node *m)
{
  struct map_node *r_map;

  r_map = _stp_map_iter(map, m);
  _new_map_del_node(map, m);

  return r_map;
}

/** Clears all the elements in a map.
 * @param map 
 */

static void _stp_map_clear(MAP map)
{
	struct map_node *m;

	map->num = 0;

	while (!mlist_empty(&map->head)) {
		m = mlist_map_node(mlist_next(&map->head));

		/* remove node from old hash list */
		mhlist_del_init(&m->hnode);

		/* remove from entry list */
		mlist_del(&m->lnode);

		/* add to free pool */
		mlist_add(&m->lnode, &map->pool);
	}
}

static void _stp_pmap_clear(PMAP pmap)
{
	int i;

	for_each_possible_cpu(i) {
		MAP m = _stp_pmap_get_map (pmap, i);
		_stp_map_clear(m);
	}
	_stp_map_clear(_stp_pmap_get_agg(pmap));
}


/* sort keynum values */
#define SORT_COUNT -5 /* see also translate.cxx:visit_foreach_loop */
#define SORT_SUM   -4
#define SORT_MIN   -3
#define SORT_MAX   -2
#define SORT_AVG   -1

/* comparison function for sorts. */
static int _stp_cmp (struct mlist_head *h1, struct mlist_head *h2,
		     int keynum, int dir, map_get_key_fn get_key)
{
	int64_t a = 0, b = 0;
	int type = END;
	key_data k1 = (*get_key)(mlist_map_node(h1), keynum, &type);
	key_data k2 = (*get_key)(mlist_map_node(h2), keynum, NULL);
	if (type == INT64) {
		a = k1.val;
		b = k2.val;
	} else if (type == STRING) {
		a = strcmp(k1.strp, k2.strp);
		b = 0;
	} else if (type == STAT) {
		stat_data *sd1 = k1.statp;
		stat_data *sd2 = k2.statp;
		switch (keynum) {
		case SORT_COUNT:
			a = sd1->count;
			b = sd2->count;
			break;
		case SORT_SUM:
			a = sd1->sum;
			b = sd2->sum;
			break;
		case SORT_MIN:
			a = sd1->min;
			b = sd2->min;
			break;
		case SORT_MAX:
			a = sd1->max;
			b = sd2->max;
			break;
		case SORT_AVG:
			a = _stp_div64 (NULL, sd1->sum, sd1->count);
			b = _stp_div64 (NULL, sd2->sum, sd2->count);
			break;
		default:
			/* should never happen */
			a = b = 0;
		}
	}
	if ((a < b && dir > 0) || (a > b && dir < 0))
		return 1;
	return 0;
}

/* swap function for bubble sort */
static inline void _stp_swap (struct mlist_head *a, struct mlist_head *b)
{
	mlist_del(a);
	mlist_add(a, b);
}


/** Sort an entire array.
 * Sorts an entire array using merge sort.
 *
 * @param map Map
 * @param keynum 0 for the value, or a positive number for the key number to sort on.
 * @param dir Sort Direction. -1 for low-to-high. 1 for high-to-low.
 * @sa _stp_map_sortn()
 */

static void _stp_map_sort (MAP map, int keynum, int dir,
			   map_get_key_fn get_key)
{
        struct mlist_head *p, *q, *e, *tail;
        int nmerges, psize, qsize, i, insize = 1;
	struct mlist_head *head = &map->head;

	if (mlist_empty(head))
		return;

        do {
		tail = head;
		p = mlist_next(head);
                nmerges = 0;

                while (p) {
                        nmerges++;
                        q = p;
                        psize = 0;
                        for (i = 0; i < insize; i++) {
                                psize++;
                                q = mlist_next(q) == head ? NULL : mlist_next(q);
                                if (!q)
                                        break;
                        }

                        qsize = insize;
                        while (psize > 0 || (qsize > 0 && q)) {
                                if (psize && (!qsize || !q ||
					      !_stp_cmp(p, q, keynum, dir, get_key))) {
                                        e = p;
                                        p = mlist_next(p) == head ? NULL : mlist_next(p);
                                        psize--;
                                } else {
                                        e = q;
                                        q = mlist_next(q) == head ? NULL : mlist_next(q);
                                        qsize--;
                                }

				/* now put 'e' on tail of list and make it our new tail */
				mlist_del(e);
				mlist_add(e, tail);
				tail = e;
                        }
                        p = q;
                }
                insize += insize;
        } while (nmerges > 1);
}

/** Get the top values from an array.
 * Sorts an array such that the start of the array contains the top
 * or bottom 'n' values. Use this when sorting the entire array
 * would be too time-consuming and you are only interested in the
 * highest or lowest values.
 *
 * @param map Map
 * @param n Top (or bottom) number of elements. 0 sorts the entire array.
 * @param keynum 0 for the value, or a positive number for the key number to sort on.
 * @param dir Sort Direction. -1 for low-to-high. 1 for high-to-low.
 * @sa _stp_map_sort()
 */
static void _stp_map_sortn(MAP map, int n, int keynum, int dir,
			   map_get_key_fn get_key)
{
	if (n == 0 || n > 30) {
		_stp_map_sort(map, keynum, dir, get_key);
	} else {
		struct mlist_head *head = &map->head;
		struct mlist_head *c, *a, *last, *tmp;
		int num, swaps = 1;

		if (mlist_empty(head))
			return;

		/* start off with a modified bubble sort of the first n elements */
		while (swaps) {
			num = n;
			swaps = 0;
			a = mlist_next(head);
			c = mlist_next(mlist_next(a));
			while ((mlist_next(a) != head) && (--num > 0)) {
				if (_stp_cmp(a, mlist_next(a), keynum, dir, get_key)) {
					swaps++;
					_stp_swap(a, mlist_next(a));
				}
				a = mlist_prev(c);
				c = mlist_next(c);
			}
		}

		/* Now use a kind of insertion sort for the rest of the array. */
		/* Each element is tested to see if it should be be in the top 'n' */
		last = a;
		a = mlist_next(a);
		while (a != head) {
			tmp = mlist_next(a);
			c = last;
			while (c != head && _stp_cmp(c, a, keynum, dir, get_key))
				c = mlist_prev(c);
			if (c != last) {
				mlist_del(a);
				mlist_add(a, c);
				last = mlist_prev(last);
			}
			a = tmp;
		}
	}
}

static struct map_node *_stp_new_agg(MAP agg, struct mhlist_head *ahead,
				     struct map_node *ptr, map_update_fn update)
{
	struct map_node *aptr;
	/* copy keys and aggregate */
	aptr = _new_map_create(agg, ahead);
	if (aptr == NULL)
		return NULL;
	(*update)(agg, aptr, ptr, 0);
	return aptr;
}

/** Aggregate per-cpu maps.
 * This function aggregates the per-cpu maps into an aggregated
 * map. A pointer to that aggregated map is returned.
 * 
 * A write lock must be held on the map during this function.
 *
 * @param map A pointer to a pmap.
 * @returns a pointer to the aggregated map. Null on failure.
 */
static MAP _stp_pmap_agg (PMAP pmap, map_update_fn update, map_cmp_fn cmp)
{
	int i, hash;
	MAP m, agg;
	struct map_node *ptr, *aptr = NULL;
	struct mhlist_head *head, *ahead;
	struct mhlist_node *e, *f;
	int quit = 0;

	agg = _stp_pmap_get_agg(pmap);

        /* FIXME. we either clear the aggregation map or clear each local map */
	/* every time we aggregate. which would be best? */
	_stp_map_clear (agg);

	for_each_possible_cpu(i) {
		m = _stp_pmap_get_map (pmap, i);
		/* walk the hash chains. */
		for (hash = 0; hash <= m->hash_table_mask; hash++) {
			head = &m->hashes[hash];
			ahead = &agg->hashes[hash];
			mhlist_for_each_entry(ptr, e, head, hnode) {
				int match = 0;
				mhlist_for_each_entry(aptr, f, ahead, hnode) {
					if ((*cmp)(ptr, aptr)) {
						match = 1;
						break;
					}
				}
				if (match)
					(*update)(agg, aptr, ptr, 1);
				else {
					if (!_stp_new_agg(agg, ahead, ptr, update)) {
                                                agg = NULL;
						goto out;
                                                // NB: break would head out to the for (hash...) 
                                                // loop, which behaves badly with an agg==NULL.
					}
				}
			}
		}
	}

out:
	return agg;
}

static struct map_node *_new_map_create (MAP map, struct mhlist_head *head)
{
	struct map_node *m;
	if (mlist_empty(&map->pool)) {
		if (!map->wrap) {
			/* ERROR. no space left */
			return NULL;
		}
		m = mlist_map_node(mlist_next(&map->head));
		mhlist_del_init(&m->hnode);
	} else {
		m = mlist_map_node(mlist_next(&map->pool));
		map->num++;
	}
	mlist_move_tail(&m->lnode, &map->head);

	/* add node to new hash list */
	mhlist_add_head(&m->hnode, head);
	return m;
}

static void _new_map_del_node (MAP map, struct map_node *n)
{
	/* remove node from old hash list */
	mhlist_del_init(&n->hnode);

	/* remove from entry list */
	mlist_del(&n->lnode);

	/* add it back to the pool */
	mlist_add(&n->lnode, &map->pool);

	map->num--;
}

static int _new_map_set_int64 (MAP map, int64_t *dst, int64_t val, int add)
{
	if (add)
		*dst += val;
	else
		*dst = val;

	return 0;
}

static int _new_map_set_str (MAP map, char *dst, char *val, int add)
{
	if (add)
		str_add(dst, val);
	else
		str_copy(dst, val);

	return 0;
}

static int _new_map_set_stat (MAP map, struct stat_data *sd, int64_t val, int add)
{
	if (!add) {
		Hist st = &map->hist;
		sd->count = 0;
		if (st->type != HIST_NONE) {
			int j;
			for (j = 0; j < st->buckets; j++)
				sd->histogram[j] = 0;
		}
	}
	__stp_stat_add (&map->hist, sd, val);
	return 0;
}

static int _new_map_copy_stat (MAP map, struct stat_data *sd1, struct stat_data *sd2, int add)
{
	Hist st = &map->hist;

        if (sd2 == NULL) {
                sd1->count = 0;
                if (st->type != HIST_NONE) {
                        int j;
                        for (j = 0; j < st->buckets; j++)
                                sd1->histogram[j] = 0;
                }
        } else if (add && sd1->count > 0 && sd2->count > 0) {
		sd1->count += sd2->count;
		sd1->sum += sd2->sum;
		if (sd2->min < sd1->min)
			sd1->min = sd2->min;
		if (sd2->max > sd1->max)
			sd1->max = sd2->max;
		if (st->type != HIST_NONE) {
			int j;
			for (j = 0; j < st->buckets; j++)
				sd1->histogram[j] += sd2->histogram[j];
		}
	} else {
		sd1->count = sd2->count;
		sd1->sum = sd2->sum;
		sd1->min = sd2->min;
		sd1->max = sd2->max;
		if (st->type != HIST_NONE) {
			int j;
			for (j = 0; j < st->buckets; j++)
				sd1->histogram[j] = sd2->histogram[j];
		}
	}
	return 0;
}

/** Return the number of elements in a map
 * This function will return the number of active elements
 * in a map.
 * @param map 
 * @returns an int
 */
#define _stp_map_size(map) (map->num)

/** Return the number of elements in a pmap
 * This function will return the number of active elements
 * in all the per-cpu maps in a pmap. This is a quick sum and is
 * not the same as the number of unique elements that would
 * be in the aggragated map.
 * @param pmap 
 * @returns an int
 */
static int _stp_pmap_size (PMAP pmap)
{
	int i, num = 0;

	for_each_possible_cpu(i) {
		MAP m = _stp_pmap_get_map (pmap, i);
		num += m->num;
	}
	return num;
}
#endif /* _MAP_C_ */

