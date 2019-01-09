/* -*- linux-c -*- 
 * Map Header File
 * Copyright (C) 2005-2016 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _MAP_H_
#define _MAP_H_

#ifdef __KERNEL__
#include <linux/log2.h>
#include "linux/map_list.h"
#elif defined(__DYNINST__)
#include "dyninst/ilog2.h"
#include "dyninst/map_list.h"
#endif

/* Number of bits to add-to or subtract-from "natural" hash table size.
   0  = natural hash table size = ilog2(max-table-elements)
   +1 = double of natural hash table size: saves time, spends space
   -1 = half of natural hash table size: saves space, spends time
   -many = minimum hash table size (1 entry)
   +many = build failure
*/
#ifndef MAPHASHBIAS
#define MAPHASHBIAS 0
#endif

#define HASHTABLESIZE(entries) (1 << max_t(int, ilog2(entries)+MAPHASHBIAS, 1))
/* NB: a power of two, since we truncate hv with & rather than % */


/** @file map.h
 * @brief Header file for maps and lists 
 */
/** @addtogroup maps 
 * @todo Needs a spinlock variable to help when locks are required on the map.
 * @{
 */

/** Maximum length of strings in maps. This sets the amount of space
    reserved for each string.  This should match MAXSTRINGLEN.  If
    MAP_STRING_LENGTH is less than MAXSTRINGLEN, a user could get
    strings truncated that are stored in arrays. */
#ifndef MAP_STRING_LENGTH
#define MAP_STRING_LENGTH MAXSTRINGLEN
#endif

/** @cond DONT_INCLUDE */
#define INT64 0
#define STRING 1
#define STAT 2
#define END 3
/** @endcond */

#include "stat.h"

/* Keys are either int64 or strings, and values can also be stats */
typedef union {
	int64_t val;
	char *strp;
	stat_data *statp;
} key_data;


/* basic map element */
struct map_node {
	/* list of other nodes in the map */
	struct mlist_head lnode;

	/* list of nodes with the same hash value */
	struct mhlist_node hnode;
};

#define mlist_map_node(head) mlist_entry((head), struct map_node, lnode)

/* This structure contains all information about a map.
 * It is allocated once when _stp_map_new() is called. 
 */
struct map_root {
        /* maximum number of elements allowed in the array. */
	unsigned maxnum;

	/* current number of used elements */
	unsigned num;

	/* when more than maxnum elements, wrap or discard? */
	int wrap;

#ifdef __KERNEL__
	void *node_mem;
#endif

	/* linked list of current entries */
	struct mlist_head head;

	/* pool of unused entries. */
	struct mlist_head pool;

	/* used if this map's nodes contain stats */
	struct _Hist hist;

	/* the hash table for this array */
        unsigned hash_table_mask;
	struct mhlist_head hashes[0]; /* dynamically allocated at tail */
};

/** All maps are of this type. */
typedef struct map_root *MAP;

struct pmap; /* defined in map_runtime.h */
typedef struct pmap *PMAP;

typedef key_data (*map_get_key_fn)(struct map_node *mn, int n, int *type);
typedef void (*map_update_fn)(MAP m, struct map_node *dst, struct map_node *src, int add);
typedef int (*map_cmp_fn)(struct map_node *dst, struct map_node *src);


/** Loop through all elements of a map or list.
 * @param map 
 * @param ptr pointer to a map_node_stat, map_node_int64 or map_node_str
 *
 * @b Example:
 * @include foreach.c
 */

#define foreach(map, ptr)						\
	for (ptr = _stp_map_start(map); ptr; ptr = _stp_map_iter (map, ptr))

/** @} */


#ifdef __KERNEL__
#include "linux/map_runtime.h"
#elif defined(__DYNINST__)
#include "dyninst/map_runtime.h"
#endif


/** @cond DONT_INCLUDE */
/************* prototypes for map.c ****************/

static int int64_eq_p(int64_t key1, int64_t key2);
static void str_copy(char *dest, char *src);
static void str_add(void *dest, char *val);
static int str_eq_p(char *key1, char *key2);
static MAP _stp_map_new(unsigned max_entries, int wrap, int node_size, int cpu);
static PMAP _stp_pmap_new(unsigned max_entries, int wrap, int node_size);
static MAP _stp_map_new_hstat(unsigned max_entries, int wrap, int node_size);
static MAP _stp_map_new_hstat_log(unsigned max_entries, int wrap, int node_size);
static MAP _stp_map_new_hstat_linear(unsigned max_entries, int wrap, int node_size,
				     int start, int stop, int interval);
static void _stp_map_print_histogram(MAP map, stat_data *s);
static struct map_node * _stp_map_start(MAP map);
static struct map_node * _stp_map_iter(MAP map, struct map_node *m);
static void _stp_map_del(MAP map);
static void _stp_map_clear(MAP map);

static struct map_node *_new_map_create (MAP map, struct mhlist_head *head);
static int _new_map_set_int64 (MAP map, int64_t *dst, int64_t val, int add);
static int _new_map_set_str (MAP map, char* dst, char *val, int add);
static void _new_map_del_node (MAP map, struct map_node *n);
static PMAP _stp_pmap_new_hstat_linear (unsigned max_entries, int wrap,
					int node_size, int start, int stop,
					int interval);
static PMAP _stp_pmap_new_hstat_log (unsigned max_entries, int wrap, int node_size);
static PMAP _stp_pmap_new_hstat (unsigned max_entries, int wrap, int node_size);
static void _stp_pmap_del(PMAP pmap);
static MAP _stp_pmap_agg (PMAP pmap, map_update_fn update, map_cmp_fn cmp);
static struct map_node *_stp_new_agg(MAP agg, struct mhlist_head *ahead,
				     struct map_node *ptr, map_update_fn update);
static int _new_map_set_stat (MAP map, struct stat_data *dst, int64_t val, int add);
static int _new_map_copy_stat (MAP map, struct stat_data *dst, struct stat_data *src, int add);
static void _stp_map_sort (MAP map, int keynum, int dir, map_get_key_fn get_key);
static void _stp_map_sortn(MAP map, int n, int keynum, int dir, map_get_key_fn get_key);
/** @endcond */
#endif /* _MAP_H_ */
