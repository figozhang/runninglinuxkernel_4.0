/* -*- linux-c -*- 
 * Map list abstractions
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_MAP_LIST_H_
#define _LINUX_MAP_LIST_H_

#include <linux/list.h>

#define mlist_head	list_head
#define mlist_next	list_next
#define mlist_prev	list_prev

#define INIT_MLIST_HEAD	INIT_LIST_HEAD

#define mlist_add	list_add
#define mlist_del	list_del
#define mlist_empty	list_empty
#define mlist_entry	list_entry
#define mlist_move_tail	list_move_tail

#define mlist_for_each_safe	list_for_each_safe

static inline struct list_head* list_next(struct list_head* head)
{
	return head->next;
}

static inline struct list_head* list_prev(struct list_head* head)
{
	return head->prev;
}


#define mhlist_head	hlist_head
#define mhlist_node	hlist_node

#define INIT_MHLIST_HEAD	INIT_HLIST_HEAD
#define INIT_MHLIST_NODE	INIT_HLIST_NODE

#define mhlist_add_head	hlist_add_head
#define mhlist_del_init	hlist_del_init

#define mhlist_for_each_entry	stap_hlist_for_each_entry


#endif /* _LINUX_MAP_LIST_H_ */
