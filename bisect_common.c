/*
 * Copyright (C) 2013 B.A.T.M.A.N. contributors:
 *
 * Antonio Quartulli <antonio@open-mesh.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "main.h"
#include "bisect_common.h"
#include "bat-hosts.h"
#include "hash.h"
#include "functions.h"

static struct hashtable_t *node_hash = NULL;
static struct bisect_bat_node *curr_bat_node = NULL;

static int bisect_compare_name(void *data1, void *data2)
{
	return (memcmp(data1, data2, NAME_LEN) == 0 ? 1 : 0);
}

static int bisect_choose_name(void *data, int32_t size)
{
	unsigned char *key= data;
	uint32_t hash = 0, m_size = NAME_LEN - 1;
	size_t i;

	for (i = 0; i < m_size; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return (hash % size);
}

static struct bisect_bat_node *bisect_node_get(char *name)
{
	struct bisect_bat_node *bat_node;

	if (!name)
		return NULL;

	bat_node = (struct bisect_bat_node *)hash_find(node_hash, name);
	if (bat_node)
		goto out;

	bat_node = malloc(sizeof(*bat_node));
	if (!bat_node) {
		fprintf(stderr,
			"Could not allocate memory for data structure (out of mem?) - skipping");
		return NULL;
	}

	strncpy(bat_node->name, name, NAME_LEN);
	INIT_LIST_HEAD_FIRST(bat_node->orig_ev_list);
	INIT_LIST_HEAD_FIRST(bat_node->rt_list);
	memset(bat_node->loop_magic, 0, sizeof(bat_node->loop_magic));
	memset(bat_node->loop_magic2, 0, sizeof(bat_node->loop_magic2));
	hash_add(node_hash, bat_node);

out:
	return bat_node;
}

static struct bisect_orig_ev *
bisect_orig_event_new(struct bisect_bat_node *bat_node,
		      struct bisect_bat_node *orig_node)
{
	struct bisect_orig_ev *orig_ev;

	orig_ev = malloc(sizeof(*orig_ev));
	if (!orig_ev) {
		fprintf(stderr,
			"Could not allocate memory for orig event structure (out of mem?) - skipping");
		return NULL;
	}

	INIT_LIST_HEAD(&orig_ev->list);
	INIT_LIST_HEAD_FIRST(orig_ev->ev_list);
	INIT_LIST_HEAD_FIRST(orig_ev->rt_hist_list);
	orig_ev->orig_node = orig_node;
	list_add_tail(&orig_ev->list, &bat_node->orig_ev_list);

	return orig_ev;
}

static struct bisect_orig_ev *
bisect_orig_event_get_by_name(struct bisect_bat_node *bat_node, char *orig)
{
	struct bisect_bat_node *orig_node;
	struct bisect_orig_ev *orig_ev;

	if (!bat_node)
		return NULL;

	list_for_each_entry(orig_ev, &bat_node->orig_ev_list, list) {
		if (bisect_compare_name(orig_ev->orig_node->name, orig))
			return orig_ev;
	}

	orig_node = bisect_node_get(orig);
	if (!orig_node)
		return NULL;

	return bisect_orig_event_new(bat_node, orig_node);
}

static struct bisect_orig_ev *
bisect_orig_event_get_by_ptr(struct bisect_bat_node *bat_node,
			     struct bisect_bat_node *orig_node)
{
	struct bisect_orig_ev *orig_ev;

	if (!bat_node)
		return NULL;

	list_for_each_entry(orig_ev, &bat_node->orig_ev_list, list) {
		if (orig_ev->orig_node == orig_node)
			return orig_ev;
	}

	return bisect_orig_event_new(bat_node, orig_node);
}

static void bisect_node_free(void *data)
{
	struct bisect_orig_ev *orig_ev, *orig_ev_tmp;
	struct bisect_seqno_ev *seqno_ev, *seqno_ev_tmp;
	struct bisect_rt *rt, *rt_tmp;
	struct bisect_rt_hist *rt_hist, *rt_hist_tmp;
	struct bisect_bat_node *bat_node = (struct bisect_bat_node *)data;

	list_for_each_entry_safe(orig_ev, orig_ev_tmp,
				 &bat_node->orig_ev_list, list) {
		list_for_each_entry_safe(seqno_ev, seqno_ev_tmp,
					 &orig_ev->ev_list, list) {
			list_del((struct list_head *)&orig_ev->ev_list,
				 &seqno_ev->list, &orig_ev->ev_list);
			free(seqno_ev);
		}

		list_for_each_entry_safe(rt_hist, rt_hist_tmp,
					 &orig_ev->rt_hist_list, list) {
			list_del((struct list_head *)&orig_ev->rt_hist_list,
				 &rt_hist->list, &orig_ev->rt_hist_list);
			free(rt_hist);
		}

		list_del((struct list_head *)&bat_node->orig_ev_list,
			 &orig_ev->list, &bat_node->orig_ev_list);
		free(orig_ev);
	}

	list_for_each_entry_safe(rt, rt_tmp, &bat_node->rt_list, list) {
		list_del((struct list_head *)&bat_node->rt_list,
			 &rt->list, &bat_node->rt_list);

		free(rt->entries);
		free(rt);
	}

	free(bat_node);
}

int bisect_routing_table_new(char *orig, char *next_hop, char *old_next_hop,
			     char rt_flag)
{
	struct bisect_rt *rt, *prev_rt = NULL;
	struct bisect_seqno_ev *seqno_ev;
	struct bisect_bat_node *next_hop_node;
	struct bisect_orig_ev *orig_ev;
	struct bisect_rt_hist *rt_hist;
	int i, j = -1;
	char *name;

	if (!curr_bat_node) {
		fprintf(stderr,
			"Routing table change without preceding OGM - skipping");
		goto err;
	}

	if (!orig) {
		fprintf(stderr, "Invalid originator found - skipping");
		goto err;
	}

	if ((rt_flag != RT_FLAG_DELETE) && (!next_hop)) {
		fprintf(stderr, "Invalid next hop found - skipping");
		goto err;
	}

	if ((rt_flag == RT_FLAG_UPDATE) && (!old_next_hop)) {
		fprintf(stderr, "Invalid old next hop found - skipping");
		goto err;
	}

	next_hop_node = bisect_node_get(next_hop);
	if ((rt_flag != RT_FLAG_DELETE) && (!next_hop_node))
		goto err;

	orig_ev = bisect_orig_event_get_by_name(curr_bat_node, orig);
	if (!orig_ev)
		goto err;

	if (list_empty(&orig_ev->ev_list)) {
		fprintf(stderr,
			"Routing table change without any preceding OGM of that originator - skipping");
		goto err;
	}

	name = ((struct bisect_seqno_ev *)(orig_ev->ev_list.prev))->orig->name;
	if (!bisect_compare_name(name, orig)) {
		fprintf(stderr,
			"Routing table change does not match with last received OGM - skipping");
		goto err;
	}

	rt = malloc(sizeof(*rt));
	if (!rt) {
		fprintf(stderr,
			"Could not allocate memory for routing table (out of mem?) - skipping");
		goto err;
	}

	rt_hist = malloc(sizeof(*rt_hist));
	if (!rt_hist) {
		fprintf(stderr,
			"Could not allocate memory for routing history (out of mem?) - skipping");
		goto table_free;
	}

	INIT_LIST_HEAD(&rt->list);
	rt->num_entries = 1;

	INIT_LIST_HEAD(&rt_hist->list);
	rt_hist->prev_rt_hist = NULL;
	rt_hist->next_hop = next_hop_node;
	rt_hist->flags = rt_flag;
	memset(rt_hist->loop_magic, 0, sizeof(rt_hist->loop_magic));

	if (!(list_empty(&orig_ev->rt_hist_list)))
		rt_hist->prev_rt_hist = (struct bisect_rt_hist *)(orig_ev->rt_hist_list.prev);

	if (!(list_empty(&curr_bat_node->rt_list)))
		prev_rt = (struct bisect_rt *)(curr_bat_node->rt_list.prev);

	switch (rt_flag) {
	case RT_FLAG_ADD:
		if (prev_rt)
			rt->num_entries = prev_rt->num_entries + 1;
		break;
	case RT_FLAG_UPDATE:
		if (prev_rt) {
			rt->num_entries = prev_rt->num_entries + 1;

			/* if we had that route already we just change the entry */
			for (i = 0; i < prev_rt->num_entries; i++) {
				if (bisect_compare_name(orig,
							prev_rt->entries[i].orig)) {
					rt->num_entries = prev_rt->num_entries;
					break;
				}
			}
		}
		break;
	case RT_FLAG_DELETE:
		if (prev_rt) {
			rt->num_entries = prev_rt->num_entries + 1;

			/* if we had that route already we just change the entry */
			for (i = 0; i < prev_rt->num_entries; i++) {
				if (bisect_compare_name(orig,
							prev_rt->entries[i].orig)) {
					rt->num_entries = prev_rt->num_entries;
					break;
				}
			}

			if (rt->num_entries != prev_rt->num_entries) {
				fprintf(stderr,
				        "Found a delete entry of orig '%s' but no existing record - skipping",
				        orig);
				goto rt_hist_free;
			}

			/**
			 * we need to create a special seqno event as a timer instead
			 * of an OGM triggered that event
			 */
			seqno_ev = malloc(sizeof(struct bisect_seqno_ev));
			if (!seqno_ev) {
				fprintf(stderr,
					"Could not allocate memory for delete seqno event (out of mem?) - skipping");
				goto rt_hist_free;
			}

			INIT_LIST_HEAD(&seqno_ev->list);
			seqno_ev->orig = bisect_node_get(orig);
			seqno_ev->neigh = NULL;
			seqno_ev->prev_sender = NULL;
			seqno_ev->seqno = -1;
			seqno_ev->metric = -1;
			seqno_ev->ttl = -1;
			seqno_ev->rt_hist = NULL;
			list_add_tail(&seqno_ev->list, &orig_ev->ev_list);
		}
		break;
	default:
		fprintf(stderr, "Unknown rt_flag received: %i - skipping",
			rt_flag);
		goto rt_hist_free;
	}

	rt->entries = malloc(sizeof(struct bisect_rt_entry) * rt->num_entries);
	if (!rt->entries) {
		fprintf(stderr,
			"Could not allocate memory for routing table entries (out of mem?) - skipping");
		goto rt_hist_free;
	}

	if (prev_rt) {
		for (i = 0; i < prev_rt->num_entries; i++) {
			/* if we have a previously deleted item don't copy it
			 * over
			 */
			if (prev_rt->entries[i].flags == RT_FLAG_DELETE) {
				rt->num_entries--;
				continue;
			}

			/* if we delete one item the entries are not in sync
			 * anymore, therefore we need to counters: one for the
			 * old and one for the new routing table
			 */
			j++;

			memcpy((char *)&rt->entries[j],
			       (char *)&prev_rt->entries[i],
			       sizeof(struct bisect_rt_entry));

			if (bisect_compare_name(orig,
						rt->entries[j].orig)) {
				if (rt_flag != RT_FLAG_DELETE)
					rt->entries[j].next_hop = next_hop_node;
				rt->entries[j].flags = rt_flag;
				continue;
			}

			rt->entries[j].flags = 0;
		}
	}

	if ((rt->num_entries == 1) || (rt->num_entries != j + 1)) {
		i = rt->num_entries;
		strncpy(rt->entries[i - 1].orig, orig, NAME_LEN);
		rt->entries[i - 1].next_hop = next_hop_node;
		rt->entries[i - 1].flags = rt_flag;
	}

	rt->rt_hist = rt_hist;
	rt_hist->seqno_ev = (struct bisect_seqno_ev *)(orig_ev->ev_list.prev);
	rt_hist->seqno_ev->rt_hist = rt_hist;
	rt_hist->rt = rt;
	list_add_tail(&rt->list, &curr_bat_node->rt_list);
	list_add_tail(&rt_hist->list, &orig_ev->rt_hist_list);

	return 1;

rt_hist_free:
	free(rt_hist);
table_free:
	free(rt);
err:
	return 0;
}

int bisect_seqno_event_new(char *iface_addr, char *orig, char *prev_sender,
			   char *neigh, long long seqno, long long metric,
			   int ttl)
{
	struct bisect_bat_node *orig_node, *neigh_node, *prev_sender_node;
	struct bisect_orig_ev *orig_ev;
	struct bisect_seqno_ev *seqno_ev;

	if (!iface_addr) {
		fprintf(stderr, "Invalid interface address found - skipping");
		goto err;
	}

	if (!orig) {
		fprintf(stderr, "Invalid originator found - skipping");
		goto err;
	}

	if (!neigh) {
		fprintf(stderr, "Invalid neighbor found - skipping");
		goto err;
	}

	if ((seqno < 0) || (seqno > UINT32_MAX)) {
		fprintf(stderr, "Invalid sequence number found (%lli) - skipping",
			seqno);
		goto err;
	}

	if (metric < 0) {
		fprintf(stderr, "Invalid metric value found (%lli) - skipping", metric);
		goto err;
	}

	if ((ttl < 0) || (ttl > UINT8_MAX)) {
		fprintf(stderr, "Invalid ttl value found (%i) - skipping", ttl);
		goto err;
	}

	curr_bat_node = bisect_node_get(iface_addr);
	if (!curr_bat_node)
		goto err;

	orig_node = bisect_node_get(orig);
	if (!orig_node)
		goto err;

	neigh_node = bisect_node_get(neigh);
	if (!neigh_node)
		goto err;

	prev_sender_node = bisect_node_get(prev_sender);
	if (!prev_sender_node)
		goto err;

	orig_ev = bisect_orig_event_get_by_ptr(curr_bat_node, orig_node);
	if (!orig_ev)
		goto err;

	seqno_ev = malloc(sizeof(struct bisect_seqno_ev));
	if (!seqno_ev) {
		fprintf(stderr,
			"Could not allocate memory for seqno event (out of mem?) - skipping");
		goto err;
	}

	INIT_LIST_HEAD(&seqno_ev->list);
	seqno_ev->orig = orig_node;
	seqno_ev->neigh = neigh_node;
	seqno_ev->prev_sender = prev_sender_node;
	seqno_ev->seqno = seqno;
	seqno_ev->metric = metric;
	seqno_ev->ttl = ttl;
	seqno_ev->rt_hist = NULL;
	list_add_tail(&seqno_ev->list, &orig_ev->ev_list);

	return 1;

err:
	return 0;
}

int bisect_get_orig_addr(char *orig_name, char *orig_addr)
{
	struct bat_host *bat_host;
	struct ether_addr *orig_mac;
	char *orig_name_tmp = orig_name;

	bat_host = bat_hosts_find_by_name(orig_name_tmp);
	if (bat_host) {
		orig_name_tmp = ether_ntoa_long((struct ether_addr *)&bat_host->mac_addr);
		goto copy_name;
	}

	orig_mac = ether_aton(orig_name_tmp);

	if (!orig_mac) {
		fprintf(stderr,
			"Error - the originator is not a mac address or bat-host name: %s\n",
			orig_name);
		goto err;
	}

	/* convert the given mac address to the long format to
	 * make sure we can find it
	 */
	orig_name_tmp = ether_ntoa_long(orig_mac);

copy_name:
	strncpy(orig_addr, orig_name_tmp, NAME_LEN);
	return 1;

err:
	return 0;
}

static struct bisect_rt_hist *
bisect_get_rt_hist_by_seqno(struct bisect_orig_ev *orig_ev, long long seqno)
{
	struct bisect_seqno_ev *seqno_ev;
	struct bisect_rt_hist *rt_hist = NULL;

	list_for_each_entry(seqno_ev, &orig_ev->ev_list, list) {
		if (seqno_ev->seqno > seqno)
			break;

		if (seqno_ev->rt_hist)
			rt_hist = seqno_ev->rt_hist;
	}

	return rt_hist;
}

static struct bisect_rt_hist *
bisect_get_rt_hist_by_node_seqno(struct bisect_bat_node *bat_node,
				 struct bisect_bat_node *orig_node, long long seqno)
{
	struct bisect_orig_ev *orig_ev;
	struct bisect_rt_hist *rt_hist;

	orig_ev = bisect_orig_event_get_by_ptr(bat_node, orig_node);
	if (!orig_ev)
		return NULL;

	rt_hist = bisect_get_rt_hist_by_seqno(orig_ev, seqno);
	return rt_hist;
}

static int bisect_print_rt_path_at_seqno(struct bisect_bat_node *src_node,
					 struct bisect_bat_node *dst_node,
					 struct bisect_bat_node *next_hop,
					 long long seqno, long long seqno_rand,
					 int read_opt)
{
	struct bisect_bat_node *next_hop_tmp;
	struct bisect_orig_ev *orig_ev;
	struct bisect_rt_hist *rt_hist;
	char curr_loop_magic[LOOP_MAGIC_LEN];

	snprintf(curr_loop_magic, sizeof(curr_loop_magic), "%s%s%lli%lli",
		 src_node->name, dst_node->name, seqno, seqno_rand);
	curr_loop_magic[sizeof(curr_loop_magic) - 1] = '\0';

	printf("Path towards %s (seqno %lli ",
	       get_name_by_macstr(dst_node->name, read_opt), seqno);

	printf("via neigh %s):", get_name_by_macstr(next_hop->name, read_opt));

	next_hop_tmp = next_hop;

	while (1) {
		printf(" -> %s%s",
		       get_name_by_macstr(next_hop_tmp->name, read_opt),
		       (dst_node == next_hop_tmp ? "." : ""));

		/* destination reached */
		if (dst_node == next_hop_tmp)
			break;

		orig_ev = bisect_orig_event_get_by_ptr(next_hop_tmp,
							  dst_node);
		if (!orig_ev)
			goto out;

		/* no more data - path seems[tm] fine */
		if (list_empty(&orig_ev->ev_list))
			goto out;

		/* same here */
		if (list_empty(&orig_ev->rt_hist_list))
			goto out;

		/* we are running in a loop */
		if (memcmp(curr_loop_magic, next_hop_tmp->loop_magic,
			   LOOP_MAGIC_LEN) == 0) {
			printf("   aborted due to loop!");
			goto out;
		}

		memcpy(next_hop_tmp->loop_magic, curr_loop_magic,
		       sizeof(next_hop_tmp->loop_magic));

		rt_hist = bisect_get_rt_hist_by_seqno(orig_ev, seqno);

		/* no more routing data - what can we do ? */
		if (!rt_hist)
			break;

		next_hop_tmp = rt_hist->next_hop;
	}

out:
	printf("\n");
	return 1;
}

static int bisect_find_rt_change(struct bisect_bat_node *src_node,
				       struct bisect_bat_node *dst_node,
				       struct bisect_bat_node *curr_node,
				       long long seqno_min, long long seqno_max,
				       long long seqno_rand, int read_opt)
{
	struct bisect_orig_ev *orig_ev;
	struct bisect_rt_hist *rt_hist, *rt_hist_tmp;
	char curr_loop_magic[LOOP_MAGIC_LEN], loop_check = 0;
	int res;
	long long seqno_tmp, seqno_min_tmp = seqno_min;

	/* printf("%i: curr_node: %s ", bla,
		       get_name_by_macstr(curr_node->name, read_opt));

	printf("dst_node: %s [%i - %i]\n",
	       get_name_by_macstr(dst_node->name, read_opt), seqno_min, seqno_max); */

	/* recursion ends here */
	if (curr_node == dst_node) {
		rt_hist = bisect_get_rt_hist_by_node_seqno(src_node, dst_node,
							   seqno_max);

		if (rt_hist)
			bisect_print_rt_path_at_seqno(src_node, dst_node,
						      rt_hist->next_hop,
						      seqno_max, seqno_rand,
						      read_opt);
		return 0;
	}

	snprintf(curr_loop_magic, sizeof(curr_loop_magic), "%s%s%lli%lli",
	         src_node->name, dst_node->name,
	         seqno_min_tmp, seqno_rand);
	curr_loop_magic[sizeof(curr_loop_magic) - 1] = '\0';

	orig_ev = bisect_orig_event_get_by_ptr(curr_node, dst_node);
	if (!orig_ev)
		goto out;

	list_for_each_entry(rt_hist, &orig_ev->rt_hist_list, list) {
		/* special seqno that indicates an originator timeout */
		if (rt_hist->seqno_ev->seqno == -1) {
			printf("Woot - originator timeout ??\n");
			continue;
		}

		if ((seqno_min_tmp != -1) &&
		    (rt_hist->seqno_ev->seqno < seqno_min_tmp))
			continue;

		if ((seqno_max != -1) &&
		    (rt_hist->seqno_ev->seqno >= seqno_max))
			continue;

		/* we are running in a loop */
		if (memcmp(curr_loop_magic, rt_hist->loop_magic,
			   LOOP_MAGIC_LEN) == 0) {
			rt_hist_tmp = bisect_get_rt_hist_by_node_seqno(src_node,
								       dst_node,
								       rt_hist->seqno_ev->seqno);

			if (rt_hist_tmp)
				bisect_print_rt_path_at_seqno(src_node, dst_node,
							      rt_hist_tmp->next_hop,
							      rt_hist->seqno_ev->seqno,
							      seqno_rand, read_opt);
			goto loop;
		}

		memcpy(rt_hist->loop_magic, curr_loop_magic,
		       sizeof(rt_hist->loop_magic));
		loop_check = 1;

		/* printf("validate route after change (seqno %i) at node: %s\n",
		       rt_hist->seqno_ev->seqno,
		       get_name_by_macstr(curr_node->name, read_opt)); */

		res = bisect_find_rt_change(src_node, dst_node,
						  rt_hist->next_hop,
						  seqno_min_tmp,
						  rt_hist->seqno_ev->seqno,
						  seqno_rand, read_opt);

		seqno_min_tmp = rt_hist->seqno_ev->seqno + 1;

		/* find_rt_change() did not run into a loop and printed the path */
		if (res == 0)
			continue;

		/**
		 * retrieve routing table towards dst at that point and
		 * print the routing path
		 **/
		rt_hist_tmp = bisect_get_rt_hist_by_node_seqno(src_node,
							       dst_node,
							       rt_hist->seqno_ev->seqno);
		if (!rt_hist_tmp)
			continue;

		bisect_print_rt_path_at_seqno(src_node, dst_node,
					      rt_hist_tmp->next_hop,
					      rt_hist->seqno_ev->seqno,
					      seqno_rand, read_opt);
	}

	/* if we have no routing table changes within the seqno range
	 * the loop detection above won't be triggered
	 */
	if (!loop_check) {
		if (memcmp(curr_loop_magic, curr_node->loop_magic2,
			   LOOP_MAGIC_LEN) == 0) {
			rt_hist_tmp = bisect_get_rt_hist_by_node_seqno(src_node,
								       dst_node,
								       seqno_min);

			if (rt_hist_tmp)
				bisect_print_rt_path_at_seqno(src_node, dst_node,
							      rt_hist_tmp->next_hop,
							      seqno_min, seqno_rand,
							      read_opt);

			/* no need to print the path twice */
			if (seqno_min == seqno_max)
				goto out;
			else
				goto loop;
		}

		memcpy(curr_node->loop_magic2, curr_loop_magic,
		       sizeof(curr_node->loop_magic2));
	}

	seqno_tmp = seqno_max - 1;
	if (seqno_min == seqno_max)
		seqno_tmp = seqno_max;

	rt_hist = bisect_get_rt_hist_by_seqno(orig_ev, seqno_tmp);

	if (rt_hist)
		return bisect_find_rt_change(src_node, dst_node,
						   rt_hist->next_hop,
						   seqno_min_tmp, seqno_max,
						   seqno_rand, read_opt);

out:
	return -1;
loop:
	return -2;
}

void bisect_loop_detection(char *loop_orig, long long seqno_min,
			   long long seqno_max, char *filter_orig, int read_opt)
{
	struct bisect_bat_node *bat_node;
	struct bisect_orig_ev *orig_ev;
	struct hash_it_t *hashit = NULL;
	struct bisect_rt_hist *rt_hist, *prev_rt_hist;
	long long last_seqno = -1, seqno_count = 0;
	int res;
	char check_orig[NAME_LEN];

	printf("\nAnalyzing routing tables ");

	/* if no option was given loop_orig is empty */
	memset(check_orig, 0, NAME_LEN);
	if (!bisect_compare_name(loop_orig, check_orig))
		printf("of originator: %s ",
		       get_name_by_macstr(loop_orig, read_opt));

	if ((seqno_min == -1) && (seqno_max == -1))
		printf("[all sequence numbers]");
	else if (seqno_min == seqno_max)
		printf("[sequence number: %lli]", seqno_min);
	else
		printf("[sequence number range: %lli-%lli]", seqno_min,
		       seqno_max);

	if (!bisect_compare_name(filter_orig, check_orig))
		printf(" [filter originator: %s]",
		       get_name_by_macstr(filter_orig, read_opt));

	printf("\n");

	while (NULL != (hashit = hash_iterate(node_hash, hashit))) {
		bat_node = hashit->bucket->data;

		if (!bisect_compare_name(loop_orig, check_orig) &&
		    !bisect_compare_name(loop_orig, bat_node->name))
			continue;

		printf("\nChecking host: %s\n",
		       get_name_by_macstr(bat_node->name, read_opt));

		list_for_each_entry(orig_ev, &bat_node->orig_ev_list,
				    list) {
			if (bat_node == orig_ev->orig_node)
				continue;

			if (!bisect_compare_name(filter_orig, check_orig) &&
			    !bisect_compare_name(filter_orig,
						 orig_ev->orig_node->name))
				continue;

			/* we might have no log file from this node */
			if (list_empty(&orig_ev->ev_list)) {
				fprintf(stderr,
					"No seqno data of originator '%s' - skipping\n",
				get_name_by_macstr(orig_ev->orig_node->name,
						   read_opt));
				continue;
			}

			/* or routing tables */
			if (list_empty(&orig_ev->rt_hist_list)) {
				fprintf(stderr,
					"No routing history of originator '%s' - skipping\n",
					get_name_by_macstr(orig_ev->orig_node->name,
							   read_opt));
				continue;
			}

			list_for_each_entry(rt_hist, &orig_ev->rt_hist_list,
					    list) {
				/* special seqno that indicates an originator
				 * timeout
				 */
				if (rt_hist->seqno_ev->seqno == -1)
					continue;

				if ((seqno_min != -1) &&
				    (rt_hist->seqno_ev->seqno < seqno_min))
					continue;

				if ((seqno_max != -1) &&
				    (rt_hist->seqno_ev->seqno > seqno_max))
					continue;

				/* sometime we change the routing table more than once
				 * with the same seqno
				 */
				if (last_seqno == rt_hist->seqno_ev->seqno)
					seqno_count++;
				else
					seqno_count = 0;

				last_seqno = rt_hist->seqno_ev->seqno;

				if (rt_hist->flags == RT_FLAG_DELETE) {
					printf("Path towards %s deleted (originator timeout)\n",
						get_name_by_macstr(rt_hist->seqno_ev->orig->name,
								   read_opt));
					continue;
				}

				prev_rt_hist = rt_hist->prev_rt_hist;

				if ((prev_rt_hist) &&
				    (rt_hist->seqno_ev->seqno != prev_rt_hist->seqno_ev->seqno)) {
					if (rt_hist->seqno_ev->seqno < prev_rt_hist->seqno_ev->seqno) {
						fprintf(stderr,
						        "Smaller seqno (%lli) than previously received seqno (%lli) of orig %s triggered routing table change - skipping recursive check\n",
						        rt_hist->seqno_ev->seqno, prev_rt_hist->seqno_ev->seqno,
						        get_name_by_macstr(rt_hist->seqno_ev->orig->name, read_opt));
						goto validate_path;
					}

					if (rt_hist->seqno_ev->seqno == prev_rt_hist->seqno_ev->seqno + 1)
						goto validate_path;

					/* printf("\n=> checking orig %s in seqno range of: %i - %i ",
						get_name_by_macstr(rt_hist->seqno_ev->orig->name, read_opt),
						prev_rt_hist->seqno_ev->seqno + 1,
						rt_hist->seqno_ev->seqno);

					printf("(prev nexthop: %s)\n",
						get_name_by_macstr(prev_rt_hist->next_hop->name, read_opt)); */

					res = bisect_find_rt_change(bat_node,
								rt_hist->seqno_ev->orig,
					                        prev_rt_hist->next_hop,
					                        prev_rt_hist->seqno_ev->seqno + 1,
					                        rt_hist->seqno_ev->seqno,
					                        seqno_count, read_opt);

					if (res != -2)
						continue;
				}

validate_path:
				bisect_print_rt_path_at_seqno(bat_node,
							      rt_hist->seqno_ev->orig,
							      rt_hist->next_hop,
							      rt_hist->seqno_ev->seqno,
							      seqno_count, read_opt);
			}
		}
	}
}

void bisect_print_rt(char *rt_orig, long long seqno_min, long long seqno_max,
		     char *filter_orig, int read_opt)
{
	struct bisect_bat_node *bat_node;
	struct bisect_rt *rt;
	struct bisect_seqno_ev *seqno_ev;
	char check_orig[NAME_LEN];
	int i;

	/* if no option was given filter_orig is empty */
	memset(check_orig, 0, NAME_LEN);

	printf("Routing tables of originator: %s ",
	       get_name_by_macstr(rt_orig, read_opt));

	if ((seqno_min == -1) && (seqno_max == -1))
		printf("[all sequence numbers]");
	else if (seqno_min == seqno_max)
		printf("[sequence number: %lli]", seqno_min);
	else
		printf("[sequence number range: %lli-%lli]", seqno_min,
		       seqno_max);

	if (!bisect_compare_name(filter_orig, check_orig))
		printf(" [filter originator: %s]",
		       get_name_by_macstr(filter_orig, read_opt));

	printf("\n");

	bat_node = bisect_node_get(rt_orig);
	if (!bat_node)
		goto out;

	/* we might have no log file from this node */
	if (list_empty(&bat_node->rt_list))
		goto out;

	list_for_each_entry(rt, &bat_node->rt_list, list) {
		seqno_ev = rt->rt_hist->seqno_ev;

		if (!bisect_compare_name(filter_orig, check_orig) &&
		    !bisect_compare_name(filter_orig, seqno_ev->orig->name))
			continue;

		if ((seqno_min != -1) && (seqno_ev->seqno < seqno_min))
			continue;

		if ((seqno_max != -1) && (seqno_ev->seqno > seqno_max))
			continue;

		if (seqno_ev->seqno > -1) {
			printf("rt change triggered by OGM from: %s (metric: %lli, ttl: %i, seqno %lli",
			       get_name_by_macstr(seqno_ev->orig->name,
						  read_opt),
			       seqno_ev->metric, seqno_ev->ttl,
			       seqno_ev->seqno);
			printf(", neigh: %s",
			       get_name_by_macstr(seqno_ev->neigh->name,
						  read_opt));
			printf(", prev_sender: %s)\n",
			       get_name_by_macstr(seqno_ev->prev_sender->name,
						  read_opt));
		} else {
			printf("rt change triggered by originator timeout: \n");
		}

		for (i = 0; i < rt->num_entries; i++) {
			printf("%s %s via next hop",
			       (rt->entries[i].flags ? "   *" : "    "),
			       get_name_by_macstr(rt->entries[i].orig,
						  read_opt));
			printf(" %s",
			       get_name_by_macstr(rt->entries[i].next_hop->name,
						  read_opt));

			switch (rt->entries[i].flags) {
			case RT_FLAG_ADD:
				printf(" (route added)\n");
				break;
			case RT_FLAG_UPDATE:
				printf(" (next hop changed)\n");
				break;
			case RT_FLAG_DELETE:
				printf(" (route deleted)\n");
				break;
			default:
				printf("\n");
				break;
			}
		}

		printf("\n");
	}

out:
	return;
}

static void
bisect_seqno_trace_print_neigh(struct bisect_seqno_trace_neigh *seqno_trace_neigh,
			       struct bisect_seqno_ev *seqno_ev_parent,
			       int num_sisters, char *head, int read_opt)
{
	char new_head[MAX_LINE];
	int i;

	printf("%s%s- %s [metric: %lli, ttl: %i", head,
               (strlen(head) == 1 ? "" : num_sisters == 0 ? "\\" : "|"),
               get_name_by_macstr(seqno_trace_neigh->bat_node->name, read_opt),
               seqno_trace_neigh->seqno_ev->metric,
	       seqno_trace_neigh->seqno_ev->ttl);

	printf(", neigh: %s",
	       get_name_by_macstr(seqno_trace_neigh->seqno_ev->neigh->name,
				  read_opt));
	printf(", prev_sender: %s]",
	       get_name_by_macstr(seqno_trace_neigh->seqno_ev->prev_sender->name,
				  read_opt));

	if ((seqno_ev_parent) &&
	    (seqno_trace_neigh->seqno_ev->metric > seqno_ev_parent->metric))
		printf("  TQ UP!\n");
	else
		printf("\n");

	for (i = 0; i < seqno_trace_neigh->num_neighbors; i++) {
		snprintf(new_head, sizeof(new_head), "%s%s",
		         (strlen(head) > 1 ? head : num_sisters == 0 ? " " : head),
		         (strlen(head) == 1 ? "   " : num_sisters == 0 ? "    " : "|   "));
		new_head[sizeof(new_head) - 1] = '\0';

		bisect_seqno_trace_print_neigh(seqno_trace_neigh->neigh[i],
					       seqno_trace_neigh->seqno_ev,
					       seqno_trace_neigh->num_neighbors - i - 1,
					       new_head, read_opt);
	}
}

static void bisect_seqno_trace_print(struct list_head_first *trace_list,
				     char *trace_orig, long long seqno_min,
				     long long seqno_max, char *filter_orig,
				     int read_opt)
{
	struct bisect_seqno_trace *seqno_trace;
	char head[MAX_LINE], check_orig[NAME_LEN];
	int i;

	/* if no option was given filter_orig is empty */
	memset(check_orig, 0, NAME_LEN);

	printf("Sequence number flow of originator: %s ",
	       get_name_by_macstr(trace_orig, read_opt));

	if ((seqno_min == -1) && (seqno_max == -1))
		printf("[all sequence numbers]");
	else if (seqno_min == seqno_max)
		printf("[sequence number: %lli]", seqno_min);
	else
		printf("[sequence number range: %lli-%lli]", seqno_min,
		       seqno_max);

	if (!bisect_compare_name(filter_orig, check_orig))
		printf(" [filter originator: %s]",
		       get_name_by_macstr(filter_orig, read_opt));

	printf("\n");

	list_for_each_entry(seqno_trace, trace_list, list) {
		if (!seqno_trace->print)
			continue;

		printf("+=> %s (seqno %lli)\n",
		       get_name_by_macstr(trace_orig, read_opt),
		       seqno_trace->seqno);


		for (i = 0; i < seqno_trace->neigh.num_neighbors; i++) {

			snprintf(head, sizeof(head), "%c",
			         seqno_trace->neigh.num_neighbors == i + 1 ? '\\' : '|');
			head[sizeof(head) - 1] = '\0';

			bisect_seqno_trace_print_neigh(seqno_trace->neigh.neigh[i],
						       NULL,
						       seqno_trace->neigh.num_neighbors - i - 1,
						       head, read_opt);
		}

		printf("\n");
	}
}

static int
_bisect_seqno_trace_neigh_add(struct bisect_seqno_trace_neigh *mom,
			      struct bisect_seqno_trace_neigh *child)
{
	struct bisect_seqno_trace_neigh **data_ptr;

	data_ptr = malloc((mom->num_neighbors + 1) * sizeof(data_ptr));
	if (!data_ptr)
		return 0;

	if (mom->num_neighbors > 0) {
		memcpy(data_ptr, mom->neigh,
		       mom->num_neighbors * sizeof(data_ptr));
		free(mom->neigh);
	}

	mom->num_neighbors++;
	mom->neigh = data_ptr;
	mom->neigh[mom->num_neighbors - 1] = child;

	return 1;
}

static struct bisect_seqno_trace_neigh *
bisect_seqno_trace_neigh_add(struct bisect_seqno_trace_neigh *neigh,
			     struct bisect_bat_node *bat_node,
			     struct bisect_seqno_ev *seqno_ev)
{
	struct bisect_seqno_trace_neigh *neigh_new;
	int res;

	neigh_new = malloc(sizeof(*neigh_new));
	if (!neigh_new)
		goto err;

	neigh_new->bat_node = bat_node;
	neigh_new->seqno_ev = seqno_ev;
	neigh_new->num_neighbors = 0;

	res = _bisect_seqno_trace_neigh_add(neigh, neigh_new);
	if (res < 1)
		goto free_neigh;

	return neigh_new;

free_neigh:
	free(neigh_new);
err:
	return NULL;
}

static struct bisect_seqno_trace_neigh *
bisect_seqno_trace_find_neigh(struct bisect_bat_node *neigh,
			      struct bisect_bat_node *prev_sender,
			      struct bisect_seqno_trace_neigh *trace_neigh)
{
	struct bisect_seqno_trace_neigh *tmp, *ret;
	int i;

	for (i = 0; i < trace_neigh->num_neighbors; i++) {
		tmp = trace_neigh->neigh[i];

		if ((neigh == tmp->bat_node) &&
		    (prev_sender == tmp->seqno_ev->neigh))
			return tmp;

		ret = bisect_seqno_trace_find_neigh(neigh, prev_sender, tmp);
		if (ret)
			return ret;
	}

	return NULL;
}

static void
bisect_seqno_trace_neigh_free(struct bisect_seqno_trace_neigh *neigh)
{
	int i;

	for (i = 0; i < neigh->num_neighbors; i++)
		bisect_seqno_trace_neigh_free(neigh->neigh[i]);

	if (neigh->num_neighbors > 0)
		free(neigh->neigh);

	free(neigh);
}

static int bisect_seqno_trace_fix_leaf(struct bisect_seqno_trace_neigh *mom,
				       struct bisect_seqno_trace_neigh *old_mom,
				       struct bisect_seqno_trace_neigh *child)
{
	struct bisect_seqno_trace_neigh **data_ptr, *neigh;
	int i, j = 0;

	data_ptr = malloc((old_mom->num_neighbors - 1) * sizeof(neigh));
	if (!data_ptr)
		return 0;

	/* copy all children except the child that is going to move */
	for (i = 0; i < old_mom->num_neighbors; i++) {
		neigh = old_mom->neigh[i];

		if (neigh != child) {
			data_ptr[j] = neigh;
			j++;
		}
	}

	old_mom->num_neighbors--;
	free(old_mom->neigh);
	old_mom->neigh = data_ptr;

	return _bisect_seqno_trace_neigh_add(mom, child);
}

static int
bisect_seqno_trace_check_leaves(struct bisect_seqno_trace *seqno_trace,
				struct bisect_seqno_trace_neigh *new)
{
	struct bisect_seqno_trace_neigh *tmp;
	int i, res;

	for (i = 0; i < seqno_trace->neigh.num_neighbors; i++) {
		tmp = seqno_trace->neigh.neigh[i];

		if ((tmp->seqno_ev->neigh == new->bat_node) &&
		    (tmp->seqno_ev->prev_sender == new->seqno_ev->neigh)) {
			res = bisect_seqno_trace_fix_leaf(new,
							  &seqno_trace->neigh,
							  tmp);
			if (res < 1)
				return res;

			/* restart checking procedure because we just changed
			 * the array we are working on
			 */
			return bisect_seqno_trace_check_leaves(seqno_trace,
							       new);
		}
	}

	return 1;
}

static struct bisect_seqno_trace *
bisect_seqno_trace_new(struct bisect_seqno_ev *seqno_ev)
{
	struct bisect_seqno_trace *seqno_trace;

	seqno_trace = malloc(sizeof(*seqno_trace));
	if (!seqno_trace) {
		fprintf(stderr, "Could not allocate memory for seqno tracing data (out of mem?)\n");
		return NULL;
	}

	INIT_LIST_HEAD(&seqno_trace->list);
	seqno_trace->seqno = seqno_ev->seqno;
	seqno_trace->print = 0;
	seqno_trace->neigh.num_neighbors = 0;

	return seqno_trace;
}

static void bisect_seqno_trace_free(struct bisect_seqno_trace *seqno_trace)
{
	int i;

	for (i = 0; i < seqno_trace->neigh.num_neighbors; i++)
		bisect_seqno_trace_neigh_free(seqno_trace->neigh.neigh[i]);

	free(seqno_trace);
}

static int bisect_seqno_trace_add(struct list_head_first *trace_list,
				  struct bisect_bat_node *bat_node,
				  struct bisect_seqno_ev *seqno_ev,
				  char print_trace)
{
	struct bisect_seqno_trace *trace = NULL, *trace_tmp = NULL;
	struct bisect_seqno_trace *trace_prev = NULL, *tmp_prev, *tmp_next;
	struct bisect_seqno_trace_neigh *neigh;

	list_for_each_entry(trace_tmp, trace_list, list) {
		if (trace_tmp->seqno == seqno_ev->seqno) {
			trace = trace_tmp;
			break;
		}

		if (trace_tmp->seqno > seqno_ev->seqno)
			break;

		trace_prev = trace_tmp;
	}

	if (!trace) {
		trace = bisect_seqno_trace_new(seqno_ev);
		if (!trace)
			goto err;

		tmp_prev = (struct bisect_seqno_trace *)trace_list->prev;
		tmp_next = (struct bisect_seqno_trace *)trace_list->next;
		if ((list_empty(trace_list)) ||
		    (seqno_ev->seqno > tmp_prev->seqno))
			list_add_tail(&trace->list, trace_list);
		else if (seqno_ev->seqno < tmp_next->seqno)
			list_add_before((struct list_head *)trace_list,
					trace_list->next, &trace->list);
		else
			list_add_before(&trace_prev->list, &trace_tmp->list,
					&trace->list);
	}

	if (print_trace)
		trace->print = print_trace;

	neigh = bisect_seqno_trace_find_neigh(seqno_ev->neigh,
					      seqno_ev->prev_sender,
					      &trace->neigh);

	/* no neighbor found to hook up to - adding new root node */
	if (!neigh)
		neigh = bisect_seqno_trace_neigh_add(&trace->neigh,
						     bat_node, seqno_ev);
	else
		neigh = bisect_seqno_trace_neigh_add(neigh, bat_node,
						     seqno_ev);

	if (neigh)
		bisect_seqno_trace_check_leaves(trace, neigh);

	return 1;

err:
	return 0;
}

void bisect_trace_seqnos(char *trace_orig, long long seqno_min,
			 long long seqno_max, char *filter_orig, int read_opt)
{
	struct bisect_bat_node *bat_node;
	struct bisect_orig_ev *orig_ev;
	struct bisect_seqno_ev *seqno_ev;
	struct hash_it_t *hashit = NULL;
	struct list_head_first trace_list;
	struct bisect_seqno_trace *seqno_trace, *seqno_trace_tmp;
	char check_orig[NAME_LEN], print_trace;
	int res;

	/* if no option was given filter_orig is empty */
	memset(check_orig, 0, NAME_LEN);
	INIT_LIST_HEAD_FIRST(trace_list);

	while (NULL != (hashit = hash_iterate(node_hash, hashit))) {
		bat_node = hashit->bucket->data;

		list_for_each_entry(orig_ev, &bat_node->orig_ev_list, list) {

			/* we might have no log file from this node */
			if (list_empty(&orig_ev->ev_list))
				continue;

			list_for_each_entry(seqno_ev,
					    &orig_ev->ev_list, list) {
				/* special seqno that indicates an originator
				 * timeout
				 */
				if (seqno_ev->seqno == -1)
					continue;

				if (!bisect_compare_name(trace_orig,
							 seqno_ev->orig->name))
					continue;

				if ((seqno_min != -1) &&
				    (seqno_ev->seqno < seqno_min))
					continue;

				if ((seqno_max != -1) &&
				    (seqno_ev->seqno > seqno_max))
					continue;

				/* if no filter option was given all seqno
				 * traces are to be printed
				 */
				print_trace = bisect_compare_name(filter_orig,
								  check_orig);

				if (!bisect_compare_name(filter_orig,
							 check_orig) &&
				    bisect_compare_name(filter_orig,
							bat_node->name))
					print_trace = 1;

				res = bisect_seqno_trace_add(&trace_list,
							     bat_node,
							     seqno_ev,
							     print_trace);
				if (res < 1)
					goto out;
			}
		}
	}

	bisect_seqno_trace_print(&trace_list, trace_orig, seqno_min, seqno_max,
				 filter_orig, read_opt);

out:
	list_for_each_entry_safe(seqno_trace, seqno_trace_tmp, &trace_list,
				 list) {
		list_del((struct list_head *)&trace_list, &seqno_trace->list,
			 &trace_list);
		bisect_seqno_trace_free(seqno_trace);
	}

	return;
}

int bisect_hash_init()
{
	node_hash = hash_new(64, bisect_compare_name, bisect_choose_name);
	if (node_hash == NULL)
		return -1;

	return 0;
}

void bisect_hash_free()
{
	if (node_hash)
		hash_delete(node_hash, bisect_node_free);
}
