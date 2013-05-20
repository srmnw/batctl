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

#include "list-batman.h"

#define NAME_LEN 18
#define MAX_LINE 256
#define LOOP_MAGIC_LEN ((2 * NAME_LEN) + (2 * sizeof(int)) - 2)

#define RT_FLAG_ADD 1
#define RT_FLAG_UPDATE 2
#define RT_FLAG_DELETE 3

struct bisect_bat_node {
	char name[NAME_LEN];
	struct list_head_first orig_ev_list;
	struct list_head_first rt_list;
	char loop_magic[LOOP_MAGIC_LEN];
	char loop_magic2[LOOP_MAGIC_LEN];
};

struct bisect_orig_ev {
	struct list_head list;
	struct bisect_bat_node *orig_node;
	struct list_head_first ev_list;
	struct list_head_first rt_hist_list;
};

struct bisect_rt {
	struct list_head list;
	int num_entries;
	struct bisect_rt_entry *entries;
	struct bisect_rt_hist *rt_hist;
};

struct bisect_rt_hist {
	struct list_head list;
	struct bisect_rt *rt;
	struct bisect_rt_hist *prev_rt_hist;
	struct bisect_seqno_ev *seqno_ev;
	struct bisect_bat_node *next_hop;
	char flags;
	char loop_magic[LOOP_MAGIC_LEN];
};

struct bisect_rt_entry {
	char orig[NAME_LEN];
	struct bisect_bat_node *next_hop;
	char flags;
};

struct bisect_seqno_ev {
	struct list_head list;
	struct bisect_bat_node *orig;
	struct bisect_bat_node *neigh;
	struct bisect_bat_node *prev_sender;
	long long seqno;
	int tq;
	int ttl;
	struct bisect_rt_hist *rt_hist;
};

struct bisect_seqno_trace_neigh {
	struct bisect_bat_node *bat_node;
	struct bisect_seqno_ev *seqno_ev;
	int num_neighbors;
	struct bisect_seqno_trace_neigh **neigh;
};

struct bisect_seqno_trace {
	struct list_head list;
	long long seqno;
	char print;
	struct bisect_seqno_trace_neigh neigh;
};

int bisect_seqno_event_new(char *iface_addr, char *orig, char *prev_sender,
			   char *neigh, long long seqno, int tq, int ttl);
int bisect_routing_table_new(char *orig, char *next_hop, char *old_next_hop,
			     char rt_flag);
int bisect_get_orig_addr(char *orig_name, char *orig_addr);
void bisect_trace_seqnos(char *trace_orig, long long seqno_min,
			 long long seqno_max, char *filter_orig, int read_opt);
void bisect_loop_detection(char *loop_orig, long long seqno_min,
			   long long seqno_max, char *filter_orig, int read_opt);
int bisect_hash_init();
void bisect_hash_free();
void bisect_print_rt(char *rt_orig, long long seqno_min, long long seqno_max,
		     char *filter_orig, int read_opt);
