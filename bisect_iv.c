/*
 * Copyright (C) 2009-2013 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <lindner_marek@yahoo.de>
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
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "main.h"
#include "bisect.h"
#include "bisect_common.h"
#include "bat-hosts.h"
#include "hash.h"
#include "functions.h"

static void bisect_iv_usage(void)
{
	fprintf(stderr, "Usage: batctl bisect_iv [parameters] <file1> <file2> .. <fileN>\n");
	fprintf(stderr, "parameters:\n");
	fprintf(stderr, " \t -h print this help\n");
	fprintf(stderr, " \t -l run a loop detection of given mac address or bat-host (default)\n");
	fprintf(stderr, " \t -n don't convert addresses to bat-host names\n");
	fprintf(stderr, " \t -o only display orig events that affect given mac address or bat-host\n");
	fprintf(stderr, " \t -r print routing tables of given mac address or bat-host\n");
	fprintf(stderr, " \t -s seqno range to limit the output\n");
	fprintf(stderr, " \t -t trace seqnos of given mac address or bat-host\n");
}

static int bisect_iv_parse_log_file(char *file_path)
{
	FILE *fd;
	char line_buff[MAX_LINE], *start_ptr, *start_ptr_safe, *tok_ptr;
	char *neigh, *iface_addr, *orig, *prev_sender, rt_flag;
	int line_count = 0, tq, ttl, i, res, max;
	long long seqno;

	fd = fopen(file_path, "r");

	if (!fd) {
		fprintf(stderr, "Error - could not open file '%s': %s\n", file_path, strerror(errno));
		return 0;
	}

	while (fgets(line_buff, sizeof(line_buff), fd) != NULL) {
		/* ignore the timestamp at the beginning of each line */
		start_ptr = line_buff + 13;
		line_count++;

		if (strstr(start_ptr, "Received BATMAN packet via NB")) {
			strtok_r(start_ptr, " ", &start_ptr_safe);
			neigh = iface_addr = orig = prev_sender = NULL;
			seqno = tq = ttl = -1;

			for (i = 0; i < 21; i++) {
				tok_ptr = strtok_r(NULL, " ", &start_ptr_safe);
				if (!tok_ptr)
					break;

				switch (i) {
				case 4:
					neigh = tok_ptr;
					neigh[strlen(neigh) - 1] = 0;
					break;
				case 7:
					iface_addr = tok_ptr + 1;
					iface_addr[strlen(iface_addr) - 1] = 0;
					break;
				case 10:
					orig = tok_ptr;
					orig[strlen(orig) - 1] = 0;
					break;
				case 14:
					prev_sender = tok_ptr;
					prev_sender[strlen(prev_sender) - 1] = 0;
					break;
				case 16:
					seqno = strtoll(tok_ptr, NULL, 10);
					break;
				case 18:
					tq = strtol(tok_ptr, NULL, 10);
					break;
				case 20:
					ttl = strtol(tok_ptr, NULL, 10);
					break;
				}
			}

			if (ttl ==  -1) {
				fprintf(stderr, "Broken 'received packet' line found - skipping [file: %s, line: %i]\n", file_path, line_count);
				continue;
			}

// 			fprintf(stderr, "received packet  (line %i): neigh: '%s', iface_addr: '%s', orig: '%s', prev_sender: '%s', seqno: %i, tq: %i, ttl: %i\n", line_count, neigh, iface_addr, orig, prev_sender, seqno, tq, ttl);

			res = bisect_seqno_event_new(iface_addr, orig,
						     prev_sender, neigh, seqno,
						     tq, ttl);
			if (res < 1)
				fprintf(stderr, " [file: %s, line: %i]\n", file_path, line_count);

		} else if (strstr(start_ptr, "Adding route towards") ||
			   strstr(start_ptr, "Changing route towards") ||
			   strstr(start_ptr, "Deleting route towards")) {

			rt_flag = RT_FLAG_UPDATE;
			max = 12;

			if (strstr(start_ptr, "Adding route towards")) {
				rt_flag = RT_FLAG_ADD;
				max = 5;
			} else if (strstr(start_ptr, "Deleting route towards")) {
				rt_flag = RT_FLAG_DELETE;
				max = 3;
			}

			strtok_r(start_ptr, " ", &start_ptr_safe);
			orig = neigh = prev_sender = NULL;

			for (i = 0; i < max; i++) {
				tok_ptr = strtok_r(NULL, " ", &start_ptr_safe);
				if (!tok_ptr)
					break;

				switch (i) {
				case 2:
					orig = tok_ptr;
					if (rt_flag == RT_FLAG_DELETE)
						orig[strlen(orig) - 1] = 0;
					break;
				case 4:
					if (rt_flag == RT_FLAG_ADD) {
						neigh = tok_ptr;
						neigh[strlen(neigh) - 2] = 0;
					}
					break;
				case 5:
					neigh = tok_ptr;
					break;
				case 9:
					prev_sender = tok_ptr;
					prev_sender[strlen(prev_sender) - 2] = 0;
					break;
				}
			}

// 			printf("route (file: %s, line %i): orig: '%s', neigh: '%s', prev_sender: '%s'\n",
// 			       file_path, line_count, orig, neigh, prev_sender);

			if (((rt_flag == RT_FLAG_ADD) && (!neigh)) ||
			    ((rt_flag == RT_FLAG_UPDATE) && (!prev_sender)) ||
			    ((rt_flag == RT_FLAG_DELETE) && (!orig))) {
				fprintf(stderr, "Broken '%s route' line found - skipping [file: %s, line: %i]\n",
				        (rt_flag == RT_FLAG_UPDATE ? "changing" :
				        (rt_flag == RT_FLAG_ADD ? "adding" : "deleting")),
				        file_path, line_count);
				continue;
			}

			res = bisect_routing_table_new(orig, neigh, prev_sender,
						       rt_flag);
			if (res < 1)
				fprintf(stderr, " [file: %s, line: %i]\n", file_path, line_count);
		}
	}

// 	printf("File '%s' parsed (lines: %i)\n", file_path, line_count);
	fclose(fd);
	return 1;
}

int bisect_iv(int argc, char **argv)
{
	int ret = EXIT_FAILURE, res, optchar, found_args = 1;
	int read_opt = USE_BAT_HOSTS, num_parsed_files;
	long long tmp_seqno, seqno_max = -1, seqno_min = -1;
	char *trace_orig_ptr = NULL, *rt_orig_ptr = NULL, *loop_orig_ptr = NULL;
	char orig[NAME_LEN], filter_orig[NAME_LEN], *dash_ptr, *filter_orig_ptr = NULL;

	memset(orig, 0, NAME_LEN);
	memset(filter_orig, 0, NAME_LEN);

	while ((optchar = getopt(argc, argv, "hl:no:r:s:t:")) != -1) {
		switch (optchar) {
		case 'h':
			bisect_iv_usage();
			return EXIT_SUCCESS;
		case 'l':
			loop_orig_ptr = optarg;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			found_args += 1;
			break;
		case 'o':
			filter_orig_ptr = optarg;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		case 'r':
			rt_orig_ptr = optarg;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		case 's':
			dash_ptr = strchr(optarg, '-');
			if (dash_ptr)
				*dash_ptr = 0;

			tmp_seqno = strtol(optarg, NULL , 10);
			if ((tmp_seqno >= 0) && (tmp_seqno <= UINT32_MAX))
				seqno_min = tmp_seqno;
			else
				fprintf(stderr, "Warning - given sequence number is out of range: %lli\n", tmp_seqno);

			if (dash_ptr) {
				tmp_seqno = strtol(dash_ptr + 1, NULL , 10);
				if ((tmp_seqno >= 0) && (tmp_seqno <= UINT32_MAX))
					seqno_max = tmp_seqno;
				else
					fprintf(stderr, "Warning - given sequence number is out of range: %lli\n", tmp_seqno);

				*dash_ptr = '-';
			}

			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		case 't':
			trace_orig_ptr = optarg;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		default:
			bisect_iv_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc <= found_args + 1) {
		fprintf(stderr, "Error - need at least 2 log files to compare\n");
		bisect_iv_usage();
		goto err;
	}

	if (bisect_hash_init()) {
		fprintf(stderr, "Error - could not create node hash table\n");
		goto err;
	}

	bat_hosts_init(read_opt);
	num_parsed_files = 0;

	if ((rt_orig_ptr) && (trace_orig_ptr)) {
		fprintf(stderr, "Error - the 'print routing table' option can't be used together with the 'trace seqno' option\n");
		goto err;
	} else if ((loop_orig_ptr) && (trace_orig_ptr)) {
		fprintf(stderr, "Error - the 'loop detection' option can't be used together with the 'trace seqno' option\n");
		goto err;
	} else if ((loop_orig_ptr) && (rt_orig_ptr)) {
		fprintf(stderr, "Error - the 'loop detection' option can't be used together with the 'print routing table' option\n");
		goto err;
	} else if (rt_orig_ptr) {
		res = bisect_get_orig_addr(rt_orig_ptr, orig);

		if (res < 1)
			goto err;
	} else if (trace_orig_ptr) {
		res = bisect_get_orig_addr(trace_orig_ptr, orig);

		if (res < 1)
			goto err;
	} else if (loop_orig_ptr) {
		res = bisect_get_orig_addr(loop_orig_ptr, orig);

		if (res < 1)
			goto err;
	}

	/* we search a specific seqno - no range */
	if ((seqno_min > 0) && (seqno_max == -1))
		seqno_max = seqno_min;

	if (seqno_min > seqno_max) {
		fprintf(stderr, "Error - the sequence range minimum (%lli) should be smaller than the maximum (%lli)\n",
		       seqno_min, seqno_max);
		goto err;
	}

	if (filter_orig_ptr) {
		res = bisect_get_orig_addr(filter_orig_ptr, filter_orig);

		if (res < 1)
			goto err;
	}

	while (argc > found_args) {
		res = bisect_iv_parse_log_file(argv[found_args]);

		if (res > 0)
			num_parsed_files++;

		found_args++;
	}

	if (num_parsed_files < 2) {
		fprintf(stderr, "Error - need at least 2 log files to compare\n");
		goto err;
	}

	if (trace_orig_ptr)
		bisect_trace_seqnos(orig, seqno_min, seqno_max, filter_orig,
				    read_opt);
	else if (rt_orig_ptr)
		bisect_print_rt(orig, seqno_min, seqno_max, filter_orig,
				read_opt);
	else
		bisect_loop_detection(orig, seqno_min, seqno_max, filter_orig,
				      read_opt);

	ret = EXIT_SUCCESS;

err:
	bisect_hash_free();
	bat_hosts_free();
	return ret;
}
