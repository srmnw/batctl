// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Alexander Sarmanow <asarmanow@gmail.com>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <netinet/if_ether.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "batman_adv.h"
#include "debug.h"
#include "main.h"
#include "netlink.h"
#include "genl_json.h"

static int translocal_json_callback(struct nl_msg *msg, void *arg)
{
	struct nlquery_opts *query_opts = arg;
	struct json_opts *json_opts;
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *ghdr;

	json_opts = container_of(query_opts, struct json_opts, query_opts);

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_LOCAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	netlink_print_json_entries(attrs, json_opts);
	json_opts->is_first = 0;

	return NL_OK;
}

static int netlink_print_translocal_json(struct state *state)
{
	int ret;
	struct json_opts json_opts = {
		.is_first = 1,
		.query_opts = {
			.err = 0,
		},
	};

	putc('[', stdout);
	ret = netlink_query_common(state, state->mesh_ifindex,
				   BATADV_CMD_GET_TRANSTABLE_LOCAL,
				   translocal_json_callback,
				   NLM_F_DUMP, &json_opts.query_opts);
	puts("]\n");

	return ret;
}

static struct debug_json_data batctl_debug_json_translocal = {
	.netlink_fn = netlink_print_translocal_json,
};

COMMAND_NAMED(DEBUGJSON, translocal_json, "tlj", handle_debug_json,
	      COMMAND_FLAG_MESH_IFACE | COMMAND_FLAG_NETLINK,
	      &batctl_debug_json_translocal, "");
