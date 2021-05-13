/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Alexander Sarmanow <asarmanow@gmail.com>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <netlink/netlink.h>
#include <netlink/attr.h>

#include "genl_json.h"
#include "batman_adv.h"
#include "netlink.h"
#include "main.h"

static void nljson_print_str(struct nlattr *attrs[], int idx)
{
	const char *value;

	value = nla_get_string(attrs[idx]);

	putc('"', stdout);
	sanitize_string(value);
	putc('"', stdout);
}

static void nljson_print_uint8_t(struct nlattr *attrs[], int idx)
{
	uint8_t value = nla_get_u8(attrs[idx]);
	printf("%u", value);
}

static void nljson_print_uint16_t(struct nlattr *attrs[], int idx)
{
	uint16_t value = nla_get_u16(attrs[idx]);
	printf("%u", value);
}

static void nljson_print_uint32_t(struct nlattr *attrs[], int idx)
{
	uint32_t value = nla_get_u32(attrs[idx]);
	printf("%u", value);
}

static void nljson_print_uint64_t(struct nlattr *attrs[], int idx)
{
	uint64_t value = nla_get_u64(attrs[idx]);
	printf("%llu", value);
}

static void nljson_print_mac(struct nlattr *attrs[], int idx)
{
	uint8_t *value = nla_data(attrs[idx]);
	printf("\"%02x:%02x:%02x:%02x:%02x:%02x\"",
		value[0], value[1], value[2], value[3], value[4], value[5]);
}

static void nljson_print_flag(struct nlattr *attrs[], int idx)
{
	if (nla_get_flag(attrs[idx]))
		printf("true");
}

void sanitize_string(const char *str)
{
	while (*str) {
		if (*str == '"' || *str == '\\') {
			putchar('\\');
			putchar(*str);
		} else if (*str == '\\') {
			printf("\\\\");
		} else if (!isprint(*str)) {
			printf("\\x%02x", *str);
		} else {
			printf("%c", *str);
		}
		str++;
	}
}

void netlink_print_json_entries(struct nlattr *attrs[], struct json_opts *json_opts)
{
	bool first_valid_attr = true;
	int i;

	if (!json_opts->is_first)
		printf(",");

	printf("{");
	for (i = 0; i < BATADV_ATTR_MAX + 1; i++) {
		if (!attrs[i])
			continue;

		if (!batadv_netlink_policy_json[i].cb)
			continue;

		if (!first_valid_attr)
			printf(",");

		putc('"', stdout);
		sanitize_string(batadv_netlink_policy_json[i].name);
		printf("\":");
		batadv_netlink_policy_json[i].cb(attrs, i);

		first_valid_attr = false;
	}
	printf("}");
}


struct nla_policy_json batadv_netlink_policy_json[NUM_BATADV_ATTR] = {
	[BATADV_ATTR_VERSION] = {
		.name = "version",
		.cb = nljson_print_str,
	},
	[BATADV_ATTR_ALGO_NAME] = {
		.name = "algo_name",
		.cb = nljson_print_str,
	},
	[BATADV_ATTR_MESH_IFINDEX] = {
		.name = "mesh_ifindex",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_MESH_IFNAME] = {
		.name = "mesh_ifname",
		.cb = nljson_print_str,
	},
	[BATADV_ATTR_MESH_ADDRESS] = {
		.name = "mesh_address",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_HARD_IFINDEX] = {
		.name = "hard_ifindex",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_HARD_IFNAME] = {
		.name = "hard_ifname",
		.cb = nljson_print_str,
	},
	[BATADV_ATTR_HARD_ADDRESS] = {
		.name = "hard_address",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_ORIG_ADDRESS] = {
		.name = "orig_address",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_TPMETER_RESULT] = {
		.name = "tpmeter_result",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_TPMETER_TEST_TIME] = {
		.name = "tpmeter_test_time",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_TPMETER_BYTES] = {
		.name = "tpmeter_bytes",
		.cb = nljson_print_uint64_t
	},
	[BATADV_ATTR_TPMETER_COOKIE] = {
		.name = "tpmeter_cookie",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_PAD] = {
		.name = "pad",
	},
	[BATADV_ATTR_ACTIVE] = {
		.name = "active",
		.cb = nljson_print_flag,
	},
	[BATADV_ATTR_TT_ADDRESS] = {
		.name = "tt_address",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_TT_TTVN] = {
		.name = "tt_ttvn",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_TT_LAST_TTVN] = {
		.name = "last_ttvn",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_TT_CRC32] = {
		.name = "crc32",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_TT_VID] = {
		.name = "tt_vid",
		.cb = nljson_print_uint16_t,
	},
	[BATADV_ATTR_TT_FLAGS] = {
		.name = "tt_flags",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_FLAG_BEST] = {
		.name = "best",
		.cb = nljson_print_flag,
	},
	[BATADV_ATTR_LAST_SEEN_MSECS] = {
		.name = "last_seen_msecs",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_NEIGH_ADDRESS] = {
		.name = "neigh_address",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_TQ] = {
		.name = "tq",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_THROUGHPUT] = {
		.name = "throughput",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_BANDWIDTH_UP] = {
		.name = "bandwidth_up",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_BANDWIDTH_DOWN] = {
		.name = "bandwidth_down",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_ROUTER] = {
		.name = "router",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_BLA_OWN] = {
		.name = "bla_own",
		.cb = nljson_print_flag,
	},
	[BATADV_ATTR_BLA_ADDRESS] = {
		.name = "bla_address",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_BLA_VID] = {
		.name = "bla_vid",
		.cb = nljson_print_uint16_t,
	},
	[BATADV_ATTR_BLA_BACKBONE] = {
		.name = "bla_backbone",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_BLA_CRC] = {
		.name = "bla_crc",
		.cb = nljson_print_uint16_t,
	},
	[BATADV_ATTR_DAT_CACHE_IP4ADDRESS] = {
		.name = "dat_cache_ip4_address",
	},
	[BATADV_ATTR_DAT_CACHE_HWADDRESS] = {
		.name = "dat_cache_hw_address",
		.cb = nljson_print_mac,
	},
	[BATADV_ATTR_DAT_CACHE_VID] = {
		.name = "dat_cache_vid",
		.cb = nljson_print_uint16_t,
	},
	[BATADV_ATTR_MCAST_FLAGS] = {
		.name = "mcast_flags",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_MCAST_FLAGS_PRIV] = {
		.name = "mcast_flags_priv",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_VLANID] = {
		.name = "vlan_id",
		.cb = nljson_print_uint16_t,
	},
	[BATADV_ATTR_AGGREGATED_OGMS_ENABLED] = {
		.name = "aggregated_ogms_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_AP_ISOLATION_ENABLED] = {
		.name = "ap_isolation_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_ISOLATION_MARK] = {
		.name = "isolation_mark",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_ISOLATION_MASK] = {
		.name = "isolation_mask",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_BONDING_ENABLED] = {
		.name = "bonding_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED] = {
		.name = "bridge_loop_avoidance_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED] = {
		.name = "distributed_arp_table_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_FRAGMENTATION_ENABLED] = {
		.name = "fragmented_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_GW_BANDWIDTH_DOWN] = {
		.name = "bandwidth_down",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_GW_BANDWIDTH_UP] = {
		.name = "bandwidth_up",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_GW_MODE] = {
		.name = "gw_mode",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_GW_SEL_CLASS] = {
		.name = "gw_sel_class",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_HOP_PENALTY] = {
		.name = "hop_penalty",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_LOG_LEVEL] = {
		.name = "log_level",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_MULTICAST_FORCEFLOOD_ENABLED] = {
		.name = "multicast_forceflood_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_NETWORK_CODING_ENABLED] = {
		.name = "network_coding_enabled",
		.cb = nljson_print_uint8_t,
	},
	[BATADV_ATTR_ORIG_INTERVAL] = {
		.name = "orig_interval",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_ELP_INTERVAL] = {
		.name = "elp_interval",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_THROUGHPUT_OVERRIDE] = {
		.name = "throughput_override",
		.cb = nljson_print_uint32_t,
	},
	[BATADV_ATTR_MULTICAST_FANOUT] = {
		.name = "multicast_fanout",
		.cb = nljson_print_uint32_t,
	},
};
