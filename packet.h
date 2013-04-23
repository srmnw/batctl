/* Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
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
 */

#ifndef _NET_BATMAN_ADV_PACKET_H_
#define _NET_BATMAN_ADV_PACKET_H_

/**
 * enum batadv_packettype - types for batman-adv encapsulated packets
 * @BATADV_UNICAST_TVLV: unicast packet carrying TVLV containers
 */
enum batadv_packettype {
	BATADV_IV_OGM		= 0x01,
	BATADV_ICMP		= 0x02,
	BATADV_UNICAST		= 0x03,
	BATADV_BCAST		= 0x04,
	BATADV_VIS		= 0x05,
	BATADV_UNICAST_FRAG	= 0x06,
	BATADV_UNICAST_4ADDR	= 0x09,
	BATADV_CODED		= 0x0a,
	BATADV_UNICAST_TVLV	= 0x0b,
};

/**
 * enum batadv_subtype - packet subtype for unicast4addr
 * @BATADV_P_DATA: user payload
 * @BATADV_P_DAT_DHT_GET: DHT request message
 * @BATADV_P_DAT_DHT_PUT: DHT store message
 * @BATADV_P_DAT_CACHE_REPLY: ARP reply generated by DAT
 */
enum batadv_subtype {
	BATADV_P_DATA			= 0x01,
	BATADV_P_DAT_DHT_GET		= 0x02,
	BATADV_P_DAT_DHT_PUT		= 0x03,
	BATADV_P_DAT_CACHE_REPLY	= 0x04,
};

/* this file is included by batctl which needs these defines */
#define BATADV_COMPAT_VERSION 15

enum batadv_iv_flags {
	BATADV_NOT_BEST_NEXT_HOP   = BIT(3),
	BATADV_PRIMARIES_FIRST_HOP = BIT(4),
	BATADV_VIS_SERVER	   = BIT(5),
	BATADV_DIRECTLINK	   = BIT(6),
};

/* ICMP message types */
enum batadv_icmp_packettype {
	BATADV_ECHO_REPLY	       = 0,
	BATADV_DESTINATION_UNREACHABLE = 3,
	BATADV_ECHO_REQUEST	       = 8,
	BATADV_TTL_EXCEEDED	       = 11,
	BATADV_PARAMETER_PROBLEM       = 12,
};

/* vis defines */
enum batadv_vis_packettype {
	BATADV_VIS_TYPE_SERVER_SYNC   = 0,
	BATADV_VIS_TYPE_CLIENT_UPDATE = 1,
};

/* fragmentation defines */
enum batadv_unicast_frag_flags {
	BATADV_UNI_FRAG_HEAD	  = BIT(0),
	BATADV_UNI_FRAG_LARGETAIL = BIT(1),
};

/* tt data subtypes */
#define BATADV_TT_DATA_TYPE_MASK 0x0F

/**
 * enum batadv_tt_data_flags - flags for tt data tvlv
 * @BATADV_TT_OGM_DIFF: TT diff propagated through OGM
 * @BATADV_TT_REQUEST: TT request message
 * @BATADV_TT_RESPONSE: TT response message
 * @BATADV_TT_FULL_TABLE: contains full table to replace existing table
 */
enum batadv_tt_data_flags {
	BATADV_TT_OGM_DIFF   = BIT(0),
	BATADV_TT_REQUEST    = BIT(1),
	BATADV_TT_RESPONSE   = BIT(2),
	BATADV_TT_FULL_TABLE = BIT(4),
};

/* BATADV_TT_CLIENT flags.
 * Flags from BIT(0) to BIT(7) are sent on the wire, while flags from BIT(8) to
 * BIT(15) are used for local computation only
 */
enum batadv_tt_client_flags {
	BATADV_TT_CLIENT_DEL     = BIT(0),
	BATADV_TT_CLIENT_ROAM    = BIT(1),
	BATADV_TT_CLIENT_WIFI    = BIT(2),
	BATADV_TT_CLIENT_TEMP	 = BIT(3),
	BATADV_TT_CLIENT_NOPURGE = BIT(8),
	BATADV_TT_CLIENT_NEW     = BIT(9),
	BATADV_TT_CLIENT_PENDING = BIT(10),
};

/* claim frame types for the bridge loop avoidance */
enum batadv_bla_claimframe {
	BATADV_CLAIM_TYPE_CLAIM		= 0x00,
	BATADV_CLAIM_TYPE_UNCLAIM	= 0x01,
	BATADV_CLAIM_TYPE_ANNOUNCE	= 0x02,
	BATADV_CLAIM_TYPE_REQUEST	= 0x03,
};

/**
 * enum batadv_tvlv_type - tvlv type definitions
 * @BATADV_TVLV_GW: gateway tvlv
 * @BATADV_TVLV_DAT: distributed arp table tvlv
 * @BATADV_TVLV_NC: network coding tvlv
 * @BATADV_TVLV_TT: translation table tvlv
 * @BATADV_TVLV_ROAM: roaming advertisement tvlv
 */
enum batadv_tvlv_type {
	BATADV_TVLV_GW		= 0x01,
	BATADV_TVLV_DAT		= 0x02,
	BATADV_TVLV_NC		= 0x03,
	BATADV_TVLV_TT		= 0x04,
	BATADV_TVLV_ROAM	= 0x05,
};

/* the destination hardware field in the ARP frame is used to
 * transport the claim type and the group id
 */
struct batadv_bla_claim_dst {
	uint8_t magic[3];	/* FF:43:05 */
	uint8_t type;		/* bla_claimframe */
	__be16 group;		/* group id */
};

struct batadv_header {
	uint8_t  packet_type;
	uint8_t  version;  /* batman version field */
	uint8_t  ttl;
	/* the parent struct has to add a byte after the header to make
	 * everything 4 bytes aligned again
	 */
};

/**
 * struct batadv_ogm_packet - ogm (routing protocol) packet
 * @header: common batman packet header
 * @tvlv_len: length of tvlv data following the ogm header
 */
struct batadv_ogm_packet {
	struct batadv_header header;
	uint8_t  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	__be32   seqno;
	uint8_t  orig[ETH_ALEN];
	uint8_t  prev_sender[ETH_ALEN];
	uint8_t  reserved;
	uint8_t  tq;
	__be16   tvlv_len;
} __packed;

#define BATADV_OGM_HLEN sizeof(struct batadv_ogm_packet)

struct batadv_icmp_packet {
	struct batadv_header header;
	uint8_t  msg_type; /* see ICMP message types above */
	uint8_t  dst[ETH_ALEN];
	uint8_t  orig[ETH_ALEN];
	__be16   seqno;
	uint8_t  uid;
	uint8_t  reserved;
};

#define BATADV_RR_LEN 16

/* icmp_packet_rr must start with all fields from imcp_packet
 * as this is assumed by code that handles ICMP packets
 */
struct batadv_icmp_packet_rr {
	struct batadv_header header;
	uint8_t  msg_type; /* see ICMP message types above */
	uint8_t  dst[ETH_ALEN];
	uint8_t  orig[ETH_ALEN];
	__be16   seqno;
	uint8_t  uid;
	uint8_t  rr_cur;
	uint8_t  rr[BATADV_RR_LEN][ETH_ALEN];
};

/* All packet headers in front of an ethernet header have to be completely
 * divisible by 2 but not by 4 to make the payload after the ethernet
 * header again 4 bytes boundary aligned.
 *
 * A packing of 2 is necessary to avoid extra padding at the end of the struct
 * caused by a structure member which is larger than two bytes. Otherwise
 * the structure would not fulfill the previously mentioned rule to avoid the
 * misalignment of the payload after the ethernet header. It may also lead to
 * leakage of information when the padding it not initialized before sending.
 */
#pragma pack(2)

struct batadv_unicast_packet {
	struct batadv_header header;
	uint8_t  ttvn; /* destination translation table version number */
	uint8_t  dest[ETH_ALEN];
	/* "4 bytes boundary + 2 bytes" long to make the payload after the
	 * following ethernet header again 4 bytes boundary aligned
	 */
};

/**
 * struct batadv_unicast_4addr_packet - extended unicast packet
 * @u: common unicast packet header
 * @src: address of the source
 * @subtype: packet subtype
 */
struct batadv_unicast_4addr_packet {
	struct batadv_unicast_packet u;
	uint8_t src[ETH_ALEN];
	uint8_t subtype;
	uint8_t reserved;
	/* "4 bytes boundary + 2 bytes" long to make the payload after the
	 * following ethernet header again 4 bytes boundary aligned
	 */
};

struct batadv_unicast_frag_packet {
	struct batadv_header header;
	uint8_t  ttvn; /* destination translation table version number */
	uint8_t  dest[ETH_ALEN];
	uint8_t  flags;
	uint8_t  align;
	uint8_t  orig[ETH_ALEN];
	__be16   seqno;
} __packed;

struct batadv_bcast_packet {
	struct batadv_header header;
	uint8_t  reserved;
	__be32   seqno;
	uint8_t  orig[ETH_ALEN];
	/* "4 bytes boundary + 2 bytes" long to make the payload after the
	 * following ethernet header again 4 bytes boundary aligned
	 */
};

#pragma pack()

struct batadv_vis_packet {
	struct batadv_header header;
	uint8_t  vis_type;	 /* which type of vis-participant sent this? */
	__be32   seqno;		 /* sequence number */
	uint8_t  entries;	 /* number of entries behind this struct */
	uint8_t  reserved;
	uint8_t  vis_orig[ETH_ALEN];	/* originator reporting its neighbors */
	uint8_t  target_orig[ETH_ALEN]; /* who should receive this packet */
	uint8_t  sender_orig[ETH_ALEN]; /* who sent or forwarded this packet */
};

/**
 * struct batadv_coded_packet - network coded packet
 * @header: common batman packet header and ttl of first included packet
 * @reserved: Align following fields to 2-byte boundaries
 * @first_source: original source of first included packet
 * @first_orig_dest: original destinal of first included packet
 * @first_crc: checksum of first included packet
 * @first_ttvn: tt-version number of first included packet
 * @second_ttl: ttl of second packet
 * @second_dest: second receiver of this coded packet
 * @second_source: original source of second included packet
 * @second_orig_dest: original destination of second included packet
 * @second_crc: checksum of second included packet
 * @second_ttvn: tt version number of second included packet
 * @coded_len: length of network coded part of the payload
 */
struct batadv_coded_packet {
	struct batadv_header header;
	uint8_t  first_ttvn;
	/* uint8_t  first_dest[ETH_ALEN]; - saved in mac header destination */
	uint8_t  first_source[ETH_ALEN];
	uint8_t  first_orig_dest[ETH_ALEN];
	__be32   first_crc;
	uint8_t  second_ttl;
	uint8_t  second_ttvn;
	uint8_t  second_dest[ETH_ALEN];
	uint8_t  second_source[ETH_ALEN];
	uint8_t  second_orig_dest[ETH_ALEN];
	__be32   second_crc;
	__be16   coded_len;
};

/**
 * struct batadv_unicast_tvlv - generic unicast packet with tvlv payload
 * @header: common batman packet header
 * @reserved: reserved field (for packet alignment)
 * @src: address of the source
 * @dst: address of the destination
 * @tvlv_len: length of tvlv data following the unicast tvlv header
 */
struct batadv_unicast_tvlv_packet {
	struct batadv_header header;
	uint8_t reserved;
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	__be16  tvlv_len;
};

/**
 * struct batadv_tvlv_hdr - base tvlv header struct
 * @long_tvlv: flag indicating whether this is a short tvlv container (max 256
 *  bytes) or a long tvlv one (up to ETH_DATA_LEN)
 * @type: tvlv container type (see batadv_tvlv_type)
 * @version: tvlv container version
 */
struct batadv_tvlv_hdr {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint8_t long_tvlv:1;
	uint8_t type:7;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t type:7;
	uint8_t long_tvlv:1;
#else
#error "unknown bitfield endianess"
#endif
	uint8_t version;
};

/**
 * struct batadv_tvlv_short - short tvlv header struct
 * @tvlv_hdr: base tvlv header
 * @len: tvlv container length (limited to 255 bytes)
 */
struct batadv_tvlv_short {
	struct batadv_tvlv_hdr tvlv_hdr;
	uint8_t len;
};

/**
 * struct batadv_tvlv_long - long tvlv header struct
 * @tvlv_hdr: base tvlv header
 * @len: tvlv container length
 */
struct batadv_tvlv_long {
	struct batadv_tvlv_hdr tvlv_hdr;
	__be16 len;
};

/**
 * struct batadv_tvlv_gateway_data - gateway data propagated through gw tvlv
 *  container
 * @bandwidth_down: advertised uplink download bandwidth
 * @bandwidth_up: advertised uplink upload bandwidth
 */
struct batadv_tvlv_gateway_data {
	uint32_t bandwidth_down;
	uint32_t bandwidth_up;
};

/**
 * struct tvlv_tt_data - tt data propagated through the tt tvlv container
 * @flags: translation table flags (see batadv_tt_data_flags)
 * @ttvn: translation table version number
 * @crc: crc16 checksum of the local translation table
 */
struct batadv_tvlv_tt_data {
	uint8_t flags;
	uint8_t ttvn;
	__be16  crc;
};

/**
 * struct batadv_tvlv_tt_change - translation table diff data
 * @flags: status indicators concerning the non-mesh client (see
 *  batadv_tt_client_flags)
 * @reserved: reserved field
 * @addr: mac address of non-mesh client that triggered this tt change
 */
struct batadv_tvlv_tt_change {
	uint8_t flags;
	uint8_t reserved;
	uint8_t addr[ETH_ALEN];
};

/**
 * struct batadv_tvlv_roam_adv - roaming advertisement
 * @client: mac address of roaming client
 */
struct batadv_tvlv_roam_adv {
	uint8_t client[ETH_ALEN];
};

#endif /* _NET_BATMAN_ADV_PACKET_H_ */
