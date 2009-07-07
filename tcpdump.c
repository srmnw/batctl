/* Copyright (C) 2007-2009 B.A.T.M.A.N. contributors:
 * Andreas Langer <a.langer@q-dsl.de>
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/if_ether.h>

#include "main.h"
#include "tcpdump.h"
#include "packet.h"
#include "bat-hosts.h"


void tcpdump_usage(void)
{
	printf("Usage: batctl tcpdump [options] interface [interface]\n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't convert addesses to bat-host names\n");
	printf(" \t -p dump specific packet type\n");
	printf(" \t\t%d - batman ogm packets\n", DUMP_TYPE_BATOGM);
	printf(" \t\t%d - batman icmp packets\n", DUMP_TYPE_BATICMP);
	printf(" \t\t%d - batman unicast packets\n", DUMP_TYPE_BATUCAST);
	printf(" \t\t%d - batman broadcast packets\n", DUMP_TYPE_BATBCAST);
	printf(" \t\t%d - batman vis packets\n", DUMP_TYPE_BATVIS);
	printf(" \t\t%d - non batman packets\n", DUMP_TYPE_NONBAT);
	printf(" \t\t%d - batman ogm & non batman packets\n", DUMP_TYPE_BATOGM | DUMP_TYPE_NONBAT);
	printf(" \t -v verbose\n");
}

void print_time(void)
{
	struct timeval tv;
	struct tm *tm;

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);

	printf("%02d:%02d:%02d.%06ld ", tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
}

int dump_arp(unsigned char *packet_buff, ssize_t buff_len)
{
	if ((size_t)buff_len < sizeof(struct ether_arp)) {
		printf("Warning - dropping received ARP packet as it is smaller than expected (%zd): %zd\n",
			sizeof(struct ether_arp), (size_t)buff_len);
		return -1;
	}

	print_time();
	struct ether_arp *arphdr = (struct ether_arp *)packet_buff;

	switch (ntohs(arphdr->arp_op)) {
	case ARPOP_REQUEST:
		printf("ARP, Request who-has %s", inet_ntoa(*(struct in_addr *)&arphdr->arp_tpa));
		printf(" tell %s, length %zd\n", inet_ntoa(*(struct in_addr *)&arphdr->arp_spa), buff_len);
		break;
	case ARPOP_REPLY:
		printf("ARP, Reply %s is-at %s, length %zd\n", inet_ntoa(*(struct in_addr *)&arphdr->arp_spa),
			ether_ntoa((struct ether_addr *)&arphdr->arp_sha), buff_len);
		break;
	default:
		printf("ARP, unknown op code: %i\n", ntohs(arphdr->arp_op));
	}

	return 1;
}

// void print_ether(unsigned char *buff) {
//
// 	struct ether_header *eth = (struct ether_header*)buff;
// 	struct bat_host *bat_host;
// 	struct tm *tm;
// 	time_t tnow;
//
// 	char *name_shost = NULL, *name_dhost = NULL;
//
// 	/* get localtime */
// 	time( &tnow );
// 	tm = localtime(&tnow);
//
// 	if (print_names) {
//
// 		bat_host = bat_hosts_find_by_mac((char *)eth->ether_shost);
//
// 		if (bat_host)
// 			name_shost = bat_host->name;
//
// 		bat_host = bat_hosts_find_by_mac((char *)eth->ether_dhost);
//
// 		if (bat_host)
// 			name_dhost = bat_host->name;
//
// 	}
//
// 	printf("%02d:%02d:%02d ", tm->tm_hour, tm->tm_min, tm->tm_sec );
//
// 	if (!name_shost)
// 		name_shost = ether_ntoa((struct ether_addr *)eth->ether_shost);
//
// 	printf("%s -> ", name_shost );
//
// 	if (!name_dhost)
// 		name_dhost = ether_ntoa((struct ether_addr *)eth->ether_dhost);
//
// 	printf("%s ", name_dhost );
//
// 	return;
// }

void dump_batman_ogm(unsigned char *packet_buff, ssize_t buff_len)
{
// 	struct batman_packet *bp = (struct batman_packet *)buff;
// 	struct bat_host *bat_host;
// 	char *name_orig = NULL, *name_old_orig=NULL;
//
// 	if (print_names) {
//
// 		bat_host = bat_hosts_find_by_mac((char *)bp->orig);
// 		if (bat_host)
// 			name_orig = bat_host->name;
//
// 		bat_host = bat_hosts_find_by_mac((char *)bp->old_orig);
// 		if (bat_host)
// 			name_old_orig = bat_host->name;
//
// 	}
//
// 	if (!name_orig)
// 		name_orig = ether_ntoa((struct ether_addr*) bp->orig);
//
// 	printf("BAT %s ", name_orig);
//
// 	if (!name_old_orig)
// 		name_old_orig = ether_ntoa((struct ether_addr*) bp->old_orig);
//
// 	printf("%s (seqno %d, tq %d, TTL %d, V %d, UD %d, DL %d)\n", name_old_orig, ntohs(bp->seqno), bp->tq,
// 	       bp->ttl, bp->version, (bp->flags & UNIDIRECTIONAL ? 1 : 0), (bp->flags & DIRECTLINK ? 1 : 0));

	return;
}

void dump_batman_icmp(unsigned char *packet_buff, ssize_t buff_len)
{
// 	struct icmp_packet *ip = (struct icmp_packet *)buff;
// 	struct bat_host *bat_host;
// 	char *name_orig = NULL, *name_dst=NULL;
//
// 	if (print_names) {
//
// 		bat_host = bat_hosts_find_by_mac((char *)ip->orig);
//
// 		if (bat_host)
// 			name_orig = bat_host->name;
//
// 		bat_host = bat_hosts_find_by_mac((char *)ip->dst);
//
// 		if (bat_host)
// 			name_dst = bat_host->name;
//
// 	}
//
// 	if (!name_orig)
// 		name_orig = ether_ntoa((struct ether_addr*) ip->orig);
//
// 	printf("BAT_ICMP %s", name_orig );
//
// 	switch( ip->msg_type ) {
// 		case ECHO_REPLY:
// 			printf(" ECHO_REP");
// 			break;
// 		case DESTINATION_UNREACHABLE:
// 			printf(" UNREACH");
// 			break;
// 		case ECHO_REQUEST:
// 			printf(" ECHO_REQ");
// 			break;
// 		case TTL_EXCEEDED:
// 			printf(" TTL_EXC");
// 			break;
// 		default:
// 			printf("unknown");
// 	}
//
// 	if (!name_dst)
// 		name_dst = ether_ntoa((struct ether_addr*) ip->dst);
//
// 	printf(" %s\n", name_dst );
// 	return;
}

void dump_batman_ucast(unsigned char *packet_buff, ssize_t buff_len)
{
// 	struct ether_header *eth1 = (struct ether_header*) ( buff + sizeof( struct unicast_packet) );
//
// 	if( ntohs( eth1->ether_type ) == ETH_P_IP ) {
// 		struct ip *ip = (struct ip*) ( buff + ( sizeof(struct ether_header) ) + sizeof(struct unicast_packet ) );
// 		printf("BAT_UNI IP V%u %s -> ", ip->ip_v, inet_ntoa( ip->ip_src) );
// 		printf("%s ", inet_ntoa( ip->ip_dst ) );
// 		switch( ip->ip_p ) {
// 			case ICMP:
// 				printf("ICMP\n");
// 				break;
// 			case TCP:
// 				printf("TCP\n");
// 				break;
// 			case UDP:
// 				printf("UDP\n");
// 				break;
// 			default:
// 				printf("unknown IP protocol\n");
// 		}
// 	} else if( ntohs( eth1->ether_type ) == ETH_P_ARP ) {
// 		printf("BAT_UNI ");
// 		print_arp(buff + sizeof( struct unicast_packet ) + sizeof( struct ether_header ));
// 	} else {
// 		printf("BAT_UNI unknow ether type %x\n", ntohs( eth1->ether_type ) );
// 	}
}

// void print_packet(int length, unsigned char *buf)
// {
// 	int i = 0;
// 	printf("\n");
// 	for( ; i < length; i++ ) {
// 		if( i == 0 )
// 			printf("0000| ");
//
// 		if( i != 0 && i%8 == 0 )
// 			printf("  ");
// 		if( i != 0 && i%16 == 0 )
// 			printf("\n%04d| ", i/16*10);
//
// 		printf("%02x ", buf[i] );
// 	}
// 	printf("\n\n");
// 	return;
// }

void dump_batman_bcast(unsigned char *packet_buff, ssize_t buff_len)
{
// 	struct bcast_packet *bc = (struct bcast_packet*)buff;
// 	struct bat_host *bat_host;
// 	char *name_orig = NULL;
//
// 	if (print_names) {
// 		bat_host = bat_hosts_find_by_mac((char *)bc->orig);
// 		if (bat_host)
// 			name_orig = bat_host->name;
// 	}
//
// 	if(!name_orig)
// 		name_orig = ether_ntoa((struct ether_addr*) bc->orig);
//
// 	printf("BAT_BCAST %s", name_orig );
//
//
// 	if( ntohs(((struct ether_header*)(buff + sizeof( struct bcast_packet )))->ether_type) == ETH_P_ARP )
// 		print_arp( buff + sizeof( struct bcast_packet ) + sizeof( struct ether_header ));
// // 		if( verbose ) {
// // 			printf("\n\tether source = %s",ether_ntoa( (struct ether_addr *) eth->ether_shost ) );
// // 			printf(" ether dest. = %s", ether_ntoa( (struct ether_addr *)eth->ether_dhost ) );
// // 			printf("\n\tsender = %s %u.%u.%u.%u\n\ttarget = %s %u.%u.%u.%u\n", ether_ntoa((struct ether_addr*) arp->ar_sha ),arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3],
// // 			 ether_ntoa((struct ether_addr*) arp->ar_tha ),arp->ar_tip[0], arp->ar_tip[1], arp->ar_tip[2], arp->ar_tip[3]);
// // 		} else
// 			printf("\n");

}

int tcpdump(int argc, char **argv)
{
	struct ifreq req;
	struct timeval tv;
	struct dump_if *dump_if;
	struct list_head *list_pos;
	struct batman_packet *batman_packet;
	struct list_head_first dump_if_list;
	fd_set wait_sockets, tmp_wait_sockets;
	ssize_t read_len;
	int ret = EXIT_FAILURE, res, optchar, found_args = 1, max_sock = 0, ether_type, tmp;
	unsigned char dump_level = DUMP_TYPE_BATOGM | DUMP_TYPE_BATICMP |
		DUMP_TYPE_BATUCAST | DUMP_TYPE_BATBCAST | DUMP_TYPE_BATVIS | DUMP_TYPE_NONBAT;
	unsigned char use_bat_hosts = 1, verbose = 0, packet_buff[2000];

	while ((optchar = getopt(argc, argv, "vnp:h")) != -1) {
		switch (optchar) {
		case 'h':
			tcpdump_usage();
			return EXIT_SUCCESS;
		case 'v':
			verbose = 1;
			found_args += 1;
			break;
		case 'n':
			use_bat_hosts = 0;
			found_args +=1;
			break;
		case 'p':
			tmp = strtol(optarg, NULL , 10);
			if ((tmp > 0) && (tmp <= dump_level))
				dump_level = tmp;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		default:
			tcpdump_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc <= found_args) {
		printf("Error - target interface not specified\n");
		tcpdump_usage();
		return EXIT_FAILURE;
	}

	bat_hosts_init();

	/* init interfaces list */
	INIT_LIST_HEAD_FIRST(dump_if_list);
	FD_ZERO(&wait_sockets);

	while (argc > found_args) {

		dump_if = malloc(sizeof(struct dump_if));
		memset(dump_if, 0, sizeof(struct dump_if));
		INIT_LIST_HEAD(&dump_if->list);

		dump_if->dev = argv[found_args];

		if (strlen(dump_if->dev) > IFNAMSIZ - 1) {
			printf("Error - interface name too long: %s\n", dump_if->dev);
			goto out;
		}

		dump_if->raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

		if (dump_if->raw_sock < 0) {
			printf("Error - can't create raw socket: %s\n", strerror(errno));
			goto out;
		}

		memset(&req, 0, sizeof (struct ifreq));
		strncpy(req.ifr_name, dump_if->dev, IFNAMSIZ);

		res = ioctl(dump_if->raw_sock, SIOCGIFINDEX, &req);

		if (res < 0) {
			printf("Error - can't create raw socket (SIOCGIFINDEX): %s\n", strerror(errno));
			close(dump_if->raw_sock);
			goto out;
		}

		dump_if->addr.sll_family   = AF_PACKET;
		dump_if->addr.sll_protocol = htons(ETH_P_ALL);
		dump_if->addr.sll_ifindex  = req.ifr_ifindex;

		res = bind(dump_if->raw_sock, (struct sockaddr *)&dump_if->addr, sizeof(struct sockaddr_ll));

		if (res < 0) {
			printf("Error - can't bind raw socket: %s\n", strerror(errno));
			close(dump_if->raw_sock);
			goto out;
		}

		if (dump_if->raw_sock > max_sock)
			max_sock = dump_if->raw_sock;

		FD_SET(dump_if->raw_sock, &wait_sockets);
		list_add_tail(&dump_if->list, &dump_if_list);
		found_args++;
	}

	while (1) {

		memcpy(&tmp_wait_sockets, &wait_sockets, sizeof(fd_set));

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		res = select(max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv);

		if (res == 0)
			continue;

		if (res < 0) {
			printf("Error - can't select on raw socket: %s\n", strerror(errno));
			continue;
		}

		list_for_each(list_pos, &dump_if_list) {

			dump_if = list_entry(list_pos, struct dump_if, list);

			if (!FD_ISSET(dump_if->raw_sock, &tmp_wait_sockets))
				continue;

			read_len = read(dump_if->raw_sock, packet_buff, sizeof(packet_buff));

			if (read_len < 0) {
				printf("Error - can't read from interface '%s': %s\n", dump_if->dev, strerror(errno));
				continue;
			}

			if ((size_t)read_len < sizeof(struct ether_header)) {
				printf("Warning - dropping received packet as it is smaller than expected (%zd): %zd\n",
					sizeof(struct ether_header), read_len);
				continue;
			}

			ether_type = ntohs(((struct ether_header *)packet_buff)->ether_type);

			switch (ether_type) {
			case ETH_P_ARP:
				if (dump_level & DUMP_TYPE_NONBAT)
					dump_arp(packet_buff + sizeof(struct ether_header), read_len - sizeof(struct ether_header));
				break;

// 			case ETH_P_IP:
// 				printf("ip comming soon\n");
// 				break;

			case ETH_P_BATMAN:
				batman_packet = (struct batman_packet *)(packet_buff + sizeof(struct ether_header));

				switch (batman_packet->packet_type) {
				case BAT_PACKET:
					if (dump_level & DUMP_TYPE_BATOGM)
						dump_batman_ogm(packet_buff, read_len);
					break;
				case BAT_ICMP:
					if (dump_level & DUMP_TYPE_BATICMP)
						dump_batman_icmp(packet_buff, read_len);
					break;
				case BAT_UNICAST:
					if (dump_level & DUMP_TYPE_BATUCAST)
						dump_batman_ucast(packet_buff, read_len);
					break;
				case BAT_BCAST:
					if (dump_level & DUMP_TYPE_BATBCAST)
						dump_batman_bcast(packet_buff, read_len);
					break;
				case BAT_VIS:
					if (dump_level & DUMP_TYPE_BATVIS)
						printf("Warning - batman vis packet received: function not implemented yet\n");
					break;
				}

				break;
			}

			fflush(stdout);
		}

	}

	ret = EXIT_SUCCESS;

out:
	list_for_each(list_pos, &dump_if_list) {
		dump_if = list_entry(list_pos, struct dump_if, list);
		close(dump_if->raw_sock);
	}

	bat_hosts_free();
	return ret;
}
