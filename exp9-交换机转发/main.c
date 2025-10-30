#include "base.h"
#include "ether.h"
#include "mac.h"
#include "utils.h"

#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// handle packet
// 1. if the dest mac address is found in mac_port table, forward it; otherwise, 
// broadcast it.
// 2. put the src mac -> iface mapping into mac hash table.
void handle_packet(iface_info_t *rx_iface, char *packet, int len)
{
	// TODO: implement the packet forwarding process here
	//fprintf(stdout, "TODO: implement the packet forwarding process here.\n");

	struct ether_header *eh = (struct ether_header *)packet;
	u8 *src_mac = eh->ether_shost;
	u8 *dst_mac = eh->ether_dhost;

	// 学习源 MAC 地址
	insert_mac_port(src_mac, rx_iface);

	// 判断是否为广播地址
	u8 broadcast_mac[ETH_ALEN];
	memset(broadcast_mac, 0xFF, ETH_ALEN);

	if (memcmp(dst_mac, broadcast_mac, ETH_ALEN) == 0) {
		// 广播
		broadcast_packet(rx_iface, packet, len);
		free(packet);
		return;
	}

	// 单播处理
	iface_info_t *tx_iface = lookup_port(dst_mac);

	if (tx_iface && tx_iface != rx_iface) {
		// 已知单播，且目标端口不是接收端口
		iface_send_packet(tx_iface, packet, len);
	} else {
		// 未知单播 或 发回原端口，进行泛洪
		broadcast_packet(rx_iface, packet, len);
	}
	//log(DEBUG, "the dst mac address is " ETHER_STRING ".\n", ETHER_FMT(eh->ether_dhost));

	free(packet);
}

// run user stack, receive packet on each interface, and handle those packet
// like normal switch
void ustack_run()
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	char buf[ETH_FRAME_LEN];
	int len;

	while (1) {
		int ready = poll(instance->fds, instance->nifs, -1);
		if (ready < 0) {
			perror("Poll failed!");
			break;
		}
		else if (ready == 0)
			continue;

		for (int i = 0; i < instance->nifs; i++) {
			if (instance->fds[i].revents & POLLIN) {
				len = recvfrom(instance->fds[i].fd, buf, ETH_FRAME_LEN, 0, \
						(struct sockaddr*)&addr, &addr_len);
				if (len <= 0) {
					log(ERROR, "receive packet error: %s", strerror(errno));
				}
				else if (addr.sll_pkttype == PACKET_OUTGOING) {
					// XXX: Linux raw socket will capture both incoming and
					// outgoing packets, while we only care about the incoming ones.

					// log(DEBUG, "received packet which is sent from the "
					// 		"interface itself, drop it.");
				}
				else {
					iface_info_t *iface = fd_to_iface(instance->fds[i].fd);
					if (!iface) 
						continue;

					char *packet = malloc(len);
					if (!packet) {
						log(ERROR, "malloc failed when receiving packet.");
						continue;
					}
					memcpy(packet, buf, len);
					handle_packet(iface, packet, len);
				}
			}
		}
	}
}

int main(int argc, const char **argv)
{
	if (getuid() && geteuid()) {
		printf("Permission denied, should be superuser!\n");
		exit(1);
	}

	init_ustack();

	init_mac_port_table();

	ustack_run();

	return 0;
}
