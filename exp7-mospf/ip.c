#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (ip->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}

		free(packet);
	}
	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters)) {
		assert(ip->protocol == IPPROTO_MOSPF);
		handle_mospf_packet(iface, packet, len);

		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	//assert(0 && "TODO: function ip_forward_packet not implemented!");
	struct iphdr *ip = packet_to_ip_hdr(packet);
    // 首先减少 TTL（生存时间），如果 <= 1，则发送 ICMP Time Exceeded
    ip->ttl--;
    if (ip->ttl <= 0) {
        icmp_send_packet(packet,len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
        free(packet);
        return;
    }

    // 更新 IP 校验和：因为 TTL 改了，必须重新计算
    ip->checksum = 0;
    ip->checksum = ip_checksum(ip);

    // 转发数据包：使用路由表查找下一跳
    rt_entry_t *entry = longest_prefix_match(ip_dst);
    if (!entry) {
        // 如果找不到路由，说明目标不可达，发送 ICMP Host Unreachable
        log(DEBUG,"can't find route");
        icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
        free(packet);
        return;
    }else{
        ip_send_packet(packet,len);
        

    }
}
