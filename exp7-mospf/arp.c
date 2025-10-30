#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include "ip.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// handle arp packet
// If the dest ip address of this arp packet is not equal to the ip address of the incoming iface, drop it.
// If it is an arp request packet, send arp reply to the destination, insert the ip->mac mapping into arpcache.
// If it is an arp reply packet, insert the ip->mac mapping into arpcache.
// Tips:
// You can use functions: htons, htonl, ntohs, ntohl to convert host byte order and network byte order (16 bits use ntohs/htons, 32 bits use ntohl/htonl).
// You can use function: packet_to_ether_arp() in arp.h to get the ethernet header in a packet.
// 如果ARP数据包的目标IP地址与收到它的接口的IP地址不相等，则丢弃它
// 否则，如果是ARP Request数据包，则发送ARP Reply数据包，并插入该数据包的IP->MAC映射
//      如果是ARP Reply数据包，则插入该数据包的IP->MAC映射
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	//assert(0 && "TODO: function handle_arp_packet not implemented!");
	//获取以太网帧和ARP头部指针
	//struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arp = packet_to_ether_arp(packet);
	if (ntohl(arp->arp_tpa) != iface->ip) {
    // 不是发给本机的ARP包，直接丢弃
        log(DEBUG,"thoroughly throw");
		free(packet);
    	return;
	}
    if (ntohs(arp->arp_op) == ARPOP_REPLY){
	    arpcache_insert(ntohl(arp->arp_spa),arp->arp_sha);
    }else if(ntohs(arp->arp_op) == ARPOP_REQUEST){
        arp_send_reply(iface,arp);
        arpcache_insert(ntohl(arp->arp_spa),arp->arp_sha);
	}
	free(packet);
}

// send an arp reply packet
// Encapsulate an arp reply packet, send it out through iface_send_packet.
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//assert(0 && "TODO: function arp_send_reply not implemented!");
	//构造ARP Reply数据包
		//分配内存保存ARP回复包（14字节以太网头 + 28字节ARP头 = 42字节）
		char *reply_packet;
		reply_packet=(char*)malloc(ETHER_HDR_SIZE+sizeof(struct ether_arp));
		struct ether_header* eth_reply = (struct ether_header *)reply_packet;
		struct ether_arp *arp_reply = packet_to_ether_arp(reply_packet);

        //填充以太网头
        memcpy(eth_reply->ether_dhost,req_hdr->arp_sha,ETH_ALEN);// 目标MAC = 请求者的MAC
		memcpy(eth_reply->ether_shost,iface->mac,ETH_ALEN);// 源MAC = 本接口的MAC
		eth_reply->ether_type = htons(ETH_P_ARP);

		//填充ARP头
        arp_reply->arp_hrd = htons(ARPHRD_ETHER);     // 硬件类型：以太网 = 1
        arp_reply->arp_pro = htons(ETH_P_IP);         // 协议类型：IPv4 = 0x0800
        arp_reply->arp_hln = ETH_ALEN;                // 硬件地址长度：6
        arp_reply->arp_pln = 4;                       // 协议地址长度：4
        arp_reply->arp_op = htons(ARPOP_REPLY);       // 操作码：Reply = 2

		memcpy(arp_reply->arp_sha, iface->mac, ETH_ALEN);           // Sender MAC = 本机
        arp_reply->arp_spa = htonl(iface->ip);                      // Sender IP = 本机 IP（网络序）
        //log(DEBUG,"target ip %s",htonl(req_hdr->arp_sha));
        memcpy(arp_reply->arp_tha, req_hdr->arp_sha, ETH_ALEN);         // Target MAC = 请求方
        arp_reply->arp_tpa = req_hdr->arp_spa;                          // Target IP = 请求方 IP

        // 发送该ARP Reply
        iface_send_packet(iface, reply_packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send an arp request
// Encapsulate an arp request packet, send it out through iface_send_packet.
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	//assert(0 && "TODO: function arp_send_request not implemented!");
	// 分配 ARP 请求报文内存：ARP报文 + 以太网头部
    int packet_len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
    char *packet = (char *)malloc(packet_len);
    // if (!packet) {
    //     perror("malloc failed");
    //     return;
    // }

    // 指针定位
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);

    // 填写以太网头部
    memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);        // 源MAC：本接口MAC
    memset(eth_hdr->ether_dhost, (u8)0xff, ETH_ALEN);              // 目的MAC：广播地址 FF:FF:FF:FF:FF:FF
    eth_hdr->ether_type = htons(ETH_P_ARP);                    // 上层协议类型：ARP (0x0806)

    // 填写 ARP 报文
    arp_hdr->arp_hrd = htons(ARPHRD_ETHER);    // 硬件类型：以太网
    arp_hdr->arp_pro = htons(ETH_P_IP);        // 协议类型：IPv4
    arp_hdr->arp_hln = (u8)ETH_ALEN;              // 硬件地址长度：6
    arp_hdr->arp_pln = (u8)4;                     // 协议地址长度：4
    arp_hdr->arp_op  = htons(ARPOP_REQUEST);  // 操作码：ARP Request

    memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);        // Sender MAC：本接口MAC
    arp_hdr->arp_spa = htonl(iface->ip);                   // Sender IP：本接口IP
    memset(arp_hdr->arp_tha, 0, ETH_ALEN);              // Target MAC：未知，填0
    arp_hdr->arp_tpa = htonl(dst_ip);                      // Target IP：目标IP

    // 发送 ARP 报文
    iface_send_packet(iface, packet, packet_len);

    // 释放分配的内存
    //free(packet);
}

// send (IP) packet through arpcache lookup 
// Lookup the mac address of dst_ip in arpcache.
// If it is found, fill the ethernet header and emit the packet by iface_send_packet.
// Otherwise, pending this packet into arpcache and send arp request.
// 在ARP缓存表中查找目标IP的MAC地址
// 如果找到，则填充以太网帧头部并通过iface_send_packet函数发送数据包
// 否则，将此数据包挂入arpcache并发送ARP Request
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	//assert(0 && "TODO: function iface_send_packet_by_arp not implemented!");
    //log(DEBUG,"in iface_send_packet");
    u8 dst_mac[ETH_ALEN];
    struct ether_header *eh = (struct ether_header *)packet;
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    eh->ether_type = htons(ETH_P_IP);
    // 如果缓存中能找到 IP->MAC 映射，直接发送
    if (arpcache_lookup(dst_ip, dst_mac)) {
        // 填写以太网帧头
        //log(DEBUG,"found the mac of %x, send this packet", dst_ip);
        memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
        iface_send_packet(iface, packet, len);
    } else {
        // 否则缓存中没有，挂入待处理队列并触发ARP请求
        //log(DEBUG,"没成功找到IP-MAC映射");

        // 将该包加入ARP等待队列，同时会发送ARP请求
        arpcache_append_packet(iface, dst_ip, packet, len);
    }
}
