#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// icmp_send_packet has two main functions:
// 1.handle icmp packets sent to the router itself (ICMP ECHO REPLY).
// 2.when an error occurs, send icmp error packets.
// Note that the structure of these two icmp packets is different, you need to malloc different sizes of memory.
// Some function and macro definitions in ip.h/icmp.h can help you.
// 1.处理发送给路由器自身的 icmp 数据包（ICMP ECHO REPLY）
// 2.当发生错误时，发送 icmp 错误数据包。
// 注意，这两个icmp数据包的结构不同，需要malloc不同大小的内存。
// 以及，包中有些字段可能在前几个函数中已经被转换成主机序了，但不要忘记仍有部分字段需要转换
// 注意更新checksum的时机，以及可以利用ip_base.c中定义的ip_init_hdr来初始化ip头部
// ip.h/icmp.h中定义了一些函数和宏，说不定有用
// send icmp packet

void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	//fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	int packet_len = 0; 
	struct iphdr *in_ip_hdr = packet_to_ip_hdr(in_pkt);

	if (type == ICMP_ECHOREPLY) {
		packet_len = len;
	} else {
		packet_len = ETHER_HDR_SIZE + ICMP_HDR_SIZE + IP_BASE_HDR_SIZE + IP_HDR_SIZE(in_ip_hdr) + 8;
	}

	char *packet = (char *)malloc(packet_len);

	struct ether_header *eh = (struct ether_header *)packet;
    eh->ether_type = htons(ETH_P_IP);

	struct iphdr *out_ip_hdr = packet_to_ip_hdr(packet);

	rt_entry_t *rt_entry = longest_prefix_match(ntohl(in_ip_hdr->saddr));

    ip_init_hdr(out_ip_hdr,
                rt_entry->iface->ip,
                ntohl(in_ip_hdr->saddr),
                packet_len - ETHER_HDR_SIZE,
                IPPROTO_ICMP);

	struct icmphdr * icmp_hdr = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(in_ip_hdr));
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	
	if (type != ICMP_ECHOREPLY) {
		memset((char*)icmp_hdr + ICMP_HDR_SIZE - 4, 0, 4);
		memcpy((char*)icmp_hdr + ICMP_HDR_SIZE, in_ip_hdr, IP_HDR_SIZE(in_ip_hdr) + 8);
	} else {
		memcpy((char*)icmp_hdr + ICMP_HDR_SIZE - 4,
		(char*)in_ip_hdr + IP_HDR_SIZE(in_ip_hdr) + 4,
		len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_ip_hdr) - 4);
	}
	icmp_hdr->checksum = icmp_checksum(icmp_hdr, packet_len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_ip_hdr));
	ip_send_packet(packet, packet_len);
}

// void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
// {
// 	//assert(0 && "TODO: function icmp_send_packet not implemented!");
// 	struct iphdr *in_ip = packet_to_ip_hdr(in_pkt);
//     char *out_pkt = NULL;
//     int out_len = 0;

//     if (type == ICMP_ECHOREPLY) {
//         // 回复 Echo Request：ICMP 头 + data 原样拷贝
//         int ip_hdr_len = IP_HDR_SIZE(in_ip);
//         int icmp_data_len = len - ETHER_HDR_SIZE - ip_hdr_len;

//         out_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_data_len;
//         out_pkt = (char *)malloc(out_len);
//         memset(out_pkt, 0, out_len);

//         // 拷贝 ICMP 数据
//         char *icmp_data = in_pkt + ETHER_HDR_SIZE + ip_hdr_len;
//         char *out_icmp = out_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE;
//         memcpy(out_icmp, icmp_data, icmp_data_len);

//         // 设置 ICMP type 和 code
//         struct icmphdr *icmp_hdr = (struct icmphdr *)out_icmp;
//         icmp_hdr->type = type;
//         icmp_hdr->code = code;
//         //icmp_hdr->icmp_sequence++;
//         icmp_hdr->checksum = icmp_checksum(icmp_hdr, icmp_data_len);

//         // 初始化 IP 头部
//         //struct iphdr *out_ip = (struct iphdr *)(out_pkt + ETHER_HDR_SIZE);
// 		struct iphdr *out_ip = (struct iphdr *)packet_to_ip_hdr(out_pkt);
//         ip_init_hdr(out_ip, in_ip->daddr, in_ip->saddr,
//                     IP_BASE_HDR_SIZE + icmp_data_len, IPPROTO_ICMP);
//     } else {
//         // ICMP 错误报文（Time Exceeded, Destination Unreachable）
//         // ICMP 头 + 原 IP 首部 + 前 8 字节 data
//         int icmp_payload_len = IP_HDR_SIZE(in_ip) + ICMP_COPIED_DATA_LEN;
//         int icmp_len = ICMP_HDR_SIZE + icmp_payload_len;
//         out_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;

//         out_pkt = (char *)malloc(out_len);
//         memset(out_pkt, 0, out_len);

//         // 构造 ICMP 报文
//         struct icmphdr *icmp_hdr = (struct icmphdr *)(out_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
//         icmp_hdr->type = type;
//         icmp_hdr->code = code;
//         //icmp_hdr->icmp_sequence++;
//         icmp_hdr->checksum = 0;

//         // 拷贝原 IP 头和前 8 字节数据
//         char *icmp_data = (char *)(icmp_hdr + 1);
//         memcpy(icmp_data, in_ip, icmp_payload_len);

//         // 计算 ICMP checksum
//         icmp_hdr->checksum = icmp_checksum(icmp_hdr, icmp_len);

//         // 初始化 IP 头
// 		struct iphdr *out_ip = (struct iphdr *)packet_to_ip_hdr(out_pkt);
//         ip_init_hdr(out_ip, in_ip->daddr, in_ip->saddr,
//                     IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);
//     }

//     // 发送构造好的 IP 包
//     ip_send_packet(out_pkt, out_len);
//     log(DEBUG,"successfully send icmp_send_packet");
// 	//free(out_pkt);
// }
