#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "log.h"
#include "icmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	//assert(0 && "TODO: function arpcache_lookup not implemented!");
	pthread_mutex_lock(&arpcache.lock);
	for(int i=0; i < MAX_ARP_SIZE; i++){
		struct arp_cache_entry *entry = &arpcache.entries[i];
		if(entry->valid == 1 && entry->ip4 == ip4){
			//找到匹配项
			memcpy(mac,entry->mac,ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// insert the IP->mac mapping into arpcache, need pthread_mutex_lock/unlock
// If there is a timeout entry (attribute valid in struct) in arpcache, replace it.
// If there isn't a timeout entry in arpcache, randomly replace one.
// If there are pending packets waiting for this mapping, fill the ethernet header for each of them, and send them out.
// 将IP->MAC映射插入到arpcache中，需要上锁
// 如果ARP缓存表中存在超时条目(valid = 0)，就替换它
// 如果ARP缓存表中不存在超时条目，就随机替换一个
// 如果有等待此IP->MAC映射的待发送数据包，则为每个数据包填充以太网头，并将其发送出去
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(用arp_req结构体封装)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	//ssert(0 && "TODO: function arpcache_insert not implemented!");
	pthread_mutex_lock(&arpcache.lock);
    log(DEBUG, "insert ARP entry for IP: %x", ip4);
	//插入或替换一个ARP缓存条目
	int inserted = 0;
	for(int i = 0; i < MAX_ARP_SIZE; i++){
		struct arp_cache_entry* entry = &arpcache.entries[i];
		if(!entry->valid){
        //if(entry->ip4 == 0){
		//if(arpcache.entries[i].valid != 0){
			//找到一个超时条目，直接替换
			entry->ip4 = ip4;
			memcpy(entry->mac,mac,ETH_ALEN);
			entry->added = time(NULL);//被插入的时间等于现在的时间
			entry->valid = 1;
			inserted = 1;
		}
	}
	if(!inserted){
		//没有超时条目，随机换一个
		int idx = rand()%MAX_ARP_SIZE;
		arpcache.entries[idx].ip4 = ip4;
		memcpy(arpcache.entries[idx].mac,mac,ETH_ALEN);
		arpcache.entries[idx].added = time(NULL);
		arpcache.entries[idx].valid = 1;
	}
	//检查是否有等待此IP->mac映射的待发送数据包
	struct arp_req *req = NULL, *req_tmp;
    list_for_each_entry_safe(req, req_tmp, &(arpcache.req_list), list) {
        if (req->ip4 == ip4) {
            // 找到等待这个 IP 的 pending 请求
            struct cached_pkt *pkt = NULL, *pkt_tmp;
            list_for_each_entry_safe(pkt, pkt_tmp, &(req->cached_packets), list) {
                // 对每个缓存的报文，补全以太网头部并发送
                pthread_mutex_unlock(&arpcache.lock);
                struct ether_header *eh = (struct ether_header *)pkt->packet;
                memcpy(eh->ether_dhost, mac, ETH_ALEN);
                iface_send_packet(req->iface, pkt->packet, pkt->len);
				pthread_mutex_lock(&arpcache.lock);
                list_delete_entry(&pkt->list);
				free(pkt);
            }
            // 从 req_list 中删除该请求并释放内存
            list_delete_entry(&req->list);
            free(req);
			break;
        }
    }
	pthread_mutex_unlock(&arpcache.lock);
}

// append the packet to arpcache
// Look up in the list which stores pending packets, if there is already an entry with the same IP address and iface, 
// which means the corresponding arp request has been sent out, just append this packet at the tail of that entry (The entry may contain more than one packet).
// Otherwise, malloc a new entry with the given IP address and iface, append the packet, and send arp request.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
// 在存储待处理数据包的链表中查找，如果已存在需要相同IP->MAC映射的条目，
// 这说明已经发送过有关ARP Request，只需将该数据包附加到该条目链表的末尾（该条目可能包含多个数据包）
// 否则，malloc一个新条目，在其链表上附加数据包，并发送ARP Request
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	 pthread_mutex_lock(&arpcache.lock);

    // Step 1: 遍历 req_list，看是否已有等待该 IP 的请求
    struct arp_req *req;
    list_for_each_entry(req, &arpcache.req_list, list) {
        if (req->ip4 == ip4 && req->iface == iface) {
            // 找到已存在的请求，只需添加 packet 到 cached_packets

            struct cached_pkt *new_pkt = malloc(sizeof(struct cached_pkt));
            new_pkt->packet = packet;
            new_pkt->len = len;
            list_add_tail(&new_pkt->list, &req->cached_packets);

            pthread_mutex_unlock(&arpcache.lock);
            return;
        }
    }

    // Step 2: 没有找到对应的 req，分配新的 arp_req
    struct arp_req *new_req = malloc(sizeof(struct arp_req));
    new_req->iface = iface;
    new_req->ip4 = ip4;
    new_req->sent = time(NULL);
    new_req->retries = 1;
    init_list_head(&new_req->cached_packets);

    // 添加当前 packet 到 cached_packets 中
    struct cached_pkt *new_pkt = malloc(sizeof(struct cached_pkt));
    new_pkt->packet = packet;
    new_pkt->len = len;
    list_add_tail(&new_pkt->list, &new_req->cached_packets);

    // 添加到 req_list
    list_add_tail(&new_req->list, &arpcache.req_list);

    // Step 3: 发送一条 ARP Request 请求
    arp_send_request(iface, ip4);

    pthread_mutex_unlock(&arpcache.lock);
    // pthread_mutex_lock(&arpcache.lock);
	// struct arp_req *req_entry = NULL, *q;
	// int found_same_ip_entry = 0;
	// list_for_each_entry_safe(req_entry, q, &(arpcache.req_list), list){
	// 	if(req_entry->ip4 == ip4){
	// 		int found_same_ip_entry = 1;
	// 		break;
	// 	}
	// }
	// if(found_same_ip_entry == 0){
	// 	req_entry = (struct arp_req *) malloc(sizeof(struct arp_req));
	// 	init_list_head(&(req_entry->list));
	// 	req_entry->ip4 = ip4;
	// 	init_list_head(&(req_entry->cached_packets));
	// 	req_entry->iface = (iface_info_t *) malloc(sizeof(iface_info_t));
	// 	memcpy(req_entry->iface, iface, sizeof(iface_info_t));
	// 	req_entry->sent = 0;
	// 	req_entry->retries = 0;	
	// 	list_add_tail(&(req_entry->list), &(arpcache.req_list));
	// }
	// struct cached_pkt *pkt = (struct cached_pkt *) malloc(sizeof(struct cached_pkt));
	// pkt->packet = packet;
	// pkt->len = len;
	// init_list_head(&(pkt->list));
	// list_add_tail(&(pkt->list), &(req_entry->cached_packets));
	// //send arp request
	// arp_send_request(iface, ip4);
	// req_entry->retries ++;
	// req_entry->sent = time(NULL);
	// pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
// for IP->mac entry, if the entry has been in the table for more than 15 seconds, remove it from the table
// for pending packets, if the arp request is sent out 1 second ago, while the reply has not been received, retransmit the arp request
// If the arp request has been sent 5 times without receiving arp reply, for each pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets
// tips
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
// 每一秒扫描一次arpcache
// 对于每个IP->MAC映射，如果该条目在ARP缓存表中已存在超过15秒，则将其valid属性置为0
// 对于正在进行ARP Request的条目，如果1秒前发出过一次请求，但仍未收到答复，则重传并将重传计数+1
// 如果重传次数已达五次而未收到ARP Reply，则对每个待处理数据包的源IP地址，
// 发送ICMP Error Packet (DEST_HOST_UNREACHABLE)，并丢弃这些数据包
// 注意，在arpcache_append_packet第一次发送ARP Request时，就算做一次重传，
// 所以这里与其理解为重传，不如理解为发送ARP Request的次数
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		//assert(0 && "TODO: function arpcache_sweep not implemented!");
		pthread_mutex_lock(&arpcache.lock);

		// Step 1: 扫描缓存表，清除过期项
        for (int i = 0; i < MAX_ARP_SIZE; i++) {
            if (arpcache.entries[i].valid && (time(NULL) - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)) {
                arpcache.entries[i].valid = 0;
            }
        }

        // Step 2: 遍历等待 ARP 回复的 req_list
        struct arp_req *req = NULL, *next_req;
        list_for_each_entry_safe(req, next_req, &arpcache.req_list, list) {
            if(req->retries < ARP_REQUEST_MAX_RETRIES && time(NULL) - req->sent >= 1){
				arp_send_request(req->iface, req->ip4);
				req->sent = time(NULL);
				req->retries ++;
			}
			else if(req->retries >= ARP_REQUEST_MAX_RETRIES){
				struct cached_pkt *pkt = NULL, *p;
				list_for_each_entry_safe(pkt, p, &(req->cached_packets), list){
					pthread_mutex_unlock(&arpcache.lock);
					icmp_send_packet(pkt->packet, pkt->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
					pthread_mutex_lock(&arpcache.lock);
					list_delete_entry(&(pkt->list));
					free(pkt->packet);
					free(pkt);
				}
				list_delete_entry(&(req->list));
				free(req);
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
