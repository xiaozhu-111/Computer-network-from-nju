#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}

// init tcp hash table and tcp timer
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
void free_tcp_sock(struct tcp_sock *tsk)
{
    if (!tsk) return;

    if (--tsk->ref_cnt > 0) return;

	log(DEBUG, "Free tcp sock "IP_FMT":%d", 
        NET_IP_FMT_STR(tsk->sk_sip), ntohs(tsk->sk_sport));
    //释放资源
    if (tsk->rcv_buf) free_ring_buffer(tsk->rcv_buf);
    if (tsk->wait_connect) free_wait_struct(tsk->wait_connect);
    if (tsk->wait_accept) free_wait_struct(tsk->wait_accept);
    if (tsk->wait_recv) free_wait_struct(tsk->wait_recv);
    if (tsk->wait_send) free_wait_struct(tsk->wait_send);
	
    free(tsk);
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
// 计算哈希值，定位哈希表中的桶
int hash = tcp_hash_function(saddr, daddr, sport, dport);

// 获取桶链表头
struct list_head *list = &tcp_established_sock_table[hash];

// 定义指向 tcp_sock 的临时变量
struct tcp_sock *tsk ;

// 遍历该桶的链表
list_for_each_entry(tsk, list, hash_list) {
	// 匹配四元组
	if (tsk->sk_sip == saddr &&
		tsk->sk_dip == daddr &&
		tsk->sk_sport == sport &&
		tsk->sk_dport == dport) {
		// 匹配成功，返回找到的 tcp_sock
		return tsk;
	}
}

// 没找到，返回 NULL
return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
// 计算哈希值
int hash = tcp_hash_function(0, 0, sport, 0);

// 取出对应哈希桶链表头
struct list_head *list = &tcp_listen_sock_table[hash];

// 遍历链表
struct tcp_sock *tsk;
list_for_each_entry(tsk, list, hash_list) {
	if (tsk->sk_sport == sport) {
		return tsk;
	}
}

// 没找到，返回 NULL
return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);

	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	tsk->ref_cnt += 1;

	return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, bind_hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;

	return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;

	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.

int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

    // 分配本地端口
    // 传入一个端口，例如 0，表示让 tcp_sock_set_sport 自动选择一个端口
	// 设置目标地址和端口(网络字节序转主机字节序)
	tsk->sk_sip=(0x0a000002);
    tsk->sk_dip = ntohl(skaddr->ip);
    tsk->sk_dport = ntohs(skaddr->port);
	tsk->sk_sport = tcp_get_port();
    if (tsk->sk_sport == 0 && tcp_sock_set_sport(tsk, 0) < 0) {
        // 错误信息更具体，显示源端口设置失败
		log(ERROR, "Failed to allocate source port");
		return 1;  // 错误返回
    }
	tcp_bind_hash(tsk);
	// 使用路由表查找源IP地址
    rt_entry_t *entry = longest_prefix_match(tsk->sk_dip);
    if (!entry || !entry->iface) {
        log(ERROR, "No route to host "IP_FMT, NET_IP_FMT_STR(tsk->sk_dip));
        return 1;
    }
//tsk->sk_sip = entry->iface->ip;
	//log(DEBUG, "1");
    // 2. 设置状态为 SYN_SENT
    tcp_set_state(tsk, TCP_SYN_SENT);
	//log(DEBUG, "2");

    // 3. 哈希进 established_table
	if (tcp_hash(tsk) < 0) {
        log(ERROR, "Failed to hash TCP sock");
        return 1;
    }
	//log(DEBUG, "3");

    // 4. 发送 SYN 包
    tcp_send_control_packet(tsk, TCP_SYN);
	sleep_on(tsk->wait_connect);
	//log(DEBUG, "4");

//    // 5. 阻塞等待连接完成（SYN/ACK -> ESTABLISHED）
//     if (sleep_on(tsk->wait_connect) < 0) {
//         fprintf(stderr, "Error in waiting for connection to be established\n");
//         return 1;
//     }

    // 6. 判断是否连接成功
    // if (tsk->state == TCP_ESTABLISHED) {
	// 	wake_up(tsk->wait_connect);
    //     return 0;   // 成功
    // }else {
	// 	log(ERROR, "Connection failed");
	// 	return 1;
	// }

    return 1;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	 // 监听状态只能从 TCP_CLOSED 或 TCP_LISTEN 进入
	 if (tsk->state != TCP_CLOSED && tsk->state != TCP_LISTEN) {
        return -1; // 非法状态
    }

    // 设置最大等待连接数
    tsk->backlog = backlog;
	tcp_set_state(tsk, TCP_LISTEN);
    if (tcp_hash(tsk) < 0) return -1; // 哈希到listen_table
    
    log(DEBUG, "Server listening on port %d", ntohs(tsk->sk_sport));
    return 0;
    // // 切换 TCP 状态
    // tsk->state = TCP_LISTEN;

    // // 调用 tcp_hash 进行插入
    // if (tcp_hash(tsk) < 0) {
    //     return -1; // 哈希插入失败
    // }

    // return 0; // 成功
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	if (!tsk || tsk->state != TCP_LISTEN) {
        log(ERROR, "Socket not in LISTEN state");
        return NULL;
    }

    while (list_empty(&tsk->accept_queue)) {
        if (sleep_on(tsk->wait_accept) < 0) {
            log(ERROR, "Accept interrupted");
            return NULL;
        }
    }

    struct tcp_sock *csk = tcp_sock_accept_dequeue(tsk);
    if (!csk) {
        log(ERROR, "Dequeue failed");
        return NULL;
    }

    log(DEBUG, "Accept new connection from "IP_FMT":%d",
        NET_IP_FMT_STR(csk->sk_dip), ntohs(csk->sk_dport));
    return csk;
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk)
{
	// 确保 tsk 有效
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    if (!tsk) {
        return;
    }

    // 如果 socket 处于 LISTEN 状态，直接释放资源
    if (tsk->state == TCP_LISTEN) {
        tcp_unhash(tsk); // 从监听哈希表中移除
        //free_tcp_sock(tsk); // 释放 socket 资源
        return;
    }

    // 如果 socket 仍然处于连接状态，发送 FIN 包关闭连接
    if (tsk->state == TCP_ESTABLISHED&&ring_buffer_empty(tsk->rcv_buf)) {
        tcp_send_control_packet(tsk, TCP_FIN);
        tcp_set_state(tsk, TCP_FIN_WAIT_1);
    } 
    else if (tsk->state == TCP_CLOSE_WAIT) {
        tcp_send_control_packet(tsk, TCP_FIN|TCP_ACK);
        tcp_set_state(tsk, TCP_LAST_ACK);
    } 
    else if(tsk->state == TCP_LAST_ACK){
		tcp_send_control_packet(tsk, TCP_ACK);
        tcp_set_state(tsk, TCP_CLOSED);
	}
	else if (tsk->state == TCP_SYN_SENT || tsk->state == TCP_SYN_RECV) {
        // 如果在握手阶段直接关闭，发送 RST 终止连接
        tcp_send_control_packet(tsk, TCP_RST);
        tcp_set_state(tsk, TCP_CLOSED);
    }
	sleep_on(tsk->wait_recv);
    // 解除绑定并从哈希表中移除
    //tcp_bind_unhash(tsk);
    tcp_unhash(tsk);
	log(DEBUG,"Successfully end");
    // 释放 socket 资源
    //free_tcp_sock(tsk);
}

//返回值：0表示读到流结尾，对方关闭连接；-1表示出现错误；正值表示读取的数据长度
int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	sleep_on(tsk->wait_recv);
	if(tsk->state==TCP_ESTABLISHED){
		pthread_mutex_lock(&(tsk->rcv_buf->lock));
		int size = read_ring_buffer(tsk->rcv_buf, buf, len);
		log(DEBUG,"read-size:%d",size);
		pthread_mutex_unlock(&(tsk->rcv_buf->lock));
		//fprintf(stdout, "size is %d\n", size);
		if(size > 0) return size;
		else return -1;
	}
	pthread_mutex_lock(&(tsk->rcv_buf->lock));
	int valid = ring_buffer_empty(tsk->rcv_buf);
	pthread_mutex_unlock(&(tsk->rcv_buf->lock));
	if(valid){
		sleep_on(tsk->wait_recv);
	}

	pthread_mutex_lock(&(tsk->rcv_buf->lock));

	if(tsk->state==TCP_ESTABLISHED) {
		int size = read_ring_buffer(tsk->rcv_buf, buf, len);
		if(size == 0) return -1;
		else return size;
	}
	int size = read_ring_buffer(tsk->rcv_buf, buf, len);
	pthread_mutex_unlock(&(tsk->rcv_buf->lock));


return size;
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	// int rlen = 0;

    // // while ((rlen = ring_buffer_used(tsk->rcv_buf)) == 0) {
    // //     sleep_on(tsk->wait_recv); // 没有数据就睡眠等待
    // // }

    // pthread_mutex_lock(&tsk->rcv_buf->lock);
    // rlen = read_ring_buffer(tsk->rcv_buf, buf, len);
    // pthread_mutex_unlock(&tsk->rcv_buf->lock);

    // return rlen;
}
// 返回值：-1表示出现错误；正值表示写入的数据长度
int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len)
{
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	int left_length = len;
	log(DEBUG,"SOCK-write %s",buf);
	while(1){
		if(tsk->snd_wnd > 0){
			
			char* send_buf;
			send_buf = buf + len - left_length;
			
			int send_length_temp, send_length;
			if(less_or_equal_32b(tsk->snd_wnd, (u32)left_length)){
				send_length_temp = (int)tsk->snd_wnd;
			}
			else{
				send_length_temp = left_length;
			}
			if(send_length_temp < 1500 - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE){
				send_length = send_length_temp;
			}
			else{
				send_length = 1500 - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;
			}
			left_length -= send_length;
			
			char* packet;
			packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + send_length);
			
			
			char* data_area;
			data_area = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
			memcpy(data_area, buf, send_length);
			
			//fprintf(stdout, "sendlength is %d\n", send_length);
			tcp_send_packet(tsk, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + send_length);
			
			if(left_length <= 0) {
				log(DEBUG,"write-len %d",len);
			return len;}
		}
		else{
			fprintf(stdout, "sleep on send\n");
			sleep_on(tsk->wait_send);
			fprintf(stdout, "wake up send\n");
		}
		
	}
	// //int max_data_len = min(len, TCP_DEFAULT_MSS); // 单次最大数据大小,防止一次发送过多数据
    // //int pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + max_data_len;
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	// int pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + len;

    // char *packet = malloc(pkt_len);
    // memset(packet, 0, pkt_len);

    // // 填入 payload
    // char *payload = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
    // //memcpy(payload, buf, max_data_len);
    // memcpy(payload, buf, len);

    // tcp_send_control_packet(tsk, packet);
	// //tcp_send_data_packet(tsk, packet,strlen(*packet));
    // free(packet);

    // //return max_data_len;
	// return len;
}
