#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"
//#include "tcp_out.h"
//#include "tcp_in.h"
//#include <stddef.h>
// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.




struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table
//*****
void tcp_sock_init(struct tcp_sock *tsk) {
    pthread_mutex_init(&tsk->sk_lock, NULL);
    pthread_mutex_init(&tsk->rcv_buf_lock, NULL);
    pthread_mutex_init(&tsk->send_buf_lock, NULL);
}

void tcp_sock_destroy(struct tcp_sock *tsk) {
    pthread_mutex_destroy(&tsk->sk_lock);
    pthread_mutex_destroy(&tsk->rcv_buf_lock);
    pthread_mutex_destroy(&tsk->send_buf_lock);
}
//


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

    //
    tcp_sock_init(tsk);
    //
	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

    //
    tsk->waitretran=0;
    tsk->retrans_timer.enable=0;
    tsk->persist_timer.enable=0;

	// init_list_head(&tsk->list);
	// init_list_head(&tsk->listen_queue);
	// init_list_head(&tsk->accept_queue);
    // init_list_head(&tsk->send_buf);
    // init_list_head(&tsk->rcv_ofo_buf);
    init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);
	init_list_head(&tsk->send_buf);
	init_list_head(&tsk->rcv_ofo_buf);
	init_list_head(&tsk->hash_list);
	init_list_head(&tsk->bind_hash_list);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();
    tsk->wait_recv1 = alloc_wait_struct();

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
	//初始代码

    if (!tsk) return;

    //pthread_mutex_lock(&tsk->lock);
    
    if (tsk->ref_cnt-- > 0) {
        //pthread_mutex_unlock(&tsk->lock);
        return;
    }

    // 释放资源
    //pthread_mutex_unlock(&tsk->lock); // 释放锁
    if (tsk->rcv_buf) free_ring_buffer(tsk->rcv_buf);
    if (tsk->wait_connect) free_wait_struct(tsk->wait_connect);
    if (tsk->wait_accept) free_wait_struct(tsk->wait_accept);
    if (tsk->wait_recv) free_wait_struct(tsk->wait_recv);
    if (tsk->wait_send) free_wait_struct(tsk->wait_send);
    if(tsk->wait_recv1 ) free_wait_struct(tsk->wait_recv1);
    //
    tcp_sock_destroy(tsk);
    //
    free(tsk); // 释放 tcp_sock 结构体
	
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
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
	//初始代码

	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
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
    	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

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

    return 1;
	// //初始代码
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	// if (!tsk || !skaddr) return -1;
	// // 1. 初始化四元组
    // //tsk->sk_dip = skaddr->ip;       // 目的 IP
    // //tsk->sk_dport = skaddr->port;    // 目的端口

    // // 1. 初始化四元组（转换为主机字节序后赋值）
    // tsk->sk_dip = ntohl(skaddr->ip);       // 目的 IP
    // tsk->sk_dport = ntohs(skaddr->port);   // 目的端口
    

    // fprintf(stdout,"TCP connection1\n");
    // tsk->sk_sip = 0x0A000002;  // 10.0.0.2
    // u16 port = 0;  // 可以设为 0，表示由系统自动分配端口
    // if (tcp_sock_set_sport(tsk, port) < 0) {  // 如果设置源端口失败，返回错误
    //     return -1;
    // }
    // fprintf(stdout,"TCP connection2\n");

    // // 4. 进入 TCP_SYN_SENT 状态
    // tcp_set_state(tsk,TCP_SYN_SENT);
    // //tsk->state = TCP_SYN_SENT;
    // // 2. 直接哈希到 bind_table（不调用 tcp_bind_hash）
    // if (tcp_hash(tsk) < 0)
    //     return -1;

    // // 3. 发送 SYN 报文
    // fprintf(stdout,"TCP connection3\n");
    // tcp_send_control_packet(tsk, TCP_SYN);

    
    // fprintf(stdout,"TCP connection4\n");
    // // 5. 进入 wait_connect 等待对方 SYN+ACK
    // //sleep_on(tsk->wait_connect);

    // // 6. 如果连接成功，返回 0，否则返回 -1
    // //return (tsk->state == TCP_ESTABLISHED) ? 0 : -1;


    // int ret = sleep_on(tsk->wait_connect);
    // fprintf(stdout,"TCP connection5\n");
    // // 5. 判断是否成功
    // if (ret == 0 && tsk->state == TCP_ESTABLISHED) {
    //     fprintf(stdout,"TCP connection established.\n");
    //     return 0;  // 连接成功
    // }
    // fprintf(stdout,"TCP connection6\n");

	// //初始代码
	// return -1;
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
	//初始代码
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	// if (!tsk || tsk->state != TCP_LISTEN)
    //     return NULL;

    // fprintf(stdout, "accept1\n");
    // struct tcp_sock *new_tsk = NULL;

    // while (list_empty(&tsk->accept_queue)) {
    //     // 进入等待，直到新连接到达
    //     sleep_on(tsk->wait_accept);
    // }
    // fprintf(stdout, "accept2\n");
    // // 获取 `accept_queue` 的第一个节点
    // struct list_head *first = tsk->accept_queue.next;
    // new_tsk = list_entry(first, struct tcp_sock, list);
    // fprintf(stdout, "accept3\n");
    // // 从队列中移除
    // list_delete_entry(first);
    // fprintf(stdout, "accept4\n");
    // // 更新 `accept_backlog`
    // tsk->accept_backlog--;

    // return new_tsk;
	
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk)
{		// 确保 tsk 有效
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    // if (!tsk) {
    //     return;
    // }
    // switch (tsk->state) {
    //     case TCP_LISTEN:
    //     // 如果 socket 处于 LISTEN 状态，直接释放资源
    //         tcp_unhash(tsk); // 从监听哈希表中移除
    //          //free_tcp_sock(tsk); // 释放 socket 资源
    //         return;

    //     case TCP_ESTABLISHED:
    //     // 如果 socket 仍然处于连接状态，发送 FIN 包关闭连接
    //         tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
    //         tcp_set_state(tsk, TCP_FIN_WAIT_1);
    //         sleep_on(tsk->wait_recv);
    //         break;

    //     case TCP_CLOSE_WAIT:
    //         log(DEBUG, "switch from close");
    //         tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
    //         tcp_set_state(tsk, TCP_LAST_ACK);
    //         sleep_on(tsk->wait_recv);
    //         break;

    //     case TCP_LAST_ACK:
    //         log(DEBUG, "switch from close");
    //         tcp_set_state(tsk, TCP_CLOSED);
    //         break;

    //     case TCP_SYN_SENT:
    //     case TCP_SYN_RECV:
    //     // 如果在握手阶段直接关闭，发送 RST 终止连接
    //         tcp_send_control_packet(tsk, TCP_RST);
    //         tcp_set_state(tsk, TCP_CLOSED);
    //         break;

    //     default:
    //         break;
    // }

    // // 通用处理：等待、移除哈希
    // sleep_on(tsk->wait_recv);
    // // 解除绑定并从哈希表中移除
    // tcp_unhash(tsk);
    // log(DEBUG, "Successfully end close");
    // // 释放 socket 资源
    // //free_tcp_sock(tsk);

    // 如果 socket 处于 LISTEN 状态，直接释放资源
    if (tsk->state == TCP_LISTEN) {
        tcp_unhash(tsk); // 从监听哈希表中移除
        //free_tcp_sock(tsk); // 释放 socket 资源
        return;
    }

    // 如果 socket 仍然处于连接状态，发送 FIN 包关闭连接
   // if (tsk->state == TCP_ESTABLISHED && ring_buffer_empty(tsk->rcv_buf)) {
	if (tsk->state == TCP_ESTABLISHED ) {
		tcp_send_control_packet(tsk, TCP_FIN|TCP_ACK);
        tcp_set_state(tsk, TCP_FIN_WAIT_1);
        sleep_on(tsk->wait_recv);
    } 
    if (tsk->state == TCP_CLOSE_WAIT) {
		log(DEBUG,"switch from close");
        tcp_send_control_packet(tsk, TCP_FIN|TCP_ACK);
        tcp_set_state(tsk, TCP_LAST_ACK);
        sleep_on(tsk->wait_recv);
    } 
    if(tsk->state == TCP_LAST_ACK){
		//tcp_send_control_packet(tsk, TCP_ACK);
		log(DEBUG,"switch from close");
        tcp_set_state(tsk, TCP_CLOSED);
	}
	if (tsk->state == TCP_SYN_SENT || tsk->state == TCP_SYN_RECV) {
        // 如果在握手阶段直接关闭，发送 RST 终止连接
        tcp_send_control_packet(tsk, TCP_RST);
        tcp_set_state(tsk, TCP_CLOSED);
    }
	sleep_on(tsk->wait_recv);
    // 解除绑定并从哈希表中移除
    //tcp_bind_unhash(tsk);
    tcp_unhash(tsk);
	log(DEBUG,"Successfully end close");
    // 释放 socket 资源
    //free_tcp_sock(tsk);
}
int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len) {
    //log(DEBUG,"get_read_lock_success");
    if (!tsk || !buf || len <= 0)
        return -1;  // 无效参数
    // 阻塞等待接收缓冲区中有数据可读
    //log(DEBUG,"in sleep");
    sleep_on(tsk->wait_recv1);
	//log(DEBUG,"end-sleep");

    pthread_mutex_lock(&tsk->rcv_buf_lock);

    if (!tsk->rcv_buf) {
        pthread_mutex_unlock(&tsk->rcv_buf_lock);
        return -1;  // 接收缓冲区未初始化
    }
     //log(DEBUG,"after while in read");
    // 从接收缓冲区中提取数据
    int read_bytes = read_ring_buffer(tsk->rcv_buf, buf, len);

    // 若未读取任何数据且连接已关闭，则返回EOF
    if (read_bytes == 0 && tsk->state == TCP_CLOSED) {
        pthread_mutex_unlock(&tsk->rcv_buf_lock);
        return 0;
    }
//log(DEBUG,"end-read_len=%d",size);
    pthread_mutex_unlock(&tsk->rcv_buf_lock);
    return read_bytes;
}

// int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len) {
    
//     if (!tsk || !buf || len <= 0) {
//         return -1; // 参数错误
//     }
//    	//log(DEBUG,"in sleep");
//     sleep_on(tsk->wait_recv1);
// 	//log(DEBUG,"end-sleep");
//     pthread_mutex_lock(&tsk->rcv_buf_lock);
//     struct ring_buffer *rbuf = tsk->rcv_buf;
//     if (!rbuf) {
//     //if(tsk->rcv_buf && ring_buffer_empty(tsk->rcv_buf)){
//         pthread_mutex_unlock(&tsk->rcv_buf_lock);
//         return -1; // 缓冲区没有初始化
//     }
//     //log(DEBUG,"after while in read");
//     // 读取数据
//     int size = read_ring_buffer(tsk->rcv_buf, buf, len);

//     if (size == 0 && tsk->state == 0) { // 检查连接是否已关闭
//     //if(ring_buffer_used(tsk->rcv_buf) == 0 && tsk->state == TCP_CLOSE_WAIT){
//         pthread_mutex_unlock(&tsk->rcv_buf_lock);
//         fprintf(stdout,"Tcp_sock_read prepare5\n");
//         return 0; // 读取到流结尾
//     }
//     //log(DEBUG,"end-read_len=%d",size);
//     pthread_mutex_unlock(&tsk->rcv_buf_lock);
//     return size;
// }



//在发送报文时将其加入发送队列
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len)
{
    log(DEBUG,"in tcp_send_add");
    pthread_mutex_lock(&tsk->send_buf_lock);  // 上锁

    // 1. 分配 send_buffer_entry
    struct send_buffer_entry *entry = (struct send_buffer_entry*)malloc(sizeof(struct send_buffer_entry));
    if (!entry) {
        pthread_mutex_unlock(&tsk->send_buf_lock);
        return;  // 内存不足，可改为返回错误码
    }

    // 2. 深拷贝报文数据
    char*packet_temp;
    packet_temp=(char*)malloc(len);
    //entry->packet = (char*)malloc(len);
    if (!packet_temp) {
        free(entry);
        pthread_mutex_unlock(&tsk->send_buf_lock);
        return;  // 内存不足
    }
    //memcpy(entry->packet, packet, len);
    memcpy(packet_temp,packet,len);
    entry->len = len;
    entry->packet=packet_temp;
    // 3. 获取 TCP 序号（需确保 packet 是完整 TCP 报文）
    struct tcphdr *tcp = packet_to_tcp_hdr(packet);
    //entry->seq = ntohl(tcp->seq)+ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
    entry->seq = ntohl(tcp->seq);
    //entry->seq_end=ntohl(tcp->seq) + len-(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE);
    //log(DEBUG,"%d-%d",entry->seq,entry->seq);
    if(tsk->retrans_timer.type==0){
        log(DEBUG,"not start");
    }
    //entry->seq = tcp->seq; 
    // 4. 初始化链表节点并加入发送队列
    init_list_head(&entry->list);
    list_add_tail(&entry->list, &tsk->send_buf);
    //log(DEBUG, "send packet len = %d", entry->len);
    pthread_mutex_unlock(&tsk->send_buf_lock);  // 解锁
}

// 发送数据并存入发送队列
int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len) {

    // log(DEBUG,"I'm in tcp_sock_write");
	// log(DEBUG,"%d",strlen(buf));
    if (!tsk || !buf || len <= 0) {
        return -1;
    }

    pthread_mutex_lock(&tsk->sk_lock);

    int bytes_sent = 0;
    //log(DEBUG,"to send 0");
    while (bytes_sent < len) {
        // 若发送窗口不可用，则等待
        //log(DEBUG,"in while");
        while (!tcp_tx_window_test(tsk)) {
            fprintf(stdout, "[tcp_sock_write] Waiting: send window not ready\n");
            tcp_set_persist_timer(tsk);
            pthread_mutex_unlock(&tsk->sk_lock);
            sleep_on(tsk->wait_send);
            fprintf(stdout, "sleep on send\n");
            pthread_mutex_lock(&tsk->sk_lock);
        }
        fprintf(stdout, "wake up send\n");
        int remaining = len - bytes_sent;
        //int allowed = min(tsk->snd_wnd, remaining);
        int allowed = tsk->snd_wnd < remaining ? tsk->snd_wnd : remaining;
        if (allowed <= 0) break;
        // Prepare packet
        // 动态分配数据包空间
        int total_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + allowed;
        char *pkt = malloc(total_len);
        if (!pkt) {
            log(ERROR, "Memory allocation failed while creating packet.");
            break;
        }
        memset(pkt, 0, total_len);

        // 设置 IP 和 TCP 首部指针
        struct iphdr *iph = packet_to_ip_hdr(pkt);
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + IP_BASE_HDR_SIZE);
        char *payload = (char *)tcph + TCP_BASE_HDR_SIZE;

        memcpy(payload, buf + bytes_sent, allowed);

        tcp_send_packet(tsk, pkt, total_len);
        // struct send_buffer_entry *entry = malloc(sizeof(struct send_buffer_entry));
        // entry->packet = packet;
        // entry->length = packet_len;
        // list_add_tail(&entry->list, &tsk->send_buf);
        
        // // ✅ 启动重传定时器
        // if (!tsk->retrans_timer.enable)
        //     tcp_set_retrans_timer(tsk);
        log(DEBUG, "after send: snd_nxt=%u", tsk->snd_nxt);
        //tsk->snd_nxt += send_length;               // ✅ Important!

        tcp_set_retrans_timer(tsk);
        log(DEBUG, "write-len %d", bytes_sent);
        bytes_sent += allowed;
        fprintf(stdout, "[tcp_sock_write] Wrote %d bytes, total: %d\n", allowed, bytes_sent);
    }

    pthread_mutex_unlock(&tsk->sk_lock);
    return bytes_sent;
}

// int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len) {
//     fprintf(stdout, "tcp_sock_write: start\n");
    
//     // static pthread_mutex_t write_lock = PTHREAD_MUTEX_INITIALIZER;  // 自定义锁
//     // pthread_mutex_lock(&write_lock);
//     pthread_mutex_lock(&tsk->sk_lock);
//     if (!tsk || !buf || len <= 0) {
//         pthread_mutex_unlock(&tsk->sk_lock);
//         fprintf(stdout, "tcp_sock_write: wrong\n");
//         return -1; // 参数错误
//     }
//     fprintf(stdout, "len: %d\n",len);
    
//     fprintf(stdout, "tcp_sock_write: start1\n");
//     int total_written = 0;
//     while (total_written < len) {
//         fprintf(stdout, "tcp_sock_write: while\n");
//         while (!tcp_tx_window_test(tsk)) {
//             fprintf(stdout, "tcp_sock_write: waiting for send window\n");
//             tcp_set_persist_timer(tsk);
//             pthread_mutex_unlock(&tsk->sk_lock);
//             sleep_on(tsk->wait_send);
//             pthread_mutex_lock(&tsk->sk_lock);
//         }
//         int writable = min(tsk->snd_wnd, len - total_written);
//         if (writable <= 0) {
//             break; // 发送窗口已满，无法继续写入
//         }
//         // 创建 TCP 数据包
//         char *packet = tcp_create_packet(tsk, buf + total_written, writable);
//         if (!packet) {
//             fprintf(stdout, "tcp_sock_write: packet wrong\n");
//             break; // 内存分配失败
//         }
//         tcp_send_packet(tsk, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + writable);
//         tcp_set_retrans_timer(tsk);
//         //pthread_mutex_unlock(&tsk->sk_lock);

//         total_written += writable;
//         fprintf(stdout, "tcp_sock_write: while end\n");      
//     }
    
//     //pthread_mutex_unlock(&write_lock);
//     pthread_mutex_unlock(&tsk->sk_lock);

//     return total_written;
// }

int tcp_move_rcv_ofo_buffer(struct tcp_sock *tsk)
{
    
    fprintf(stdout,"tcp_move_recv_ofo_buffer start\n");
    struct recv_ofo_buf_entry *entry, *q;
    int moved = 0;

    pthread_mutex_lock(&tsk->rcv_buf_lock);
    list_for_each_entry_safe(entry, q, &tsk->rcv_ofo_buf, list) {
        fprintf(stdout,"tcp_move_recv_ofo_buffer %d,%d\n",entry->seq,tsk->rcv_nxt);
        // 1. 检查是否是预期的序列号（连续）
        if (less_than_32b(entry->seq,tsk->rcv_nxt) || less_than_32b(tsk->rcv_nxt,entry->seq)) {
            fprintf(stdout,"tcp_move_recv_ofo_buffer out of order\n");
            break;  // 遇到乱序包，停止搬运
        }
        fprintf(stdout,"tcp_move_recv_ofo_buffer 3444\n");
        // 1.1 检查接收缓冲区是否有空间
        struct ring_buffer *rbuf = tsk->rcv_buf;
        fprintf(stdout,"yyy %d,%d\n",rbuf->size,ring_buffer_used(rbuf));
        if (ring_buffer_free(tsk->rcv_buf) < entry->len) {
            fprintf(stdout,"tcp_move_recv_ofo_buffer rcv_buf full %d,%d\n",ring_buffer_free(tsk->rcv_buf),entry->len);
            break;  // 缓冲区满，不能等待，直接返回
        }
        fprintf(stdout,"tcp_move_recv_ofo_buffer 34555\n");
        // 1.2 写入接收缓冲区
        write_ring_buffer(tsk->rcv_buf, entry->packet, entry->len);
        // log(DEBUG, "write_ring_buffer");

        // 2. 更新接收窗口
        tsk->rcv_nxt += entry->len;
        tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);

        // 3. 从乱序队列中移除并释放内存
        list_delete_entry(&entry->list);
        free(entry->packet);
        free(entry);
        fprintf(stdout,"tcp_move_recv_ofo_buffer 2\n");
        moved++;
    }
    pthread_mutex_unlock(&tsk->rcv_buf_lock);

    // 4. 唤醒等待线程
    if (moved > 0) {
        fprintf(stdout,"tcp_move_recv_ofo_buffer wake up\n");
        wake_up(tsk->wait_recv1);
    }

    fprintf(stdout,"tcp_move_recv_ofo_buffer finish\n");
    
    // log(DEBUG, "moved=%d", moved);
    return moved;
}
//新增数据包放入缓冲区
int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb)
{
        //log(DEBUG,"in rcv_ofo_buffer");
    //pthread_mutex_lock(&tsk->rcv_buf_lock);
    
    if (less_or_equal_32b(cb->seq_end, tsk->rcv_nxt)) {
        //pthread_mutex_unlock(&tsk->rcv_buf_lock);
        log(DEBUG,"direct return");
        return -1;
    }
    // if (!cb || !cb->ip) {
    //     log(ERROR, "cb or cb->ip is NULL!");
    //     return -1;
    // }
    // 计算整包长度
    int packet_len = cb->pl_len;
    // 创建新的 recv_ofo_buf_entry
    struct recv_ofo_buf_entry *new_entry = malloc(sizeof(struct recv_ofo_buf_entry));
    if (!new_entry) {
        //pthread_mutex_unlock(&tsk->rcv_buf_lock);
        //log(DEBUG,"1");
        return -1;
    }
    new_entry->packet = malloc(packet_len);
    if (!new_entry->packet) {
        free(new_entry);
        //pthread_mutex_unlock(&tsk->rcv_buf_lock);
        //log(DEBUG,"2");
        return -1;
    }
    memcpy(new_entry->packet, cb->payload, packet_len);
    new_entry->len = packet_len;
    new_entry->seq = cb->seq;
    new_entry->seq_end = cb->seq_end;
    //init_list_head(&new_entry->list);
    // 插入到乱序缓冲区（按seq升序）
    struct recv_ofo_buf_entry *entry, *tmp;
    int inserted = 0;
    list_for_each_entry_safe(entry, tmp, &tsk->rcv_ofo_buf, list) {
        
        // 重复报文直接丢弃
       if (!(new_entry->seq_end <= entry->seq || new_entry->seq >= entry->seq_end)) {
            // 重叠或完全相同，认为重复
            free(new_entry->packet);
            free(new_entry);
            //pthread_mutex_unlock(&tsk->rcv_buf_lock);
            return -1;
        }

        // 找到插入点（比它seq小）
        if (less_than_32b(new_entry->seq, entry->seq)) {
            list_add_tail(&new_entry->list, &entry->list);
            inserted = 1;
            break;
        }
    }
    // 插入到末尾
    if (inserted == 0)
        list_add_tail(&new_entry->list, &tsk->rcv_ofo_buf);

    // 尝试将数据从乱序队列上送到 rcv_buf
    tcp_move_rcv_ofo_buffer(tsk);
    //log(DEBUG,"out of move");
    //pthread_mutex_unlock(&tsk->rcv_buf_lock);
    return 0;
    
}

int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack) {
    pthread_mutex_lock(&tsk->send_buf_lock);
    struct send_buffer_entry  *q, *entry;
    int updated = 0;
    if (list_empty(&tsk->send_buf)) {
        log(DEBUG, "send_buf is empty when update.");
    } else {
        log(DEBUG, "send_buf is NOT empty when update.");
    }
   //entry = tsk;
    list_for_each_entry_safe(entry, q, &tsk->send_buf, list) {
        
        //u32 seq = entry->seq;
        // log(DEBUG, "entry: seq=%u, seq_end=%u,ack=%d", entry->seq, entry->seq_end,ack);
        // if(less_or_equal_32b(entry->seq_end,ack)){

        if (less_than_32b(entry->seq , ack)) {
            //log(DEBUG,"delete %d",entry->seq_end);
            
            list_delete_entry(&entry->list);
            free(entry->packet);
            free(entry);
            updated++;
        } else {
            // 因为发送缓冲区是按序排列的，之后的都不会被ACK
            break; 
        }
    }

    if (list_empty(&tsk->send_buf))
        tcp_unset_retrans_timer(tsk);

    pthread_mutex_unlock(&tsk->send_buf_lock);
    //fprintf(stdout,"update remove %d\n",removed);
    return updated;
}

int tcp_retrans_send_buffer(struct tcp_sock *tsk)
{
    pthread_mutex_lock(&tsk->send_buf_lock);

    if (list_empty(&tsk->send_buf)) {
        pthread_mutex_unlock(&tsk->send_buf_lock);
        return -1;
    }

    // 1. 获取队头元素
    struct send_buffer_entry *entry = list_entry(tsk->send_buf.next, struct send_buffer_entry, list);
    // struct send_buffer_entry *entry;
    // list_for_each_entry_safe(entry,&(tsk->send_buf),list);
    log(DEBUG,"len:%d",entry->len);//包中数据的长度
    char *old_packet = entry->packet;
    int len = entry->len;
    
    // 2. 拷贝数据包
    char *new_packet = (char *)malloc(len);
    memcpy(new_packet, old_packet, len);
    
    // // 3. 修改 ACK 号
    // struct iphdr *iph = (struct iphdr *)new_packet;
    // struct tcphdr *tcph = (struct tcphdr *)(new_packet + IP_HDR_SIZE(iph));
    
    // //tcph->ack = htonl(tsk->rcv_nxt);  // 更新为当前接收窗口期望的 seq 
    // tcph->seq=htonl(entry->seq);
    // tcph->ack = tsk->rcv_nxt;
    // // 4. 更新 TCP checksum（确保 off 字段正确）
    // tcph->off = 5 << 4;  // TCP header 长度为 20 字节
    // tcph->checksum = 0;
    // tcph->checksum = tcp_checksum(iph, tcph);

    //yixia youyong 
    struct iphdr *iph=packet_to_ip_hdr(new_packet);
    // struct tcphdr *tcph = packet_to_tcp_hdr(new_packet);
    struct tcphdr *tcp = (struct tcphdr *)((char *)iph + IP_BASE_HDR_SIZE);

    int ip_len = len - ETHER_HDR_SIZE;
	int tcp_len = ip_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

    memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);
    tcp->sport = htons(tsk->sk_sport);
    tcp->dport = htons(tsk->sk_dport);
    tcp->seq = htonl(entry->seq);
    tcp->ack = htonl(tsk->rcv_nxt);
    tcp->off = TCP_HDR_OFFSET;
    tcp->flags = TCP_PSH|TCP_ACK;
    tcp->rwnd = htons(tsk->rcv_wnd);

	ip_init_hdr(iph, tsk->sk_sip, tsk->sk_dip, ip_len, IPPROTO_TCP); 

    tcp->checksum = tcp_checksum(iph, tcp);
    iph->checksum = ip_checksum(iph);//update checksum
    // log(DEBUG, "Seq=%u, Ack=%u, Flags=0x%x", 
    //     (tcph->seq), (tcph->ack), tcph->flags);

    // 5. 重传发送
    ip_send_packet(new_packet, len);
    log(DEBUG,"ip_send_len:%d",len);
    log(DEBUG,"successfully send old packet");
    pthread_mutex_unlock(&tsk->send_buf_lock);
    return 0;
}

// 使用tsk->snd_una, tsk->snd_wnd, tsk->snd_nxt计算剩余窗口大小，如果大于TCP_MSS，则返回1，否则返回0
int tcp_tx_window_test(struct tcp_sock *tsk)
{
    // fprintf(stdout, "TODO:tcp_tx_window_text\n");
    // u32 snd_end = tsk->snd_una + tsk->snd_wnd;

    // if (snd_end >= tsk->snd_nxt) {
    //     u32 win_remain = snd_end - tsk->snd_nxt;
    //     fprintf(stdout, "normal window test\n");
    //     int answer = win_remain >= TCP_MSS ? 1 : 0;
    //     fprintf(stdout,"**********************%d\n",win_remain >= TCP_MSS ? 1 : 0);
    //     return win_remain >= TCP_MSS ? 1 : 0;
    // } else {
    //     // 理论上不应该出现（snd_nxt 超过窗口末端），但我们保守处理
    //     fprintf(stdout, "abnormal window test\n");
    //     return -1;
    // }
     //fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    // 计算已发送但未确认的数据量
    u32 unacked = tsk->snd_nxt - tsk->snd_una;
    
    // 计算剩余可用窗口大小
    u32 remaining_window = tsk->snd_wnd - unacked;
     
    // 检查剩余窗口是否至少能容纳一个MSS
    return (remaining_window > TCP_MSS) ? 1 : 0;
}
