#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
    u8 flags, u16 rwnd)
{
memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

tcp->sport = htons(sport);
tcp->dport = htons(dport);
tcp->seq = htonl(seq);
tcp->ack = htonl(ack);
tcp->off = TCP_HDR_OFFSET;
tcp->flags = flags;
tcp->rwnd = htons(rwnd);
}

static struct list_head timer_list;
#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)
// 定义互斥锁
pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

/// ////
static struct list_head timer_list1;
static struct list_head timer_list2;
void tcp_set_persist_timer(struct tcp_sock *tsk) {
    // 1. 检查定时器是否已启用（线程安全读取）
    if (tsk->persist_timer.enable)
        return;
    // 2. 初始化定时器节点（防御性编程）
    // init_list_head(&tsk->retrans_timer.list);

        
    // 3. 配置定时器参数
    tsk->persist_timer.type = 2;
    tsk->persist_timer.enable = 1;
    tsk->persist_timer.timeout = time(NULL) + TCP_RETRANS_INTERVAL_INITIAL/1000000;
    // 4. 增加引用计数（需原子操作或由调用者保证线程安全）
    //tcp_sock_inc_ref(tsk);
    tsk->ref_cnt++;
    list_add_tail(&tsk->persist_timer.list, &timer_list1);
    //fprintf(stderr, "tcp_set_persist_timer: finish\n");
}

void tcp_unset_persist_timer(struct tcp_sock *tsk) {
    // 1. 如果已经禁用，不做任何事
    if (!tsk->persist_timer.enable)
        return;

    //fprintf(stderr, "tcp_unset_persist_timer: unset\n");
    // 2. 从链表中移除timer（需要线程安全操作）
    list_delete_entry(&tsk->persist_timer.list);
     // 禁用定时器
    tsk->persist_timer.enable = 0;
    // 减少tsk引用计数
    tsk->ref_cnt--;
    //fprintf(stderr, "tcp_unset_persist_timer: finish\n");
}

void tcp_send_probe_packet(struct tcp_sock *tsk) {
    
    char buf[1] = {'1'};
    int len = 1;
    int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + len;
    char *packet = malloc(pkt_size);
    if (!packet) {
        log(ERROR, "malloc tcp packet failed.");
        return NULL;
    }

    memset(packet, 0, pkt_size);

    // 定位 IP 头部
    struct iphdr *ip = packet_to_ip_hdr(packet);

    // 定位 TCP 头部（紧随 IP 头部）
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

    // 复制数据到 TCP 数据部分
    char *tcp_payload = (char *)tcp + TCP_BASE_HDR_SIZE;
    memcpy(tcp_payload, buf, len);



    int ip_tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + 1;
	int tcp_data_len = 1;

	u32 saddr = tsk->sk_sip;
	u32	daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = tsk->snd_nxt;
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;

	tcp_init_hdr(tcp, sport, dport, seq-1, ack, TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP); 

	tcp->checksum = tcp_checksum(ip, tcp);

	ip->checksum = ip_checksum(ip);

	ip_send_packet(packet, pkt_size);
    //free(packet);
	packet = NULL;
}



void tcp_set_retrans_timer(struct tcp_sock *tsk) {

    struct tcp_timer *timer = &tsk->retrans_timer;
    //log(DEBUG,"prepare in lock");
    if (timer->enable ) {
        //log(DEBUG,"stop in this if");
        //fprintf(stdout,"have set retrans timer\n");
        timer->timeout = time(NULL) + TCP_RETRANS_INTERVAL_INITIAL/1000000;
        return;
    }

    // 初始化
    timer->type = 1;
    timer->timeout = time(NULL) + TCP_RETRANS_INTERVAL_INITIAL/1000000;
    
    log(DEBUG,"become0 in set_retrans_timer");
    timer->retrans_times = 0;
    timer->enable=1;

    // 增加引用计数，防止定时器期间被释放
    tsk->ref_cnt++;

     // 加入定时器链表
    list_add_tail(&timer->list, &timer_list2); 
    // log(DEBUG, "Set RETRANS timer for "IP_FMT":%d -> "IP_FMT":%d, timeout=%dus",
    //     NET_IP_FMT_STR(tsk->sk_sip), ntohs(tsk->sk_sport),
    //     NET_IP_FMT_STR(tsk->sk_dip), ntohs(tsk->sk_dport),
    //     timer->timeout);
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk) {
    struct tcp_timer *timer = &tsk->retrans_timer;

    //pthread_mutex_lock(&timer_list_lock);

    // 1. 如果已经禁用，不做任何事
    if (!timer->enable){
        //pthread_mutex_unlock(&timer_list_lock);
        return; 
    }
    // 2. 标记为禁用，移出链表
    timer->enable = 0;
    list_delete_entry(&tsk->retrans_timer.list);

     // 3. 减少引用计数
    tsk->ref_cnt--;
    
    // pthread_mutex_unlock(&timer_list_lock);
}

void tcp_update_retrans_timer(struct tcp_sock *tsk) {
    struct tcp_timer *timer = &tsk->retrans_timer;

    // 1. 如果定时器未启用，则无需处理
    if (timer->enable == 0)
        return; 

    // 2. 如果发送缓冲区为空，关闭定时器并唤醒发送进程
    if (list_empty(&tsk->send_buf)) {
        // 发送队列为空,删除定时器
        tcp_unset_retrans_timer(tsk);
        wake_up(tsk->wait_send); // 唤醒等待发送进程
    } else {
        // 3. 否则，重置 timeout 和重传计数
        timer->timeout = time(NULL)+TCP_RETRANS_INTERVAL_INITIAL/1000000;
        log(DEBUG,"become0 in update_retrans_timer");
        timer->retrans_times = 0;
		timer->enable = 1;
        timer->type = 1;
		 
    }


}

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    //log(DEBUG,"in tcp_scan");
	pthread_mutex_lock(&timer_list_lock); // 加锁，防止竞争条件

    struct tcp_sock *tsk, *tmp;
    time_t now = time(NULL);
    // tsk = (timer->type == 0) ? timewait_to_tcp_sock(timer) : 
    //         retranstimer_to_tcp_sock(timer);
    list_for_each_entry_safe(tsk, tmp, &timer_list, timewait.list) {
        log(DEBUG,"in this while");
        if(tsk->timewait.type==0)
        {
            if (tsk->timewait.enable && now >= tsk->timewait.timeout) {
                //fprintf(stdout, "success scan\n");
                // 从时间链表中移除
                list_delete_entry(&tsk->timewait.list);  
                tcp_set_state(tsk,TCP_CLOSED);
                
                wake_up(tsk->wait_recv);
                continue;
            }
        }
    }

    list_for_each_entry_safe(tsk, tmp, &timer_list2, retrans_timer.list) {
         // 处理Retransmission Timer（type=1）
        if (tsk->retrans_timer.enable == 1 && tsk->retrans_timer.type == 1 && now >= tsk->retrans_timer.timeout) {
            log(DEBUG,"in the next while");
            if (tsk->retrans_timer.retrans_times >= 3) {
                // 达到上限，强制关闭连接
                tcp_send_control_packet(tsk,TCP_RST);
                
                tcp_unhash(tsk);      
                wake_up(tsk->wait_connect); 
                tcp_unset_retrans_timer(tsk);
            } else {
                
                // 进行重传
                tcp_retrans_send_buffer(tsk); 
                tsk->retrans_timer.retrans_times += 1;
                tsk->retrans_timer.timeout = now + TCP_RETRANS_INTERVAL_INITIAL/1000000;//0.2
            }
        }
    }
    
    list_for_each_entry_safe(tsk, tmp, &timer_list1, persist_timer.list) {
        
        // 如果关闭，不做处理
        if (!tsk->persist_timer.enable || tsk->state == TCP_CLOSED) {
            tcp_unset_persist_timer(tsk);
            continue;
        }
        if (now < tsk->persist_timer.timeout) {
            
            log(DEBUG, "persist_timer: snd_wnd\n");
            continue;
        }
        // Persist Timer 超时处理逻辑
        if (!tcp_tx_window_test(tsk)){
            tcp_send_probe_packet(tsk);
            tcp_unset_persist_timer(tsk);
            // 重置计时器
            tcp_set_persist_timer(tsk);
        } else {
            // 关闭该定时器
            fprintf(stdout, "[persist_timer] snd_wnd = %u, stop timer\n", tsk->snd_wnd);
            tcp_unset_persist_timer(tsk);
        }
    }
  //log(DEBUG,"out this while");
    pthread_mutex_unlock(&timer_list_lock); // 解锁
    // // 安全释放资源（不在锁内操作）
    // struct tcp_sock *pos, *q;
    // list_for_each_entry_safe(pos, q, &free_list, list) {
    //     list_delete_entry(&pos->list);  // 从链表中移除节点
    //     free_tcp_sock(pos);             // 释放TCP套接字资源
    // }
    // //log(DEBUG,"end_scan");
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);
    tcp_set_state(tsk,TCP_TIME_WAIT);
    
    // Initialize timer fields
    tsk->timewait.type = 0; 
    time_t t = (int)time(NULL);
    tsk->timewait.timeout = t + 2 ; // 2 * MSL 之后超时
    tsk->timewait.enable = 1; 
    //fprintf(stdout, "%lld and %lld.\n", tsk->timewait.timeout,time(NULL));
   
    // Add to the end of timer list
    list_add_tail(&tsk->timewait.list, &timer_list); // 添加到 timer_list 尾部
    //fprintf(stdout, "Added tsk to timer_list: timewait.enable = %d\n", tsk->timewait.enable);
    // log(DEBUG, "Set TIME-WAIT timer for "IP_FMT":%d, timeout=%dus",
    //     NET_IP_FMT_STR(tsk->sk_sip), ntohs(tsk->sk_sport), 
    //     TCP_TIMEWAIT_TIMEOUT);
    pthread_mutex_unlock(&timer_list_lock); // 解锁 

}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
    init_list_head(&timer_list1);
    init_list_head(&timer_list2);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
