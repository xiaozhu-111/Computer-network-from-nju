#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"
#include<list.h>
#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
    
    fprintf(stdout, "TODO:tcp_update_window\n");
    // 1. 记录更新前是否有足够的发送窗口
    int before = tcp_tx_window_test(tsk);
    fprintf(stdout, "window_test 1st\n");
    // 2. 更新 snd_una、adv_wnd、cwnd、snd_wnd
    tsk->snd_una = cb->ack;
    tsk->adv_wnd = cb->rwnd;

    // cwnd 暂时设置为一个极大值，表示不做拥塞控制限制
    tsk->cwnd = 0x7f7f7f7f;

    // snd_wnd 是发送窗口大小，取 adv_wnd 和 cwnd 的较小值
    tsk->snd_wnd = (tsk->adv_wnd < tsk->cwnd) ? tsk->adv_wnd : tsk->cwnd;

    // 3. 检查更新后是否窗口足够发送
    int after = tcp_tx_window_test(tsk);
    fprintf(stdout, "window_test 2nd\n");
    // 4. 如果窗口从“不能发”变为“可以发”，唤醒 wait_send 队列
    if (!before && after) {
        fprintf(stdout, "0turn to 1\n");
        wake_up(tsk->wait_send);
    }
    if (before && !after) {
        // 窗口从可发送（>= MSS）变为不可发送（< MSS）
        fprintf(stdout, "*****************tcp_set_persist_timer##########\n");
        tcp_set_persist_timer(tsk);
    } else if (!before && after) {
        // 窗口从不可发送恢复为可发送
        fprintf(stdout, "*******************tcp_unset_persist_timer##########\n");
        tcp_unset_persist_timer(tsk);
    }
    fprintf(stdout, "tcp_tx_window_text finish\n");
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

//自创函数
// void process_incoming_data(struct tcp_sock *tsk, void *data, int len) {
//     fprintf(stdout, "process-1\n");
//     if (len <= 0) return;
//     fprintf(stdout, "process-12\n");
//     // 将数据复制到 TCP 连接的接收缓冲区
//     memcpy(tsk->rcv_buf + tsk->rcv_wnd, data, len);
//     tsk->rcv_wnd += len;  // 更新接收窗口大小
//     //tcp_update_window_safe(tsk, cb);
//     fprintf(stdout, "process-2\n");

//     // 唤醒等待数据的进程（比如调用 recv() 的进程）
//     wake_up(tsk->wait_recv);

//     // 发送 ACK 确认收到数据
//     tcp_send_control_packet(tsk, TCP_ACK);
// }

/*
void tcp_transmit_pending(struct tcp_sock *tsk) {
    fprintf(stdout, "Transmitting pending data...\n");
    
    struct tcp_packet *pkt;
    while (!list_empty(&tsk->send_buf)) {
        pkt = list_entry(tsk->send_buf.next, struct tcp_packet, list);
        list_del(&pkt->list);  // **从缓冲区移除**
        tcp_send_packet(tsk, pkt);
        free(pkt);  // **释放已发送的数据包**
    }

    // **如果发送完，唤醒等待的进程**
    wake_up(tsk->wait_send);
}
*/

//void tcp_scan_timer_list();
// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    pthread_mutex_lock(&tsk->sk_lock);

	//初始代码
    log(DEBUG, "Tcp_sock_process cb->flags = 0x%x",cb->flags);
    // fprintf(stdout, "cb->flags = 0x%x\n", cb->flags);
    // fprintf(stdout, "ACK = 0x%x\n", TCP_ACK);
    // fprintf(stdout, "FIN = 0x%x\n", TCP_FIN);

	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// struct in_addr addr_s, addr_d;
    // addr_s.s_addr = tsk->sk_sip;
    // addr_d.s_addr = tsk->sk_dip;
    // fprintf(stdout, "Source: %s:%u -> Dest: %s:%u\n",
    //     inet_ntoa(addr_s), ntohs(tsk->sk_sport),
    //     inet_ntoa(addr_d), ntohs(tsk->sk_dport));
    // struct in_addr src_ip, dst_ip;
    // src_ip.s_addr = cb->saddr;
    // dst_ip.s_addr = cb->daddr;

    // fprintf(stdout, "----- TCP Callback Info -----\n");
    // fprintf(stdout, "Source IP: %s\n", inet_ntoa(src_ip));
    // fprintf(stdout, "Dest IP:   %s\n", inet_ntoa(dst_ip));
    // fprintf(stdout, "Source Port: %u\n", ntohs(cb->sport));
    // fprintf(stdout, "Dest Port:   %u\n", ntohs(cb->dport));

    
	 // 如果是关闭状态，直接丢弃包
     if (tsk->state == TCP_CLOSED) {
        fprintf(stdout, "process1\n");
        pthread_mutex_unlock(&tsk->sk_lock);
        return;
    }

    // 处理各状态下的 TCP 连接
    switch (tsk->state) {
        case TCP_LISTEN:
            // 监听状态下收到 SYN 包，表示有连接请求，回复 SYN-ACK
            fprintf(stdout, "process2\n");
            if (cb->flags & TCP_SYN) {
                fprintf(stdout, "Received SYN, creating child socket.\n");

                // **创建新的子 socket**
                struct tcp_sock *new_tsk = alloc_tcp_sock();
                new_tsk->sk_sip = cb->daddr;
                new_tsk->sk_dip = cb->saddr;
                new_tsk->sk_sport = cb->dport;
                new_tsk->sk_dport = cb->sport;
                new_tsk->parent = tsk;
                fprintf(stdout, "process3\n");
                // **绑定新 socket 到 `established_table`**
                tcp_set_state(new_tsk,TCP_SYN_RECV);
                //new_tsk->state = TCP_SYN_RECV;
                if (tcp_hash(new_tsk) < 0) {
                    fprintf(stderr, "Failed to register new socket.\n");
                    free(new_tsk);
                    return;
                }
                list_add_tail(&new_tsk->list,&tsk->listen_queue);
                //tcp_sock_accept_enqueue(tsk);
                // **更新子 socket 状态**
                //new_tsk->state = TCP_SYN_RECV;
                fprintf(stdout, "process41\n");
                // **发送 SYN+ACK**
                new_tsk->snd_nxt = tcp_new_iss();
                new_tsk->rcv_nxt = cb->seq+1;
                tcp_send_control_packet(new_tsk, TCP_SYN | TCP_ACK);
                fprintf(stdout, "process4\n");
                
                
            }
            break;
            // if (cb->flags & TCP_SYN && !(cb->flags & TCP_ACK)) {
            //     // 回复 SYN+ACK 包，进入 SYN_RECV 状态
            //     fprintf(stdout, "process3\n");
            //     tcp_send_control_packet(tsk, TCP_SYN | TCP_ACK);
            //     fprintf(stdout, "process4\n");
            //     tsk->state = TCP_SYN_RECV;
            // }
            // break;

        case TCP_SYN_RECV:
            // 在 SYN_RECV 状态下，如果收到 ACK 包，则说明连接建立
            fprintf(stdout, "process5\n");
            if (cb->flags & TCP_ACK) {
                // 完成三次握手，进入 ESTABLISHED 状态
                tcp_set_state(tsk,TCP_ESTABLISHED);
                
                
                //tsk->state = TCP_ESTABLISHED;
                // 发送 ACK，完成三次握手
                fprintf(stdout, "process6\n");
                //tcp_send_control_packet(tsk,TCP_SYN | TCP_ACK);
                fprintf(stdout, "process7\n");
                // 通知等待连接的进程（如 sleep_on）
                // **从 listen_queue 移动到 accept_queue**
                //list_del(&tsk->list);
                //list_delete_entry(&tsk->list);
                tcp_sock_accept_enqueue(tsk);

                // **现在再唤醒 accept()**
                wake_up(tsk->parent->wait_accept);
                /*
                tcp_sock_accept_enqueue(tsk);
                wake_up(tsk->wait_accept);
                
                wake_up(tsk->wait_connect);
                */
            }
            break;

        case TCP_SYN_SENT:
            // 在 SYN_SENT 状态下，收到 SYN+ACK 包，表示三次握手中的第二步完成
            fprintf(stdout, "process8\n");

            if (cb->flags & TCP_SYN && cb->flags & TCP_ACK) {
                // 完成三次握手，进入 ESTABLISHED 状态
                tcp_set_state(tsk,TCP_ESTABLISHED);

                //初始化snd_wnd
                if (cb->rwnd > 0) {
                    fprintf(stdout, "update snd_wnd\n");
                    tsk->snd_wnd = cb->rwnd;
                    //wake_up(tsk->wait_send);
                }


                //tsk->state = TCP_ESTABLISHED;
                // 发送 ACK 包，完成三次握手
                fprintf(stdout, "process9\n");
                tsk->rcv_nxt=cb->seq+1;
                tcp_send_control_packet(tsk, TCP_ACK);//RCV-NXT
                fprintf(stdout, "process10\n");
                // 通知等待连接的进程（如 sleep_on）
                
                wake_up(tsk->wait_connect);
            }
            break;

        case TCP_ESTABLISHED:
            fprintf(stdout, "process11\n");
            // 在 ESTABLISHED 状态下，收到 FIN 包，表示对方关闭连接
            if (cb->flags & TCP_FIN) {
                // 进入 CLOSE_WAIT 状态，等待关闭
                tcp_set_state(tsk,TCP_CLOSE_WAIT);
                //tsk->state = TCP_CLOSE_WAIT;
                fprintf(stdout, "process12\n");
                // 发送 ACK 确认收到 FIN 包
                //tsk->snd_nxt = tcp_new_iss();
                if (tsk->rcv_nxt == cb->seq && cb->pl_len>0) {
                    // 将数据写入接收缓冲区
                    fprintf(stdout, "%d Receive data\n",cb->pl_len);
                    log(DEBUG, "Received data, writing to ring buffer\n");
                    write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
                    tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
                }

                //初始化snd_wnd
                tsk->rcv_nxt = cb->seq+1;
                //tcp_send_control_packet(tsk, TCP_ACK);
                int que = wake_up(tsk->wait_recv1);
                tcp_unset_retrans_timer(tsk);
                break;
            }
            if (cb->pl_len > 0 && cb->pl_len!=1) {

                log(DEBUG, "Receiving data\n");
                u32 seg_seq = cb->seq;
                u32 seg_seq_end = cb->seq_end;

                if (!less_than_32b(tsk->rcv_nxt, seg_seq_end)) {
                    // 忽略已确认数据
                    fprintf(stdout, "have Received data\n");
                    tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
                    tcp_send_control_packet(tsk, TCP_ACK);
                    //return;
                }
                // 情况 2：正好是我们期望的字节
                else if (tsk->rcv_nxt == seg_seq) {
                    // 将数据写入接收缓冲区
                    //fprintf(stdout, "Received data, writing to ring buffer\n");
                    log(DEBUG, "Received data, writing to ring buffer\n");
                    fprintf(stdout,"%d,qqqqqqqq\n",ring_buffer_free(tsk->rcv_buf));
                    tcp_recv_ofo_buffer_add_packet(tsk,cb);
                    tcp_send_control_packet(tsk, TCP_ACK);
                    //wake_up(tsk->wait_recv1);
                    
                }
                // 情况 3：乱序到达，未来要处理 out-of-order，这里先直接 ACK 丢弃
                else if (less_than_32b(tsk->rcv_nxt, seg_seq)) {
                    // 数据暂时丢弃（将来用 rcv_ofo_buf），仍然 ACK 告诉我现在想要哪个字节
                    fprintf(stdout, "discard\n");
                    tcp_recv_ofo_buffer_add_packet(tsk,cb);
                    tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
                    tcp_send_control_packet(tsk, TCP_ACK);
                    //return;
                }
            
                // 其他情况（可能错误）打印警告
                else{
                    fprintf(stderr, "Unexpected segment seq: seg_seq = %u, rcv_nxt = %u\n", seg_seq, tsk->rcv_nxt);
                }
            }
            else if((cb->flags & TCP_ACK) && cb->pl_len==1)
            {
                fprintf(stdout,"receive probe\n");
                wake_up(tsk->wait_recv);
                
                tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);

                tcp_send_control_packet(tsk,TCP_ACK);
                fprintf(stdout,"receive probe finish\n");
                
            }
            if(cb->flags & TCP_ACK && tsk->sk_sip == htonl(inet_addr("10.0.0.2")) )// && cb->flags & TCP_PSH)
            {
                fprintf(stdout, "process1002\n");
                tcp_update_send_buffer(tsk,cb->ack);
                tcp_update_retrans_timer(tsk);
                
                tcp_update_window_safe(tsk,cb);
            }

            if(cb->flags & TCP_ACK && cb->pl_len==0 && tsk->sk_sip == htonl(inet_addr("10.0.0.1")))// && cb->flags & TCP_PSH)
            {
                fprintf(stdout, "process1001\n");
                tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
                tcp_send_control_packet(tsk, TCP_ACK);
            }
            break;

        // case TCP_CLOSE_WAIT:
        //     // 在 CLOSE_WAIT 状态下，主动关闭连接
        //     fprintf(stdout, "process16\n");
        //     if (list_empty(&tsk->send_buf)) {
        //         tcp_set_state(tsk, TCP_LAST_ACK);
        //         tcp_send_control_packet(tsk, TCP_FIN);
        //     }
            
        //     // if (1) {//cb->flags & TCP_FIN
        //     //     // 进入 LAST_ACK 状态，发送 FIN 包
        //     //     tcp_set_state(tsk,TCP_LAST_ACK);
        //     //     //tsk->state = TCP_LAST_ACK;
        //     //     fprintf(stdout, "process17\n");
        //     //     tcp_send_control_packet(tsk, TCP_FIN);
        //     //     fprintf(stdout, "process16\n");
        //     // }
        //     break;

        case TCP_LAST_ACK:
            // 在 LAST_ACK 状态下，收到 ACK 包，表示连接被对方关闭
            
            fprintf(stdout, "process19\n");
            if (cb->flags & TCP_ACK) {
                // 完成关闭，进入 CLOSED 状态
                //tsk->state = TCP_CLOSED;
                tcp_set_state(tsk,TCP_CLOSED);

                // 唤醒等待的进程
                fprintf(stdout, "process20\n");
                wake_up(tsk->wait_recv);
                fprintf(stdout, "process21\n");
            }
            break;

        case TCP_FIN_WAIT_1:
            // 在 FIN_WAIT_1 状态下，收到对方的 FIN 包，表示对方准备关闭连接
            fprintf(stdout, "cb->flags = 0x%x\n", cb->flags);
            fprintf(stdout, "ACK|FIN = 0x%x\n", TCP_ACK | TCP_FIN);
            fprintf(stdout, "SYN|FIN = 0x%x\n", TCP_SYN | TCP_FIN);
            fprintf(stdout, "ACK|SYN = 0x%x\n", TCP_ACK | TCP_SYN);
            fprintf(stdout, "process22\n");
            if (cb->flags & TCP_ACK) {
                // 进入 FIN_WAIT_2 状态
                //tsk->state = TCP_FIN_WAIT_2;
                tcp_set_state(tsk,TCP_FIN_WAIT_2);
                // 发送 ACK 包
                fprintf(stdout, "process23\n");
                //tcp_send_control_packet(tsk, TCP_ACK);
                fprintf(stdout, "process24\n");
            }

            if (cb->flags & TCP_FIN)
            {
                //tcp_set_state(tsk,TCP_FIN_WAIT_2);
                fprintf(stdout, "process2896\n");
                tsk->rcv_nxt=cb->seq+1;
                tcp_send_control_packet(tsk, TCP_ACK);
                //tcp_set_state(tsk,TCP_TIME_WAIT);
                tcp_set_timewait_timer(tsk);
                while(tsk->state!=TCP_CLOSED)
                {
                    //fprintf(stdout, "&&&in_timewait.enable = %d\n", tsk->timewait.enable);
                    //fprintf(stdout, "&&&in_timewait.timeout = %lld\n", tsk->timewait.timeout);
                    
                    usleep(TCP_TIMER_SCAN_INTERVAL);
                    //fprintf(stdout, "wait for closed\n");
                }
            }
            
            break;

        case TCP_FIN_WAIT_2:
            fprintf(stdout, "cb->flags = 0x%x\n", cb->flags);
            // 在 FIN_WAIT_2 状态下，接收到对方的 FIN 包，表示连接关闭完成
            fprintf(stdout, "process25\n");
            if (cb->flags & TCP_ACK)
            {
                fprintf(stdout, "fin_waite_2 receive ack\n");
            }
            if (cb->flags & TCP_FIN) {
                // 进入 CLOSING 状态
                fprintf(stdout, "process26\n");
                tcp_send_control_packet(tsk, TCP_ACK);
                //tcp_set_state(tsk,TCP_TIME_WAIT);
                tcp_set_timewait_timer(tsk);
                //tsk->state = TCP_CLOSING;
                // 创建定时器线程（只创建一次）
                // pthread_t timer_thread;
                // int timer_thread_started = 0;

                // if (!timer_thread_started) {
                //     fprintf(stdout, "Starting TCP timer thread.\n");
                //     pthread_create(&timer_thread, NULL, (void *)tcp_scan_timer_list, NULL);
                //     timer_thread_started = 1;  // 标记线程已启动，避免重复创建
                // }
                while(tsk->state!=TCP_CLOSED)
                {
                    //fprintf(stdout, "&&&in_timewait.enable = %d\n", tsk->timewait.enable);
                    //fprintf(stdout, "&&&in_timewait.timeout = %lld\n", tsk->timewait.timeout);
                    
                    usleep(TCP_TIMER_SCAN_INTERVAL);
                    //fprintf(stdout, "wait for closed\n");
                }
                

            }
            break;

        case TCP_CLOSING:
            // 在 CLOSING 状态下，如果接收到对方的 FIN 包，表示双方完成了四次挥手
            fprintf(stdout, "process27\n");
            if (cb->flags & TCP_FIN) {
                // 进入 TIME_WAIT 状态
                tcp_set_state(tsk,TCP_TIME_WAIT);
                //tsk->state = TCP_TIME_WAIT;
                // 发送 ACK 包
                fprintf(stdout, "process28\n");
                tcp_send_control_packet(tsk, TCP_ACK);
                fprintf(stdout, "process29\n");
                // 设置 TIME_WAIT 计时器
                tcp_set_timewait_timer(tsk);
            }
            break;

        case TCP_TIME_WAIT:
            fprintf(stdout, "process30\n");
            tcp_set_timewait_timer(tsk);
            // 在 TIME_WAIT 状态下，不需要做任何操作，等待超时
            break;

        default:
            // 不支持的状态
            fprintf(stdout, "process31\n");
            break;
    }
    pthread_mutex_unlock(&tsk->sk_lock);
}
