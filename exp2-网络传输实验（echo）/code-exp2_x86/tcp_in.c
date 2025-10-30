#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
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

void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
    log(DEBUG,"flags=0x%x",cb->flags);
    fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    // TCP 状态机处理
    switch (tsk->state) {
        case TCP_CLOSED:
            tcp_send_reset(cb);
            break;

        case TCP_LISTEN:
            if (cb->flags & TCP_SYN) {
                struct tcp_sock *csk = alloc_tcp_sock();
                csk->parent = tsk;
                // 设置四元组（注意字节序转换）
                csk->sk_sip = cb->daddr;
                csk->sk_sport = cb->dport;
                csk->sk_dip = cb->saddr;
                csk->sk_dport = cb->sport;
                // 初始化序列号
               // csk->backlog=tsk->backlog;
                csk->iss = tcp_new_iss();
                csk->rcv_nxt = cb->seq_end;
                csk->snd_nxt = csk->iss;
                csk->ref_cnt += 1;
               // csk->snd_wnd	= cb->rwnd;
		       // csk->snd_una	= csk->iss - 1;
                tcp_set_state(csk, TCP_SYN_RECV);
                tcp_hash(csk);
                tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
                list_add_tail(&csk->list, &tsk->listen_queue);
            }
            break;

        case TCP_SYN_RECV:
            if (cb->flags & TCP_ACK) {
                tcp_set_state(tsk, TCP_ESTABLISHED);
                tsk->rcv_nxt = cb->seq_end;
                tcp_update_window_safe(tsk,cb);
                tsk->snd_una = cb->ack;
                tcp_sock_accept_enqueue(tsk);
                wake_up(tsk->parent->wait_accept);
            }
            break;
          
        case TCP_SYN_SENT:
            if ((cb->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && cb->ack == tsk->iss + 1) {
                tsk->rcv_nxt = cb->seq_end;
                tcp_update_window_safe(tsk,cb);
                tsk->snd_una = cb->ack;
                // tsk->rcv_nxt = cb->seq + 1;
                // tsk->snd_una = cb->ack - 1;
                // tsk->snd_wnd = cb->rwnd;
                tcp_set_state(tsk, TCP_ESTABLISHED);
                //wake_up(tsk->wait_connect);
                tcp_send_control_packet(tsk, TCP_ACK);
                //if(tsk->wait_connect->sleep == 1)
				wake_up(tsk->wait_connect);
                break;            
            } else {
                tcp_send_reset(cb);
            }
            // tcp_send_control_packet(tsk, TCP_RST);
	        // tcp_bind_unhash(tsk);
	        // tcp_unhash(tsk);
            break;
        case TCP_ESTABLISHED:
            log(DEBUG,"in established");
            if (cb->pl_len > 0) {
                log(DEBUG,"in if");
                //pthread_mutex_lock(&(tsk->rcv_buf->lock));
                write_ring_buffer(tsk->rcv_buf,cb->payload, cb->pl_len);
                //pthread_mutex_unlock(&(tsk->rcv_buf->lock));//这里假设按序到达
                tsk->rcv_nxt += cb->pl_len;
                tsk->snd_una=cb->ack-1;
                tcp_update_window_safe(tsk,cb);
                fprintf(stdout,"waked up by recv data, length is %d\n",cb->pl_len);
                //if(tsk->wait_recv->sleep ==1)
                wake_up(tsk->wait_recv);
                tcp_send_control_packet(tsk, TCP_ACK);
                // if (ring_buffer_free(tsk->rcv_buf) >= cb->pl_len) {
                //     pthread_mutex_lock(&tsk->rcv_buf->lock);
                //     write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
                //     pthread_mutex_unlock(&tsk->rcv_buf->lock);
        
                //     tsk->rcv_nxt = cb->seq + cb->pl_len;
        
                //     // 通知应用层有数据可读
                //     wake_up(tsk->wait_recv);
                // }
        
                // // 发 ACK 回复
                // tcp_send_control_packet(tsk, TCP_ACK);
            }
            // if (cb->flags & TCP_ACK){
            //     if (cb->ack > tsk->snd_una) {
            //         tsk->snd_una = cb->ack;
            //         tsk->adv_wnd= cb->rwnd;
            //         // 这里可以唤醒等待发送的线程（如果你实现了 wait_send）
            //         wake_up(tsk->wait_send);
            //     }
            // }
            if (cb->flags & TCP_FIN) {
                log(DEBUG,"in to FIN");
                tsk->rcv_nxt = cb->seq_end;
                tcp_update_window_safe(tsk,cb);
                tsk->snd_una = cb->ack;
                tcp_send_control_packet(tsk, TCP_ACK);
                tcp_set_state(tsk, TCP_CLOSE_WAIT);
        
                // 更新 snd_una（仅当接收到 ack）
                if (less_than_32b(tsk->snd_una, cb->ack - 1)) {
                    tsk->snd_una = cb->ack - 1;
                }
        
                // 通知接收线程：对方已关闭连接
                wake_up(tsk->wait_recv);
            }
        
            break;
        
        // case TCP_ESTABLISHED:
        //     if (cb->flags & TCP_FIN) {
        //         tsk->rcv_nxt = cb->seq + 1;
        //         tcp_send_control_packet(tsk, TCP_ACK);
        //         tcp_set_state(tsk, TCP_CLOSE_WAIT);
        //         if(less_than_32b(tsk->snd_una, cb->ack - 1)){
        //             tsk->snd_una = cb->ack - 1;
        //         }
        //         //wake_up(tsk->wait_recv);
        //     }
        //     else{
        //         tcp_send_control_packet(tsk, TCP_FIN);
        //         tcp_set_state(tsk, TCP_CLOSE_WAIT);
        //     }
        //     // 处理数据载荷
        //     if (cb->pl_len > 0) {
        //         if (ring_buffer_free(tsk->rcv_buf) >= cb->pl_len) {
        //             write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
        //             tsk->rcv_nxt = cb->seq + cb->pl_len;
        //             //wake_up(tsk->wait_recv);
        //         }
        //         tcp_send_control_packet(tsk, TCP_ACK);
        //     }
        //     break;
        case TCP_CLOSE_WAIT:
            tcp_send_control_packet(tsk, TCP_FIN);
            //tcp_send_control_packet(tsk, TCP_ACK);
            tcp_set_state(tsk, TCP_LAST_ACK);
            break;

        case TCP_FIN_WAIT_1:
            if (cb->flags & TCP_ACK) {  // 检查是否为对FIN的ACK
            tcp_set_state(tsk, TCP_FIN_WAIT_2);
            }
            break;
        case TCP_FIN_WAIT_2:
            if (cb->flags & (TCP_FIN|TCP_ACK)) {
                tcp_send_control_packet(tsk, TCP_ACK);
                tcp_set_state(tsk,TCP_TIME_WAIT);
                tsk->snd_nxt=cb->ack;//本端已发送序列号等于对端接受到序列号
                tsk->rcv_nxt = cb->seq + 1;
                if(less_than_32b(tsk->snd_una, cb->ack - 1)){
                    tsk->snd_una = cb->ack - 1;
                }
                tcp_set_timewait_timer(tsk);
            }
            break;
        case TCP_LAST_ACK:
            if (cb->flags & TCP_ACK) {
                tcp_set_state(tsk,TCP_CLOSED);
                tcp_unhash(tsk);
                log(DEBUG,"Successfully end");
               // free_tcp_sock(tsk);
            }
            break;
        case TCP_TIME_WAIT:
            sleep_on(tsk->wait_recv);
            tcp_unhash(tsk);
            break;
        default:
            log(ERROR, "Unhandled state: %d", tsk->state);
    }
}
