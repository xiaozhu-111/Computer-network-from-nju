#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "list.h"
#include "log.h"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static struct list_head timer_list;
static pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

void tcp_scan_timer_list()
{
    struct tcp_sock *to_free[1024];  // 可换成链表或动态数组
    int count = 0;

    pthread_mutex_lock(&timer_list_lock);
    
    struct tcp_timer *timer, *tmp;
    list_for_each_entry_safe(timer, tmp, &timer_list, list) {
        if (!timer->enable)
            continue;

        //timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
        time_t t = (int)time(NULL);
        // if ((timer->timeout-t- TCP_TIMER_SCAN_INTERVAL) > 0){
        //    // wake_up(tsk->wait_recv);
        //     continue;
        // }
        struct tcp_sock *tsk = timewait_to_tcp_sock(timer);
        // if (timer->type == 0) {
        //     log(DEBUG, "Freeing TIME-WAIT sock "IP_FMT":%d",
        //         NET_IP_FMT_STR(tsk->sk_sip), ntohs(tsk->sk_sport));
        //     list_delete_entry(&timer->list);
        //     to_free[count++] = tsk;  // 记录，暂不释放
        // }
       // log(DEBUG,"%d",timer->timeout);
        if(timer->timeout<t && tsk->state!=TCP_CLOSED){
            tcp_set_state(tsk, TCP_CLOSED);
            wake_up(tsk->wait_recv);
            break;
        }
    }
    pthread_mutex_unlock(&timer_list_lock);

    // for (int i = 0; i < count; ++i) {
    //     free_tcp_sock(to_free[i]);  // 解锁后再释放
    // }
}

void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
    pthread_mutex_lock(&timer_list_lock);
    
    // Initialize timer fields
    tsk->timewait.type = 0; // time-wait type
    time_t t = (int)time(NULL);
    tsk->timewait.timeout = t+2;
    tsk->timewait.enable = 1;
    init_list_head(&tsk->timewait.list);
    
    // Add to the end of timer list
    list_add_tail(&tsk->timewait.list, &timer_list);
    
    log(DEBUG, "Set TIME-WAIT timer for "IP_FMT":%d, timeout=%dus",
        NET_IP_FMT_STR(tsk->sk_sip), ntohs(tsk->sk_sport), 
        TCP_TIMEWAIT_TIMEOUT);

    pthread_mutex_unlock(&timer_list_lock);
}

void *tcp_timer_thread(void *arg)
{
    init_list_head(&timer_list);
    while (1) {
        usleep(TCP_TIMER_SCAN_INTERVAL);
        tcp_scan_timer_list();
    }
    return NULL;
}

// #include "tcp.h"
// #include "tcp_timer.h"
// #include "tcp_sock.h"

// #include <stdio.h>
// #include <unistd.h>

// static struct list_head timer_list;

// // scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
// void tcp_scan_timer_list()
// {
// 	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
// }

// // set the timewait timer of a tcp sock, by adding the timer into timer_list
// void tcp_set_timewait_timer(struct tcp_sock *tsk)
// {
// 	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
// }

// // scan the timer_list periodically by calling tcp_scan_timer_list
// void *tcp_timer_thread(void *arg)
// {
// 	init_list_head(&timer_list);
// 	while (1) {
// 		usleep(TCP_TIMER_SCAN_INTERVAL);
// 		tcp_scan_timer_list();
// 	}

// 	return NULL;
// }
