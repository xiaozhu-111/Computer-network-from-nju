#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
//int flag=0;
void *tcp_server(void *arg)
{
    u16 port = *(u16 *)arg;
    struct tcp_sock *tsk = alloc_tcp_sock();

    struct sock_addr addr;
    addr.ip = htonl(0);
    addr.port = port;
    if (tcp_sock_bind(tsk, &addr) < 0) {
        log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
        exit(1);
    }

    if (tcp_sock_listen(tsk, 3) < 0) {
        log(ERROR, "tcp_sock listen failed");
        exit(1);
    }

    log(DEBUG, "listen to port %hu.", ntohs(port));

    struct tcp_sock *csk = tcp_sock_accept(tsk);

    log(DEBUG, "accept a connection.");
    
    char rbuf[1001];
    char wbuf[1100]; // Enough space for prefix + received data
    int rlen = 0;
    while (1) {
        rlen = tcp_sock_read(csk, rbuf, 1000);
        if (rlen <= 0) {
            log(DEBUG, "tcp_sock_read return negative value, finish transmission.");
            break;
        } 
        else if (rlen > 0) {
            rbuf[rlen] = '\0';
            // Prepare response with prefix
            //log(DEBUG,"rbuf1: %s",rbuf);
            sprintf(wbuf, "server echoes: %s", rbuf);
            log(DEBUG,"rbuf2: %s",rbuf);
			log(DEBUG,"wbuf: %s",wbuf);
            tcp_sock_write(csk, wbuf, strlen(wbuf));
        }
    }

    log(DEBUG, "close this connection.");
	// if(ring_buffer_empty(tsk->rcv_buf)){
	// 	log(DEBUG,"ending");
     	tcp_sock_close(csk);
    // }
    return NULL;
}

void *tcp_client(void *arg)
{
    struct sock_addr *skaddr = arg;
    struct tcp_sock *tsk = alloc_tcp_sock();

    if (tcp_sock_connect(tsk, skaddr) < 0) {
        log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
                NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
        exit(1);
    }

    char data[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char rbuf[1100]; // Enough space for server response
    
    // Send data 5-10 times with rotated strings
    for (int i = 0; i < 5; i++) {  // Changed to 5 iterations as minimum
        log(DEBUG,"into write");
		// Rotate the string
		log(DEBUG,"%s",data);
		tcp_sock_write(tsk, data, strlen(data));
        char first_char = data[0];
        memmove(data, data+1, strlen(data)-1);
        data[strlen(data)-1] = first_char;
       // tcp_sock_write(tsk, data, strlen(data));
        log(DEBUG,"%s",data);
        log(DEBUG,"out of write");
        // Read server response
        int rlen = tcp_sock_read(tsk, rbuf, sizeof(rbuf)-1);
        if (rlen > 0) {
            rbuf[rlen] = '\0';
            printf("%s\n", rbuf);
        }
        
        sleep(1);
    }
	// if(ring_buffer_empty(tsk->rcv_buf)){
	// 	log(DEBUG,"ending");
     	tcp_sock_close(tsk);
    // }
    return NULL;
}


// // tcp server application, listens to port (specified by arg) and serves only one
// // connection request
// void *tcp_server(void *arg)
// {
// 	u16 port = *(u16 *)arg;
// 	struct tcp_sock *tsk = alloc_tcp_sock();

// 	struct sock_addr addr;
// 	addr.ip = htonl(0);
// 	addr.port = port;
// 	if (tcp_sock_bind(tsk, &addr) < 0) {
// 		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
// 		exit(1);
// 	}

// 	if (tcp_sock_listen(tsk, 3) < 0) {
// 		log(ERROR, "tcp_sock listen failed");
// 		exit(1);
// 	}

// 	log(DEBUG, "listen to port %hu.", ntohs(port));

// 	struct tcp_sock *csk = tcp_sock_accept(tsk);

// 	log(DEBUG, "accept a connection.");
// 	// int i=0;
// 	// while(1){
// 	// 	char buf[1024];  // 接收数据缓冲区
// 	//  	int len = recv(tsk->rcv_buf, buf, sizeof(buf) - 1, 0);
// 	// 	if (len > 0) {
//     // 		buf[len] = '\0';  // 添加字符串结束符
//    	// 		char reply[2048];
//     // 	snprintf(reply, sizeof(reply), "server echoes: %s", buf);
//    	// 	tcp_send_data_packet(tsk, reply, strlen(reply));
// 	// 	} else {
//     // // 客户端关闭连接或出错，退出循环
//     // 	break;
// 	// 	}
// 	// 	++i;
// 	// }
// 	sleep(5);
// 	//if(flag==1)
// 	tcp_sock_close(csk);
	
// 	return NULL;
// }

// // tcp client application, connects to server (ip:port specified by arg), each
// // time sends one bulk of data and receives one bulk of data 
// void *tcp_client(void *arg)
// {
// 	struct sock_addr *skaddr = arg;

// 	struct tcp_sock *tsk = alloc_tcp_sock();

// 	if (tcp_sock_connect(tsk, skaddr) < 0) {
// 		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
// 				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
// 		exit(1);
// 	}
	
// 	const char *str1="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
// 	const char *str2="123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0";
// 	const char *str3="23456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01";
// 	const char *str4="3456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012";
// 	const char *str5="456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123";
// 	const char *str6="56789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234";
// 	// if(tsk->state==TCP_ESTABLISHED)
// 	// tcp_send_data_packet(tsk, str1, strlen(str1));
// 	// //printf("server echoes: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n");
// 	// //while(tsk->state==TCP_ESTABLISHED){
// 	// tcp_send_data_packet(tsk, str2, strlen(str2));
// 	// //printf("server echoes: 123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0\n");

// 	// tcp_send_data_packet(tsk, str3, strlen(str3));
// 	// //printf("server echoes: 23456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01\n");

// 	// tcp_send_data_packet(tsk, str4, strlen(str4));
// 	// //printf("server echoes: 3456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012\n");

// 	// tcp_send_data_packet(tsk, str5, strlen(str5));
// 	// //printf("server echoes: 456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123\n");

// 	// tcp_send_data_packet(tsk, str6, strlen(str6));
// 	// //printf("server echoes: 56789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234\n");
// 	// // break;
// 	// // }
// 	sleep(1);
// 	// log(DEBUG, "client ready to close.");
// 	flag=1;
// 	tcp_sock_close(tsk);


// 	return NULL;
// }
