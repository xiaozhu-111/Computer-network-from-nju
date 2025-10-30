#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
#define BUF_SIZE 30000

// tcp server application, listens to port (specified by arg) and serves only one
// connection request

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

	

// 	FILE *fp = fopen("server-output.dat", "wb");
//    if (!fp) {
//         perror("fopen server-output.dat");
//         return NULL;
//     }
	

//     while (1) {
		
// 		char buffer[BUF_SIZE] = {0};
// 		int bytes_received = tcp_sock_read(csk, buffer, BUF_SIZE);
// 		// if (rlen < 0) {
// 		if (csk->state!=TCP_CLOSE_WAIT) {
// 			// 写入接收到的数据到文件
//             //log(DEBUG,"to write");
// 			fwrite(buffer, 1, bytes_received, fp);
// 			//fflush(fp);
// 		} else {
// 			fwrite(buffer, 1, bytes_received, fp);
// 			//fflush(fp);
// 			break;
// 		}
// 	}
//     //log(DEBUG,"out of while");
//     fclose(fp);
//     fprintf(stdout,"Server closed");

// 	tcp_sock_close(csk);
// 	// log(DEBUG, "file transfer completed, total received: %zu bytes", total_received);

// 	return NULL;
// }

// // tcp client application, connects to server (ip:port specified by arg), each
// // time sends one bulk of data and receives one bulk of data 

// void *tcp_client(void *arg)
// {
// 	struct sock_addr *skaddr = arg;

// 	struct tcp_sock *tsk = alloc_tcp_sock();

// 	if (tcp_sock_connect(tsk, skaddr) < 0) {
// 		fprintf(stdout,"TCP connection fail.\n");
// 		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
// 				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
// 		exit(1);
// 	}

	
// 	char buf[1000];
// 	// char buffer[10000];
//     // size_t total_sent = 0;
//     // size_t read_len = 0;
//     // while(1){
//     //     read_len=fread(buffer, 1, sizeof(buffer), input_file);
//     //     if(read_len<=0)
//     //         break;
//     //     int sent = tcp_sock_write(tsk, buffer, read_len);
//     //     if (sent < 0) {
//     //         log(ERROR, "write error occurred");
//     //         break;
//     //     }
//     //     total_sent += sent;
//     //     log(DEBUG, "sent %d bytes, total %zu bytes", sent, total_sent);
//     //     usleep(100000); // 每发送一次暂停10ms（根据测试调整）
//     // }
// 	FILE *fp = fopen("client-input.dat", "rb");
//     if (!fp) {
//         perror("fopen client-input.dat");
//         return NULL;
//     }
// 	int len;
// 	int sent, n;
//     while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
//         sent = 0;
//         while (sent < len) {
//             n = tcp_sock_write(tsk, buf + sent, len - sent);
//             if (n <= 0) {
// 				//log(ERROR, "write error occurred");
// 				break;
// 			}
//             sent += n;
//         }
//     }

//     fclose(fp);
//     sleep(1);
//     // 关闭连接（Python 代码是主动关闭，不需要等待服务器）
//     tcp_sock_close(tsk);

// 	return NULL;
// }

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

	//my code
	//char buf[1000];

	FILE *fp = fopen("server-output.dat", "wb");
    if (!fp) {
        perror("fopen server-output.dat");
        return;
    }
	// int len;

    // while ((len = tcp_sock_read(tsk, buf, sizeof(buf))) > 0) {
    //     fwrite(buf, 1, len, fp);
    // }

    while (1) {
		//a++;
		char buffer[30000] = {0};
		int bytes_received = tcp_sock_read(csk, buffer, 30000);
		if (csk->state!=TCP_CLOSE_WAIT) {
			fwrite(buffer, 1, bytes_received, fp);
		} else {
			fwrite(buffer, 1, bytes_received, fp);
			break;
		}
	}
    
    fclose(fp);
    fprintf(stdout,"Server closed");

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		fprintf(stdout,"TCP connection fail.\n");
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	//my code
	char buf[1000];
	FILE *fp = fopen("client-input.dat", "rb");
    if (!fp) {
        perror("fopen client-input.dat");
        return;
    }
	int len;

    while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
        int sent = 0;
        while (sent < len) {
            int n = tcp_sock_write(tsk, buf + sent, len - sent);
            if (n <= 0) break;
            sent += n;
        }
    }

    fclose(fp);
    sleep(1);
    // 主动关闭连接（发送 FIN）
    tcp_sock_close(tsk);

	return NULL;
}

/*
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
	
    tcp_sock_close(csk);
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
	
    tcp_sock_close(tsk);
    return NULL;
}


// tcp server application, listens to port (specified by arg) and serves only one
// connection request
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
	sleep(5);
	//if(flag==1)
	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}
	
	sleep(1);
	// log(DEBUG, "client ready to close.");
	// flag=1;
	tcp_sock_close(tsk);


	return NULL;
}
*/