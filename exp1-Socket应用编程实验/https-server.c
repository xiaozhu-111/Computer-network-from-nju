#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <pthread.h>
#include <stdlib.h>
#include <ctype.h>

void parse_http_request(const char *request, char *filepath, int *start, int *end) {
    // sscanf(request, "GET %s ", filepath);
    // *start=0;
    // *end=-1;
    // // 处理 Range 请求头
    // char *range = strstr(request, "Range: bytes=");
    // if (range) {
    //     range += strlen("Range: bytes=");
    //     *start = atoi(range);
    //     char *dash = strchr(range, '-');
    //     if (dash) {
    //         if (*(dash + 1) != '\0')
    //             *end = atoi(dash + 1);
    //         else
    //             *end = -1; // 代表到文件结尾
    //     }
    // }


    sscanf(request, "GET %s HTTP", filepath);
    // 查找 Range 头部
    char *range = strstr(request, "Range: bytes=");
    if (range) {
        range += strlen("Range: bytes=");
        char *dash = strchr(range, '-');

        if (dash) {
            *dash = '\0';  // 暂时把 `-` 变成字符串终止符
            *start = atoi(range);  // 解析 `start`
            *dash = '-';  // 恢复 `-`
            
            if (*(dash + 1) != '\0'&& isdigit(*(dash + 1)))//最终改了这个才通过了最后一个测试集
                *end = atoi(dash + 1);
            else
                *end = -1;  // 代表到文件结尾
        } else {
            *start = atoi(range);
            *end = -1;  // 只有起始值，没有结束值
        }
    } 
    else {
        *start = 0;
        *end = -1;  // 没有 Range 头部，读取整个文件
    }
}
// ========== HTTP 服务器（监听 80 端口）==========
void handle_http_request(int client) {
	char buffer[1024] = {0};
    read(client, buffer, sizeof(buffer));

    // 获取请求路径
    char path[256] = "/";
    sscanf(buffer, "GET %s ", path);

    char redirect_response[512];
    snprintf(redirect_response, sizeof(redirect_response),
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Location: https://10.0.0.1%s\r\n"
        "Content-Length: 0\r\n\r\n", path);

    send(client, redirect_response, strlen(redirect_response), 0);
    close(client);
}
// ========== HTTPS 服务器（监听 443 端口）==========
void handle_https_request(SSL* ssl) {
	if (SSL_accept(ssl) == -1) {
        perror("SSL_accept failed");
        return;
    }

    char buf[2048] = {0};
    SSL_read(ssl, buf, sizeof(buf));

    char filepath[256] = {0};
    int start = 0, end = -1;
    parse_http_request(buf, filepath, &start, &end);
	//printf("Parsed range: start=%d, end=%d\n", start, end);

    if (strcmp(filepath, "/") == 0) {
        strcpy(filepath, "index.html");
    } else {
        memmove(filepath, filepath + 1, strlen(filepath));
    }

    FILE *file = fopen(filepath, "rb");
    if (!file) {
        const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\n404 Not Found";
        SSL_write(ssl, not_found, strlen(not_found));
    } else {
        fseek(file, 0, SEEK_END);
        long filesize = ftell(file);
        rewind(file);

        if (end == -1 || end >= filesize) {
            end = filesize - 1;  // 确保 end 不会超出文件大小
        } else if (end < start) {
            end = start;  // 避免 end 小于 start
        }
        int content_length = end - start + 1;

        char header[256];
        if (start > 0 || end < filesize - 1) {
            snprintf(header, sizeof(header),
                     "HTTP/1.1 206 Partial Content\r\n"
                     "Content-Range: bytes %d-%d/%ld\r\n"
                     "Content-Length: %d\r\n\r\n",
                     start, end, filesize, content_length);
        } else {
            snprintf(header, sizeof(header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Length: %ld\r\n\r\n", filesize);
        }
		//printf("Requested range: %d-%d, File size: %ld, Content length: %d\n", start, end, filesize, content_length);

        SSL_write(ssl, header, strlen(header));
        //printf("Response Headers:\n%s\n", header);//用于验证
        fseek(file, start, SEEK_SET);
        // char *file_content = malloc(content_length);
        // fread(file_content, 1, content_length, file);
        char *file_content = malloc(content_length);
        fseek(file, start, SEEK_SET);
        size_t bytes_read = fread(file_content, 1, content_length, file);
        if (bytes_read != content_length) {
            printf("Warning: Only read %ld bytes, expected %d bytes\n", bytes_read, content_length);
        }
        fclose(file);

        SSL_write(ssl, file_content, content_length);
        free(file_content);
    }
	
    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

void *start_http_server(void *arg) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("HTTP socket creation failed");
        return NULL;
    }

    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(80);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("HTTP bind failed");
        return NULL;
    }

    listen(sock, 10);
    printf("HTTP server listening on port 80...\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr*)&client_addr, &len);
        if (client < 0) {
            perror("HTTP accept failed");
            continue;
        }
        handle_http_request(client);
    }

    close(sock);
    return NULL;
}


void *start_https_server(void *arg) {
    SSL_CTX *ctx = (SSL_CTX *)arg;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("HTTPS socket creation failed");
        return NULL;
    }

    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(443);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("HTTPS bind failed");
        return NULL;
    }

    listen(sock, 10);
    printf("HTTPS server listening on port 443...\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr*)&client_addr, &len);
        if (client < 0) {
            perror("HTTPS accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        handle_https_request(ssl);
    }

    close(sock);
    return NULL;
}

int main()
{
	pthread_t http_thread, https_thread;

    // 初始化 SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL cert or key load failed");
        exit(1);
    }

    // 创建 HTTP 和 HTTPS 线程
    pthread_create(&http_thread, NULL, start_http_server, NULL);
    pthread_create(&https_thread, NULL, start_https_server, ctx);

    pthread_join(http_thread, NULL);
    pthread_join(https_thread, NULL);

    SSL_CTX_free(ctx);
    return 0;


	// pthread_t http_thread, https_thread;//传出参数，用于获得线程的ID
    // pthread_create(&http_thread, NULL, start_http_server, NULL);//第三个参数：函数指针，线程开始执行的函数
    // pthread_create(&https_thread, NULL, start_https_server, NULL);//第四个参数：传递给线程的参数

	// // init SSL Library
	// SSL_library_init();
	// OpenSSL_add_all_algorithms();
	// SSL_load_error_strings();

	// // enable TLS method
	// const SSL_METHOD *method = TLS_server_method();
	// SSL_CTX *ctx = SSL_CTX_new(method);

	// // load certificate and private key
	// if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
	// 	perror("load cert failed");
	// 	exit(1);
	// }
	// if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
	// 	perror("load prikey failed");
	// 	exit(1);
	// }

	// // init socket, listening to port 443
	// int sock = socket(AF_INET, SOCK_STREAM, 0);//创建一个socket，失败返回-1成功返回非负整数
	// if (sock < 0) {
	// 	perror("Opening socket failed");
	// 	exit(1);
	// }
	// int enable = 1;
	// if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
	// 	perror("setsockopt(SO_REUSEADDR) failed");
	// 	exit(1);
	// }

	// struct sockaddr_in addr;
	// bzero(&addr, sizeof(addr));
	// addr.sin_family = AF_INET;
	// addr.sin_addr.s_addr = INADDR_ANY;
	// addr.sin_port = htons(443);

	// if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	// 	perror("Bind failed");
	// 	exit(1);
	// }
	// listen(sock, 10);

	// while (1) {
	// 	struct sockaddr_in caddr;
	// 	socklen_t len;
	// 	int csock = accept(sock, (struct sockaddr*)&caddr, &len);
	// 	if (csock < 0) {
	// 		perror("Accept failed");
	// 		exit(1);
	// 	}
	// 	SSL *ssl = SSL_new(ctx); 
	// 	SSL_set_fd(ssl, csock);
	// 	handle_https_request(ssl);
	// }

	// close(sock);
	// SSL_CTX_free(ctx);

	// return 0;
}
