/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: example of http client get
 * Author: Hisilicon
 * Create: 2019-12-09
 */

#include "hi_stdlib.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "app_http_client.h"
#define HTTPC_DEMO_RECV_BUFSIZE 64

#if defined (TEST_WITH_HFS)
#define SOCK_TARGET_PORT  81
static const char *g_request = "GET / HTTP/1.1\r\n\
Accept: text/html,application/xaml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n\
Accept-Language: zh-CN\r\n\
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; \
.NET4.0C; .NET4.0E; hwvcloud4; hwcloud4; .NET CLR 2.0.50727; .NET CLR 3.0.30729; \
.NET CLR 3.5.30729; WebMeeting FreePlugin)\r\n\
Accept-Encoding: gzip, deflate\r\n\
Host: 10.173.223.33:81\r\n\
Connection: Keep-Alive\r\n\
\r\n";
#else
#define SOCK_TARGET_PORT  80
static const char *g_request = "GET / HTTP/1.1\r\n\
Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n\
Host: baidu.com\r\n\
Connection: close\r\n\
\r\n";
#endif

/*****************************************************************************
* Func description: demo for http get action
*****************************************************************************/
unsigned int http_clienti_get(int argc, const char *argv[])
{
    if ((argc != 1) || (argv == NULL)) {
        return 1;
    }
    struct sockaddr_in addr = {0};
    int s, r;
    char recv_buf[HTTPC_DEMO_RECV_BUFSIZE];
    addr.sin_family = AF_INET;
    addr.sin_port = PP_HTONS(SOCK_TARGET_PORT);
    addr.sin_addr.s_addr = inet_addr(argv[0]);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return 1;
    }
    printf("... allocated socket");
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("... socket connect failed errno=%d", errno);
        lwip_close(s);
        return 1;
    }
    printf("... connected");
    if (lwip_write(s, g_request, strlen(g_request)) < 0) {
        lwip_close(s);
        return 1;
    }
    printf("... socket send success");
    struct timeval receiving_timeout;
    /* 5S Timeout */
    receiving_timeout.tv_sec = 5;
    receiving_timeout.tv_usec = 0;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &receiving_timeout, sizeof(receiving_timeout)) < 0) {
        printf("... failed to set socket receiving timeout");
        lwip_close(s);
        return 1;
    }
    printf("... set socket receiving timeout success");
    /* Read HTTP response */
    do {
        (void)memset_s(recv_buf, sizeof(recv_buf), 0, sizeof(recv_buf));
        r = lwip_read(s, recv_buf, sizeof(recv_buf) - 1);
        for (int i = 0; i < r; i++) {
            putchar(recv_buf[i]);
        }
    } while (r > 0);
    printf("... done reading from socket. Last read return=%d errno=%d\r\n", r, errno);
    lwip_close(s);
    return 0;
}

