#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include<netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if_ether.h>
#include <net/if.h>


#include "rpc.h"

#define MTU   (1500 - 42 - 200)
#define MAX_RETRY_CNT  5

void skt_close(int fd)
{
#if defined (__linux__) || defined (__CYGWIN__)
    close(fd);
#endif
#if defined (__WIN32__) || defined (WIN32) || defined (_MSC_VER)
  	closesocket(fd);
#endif
}


static int _skt_connect(const char *host, uint16_t port, int type)
{
    int sfd, ret;
    struct sockaddr_in si;

    if (inet_aton(host, &si.sin_addr) == 0) {
        fprintf(stderr, "%s: invalid ip addr.\n", host);
        return -1;
    }
    si.sin_family = AF_INET;
    si.sin_port = htons(port);

    sfd = socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP :
            IPPROTO_UDP);
    if (sfd < 0) {
        fprintf(stderr, "socket failed: %m\n");
        return -1;
    }

    ret = connect(sfd, (struct sockaddr *)&si, sizeof si);
    if (ret < 0) {
        fprintf(stderr, "connect failed: %m\n");
        skt_close(sfd);
        return -1;
    }

    return sfd;
}


int skt_tcp_connect(const char *host, uint16_t port)
{
    if (!host || port > USHRT_MAX) {
        fprintf(stderr, "args is invaild.");
        return -1;
    }
    return _skt_connect(host, port, SOCK_STREAM);
}

int skt_set_reuse(int fd, int enable)
{
    int on = !!enable;

#ifdef SO_REUSEPORT
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (unsigned char *)&on, sizeof(on))) {
        printf("setsockopt SO_REUSEPORT: %s\n", strerror(errno));
        return -1;
    }
#endif
#ifdef SO_REUSEADDR
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (unsigned char *)&on, sizeof(on))) {
        printf("setsockopt SO_REUSEADDR: %s\n", strerror(errno));
        return -1;
    }
#endif
    return 0;
}

/**
 * @brief _skt_openfd_of_hostname 如果host是主机名，调用该函数
 *
 * @param hostname  主机名
 * @param port      端口号字符串格式
 * @param type      socket type, SOCK_STREAM or SOCK_DGRAM
 *
 * @return
 */
static int skt_openfd_of_hostname(const char *hostname, const char *port,
        int type)
{
    int sfd, s;
    struct addrinfo hints, *listp, *p;
    char port_str[8] = {0};

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = type; // SOCK_DGRAM or SOCK_STREAM

    //设置了AI_NUMERICSERV 标志并且该参数未设置为NULL，
    //那么该参数必须是一个指向10进制的端口号字符串
    hints.ai_flags = AI_NUMERICSERV;   // using port number
    hints.ai_protocol = 0;          // any protocol

    s = getaddrinfo(hostname, port, &hints, &listp);
    if (0 != s) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(s));
        return -1;
    }

    for(p = listp; p != NULL; p = p->ai_next) {
        sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (-1 == sfd)
            continue;

        skt_set_reuse(sfd, 1);
        if (bind(sfd, p->ai_addr, p->ai_addrlen) == 0)
            break;

        close(sfd);
    }

#ifdef __DEBUG__
    char ip[64] = {0};
    skt_addr_ntop(ip, 64, ((struct sockaddr_in*)p->ai_addr)->sin_addr.s_addr);
    printf(">>>>> socket %d on %s:%u %s %s <<<<<\n", sfd,
                    ip,
                    ntohs(((struct sockaddr_in*)p->ai_addr)->sin_port),
                    p->ai_socktype == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM",
                    p->ai_protocol == IPPROTO_TCP ? "IPPROTO_TCP" : "IPPROTO_UDP");
#endif

    freeaddrinfo(listp);

    if ( !p ) {
        fprintf(stderr, "Can't open a connection.\n");
        return -1;
    }

    return sfd;
}


#define LISTENQ 1024
int skt_open_tcpfd(const char *host, uint16_t port)
{
    int sfd = -1;
    struct sockaddr_in si;

    if ( !host || port > USHRT_MAX ) {
        fprintf(stderr, "args is invaild.\n");
        return -1;
    }

    if (inet_aton(host, &si.sin_addr) == 0) {
        char port_str[8] = {0};
        snprintf(port_str, sizeof port_str, "%u", port);
        sfd = skt_openfd_of_hostname(host, port_str, SOCK_STREAM);
    }
    else {
        si.sin_family = AF_INET;
        si.sin_port = htons(port);

        sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (-1 == sfd) {
            fprintf(stderr, "socket failed: %m\n");
            return -1;
        }

        skt_set_reuse(sfd, 1);
        if (bind(sfd, (struct sockaddr*)&si, sizeof si) != 0) {
            fprintf(stderr, "bind failed: %m\n");
            skt_close(sfd);
            return -1;
        }
    }

    if (sfd > 0 && -1 == listen(sfd, LISTENQ)) {
        fprintf(stderr, "listen failed: %m\n");
        close(sfd);
        return -1;
    }

    return sfd;
}

int skt_set_noblk(int fd, int enable)
{
#if defined (__linux__) || defined (__CYGWIN__)
    int flag;
    flag = fcntl(fd, F_GETFL);
    if (flag == -1) {
        printf("fcntl: %s\n", strerror(errno));
        return -1;
    }
    if (enable) {
        flag |= O_NONBLOCK;
    } else {
        flag &= ~O_NONBLOCK;
    }
    if (-1 == fcntl(fd, F_SETFL, flag)) {
        printf("fcntl: %s\n", strerror(errno));
        return -1;
    }
#endif
    return 0;
}



ssize_t rpc_skt_send(int fd, char *buf, size_t len)
{
    CHECK_ARGS( !buf || !len, -1);
    ssize_t n;
    char *p = (char *)buf;
    size_t left = len;
    size_t step = MTU;
    int cnt = 0;

    while (left > 0) {
        if (left < step)
            step = left;
        n = send(fd, p, step, 0);
        if (n > 0) {
            p += n;
            left -= n;
            continue;
        } else if (n == 0) {
            perror("send");
            return -1;
        }
        if (errno == EINTR || errno == EAGAIN) {
            if (++cnt > MAX_RETRY_CNT) {
                printf("reach max retry count\n");
                break;
            }
            continue;
        }
        printf("send failed(%d): %s\n", errno, strerror(errno));
        return -1;
    }

    return (len - left);
}


ssize_t rpc_skt_recv(int fd, char *buf, size_t len)
{
    CHECK_ARGS(!buf || !len, -1);
    int n;
    char *p = (char *)buf;
    size_t left = len;
    size_t step = MTU;
    int cnt = 0;
    if (buf == NULL || len == 0) {
        printf("%s paraments invalid!\n", __func__);
        return -1;
    }
    while (left > 0) {
        if (left < step)
            step = left;
        n = recv(fd, p, step, 0);
        if (n > 0) {
            p += n;
            left -= n;
            //continue;
            break;
        } else if (n == 0) {
            //perror("recv");//peer connect closed, no need print
            return 0;
        }
        if (errno == EINTR || errno == EAGAIN) {
            if (++cnt > MAX_RETRY_CNT)
                break;
            continue;
        }
        perror("recv");
        return -1;
    }

    return (len - left);
}


int rpc_skt_init(rpc_t *r)
{
    int sfd;

    if (!r || !r->s_host) {
        return -1;
    }

    switch (r->role) {
        case rpc_client:
        {
            sfd = skt_tcp_connect(r->s_host, r->s_port);
            if (0 > sfd)
                return -1;
            skt_set_noblk(sfd, 1);
            break;
        }
        case rpc_server:
        {
            sfd = skt_open_tcpfd(r->s_host, r->s_port);
            if (0 > sfd)
                return -1;
            break;
        }
        default:
            return -1;
    }

    r->fd = sfd;

    return sfd;
}




