#ifndef _RPC_SKT_H
#define _RPC_SKT_H




#include "rpc.h"


int rpc_skt_init(rpc_t *r);

int skt_tcp_connect(const char *host, uint16_t port);
int skt_open_tcpfd(const char *host, uint16_t port);
ssize_t rpc_skt_send(int fd, char *buf, size_t len);
ssize_t rpc_skt_recv(int fd, char *buf, size_t len);
void skt_close(int fd);




#endif /* ifndef _RPC_SKT_H */
