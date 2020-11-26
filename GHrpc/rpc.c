#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include<netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "rpc.h"
#include "common.h"
#include "rpc_skt.h"
#include "event/GHepoll.h"
#include "log.h"
#include "hashmap/hashmap.h"


#define CHECK_ARGS(x, ret) {\
    if (x) {\
        fprintf(stderr, "%s:%d invailed args !!!", __FILE__, __LINE__); \
        return ret; \
    }\
}

pthread_mutex_t mutex;
pthread_cond_t cond;

hashmap_t *works_hash;



work_map_t * rpc_find_work_map(uint32_t msgid)
{
    char buff[128] = {0};
    work_map_t *wm = NULL;

    snprintf(buff, sizeof buff, "%08x", msgid);
    wm = (work_map_t *)hashmap_get(works_hash, buff);
    if (!wm) {
        logxw("msgid(%u) map work no exist", msgid);
    }
    return wm;
}


void on_server_recv(rpc_event_t *ev)
{
    if (!ev || !ev->owner)
        return;

    int fd = ev->fd;
    rpc_t *r = (rpc_t *)ev->args;
    char rbuff[1024] = {0};
    size_t rlen;
    rpc_header_t *hdr = &r->recv_pkt.hdr;

    logd("on_server_recv befor");
    rlen = rpc_skt_recv(fd, (char *)hdr, RPC_HDR_LEN);
    if (rlen < 0) {
        logw("on_client recv error");
        return;
    } else if (rlen == 0) {
        logd("on server del event: %d", fd);
        close(fd);
        GHepoll_del_event(r->eventbases, ev);
        return ;
    }

    if (rlen != RPC_HDR_LEN) {
       logw("rpc recv length not RPC_HDR_LEN");
       return ;
    }

    // rpc_header_t *hdr = (rpc_header_t *)rbuff;
    logd("s_uuid: %08x d_uuid: %08d", hdr->s_uuid, hdr->d_uuid);
    if (hdr->d_uuid != r->local_uuid) {
        logxw("rpc hdr d_uuid(%08x) != rpc local_uuid(%0x8)",hdr->d_uuid,
                r->local_uuid);
        return;
    }

    if (hdr->payload_len != 0) {
        rlen = rpc_skt_recv(fd, rbuff, hdr->payload_len);
        if (rlen < 0) {
            logw("on_client recv error");
            return;
        } else if (rlen == 0) {
            logd("on server del event: %d", fd);
            close(fd);
            GHepoll_del_event(r->eventbases, ev);
            return ;
        }

        if (rlen != hdr->payload_len) {
            logw("rpc recv length not RPC_HDR_LEN");
            return ;
        }
    }
    if (RPC_MSG_RET(hdr->msg_id) == 1) {
        // TODO
        logd("rpc need return");
    }

    // work_map_t *wm = rpc_find_work_map(hdr->msg_id);
    // if (wm) {
    //     wm->work(NULL);
    // }

    logd("on_server_recv after");
}

void on_server(rpc_event_t *ev)
{
    if (!ev || !ev->owner)
        return;

    logd("on on_server befor");
    int sockfd;
    struct sockaddr_in paddr;
    socklen_t plen;

    rpc_t *r = (rpc_t *)ev->args;

    logd(">>>>server fd: %d", r->fd);
    sockfd = accept(r->fd, (struct sockaddr *)&paddr, &plen);
    if (sockfd < 0) {
        logw("accept failed")
        return ;
    }
    rpc_event_t *e = GHepoll_create_event(sockfd, NULL, EVENT_TYPE_READ,
            on_server_recv, r, 0);
    if (-1 == GHepoll_add_event(r->eventbases, e)) {
       logxw("add event failed");
       return ;
    }

    rpc_header_t *hdr = &r->send_pkt.hdr;
    hdr->s_uuid = r->local_uuid;
    hdr->d_uuid = rpc_generate_uuid(sockfd, paddr.sin_addr.s_addr,
            paddr.sin_port);
    hdr->msg_id = RPC_BUILD_MSG_ID(RPC_GROUP_INNER_5, 0, 1, 0, RPC_CMD_INNER_3);
    hdr->timestamp = rpc_get_msec();
    hdr->payload_len = 0;
    if (rpc_skt_send(sockfd, (char *)hdr, RPC_HDR_LEN) != RPC_HDR_LEN) {
        logw("rpc skt send failed");
        return ;
    }
    logd("on server after");
}


void on_client(rpc_event_t *ev)
{
    if (!ev || !ev->owner)
        return;

    logd("on client befor");
    rpc_t *r = (rpc_t *)ev->args;
    int fd = r->fd;

    char rbuff[1024] = {0};
    size_t rlen;

    rlen = rpc_skt_recv(fd, rbuff, RPC_HDR_LEN);
    if (rlen < 0) {
        logw("on_client recv error");
        return;
    } else if (rlen == 0) {
        close(fd);
        GHepoll_del_event(r->eventbases, ev);
        return ;
    }
    rpc_header_t *hdr = (rpc_header_t *)rbuff;

    logd("client recv gid: %d  cmdid: %d", RPC_MSG_GROUP_ID(hdr->msg_id),
            RPC_MSG_CMDID(hdr->msg_id));
    if (RPC_MSG_GROUP_ID(hdr->msg_id) == RPC_GROUP_INNER_5 &&
            RPC_MSG_CMDID(hdr->msg_id) == RPC_CMD_INNER_3) {
        logd("on client connect ok !!!")
        r->server_uuid = hdr->s_uuid;
        r->local_uuid = hdr->d_uuid;
    logd("s_uuid: %08x d_uuid: %08d", r->local_uuid, r->server_uuid);
        r->state = rpc_connected;
        pthread_cond_signal(&cond);
        return ;
    }

    logd("on client after");
}


void *event_pthread(void *arg)
{
    rpc_t *r = (rpc_t *)arg;

    if ( !r ) {
        return NULL;
    }

    rpc_eventbases_t *evb = r->eventbases;

    if (evb)
        GHepoll_loop(evb);

    return (void *)0;
}

// rpc_t * rpc_server_init(const char *host, uint16_t port)
// {
//     CHECK_ARGS(!host || port < 0 || port > 65536, NULL);
//     rpc_t *rpc = NULL;

//     rpc = calloc(1, sizeof *rpc);
//     if ( !rpc ) {
//         return NULL;
//     }

//     rpc->role = rpc_server;
//     rpc->state = rpc_inited;

// }

rpc_t * rpc_init(const char *host, uint16_t port, rpc_role role)
{
    CHECK_ARGS(!host || port < 0 || port > 65536, NULL);
    rpc_t *rpc = NULL;

    rpc = calloc(1, sizeof *rpc);
    if ( !rpc ) {
        return NULL;
    }

    rpc->role = role;
    rpc->state = rpc_inited;
    rpc->s_host = strdup(host);
    rpc->s_port = port;

    int fd = rpc_skt_init(rpc);
    if (0 > fd) {
        loge("rpc skt init failed")
    }

    rpc->eventbases = create_new_epoll(16);
    if (!rpc->eventbases) {
        logxw("create epoll failed");
        goto err;
    }

    if (rpc->role == rpc_client) {
        logd("tcp connect %s:%d", host, port);
        rpc_event_t *ev = GHepoll_create_event(fd, NULL, EVENT_TYPE_READ,
                on_client, rpc, 0);
        if (-1 == GHepoll_add_event(rpc->eventbases, ev)) {
            logxw("add GHepoll event failed");
            GHepoll_event_free(ev);
            goto err;
        }

        pthread_t ev_pid;

        pthread_mutex_init(&mutex, NULL);
        pthread_cond_init(&cond, NULL);

        if(0 != pthread_create(&ev_pid, NULL, event_pthread, rpc)) {
            logw("pthread create failed");
            goto err;
        }

        logd("client pthread mutex lock");
        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&cond, &mutex);
        pthread_mutex_unlock(&mutex);
        logd("client pthread mutex unlock");
    }
    else {
        logd("tcp bind %s:%d", host, port);
        rpc->local_uuid = rpc_generate_uuid(fd, 11111111, rpc->s_port);
        rpc_event_t *ev = GHepoll_create_event(fd, NULL, EVENT_TYPE_READ,
                on_server, rpc, 0);
        if (-1 == GHepoll_add_event(rpc->eventbases, ev)) {
            logxw("add GHepoll event failed");
            GHepoll_event_free(ev);
            goto err;
        }

        pthread_t ev_pid;

        if(0 != pthread_create(&ev_pid, NULL, event_pthread, rpc)) {
            logw("pthread create failed");
            goto err;
        }
    }

    return rpc;
err:
    if (rpc->fd > 0) skt_close(rpc->fd);
    if (rpc) free(rpc);

    return 0;
}


static int rpc_pack_header(rpc_t *r, uint32_t msg_id, size_t payload_len)
{
    logd("s_uuid: %08x d_uuid: %08d", r->local_uuid, r->server_uuid);
    rpc_header_t *hdr = &r->send_pkt.hdr;
    hdr->s_uuid = r->local_uuid;
    hdr->d_uuid = r->server_uuid;
    hdr->msg_id = msg_id;
    hdr->timestamp = rpc_get_msec();
    if (hdr->timestamp == 0) {
        logxw("rpc_get_msec failed");
        return -1;
    }
    hdr->payload_len = payload_len;

    return 0;
}


int rpc_call(rpc_t *r, uint32_t msg_id, void *payload, size_t payload_len)
{
    CHECK_ARGS(!r, -1);
    rpc_pack_header(r, msg_id, payload_len);
    if (payload)
        r->send_pkt.value = payload;
    if (RPC_HDR_LEN != rpc_skt_send(r->fd, (char *)&r->send_pkt.hdr, RPC_HDR_LEN)) {
        logw("rpc send failed");
        return -1;
    }

    if (payload) {
        if (payload_len != rpc_skt_send(r->fd, payload, payload_len))  {
            logw("rpc send failed");
            return -1;
        }
    }

    return 0;
}



