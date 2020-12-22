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
// #include "hashmap/hashmap.h"
// #include "workq/workq.h"

static int rpc_pack_header(rpc_t *r, rpc_header_t *hdr, uint32_t msg_id, size_t
        payload_len);

// hashmap_t *ret_hash;
// hashmap_t *works_hash;
// int fds[2];

int rpc_register_works(rpc_t *r, work_map_t w[], unsigned int size)
{
    int  i = 0;
    char buff[128] = {0};
    work_map_t *wm;

    if (size == 0) return -1;

    if (!r->works_hash)
        r->works_hash = hashmap_create(10000000, NULL);

    for (; i < size; i++) {
        snprintf(buff, sizeof buff, "%08x", w[i].msgid);

        logd("register msgid: %s", buff);
        if((wm = hashmap_get(r->works_hash, buff)) && wm->msgid == w[i].msgid) {
            logm("work[%d] already exist", i);
            continue;
        }

        if (0 != hashmap_put(r->works_hash, buff, &w[i])) {
            logxw("hashmap_put failed");
            continue;
        }
        logd("register ok");
    }

    return 0;
}

static work_map_t * rpc_find_work_map(rpc_t *r, uint32_t msgid)
{
    char buff[128] = {0};
    work_map_t *wm = NULL;

    snprintf(buff, sizeof buff, "%08x", msgid);
    wm = (work_map_t *)hashmap_get(r->works_hash, buff);
    if (!wm) {
        logxw("msgid(%p:%s) map work no exist", r->works_hash, buff);
    }
    return wm;
}


static void * rpc_find_return_info(rpc_t *r, uint32_t msgid)
{
    char buff[128] = {0};
    char *info = NULL;

    snprintf(buff, sizeof buff, "%08x", msgid);
    info = (char *)hashmap_get(r->ret_hash, buff);
    if (!info) {
        logxw("msgid(%u) map work no exist", msgid);
    }

    return info;
}



/**
 * @brief rpc_call_send_thread 通知server线程返回数据给client
 *
 * @param fd   管道写端
 * @param value work_args_t结构体数据
 * @param len  长度
 *
 * @return 0 or -1
 */
int rpc_call_send_thread(int fd, void *value, size_t len)
{
    CHECK_ARGS(!value, -1);

    if (len != rio_writen(fd, value, len)) {
        logw("rio_writen failed");
        return -1;
    }

    return 0;
}

/*
 * server发送返回信息给client, 当client请求要求返回信息时
 * 通过pipe来通知该线程, 调用rpc_call_send_thread() 来通知
 */
void * rpc_send_ret_thread(void *args)
{
    CHECK_ARGS(!args, 0);
    rpc_t *r = (rpc_t *)args;
    int fd;
    uint32_t msgid = 0;
    char rbuff[1024] = {0};
    size_t rlen;

    while(1) {
        logd("return_thread recv info.....");
        rlen = rio_readn(r->readfd, rbuff, sizeof(work_args_t));
        if (rlen < 0) {
            logw("rio_readn failed");
            continue;
        } else if (rlen == 0) {
            logw("pipe close !!! why ? ?");
            continue;
        }

        work_args_t *wa = (work_args_t *)rbuff;
        fd = wa->sockfd;
        msgid = wa->msgid;

        char *info = rpc_find_return_info(r, msgid);
        if (info) {
            size_t len = strlen(info);
            rpc_header_t hdr;
            char sbuff[2048] = {0};

            logd("send client info: %s:%ld", info, len);
            rpc_pack_header(r, &hdr,  msgid, len);

            memcpy(sbuff, &hdr, RPC_HDR_LEN);
            memcpy(sbuff + RPC_HDR_LEN, info, len);

            // 因为多线程，分开发送接收端会偶尔出现接收错误
            // if (RPC_HDR_LEN != rpc_skt_send(fd, (char *)&hdr, RPC_HDR_LEN)) {
            //     logw("rpc send hdr failed");
            //     continue;
            // }

            // if (len != rpc_skt_send(fd, info, len)) {
            //     logw("rpc send info failed");
            // }

            if ((len+RPC_HDR_LEN) != rpc_skt_send(fd, sbuff, len+RPC_HDR_LEN)) {
                logw("rpc send info failed");
            }
        }
    }

    return 0;
}



static void on_server_recv(rpc_event_t *ev)
{
    if (!ev || !ev->owner)
        return;

    int fd = ev->fd;
    rpc_t *r = (rpc_t *)ev->args;
    char rbuff[1024] = {0};
    size_t rlen;
    rpc_header_t *hdr = &r->recv_pkt.hdr;
    work_args_t wargs = {0, NULL, 0, NULL};

    logd("on_server_recv befor");
    rlen = rpc_skt_recv(fd, (char *)hdr, RPC_HDR_LEN);
    if (rlen < 0) {
        logw("on_client recv error");
        return;
    } else if (rlen == 0) {
        logw("on server del event: %d", fd);
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

    work_map_t *wm = rpc_find_work_map(r, hdr->msg_id);
    if (wm) {
        wargs.r = r;
        wargs.msgid = hdr->msg_id;
        wargs.sockfd = fd;
        wargs.args = strdup(rbuff);
        workq_add(r->workq, wm->work, (void*)&wargs, sizeof wargs, NULL);
        pthread_cond_signal(&r->workq->cond);
    }

    if (RPC_MSG_RET(hdr->msg_id) == NEED_RETURN) {
        logd("rpc need return");
    }
    else {
        uint32_t mid = RPC_BUILD_MSG_ID(RPC_MSG_GROUP_ID(hdr->msg_id), NO_NEED_RETURN,
                RPC_DOWN, RPC_MSG_PARSE(hdr->msg_id),
                RPC_MSG_CMDID(hdr->msg_id));
        rpc_pack_header(r, &r->send_pkt.hdr,  mid, 0);
        if (RPC_HDR_LEN != rpc_skt_send(fd, (char *)&r->send_pkt.hdr, RPC_HDR_LEN)) {
            logw("rpc send hdr failed");
        }
    }

    logd("on_server_recv after");
}


static void on_server(rpc_event_t *ev)
{
    if (!ev || !ev->owner)
        return;

    logd("on on_server befor");
    int sockfd;
    struct sockaddr_in paddr;
    socklen_t plen;

    rpc_t *r = (rpc_t *)ev->args;

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

    /* client 第一次建立连接时，server需要把相关信息发送给client */
    rpc_header_t *hdr = &r->send_pkt.hdr;
    hdr->s_uuid = r->local_uuid;
    hdr->d_uuid = rpc_generate_uuid(sockfd, paddr.sin_addr.s_addr,
            paddr.sin_port);
    hdr->msg_id = RPC_BUILD_MSG_ID(RPC_GROUP_INNER_0, NO_NEED_RETURN, RPC_DOWN,
            0, RPC_CMD_INNER_0);
    hdr->timestamp = rpc_get_msec();
    hdr->payload_len = 0;
    if (rpc_skt_send(sockfd, (char *)hdr, RPC_HDR_LEN) != RPC_HDR_LEN) {
        logw("rpc skt send failed");
        return ;
    }
    logd("on server after");
}


static void on_client(rpc_event_t *ev)
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

    logd("client recv msgid: gid[%d] ret[%d] dir[%d] parse[%d] cmdid[%d]",
            RPC_MSG_GROUP_ID(hdr->msg_id),
            RPC_MSG_RET(hdr->msg_id),
            RPC_MSG_DIR(hdr->msg_id),
            RPC_MSG_PARSE(hdr->msg_id),
            RPC_MSG_CMDID(hdr->msg_id));

    /* 第一次与server建立连接时，server会发送信息确认已连接成功 */
    if (RPC_MSG_GROUP_ID(hdr->msg_id) == RPC_GROUP_INNER_0 &&
            RPC_MSG_CMDID(hdr->msg_id) == RPC_CMD_INNER_0) {
        logd("on client connect ok !!!")
        r->server_uuid = hdr->s_uuid;
        r->local_uuid = hdr->d_uuid;
        r->state = rpc_connected;
        pthread_cond_signal(&r->cond);
        return ;
    }
    else if (RPC_MSG_RET(hdr->msg_id) == NO_NEED_RETURN) { /* 不需要server返回信
                                                              息 */
        logm("call server ok");
    }
    else { /* 需要server返回信息时，我们需要解析返回的数据，解析函数自定义 */
        char ret[1024] = {0};

        logd("recv server length: %d", hdr->payload_len);
        rlen = rpc_skt_recv(fd, ret, hdr->payload_len);
        if (rlen < 0) {
            logw("on_client recv error");
            return;
        } else if (rlen == 0) {
            close(fd);
            GHepoll_del_event(r->eventbases, ev);
            return ;
        }

        work_map_t *wm = rpc_find_work_map(r, hdr->msg_id);
        if (wm) {
            work_args_t wargs = {0, NULL, 0, NULL};
            wargs.r = r;
            wargs.msgid = hdr->msg_id;
            // wargs.sockfd = fd;
            wargs.args = strdup(ret);
            workq_add(r->workq, wm->work, (void*)&wargs, sizeof wargs, NULL);
            /* 通知工作队列处理 */
            pthread_cond_signal(&r->workq->cond);
        }
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


rpc_t * rpc_init(const char *host, uint16_t port, rpc_role role)
{
    CHECK_ARGS(!host || port < 0 || port > 65536, NULL);
    rpc_t *rpc = NULL;

    rpc = calloc(1, sizeof *rpc);
    if ( !rpc ) {
        logw("calloc failed");
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

    /* client 初始化 */
    if (rpc->role == rpc_client) {
        logd("tcp connect %s:%d", host, port);
        rpc_event_t *ev = GHepoll_create_event(fd, NULL, EVENT_TYPE_READ,
                on_client, rpc, 0);
        if (-1 == GHepoll_add_event(rpc->eventbases, ev)) {
            logxw("add GHepoll event failed");
            GHepoll_event_free(ev);
            goto err;
        }

        /*
         * 创建工作队列
         * 该工作队列是：当client向server rpc 要求server返回数据时
         * 对应的处理函数，我们将它处理函数放入工作队列
         */
        rpc->workq = workq_create("rpc_client_workq", free_work_args);
        if (!rpc->workq) {
            logxw("workq_create failed");
            goto err;
        }

        pthread_t ev_pid;
        pthread_mutex_init(&rpc->mutex, NULL);
        pthread_cond_init(&rpc->cond, NULL);

        if(0 != pthread_create(&ev_pid, NULL, event_pthread, rpc)) {
            logw("pthread create failed");
            goto err;
        }

        logd("client pthread mutex lock");
        pthread_mutex_lock(&rpc->mutex);
        /* 第一次建立连接等待server发送uuid，确认连接成功 */
        pthread_cond_wait(&rpc->cond, &rpc->mutex);
        pthread_mutex_unlock(&rpc->mutex);
        logd("client pthread mutex unlock");
    }
    else {   /* server 初始化 */
        logd("tcp bind %s:%d", host, port);

        /* TODO: 11111111 因改成ip地址*/
        rpc->local_uuid = rpc_generate_uuid(fd, 11111111, rpc->s_port);

        rpc_event_t *ev = GHepoll_create_event(fd, NULL, EVENT_TYPE_READ,
                on_server, rpc, 0);
        if (-1 == GHepoll_add_event(rpc->eventbases, ev)) {
            logxw("add GHepoll event failed");
            GHepoll_event_free(ev);
            goto err;
        }

        /*
         * 创建工作队列
         * 该工作队列是：当client向server rpc 对应命令的处理函数
         * 我们将它处理函数放入工作队列
         */
        rpc->workq = workq_create("rpc_server_workq", free_work_args);
        if (!rpc->workq) {
            logxw("workq_create failed");
            goto err;
        }

        /*
         * 创建hash表，把需要server返回数据给client的数据保存, key值为msgid
         */
        rpc->ret_hash = hashmap_create(10000000, NULL);
        if (!rpc->ret_hash) {
            logxw("hashmap_create failed");
            goto err;
        }

        pthread_mutex_init(&rpc->mutex, NULL);
        pthread_cond_init(&rpc->cond, NULL);

        pthread_t ev_pid;
        if(0 != pthread_create(&ev_pid, NULL, event_pthread, rpc)) {
            logw("pthread create failed");
            goto err;
        }

        if (-1 == pipe(rpc->fds)) {
            logw("pipe failed");
            goto err;
        }

        pthread_t pid;
        if(0 != pthread_create(&pid, NULL, rpc_send_ret_thread, rpc)) {
            logw("pthread create failed");
            goto err;
        }
    }

    return rpc;
err:
    if (rpc->fd > 0) skt_close(rpc->fd);
    if (rpc) free(rpc);
    if (rpc->writefd) close(rpc->writefd);
    if (rpc->readfd) close(rpc->readfd);
    if (rpc->workq) workq_destory(rpc->workq);

    exit(1);
}


static int rpc_pack_header(rpc_t *r, rpc_header_t *hdr, uint32_t msg_id, size_t payload_len)
{
    logd("s_uuid: %08x d_uuid: %08d", r->local_uuid, r->server_uuid);
    // rpc_header_t *hdr = &r->send_pkt.hdr;
    memset(hdr, 0, RPC_HDR_LEN);
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

    if (r->state != rpc_connected) {
        logxw("rpc not connected ?");
        return -1;
    }

    rpc_pack_header(r, &r->send_pkt.hdr,  msg_id, payload_len);
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



