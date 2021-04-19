#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include <pcap.h>

#include "parse_pkt.h"
#include "log.h"
#include "debug.h"
#include "misc.h"
// #include "list.h"
#include "hashmap.h"
#include "min_heap_timer.h"
#include "packet/decode.h"
#include "save_packet.h"



#define PCAP_FILTER_STR  "tcp and port 80"


static const int tuple_max = 4;  // for test
static parse_pkt_t *parse_pkt_cfg;
volatile static int is_exit = 0; // 结束进程时设置为1
volatile static int main_exit = 0;


static int get_monotonic(struct timeval *tv)
{
    struct timespec ts;

    if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
        fprintf(stderr, "Call clock_gettime[CLOCK_MONOTONIC] failed %m\r\n");
        return gettimeofday(tv, NULL);
    }

    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000 ;

    return 0;
}


pcap_t* PPktPcapCreate(pcap_t **ph)
{
#define LIBCAP_SNAPLEN 1518  // MTU + hardware header length  1500+18
#define LIBCAP_PROMISC 1
#define LIBCAP_TIMEOUT 500
    int ret;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    const char *iface = "ens33";

    handle = pcap_create(iface, errbuf);
    if (!handle) {
        logxw("Can't create a new handle for %s.", iface);
        PPktReturnNULL;
    }

    ret =  pcap_set_snaplen(handle, LIBCAP_SNAPLEN);
    if (0 != ret) {
        logxw("Can't set snaplen, error %s.", pcap_geterr(handle));
        pcap_close(handle);
        PPktReturnNULL;
    }

    ret = pcap_set_promisc(handle, 1);
    if (0 != ret) {
        logxw("Can't set promisc mode, error %s.", pcap_geterr(handle));
        pcap_close(handle);
        PPktReturnNULL;
    }

    ret = pcap_set_timeout(handle, LIBCAP_TIMEOUT);
    if (0 != ret) {
        logxw("Can't set timeout, error %s.", pcap_geterr(handle));
        pcap_close(handle);
        PPktReturnNULL;
    }

    // ret = pcap_set_buffer_size();

    ret = pcap_activate(handle);
    if (0 != ret) {
        logxw("Can't activate the handle, error %s.", pcap_geterr(handle));
        pcap_close(handle);
        PPktReturnNULL;
    }

    struct bpf_program filter;
    ret = pcap_compile(handle, &filter, PCAP_FILTER_STR, 1, 0);
    if (0 != ret) {
        logxw("Can't pcap_compile %s, error %s.", PCAP_FILTER_STR,  pcap_geterr(handle));
        pcap_close(handle);
        PPktReturnNULL;
    }
    ret = pcap_setfilter(handle, &filter);
    if (0 != ret) {
        logxw("Can't pcap_setfilter %s, error %s.", PCAP_FILTER_STR,  pcap_geterr(handle));
        pcap_close(handle);
        PPktReturnNULL;
    }

    // datalink = pcap_datalink(handle);

    if (ph != NULL)
        *ph = handle;

    return handle;
#undef LIBCAP_PROMISC
#undef LIBCAP_SNAPLEN
#undef LIBCAP_TIMEOUT
}


int PPktPcapTryReopen(pcap_t *handle)
{
    int ret = 0;

    ret = pcap_activate(handle);
    if (0 != ret) {
        logw("Can't activate the handle, error %s.", pcap_geterr(handle));
        pcap_close(handle);
        return ret;
    }

    struct bpf_program filter;
    ret = pcap_compile(handle, &filter, PCAP_FILTER_STR, 1, 0);
    if (0 != ret) {
        logxw("Can't pcap_compile %s, error %s.", PCAP_FILTER_STR,  pcap_geterr(handle));
        pcap_close(handle);
        return ret;
    }
    ret = pcap_setfilter(handle, &filter);
    if (0 != ret) {
        logxw("Can't pcap_setfilter %s, error %s.", PCAP_FILTER_STR,  pcap_geterr(handle));
        pcap_close(handle);
        return ret;
    }
    // ret = pcap_compile();
    // ret = pcap_setfilter();
    return 0;
}



/**
 * @brief PPktPacketEnqueue 将Packet放入包队列
 *
 * @param pq 数据包队列
 * @param p  数据包
 *
 * @return 0 is ok
 */
int PPktPacketEnqueue(PacketQueue *pq, Packet *p)
{
    CHECK_ARGS(pq != NULL && p != NULL, -1);

    if (pq->head) {
        p->prev = NULL;
        p->next = pq->head;
        pq->head->prev = p;
        pq->head = p;
    }
    else {
        p->prev = NULL;
        p->next = NULL;
        pq->head = p;
        pq->tail = p;
    }
    pq->size++;

    return 0;
}



/**
 * @brief PPktPacketDequeue 从数据包队列取出数据包
 *
 * @param pq 数据包队列
 *
 * @return NULL is failed
 */
Packet *PPktPacketDequeue(PacketQueue *pq)
{
    CHECK_ARGS(pq != NULL, NULL);

    if (pq->size == 0)
        return NULL;

    Packet *p = pq->tail;
    pq->size--;

    if (pq->tail->prev) {
        pq->tail->prev->next = NULL;
        pq->tail = pq->tail->prev;
    }
    else {
        pq->head = NULL;
        pq->tail = NULL;
    }
    p->next = NULL;
    p->prev = NULL;

    return p;
}


int PPktPacketCopyOffset(Packet *p, uint32_t offset, uint8_t *pkt, uint32_t pktlen)
{
    if (unlikely(offset + pktlen > MAX_PAYLOAD_SIZE)) {
        SET_PKT_LEN(p, 0);
        return -1;
    }

    if (!p->ext_pkt) {
        uint32_t newsize = offset + pktlen;
        if (newsize <= default_packet_size) {
            memcpy(GET_PKT_DIRECT_DATA(p) + offset, pkt, pktlen);
        }
        else {
            p->ext_pkt = calloc(1, MAX_PAYLOAD_SIZE);
            if (!p->ext_pkt) {
                SET_PKT_LEN(p, 0);
                loge("calloc failed");
            }
            memcpy(p->ext_pkt, GET_PKT_DIRECT_DATA(p), GET_PKT_DIRECT_MAX_SIZE(p));
            memcpy(p->ext_pkt+offset, pkt, pktlen);
        }
    }
    else {
        memcpy(p->ext_pkt + offset, pkt, pktlen);
    }

    return 0;
}



/**
 * @brief PPktPacketCopy 拷贝包数据到Packet结构中
 *
 * @param p    Packet数据结构
 * @param pkt  包数据
 * @param pktlen 包长度
 *
 * @return 0 is ok
 */
int PPktPacketCopy(Packet *p, uint8_t *pkt, uint32_t pktlen)
{
    CHECK_ARGS(p != NULL && pkt != NULL &&  pktlen > 0, -1);
    SET_PKT_LEN(p, pktlen);
    PPktPacketCopyOffset(p, 0, pkt, pktlen);

    return 0;
}

#if 0
int PPktPacketCopy(uint8_t **dest, uint32_t *dlen, uint8_t *src, uint32_t slen)
{
    CHECK_ARGS(src != NULL && slen > 0, -1);

    if (*dlen != 0) {
        CHECK_ARGS(*dest != NULL && *dlen < slen, -1);
    }
    else {
        logd("calloc %d", slen);
        *dest = calloc(1, slen);
        *dlen = slen;
    }

    memcpy(*dest, src, *dlen);
    return 0;
}
#endif


/**
 * @brief PPktPcapCallback pcap抓包回调函数
 *
 * @param user 用户私有数据
 * @param h    包头信息
 * @param pkt 抓到的包数据
 */
static void PPktPcapCallback(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    Packet *p;
    BUG_ON(parse_pkt_cfg == NULL);
    PacketQueue *pq = parse_pkt_cfg->pktq;
    unsigned long *pcap_capture_packet_count = &parse_pkt_cfg->pcap_capture_packet_count;

    // 只处理特定类型的数据包，当然也可以在pcap初始化中设置
    EthernetHdr *ethdr = (EthernetHdr *)pkt;
    if (ntohs(ethdr->eth_type) == ETHERNET_TYPE_IP) {
        IPV4Hdr *ip4h = (IPV4Hdr *)(pkt+ETHERNET_HEADER_LEN);
        if (
            // IPV4_GET_RAW_IPPROTO(ip4h) != IPPROTO_ICMP ||
            IPV4_GET_RAW_IPPROTO(ip4h) != IPPROTO_TCP
            ) {
            logd("It't a tcp packet, need't process.");
            return;
        }
    }

    p = PacketGetFromAlloc();
    if (!p)
        loge("Can't calloc");
    // PACKET_REINIT(p);

    PPktPacketCopy(p, pkt, h->caplen);
    // logd(">>>>>>>>>>>>ext_pkt : %p, pktlen: %d", p->ext_pkt, p->pktlen);

    // 解码数据包，接某些值放到Packet结构中
    if (DECODE_OK != DecodeEthernet(p, GET_PKT_DATA(p), p->pktlen)) {
        logxw("Decode packet failed.");
        return;
    }

    BUG_ON(p->ethh == NULL);
    BUG_ON(p->ip4h == NULL);
    // BUG_ON(p->tcph == NULL);

    pthread_mutex_lock(&pq->mutex);
    PPktPacketEnqueue(pq, p);

    if (pq->size == 1) {
        pthread_mutex_unlock(&pq->mutex);
        pthread_cond_signal(&pq->cont);
    }
    else
        pthread_mutex_unlock(&pq->mutex);

    *pcap_capture_packet_count += 1;
}


// 释放tuple结构
void PPktReleaceTuple(void *data)
{
    tuple_t *tuple = (tuple_t *)data;

    if (!tuple) return;
    if (tuple->p) {
       PACKET_FREE(tuple->p);
    }

    /*
     * 联合体union中的任何一个指针申请内存之后，其他的成员都指向这个
     * 所以判断union任何一个指针成员是否为NULL就行
     */
    if (tuple->context.email) {
        if (tuple->context.email->subject) {
            free(tuple->context.email->subject);
            free(tuple->context.email);
        }
        else
            free(tuple->context.http);
        tuple->context.email = NULL;
        tuple->context.http = NULL;
    }


    if (tuple->flags & TUPLE_IS_ALLOC) {
        logd("The tuple flags is TUPLE_IS_ALLOC, free tuple");
        free(tuple);
        tuple = NULL;
    }
    else { // 如果是在初始化中申请的
        tuple_t *spare_tuple = parse_pkt_cfg->spare_tuple;

        PPKT_TUPLE_INIT(tuple);

        // 把tuple重新设置为空闲状态
        tuple->flags &= ~TUPLE_IS_CONSUME;
        tuple->flags |= TUPLE_IS_SPARE;

        // 放到空闲队列头部
        if (!spare_tuple) {
            tuple->next = NULL;
            // parse_pkt_cfg->spare_tuple = tuple;
        }
        else {
            tuple->next = spare_tuple;
            // spare_tuple = tuple;  // fix bug
            // logd(">>>>>>>>>>>> %p == %p", tuple, parse_pkt_cfg->spare_tuple);
        }
        parse_pkt_cfg->spare_tuple = tuple;
        parse_pkt_cfg->spare_tuple_count++;
    }
}


// 创建tuple
tuple_t *PPktCreateTuple()
{
    tuple_t *tuple;
    tuple_t *spare_tuple = parse_pkt_cfg->spare_tuple;
    // tuple_t *consume_tuple = parse_pkt_cfg->consume_tuple;

    if (spare_tuple != NULL) {
        tuple = spare_tuple;
        // 从空闲列表中删掉tuple, 将空闲头指针指向下一个
        parse_pkt_cfg->spare_tuple = spare_tuple->next;
        logd("In PPktCreateTuple spare_tuple: %p", parse_pkt_cfg->spare_tuple);

        parse_pkt_cfg->spare_tuple_count--;
    }
    else {
#if 0
        tuple = calloc(1, sizeof(*tuple));
        if (!tuple) {
            logw("Calloc mem(%ld) failed", sizeof(*tuple));
            exit(1);
        }
        tuple->flags |= TUPLE_IS_ALLOC;
#endif
        logm("Ah, use it maybe have bug, don't use");
        logm("解决办法1：直接扩展空闲tuple链表");
        logm("解决办法2：重新修改最小堆定时器代码，传递给定时器的数据使用双指针");
        return NULL;
    }

    // 设置该tuple为占用
    tuple->flags &= ~TUPLE_IS_SPARE;
    tuple->flags |= TUPLE_IS_CONSUME;

    // 设置创建时间，到期释放时间
    struct timeval tv;
    get_monotonic(&tv);
    tuple->cs = tv.tv_sec * 1000 + (tv.tv_usec + 999) / 1000;
    tuple->last_communicate = tuple->cs;
    tuple->expires = tuple->cs + EXPIRES;

#if 0
    if (parse_pkt_cfg->consume_tuple_count == tuple_max) {
        logd("Wow, the consume tuple count == tuple_max, let's traverse the consume tuple");
        /*TODO
         * 遍历consume_tuple, 将其中flags为TUPLE_IS_SPARE的tuple从consume_tuple中删除
         */
        tuple_t *tp, *prev_tp = NULL;
        for (tp = parse_pkt_cfg->consume_tuple; tp != NULL; tp = tp->next) {
            if (tp->flags & TUPLE_IS_SPARE) {
                if (prev_tp == NULL) {
                    parse_pkt_cfg->consume_tuple = tp->next;
                }
                else {
                    prev_tp->next = tp->next;
                }

                PPKT_TUPLE_INIT(tp);

                tp->flags &= !TUPLE_IS_CONSUME;
                tp->flags |= TUPLE_IS_SPARE;
                parse_pkt_cfg->consume_tuple_count--;
#if 0
                if (!spare_tuple) {
                    tp->next = NULL;
                    // parse_pkt_cfg->spare_tuple = tp;
                }
                else {
                    tp->next = spare_tuple;
                    // fix bug, 定义 tuple_t **sapre_tuple, *spare_tuple = tp才可以
                    // spare_tuple = tp;
                    // parse_pkt_cfg->spare_tuple = tp;
                }
                parse_pkt_cfg->spare_tuple = tp;
#endif
            }
            prev_tp = tp;
        }
    }
#endif
    return tuple;
}



int PPktParseHttpHeader(tuple_t *tuple, const uint8_t *data, uint32_t data_len)
{
    CHECK_ARGS(tuple != NULL && data != NULL && data_len > 0, -1);

    int i;
    char urlpath[256] = {0};
    char host[256] = {0};
    int urlpath_len = 0;
    int host_len = 0;
    const uint8_t *str = data;

    // GET /linux_server/0210network-secure_2.php HTTP/1.1
    if (data_len > 5 && !memcmp(data, "GET ", 4)) {
        data_len -= 4;
        str += 4;
    }
    else if (data_len > 6 && !memcmp(data, "POST ", 5)) {
        data_len -= 5;
        str += 5;
    }
    else
        return -1;

    for (i = 0; *str != ' ' && *str != '\r' && *str != '\n'; str++) {
        urlpath[i++] = *str;
    }
    urlpath[i] = '\0';
    urlpath_len = i;
    data_len -= i;

    uint8_t *p;
    // Host: www.baidu.com
    if ((p = (uint8_t *)strstr((const char *)str, "Host:")) != NULL) {
        data_len = data_len - (p - str);
        str = p;
        str += 6; data_len -= 6;
        for (i = 0; *str != '\r' && *str != '\n' && *str != ' '; str++) {
            host[i++] = *str;
        }
        host[i] = '\0';
        host_len = i;
        data_len -= i;
    }
    else {
        logxw("Wow, url request has't Host");
        return -1;
    }

    tuple->dir = 1; // client

    if (!tuple->context.http) {
        tuple->context.http = calloc(1, sizeof(struct http_context));
        if (!tuple->context.http) {
            logxw("Can't calloc");
            return -1;
        }

        struct http_context *http = tuple->context.http;

        http->url_len = snprintf(http->url, sizeof(http->url), "%s%s", host, urlpath);
        if (http->url_len != (host_len + urlpath_len)) {
            logxw("Wow, may be a error, url_len = %d", http->url_len);
            return -1;
        }
        http->domain = http->url;
        http->domain_len = host_len; // %.*s
        http->service = APP_SERVICE_HTTP; // http
        tuple->app_service = APP_SERVICE_HTTP;
    }
    else
        logd("Wow, why recv GET/POST twice");

    return 0;
}


int PPktParseHttpsHeader(tuple_t *tuple, const uint8_t *data, uint32_t data_len)
{
    const uint8_t *rest = data;
    int rest_len = data_len;
    uint8_t b;
    uint16_t w;

    if (rest_len < 43) { return -1;  }
    rest += 43; rest_len -= 43; //next will be session id
    if (rest_len < 1 ) { return -1;  }
    b = *rest + 1;rest += b ; rest_len -= b ; //skip session id
    if (rest_len < 2 ) { return -1;  }
    w = ntohs(*(const uint16_t *)rest) + 2;
    rest += w; rest_len -= w ; //skip cipher suites
    if (rest_len < 1 ) { return -1;  }
    b = *rest + 1; rest += b ; rest_len -= b ; //skip compression methods
    rest += 2; rest_len -= 2; //next will be extension

    for (;;) {
        if (rest_len < 4) return -1;
        if (rest[0] == 0 && rest[1] == 0) {// found server name extension

            if (!tuple->context.http) {
                tuple->context.http = calloc(1, sizeof(struct http_context));
                if (!tuple->context.http) {
                    logxw("Can't calloc");
                    return -1;
                }
            }

            struct http_context *http = tuple->context.http;

            rest += 7;
            rest_len -= 7;
            w = ntohs(*(const uint16_t *)rest);
            if (rest_len < w + 2) return -1;

            // https中获取不到url,只能获取host(域名)
            http->url_len = snprintf(http->url, sizeof(http->url)-1, "%.*s", w, rest + 2);
            if (http->url_len > sizeof(http->url)-1)
                http->url_len = sizeof(http->url)-1;
            http->domain = http->url;
            http->domain_len = http->url_len;
            http->service = APP_SERVICE_HTTPS;
            tuple->app_service = APP_SERVICE_HTTPS;
            return 0;
        } else {
            w = ntohs(*(const uint16_t *)(rest+2)) + 4; if (w == 0) return -1;
            rest += w ; rest_len -= w ;
        }
    }
    return -1;
}


int PPktParseEmailInfo(tuple_t *tuple, uint8_t *data, uint32_t data_len)
{
    CHECK_ARGS(tuple != NULL && data != NULL && data_len > 0, -1);

    BUG_ON(tuple->p == NULL);

    if (GET_TCP_DST_PORT(tuple->p) != 25)
        return -1;

    tuple->app_service = APP_SERVICE_EMAIL; // email

    if (!tuple->context.email) {
        tuple->context.email = calloc(1, sizeof(struct email_context));
        if (!tuple->context.email) {
            logxw("Can't calloc");
            return -1;
        }
    }

    struct email_context *email = tuple->context.email;

    if (email->get_ok == 4)
        return 0;

    uint8_t *p;
    // Date: Tue, 02 Mar 2021 22:45:38 +0800
    if ((p = (uint8_t *)strstr((const char *)data, "Date:")) != NULL) {
        char *date = email->date;
        int date_len = sizeof(email->date);
        p += 6;
        while(*p != '\r' && *p != '\n' && date_len-- > 0)
            *date++ = *p++;
        email->get_ok++;
        p = NULL;
    }

    // From: 1969555431@qq.com
    if ((p = (uint8_t *)strstr((const char *)data, "From:")) != NULL) {
        char *sender = email->sender;
        int sender_len = sizeof(email->sender);
        p += 6;
        while(*p != '\r' && *p != '\n' && sender_len-- > 0)
            *sender++ = *p++;
        email->get_ok++;
        p = NULL;
    }

    // To: qigaohua168@163.com
    if ((p = (uint8_t *)strstr((const char *)data, "To:")) != NULL) {
        char *recver = email->recver;
        int recver_len = sizeof(email->recver);
        p += 4;
        while(*p != '\r' && *p != '\n' && recver_len-- > 0)
            *recver++ = *p++;
        email->get_ok++;
        p = NULL;
    }

    // Subject: Test
    if ((p = (uint8_t *)strstr((const char *)data, "Subject:")) != NULL) {
        int subject_len = 0;
        p += 9;
        while(*p != 0x0d && *p != 0x0a) {
            subject_len++;
            p++;
        }

        email->subject = calloc(1, subject_len+1);
        if (!email->subject) {
            logw("Calloc mem(%d) failed", subject_len+1);
            return -1;
        }

        memcpy(email->subject, p-subject_len, subject_len);
        email->subject[subject_len+1] = '\0';

        email->get_ok++;
    }

    return 0;
}


tuple_t *PPktFindTuple(hashmap_t *hm, uint32_t srcip, uint32_t dstip,
        uint16_t srcport, uint16_t dstport, uint8_t protocol)
{
    tuple_t *tuple;
    char key[128] = {0};

    // 通过五元组来设置key值
    if (srcip > dstip)
        snprintf(key, sizeof key, "%u:%u|%u:%u|%u", srcip, srcport, dstip, dstport, protocol);
    else
        snprintf(key, sizeof key, "%u:%u|%u:%u|%u", dstip, dstport, srcip, srcport, protocol);
    logd(">>Find key: %s", key);
    tuple = hashmap_get(hm, key);
    if (!tuple)
        return NULL;

    if (GET_IPV4_SRC_ADDR_U32(tuple->p) != srcip
            || GET_IPV4_DST_ADDR_U32(tuple->p) != dstip
            || GET_TCP_SRC_PORT(tuple->p) != srcport
            || GET_TCP_DST_PORT(tuple->p) != dstport
            || IPV4_GET_IPPROTO(tuple->p) != protocol) {
        if (GET_IPV4_SRC_ADDR_U32(tuple->p) != dstip
                || GET_IPV4_DST_ADDR_U32(tuple->p) != srcip
                || GET_TCP_SRC_PORT(tuple->p) != dstport
                || GET_TCP_DST_PORT(tuple->p) != srcport
                || IPV4_GET_IPPROTO(tuple->p) != protocol) {

            logxw("Wow, find tuple from hashmap failed");
            return NULL;
        }
    }

    return tuple;
}


int PPktInsertTuple(hashmap_t *hm, tuple_t *tuple)
{
    CHECK_ARGS(hm != NULL && tuple != NULL, -1);

    BUG_ON(tuple->p == NULL);
    BUG_ON(tuple->p->ip4h == NULL);

    char key[128] = {0};
    uint32_t srcip = GET_IPV4_SRC_ADDR_U32(tuple->p);
    uint32_t dstip = GET_IPV4_DST_ADDR_U32(tuple->p);
    uint16_t srcport = GET_TCP_SRC_PORT(tuple->p);
    uint16_t dstport = GET_TCP_DST_PORT(tuple->p);
    uint8_t protocol = IPV4_GET_IPPROTO(tuple->p);

    if (srcip > dstip)
        snprintf(key, sizeof key, "%u:%u|%u:%u|%u", srcip, srcport, dstip, dstport, protocol);
    else
        snprintf(key, sizeof key, "%u:%u|%u:%u|%u", dstip, dstport, srcip, srcport, protocol);
    logd(">>Insert key: %s", key);
    if (0 != hashmap_put(hm, key, tuple)) {
        logxw("Can't Insert tuple key: %s", key);
        return -1;
    }

    return 0;
}


int PPktDeleteTuple(hashmap_t *hm, tuple_t *tuple)
{
    logd("Enter PPktDeleteTuple >>>");
    CHECK_ARGS(hm != NULL && tuple != NULL, -1);

    BUG_ON(tuple->p == NULL);
    BUG_ON(tuple->p->ip4h == NULL);

    char key[128] = {0};
    uint32_t srcip = GET_IPV4_SRC_ADDR_U32(tuple->p);
    uint32_t dstip = GET_IPV4_DST_ADDR_U32(tuple->p);
    uint16_t srcport = GET_TCP_SRC_PORT(tuple->p);
    uint16_t dstport = GET_TCP_DST_PORT(tuple->p);
    uint8_t protocol = IPV4_GET_IPPROTO(tuple->p);

    if (srcip > dstip)
        snprintf(key, sizeof key, "%u:%u|%u:%u|%u", srcip, srcport, dstip, dstport, protocol);
    else
        snprintf(key, sizeof key, "%u:%u|%u:%u|%u", dstip, dstport, srcip, srcport, protocol);
    logd(">>Delete key: %s", key);
    if (0 != hashmap_del(hm, key)) {
        logxw("Can't delete tuple key: %s", key);
        return -1;
    }

    logd("Enter PPktDeleteTuple <<<");
    return 0;
}



/**
 * @brief PPktAddTupleToTimer 将tuple放入定时器中, 到期则释放tuple
 *
 * @param timer 定时器结构
 * @param tuple tuple
 * @param expires_msecs 到期时间
 *
 * @return 0 is ok
 */
int PPktAddTupleToTimer(minheap_t *timer,  tuple_t *tuple, unsigned int expires_msecs)
{
    CHECK_ARGS(timer != NULL && tuple != NULL && expires_msecs > 0, -1);
    struct timeval tv;
    unsigned long expires;

    logd("add tuple to timier expires: %d", expires_msecs);

    get_monotonic(&tv);
    expires = tv.tv_sec * 1000 + tv.tv_usec / 1000 + expires_msecs; //单位毫秒
    if (0 != MinHeapAddNode(timer, tuple, expires)) {
        logxw("Wow, tuple add to tuple_timer failed");
        return -1;
    }

    if (MinHeapTimerIsWait())
        TellMinHeapTimer(CMD_HAVE_DATA);

    return 0;
}



void *PPktProcessPacket(void *args)
{
    PacketQueue *pq = parse_pkt_cfg->pktq;
    minheap_t *timer = parse_pkt_cfg->tuple_timer;
    hashmap_t *tuple_hash = parse_pkt_cfg->tuple_hash;
    Packet *p = NULL;
    tuple_t *tuple;
    enum TCP_STATE tcp_state;

    BUG_ON(pq == NULL);
    BUG_ON(timer == NULL);
    BUG_ON(tuple_hash == NULL);

    start_save_packet("/tmp", 100);

    while(1) {
        if (1 == is_exit) break;
        pthread_mutex_lock(&pq->mutex);
        if (pq->size == 0) {
            pthread_cond_wait(&pq->cont, &pq->mutex);
        }
        p = PPktPacketDequeue(pq);
        pthread_mutex_unlock(&pq->mutex);

        if (!p) continue;

        save_packet(GET_PKT_DATA(p), p->pktlen, "i:", "ens33", 5);

        tuple = PPktFindTuple(tuple_hash, GET_IPV4_SRC_ADDR_U32(p),
                GET_IPV4_DST_ADDR_U32(p), TCP_GET_SRC_PORT(p),
                GET_TCP_DST_PORT(p), IPV4_GET_IPPROTO(p));
        if (!tuple) { /* tuple_hash 没有找到, 则代表是一个syn请求建立连接包 */
            logd("== Spare tuple: %d   Consume tuple: %d",
                    parse_pkt_cfg->spare_tuple_count,
                    tuple_max - parse_pkt_cfg->spare_tuple_count);
#if 0
            if (!(TCP_ISSET_FLAG_SYN(p) > 0 && TCP_ISSET_FLAG_ACK(p) == 0)) {
                logm("It's syn packet, but not find tuple in tuple_hash.");
                PACKET_FREE(p);
                continue;
            }
#endif
            // 接收到的时fin或rst数据包，直接释放
            if (TCP_ISSET_FLAG_RST(p) || TCP_ISSET_FLAG_FIN(p)) {
                PACKET_FREE(p);
                continue;
            }
            tuple = PPktCreateTuple();
            if (!tuple) {
                logxw("Create tuple failed.");
                PACKET_FREE(p);
                continue;
            }
            if (TCP_ISSET_FLAG_SYN(p) > 0) {
                if (TCP_ISSET_FLAG_ACK(p) == 0) {
                    logd("It's SYN packet.");
                    tuple->state = TCP_CONNECT_1;
                }
                else {
                    logd("It's SYN/ACK packet.");
                    tuple->state = TCP_CONNECT_2;
                }
            }
            else if (TCP_ISSET_FLAG_ACK(p) > 0){
                logd("It's ACK packet.");
                tuple->state = TCP_CONNECT_OK;
            }
            else {
                logxw("Wow, should not be the case!");
                PPktReleaceTuple(tuple);
                continue;
            }

            tuple->p = p;
            BUG_ON(tuple->p == NULL);
            BUG_ON(tuple->p->ip4h == NULL);
            tuple->server_ip = GET_IPV4_DST_ADDR_U32(p);
            PPktInsertTuple(tuple_hash, tuple);
            PPktAddTupleToTimer(timer, tuple, EXPIRES);
            continue;
        }

#define PACKET_IS_SYN(p) (TCP_ISSET_FLAG_SYN((p)) > 0 && TCP_ISSET_FLAG_ACK((p)) == 0)
#define PACKET_IS_SYN_ACK(p) (TCP_ISSET_FLAG_SYN((p)) > 0 && TCP_ISSET_FLAG_ACK((p)) > 0)
#define PACKET_IS_ACK(p) (TCP_ISSET_FLAG_SYN((p)) == 0 && TCP_ISSET_FLAG_ACK((p)) > 0)
#define PACKET_IS_RST(p) (TCP_ISSET_FLAG_RST((p)) > 0)
#define PACKET_IS_FIN(p) (TCP_ISSET_FLAG_FIN((p)) > 0)

        tcp_state = tuple->state;

        if (PACKET_IS_SYN(p)) {
            logd("It't SYN packet, but itn't once.");
            PACKET_FREE(p);
            continue;
        }
        else if (PACKET_IS_SYN_ACK(p)) {
            logd("It's SYN/ACK packet.");
            if (tcp_state == TCP_CONNECT_1) {
                tuple->state = TCP_CONNECT_2;
            }
            else {
                logd("It't SYN/ACK packet, but itn't once.");
            }
            PACKET_FREE(p);
            continue;
        }
        else if (PACKET_IS_RST(p)) {
            logd("It't RST packet");
            PPktDeleteTuple(tuple_hash, tuple);
            PACKET_FREE(p);
            continue;
        }
        else if (PACKET_IS_FIN(p)) {
            // 根据服务器地址判断该数据包是客户端数据包还是服务器数据包
            if (tuple->server_ip == GET_IPV4_DST_ADDR_U32(p))
                tuple->dir = CLIENT_PACKET;
            else if (tuple->server_ip == GET_IPV4_SRC_ADDR_U32(p))
                tuple->dir = SERVER_PACKET;
            else {
                logxw("This is not possible");
                PACKET_FREE(p);
                continue;
            }

            // 接收到了 fin/ack 数据包
            if (tcp_state > TCP_OFF && tcp_state != TCP_DISCONNECT_OK) {
                if (tuple->dir == CLIENT_PACKET) {
                    logd("It's FIN/ACK packet, C->S");
                    tuple->state =
                        (tcp_state == TCP_CONNECT_OK
                         ? TCP_DISCONNECT_CLIENT : (tcp_state | TCP_DISCONNECT_CLIENT));
                }
                else {
                    logd("It's FIN/ACK packet, S->C");
                    tuple->state =
                        (tcp_state == TCP_CONNECT_OK
                         ? TCP_DISCONNECT_SERVER : (tcp_state | TCP_DISCONNECT_SERVER));
                }

                /*
                 * 注意: 可能tcp四次挥手断开tcp连接实际上只有三次，有的服务端会将四次挥手
                 * 第二三次挥手合并为1个报文，也就是FIN+ACK，捎带ACK机制
                 */
// #define ADD_TIMER
#ifdef ADD_TIMER
                if (tuple->state == TCP_DISCONNECT_OK) {
                    tuple->last_communicate = 0;
                    // 这里是为了尽快的释放使用中的tuple, 因为一个tcp连接申请
                    // tuple 默认是10分钟后释放
                    // 当然也可以在下面接收最后一个确认包后直接释放tuple, 但是如
                    // 果没有接收到最后一个确认包呢,那么会在10分钟后释放
                    PPktAddTupleToTimer(timer, tuple, 10000); // 10秒后释放
                }
#endif
            }
        }
        else if (PACKET_IS_ACK(p)) {
            logd("It's ACK packet");
            if (likely(tcp_state > TCP_CONNECT_2)) {
                if (tcp_state >= TCP_DISCONNECT_CLIENT) {
                    // tcp 四次挥手的确认包
                    logd("It's ACK packet of four times waved");
                    if (tcp_state == TCP_DISCONNECT_OK) {
                        // 也可以在这直接释放tuple, 不需要像上面添加10秒后释放定
                        // 时器
#ifndef ADD_TIMER
                        PPktDeleteTuple(tuple_hash, tuple);
#endif
                    }
                    PACKET_FREE(p);
                    continue;
                }
            }
            else if (tcp_state == TCP_CONNECT_2) {
                // tcp 三次握手最后的确认包
                logd("It's tcp shake hands three times the last ACK packet");
                tuple->state = TCP_CONNECT_OK;
                PACKET_FREE(p);
                continue;
            }
            else {
                logd("It's ACK packet, but didn't recv SYN and SYN/ACK packet");
                tuple->state = TCP_CONNECT_OK;
            }
        }
        else {
            logxw("Wow, I don't kown the packet type");
            PACKET_FREE(p);
            continue;
        }

#ifdef MAIN_MULTI_PTHREAD
        pthread_mutex_lock(&tuple->mutex);
#endif
        // 重新设置下tuple的最近通信时间
        struct timeval tv;
        get_monotonic(&tv);
        tuple->last_communicate = tv.tv_sec * 1000 + tv.tv_usec / 1000;
#ifdef MAIN_MULTI_PTHREAD
        pthread_mutex_unlock(&tuple->mutex);
#endif

#if 0
        // 接收到了一个 rst 数据包， 则释放tuple
        if (tuple->state > TCP_OFF && TCP_ISSET_FLAG_RST(p) > 0) {
            logd("It't RST packet");
            PPktDeleteTuple(tuple_hash, tuple);
            PACKET_FREE(p);
            continue;
        }

        // 接收到了一个 syn/ack 数据包
        if (tuple->state == TCP_CONNECT_1) {
            if (TCP_ISSET_FLAG_SYN(p) > 0 && TCP_ISSET_FLAG_ACK(p) > 0) {
                logd("It's SYN/ACK packet.");
                tuple->state = TCP_CONNECT_2;
            }
            else {
                logxw("It not is syn/ack packet, but tuple state is TCP_CONNECT_1.");
                if (TCP_ISSET_FLAG_SYN(p) > 0) { // 又是一个syn数据包
                    // PACKET_FREE(p);
                    // continue;
                }
                else if (TCP_ISSET_FLAG_ACK(p) > 0) { // 可能漏掉了syn/ack数据包
                    tuple->state == TCP_CONNECT_OK;
                }
                else {
                    logxw("Wow, should not be the case!");
                }
            }
            PACKET_FREE(p);
            continue;
        }

        // 接收到了一个 ack 确认包
        if (tuple->state == TCP_CONNECT_2) {
            if (TCP_ISSET_FLAG_SYN(p) == 0 && TCP_ISSET_FLAG_ACK(p) > 0) {
                logd("It's CONNECT OK packet.");
                tuple->state = TCP_CONNECT_OK;
            }
            else {
                logxw("It not is ack packet, but tuple state is TCP_CONNECT_2.");
                // tuple->state = TCP_CONNECT_OK;
                if (TCP_ISSET_FLAG_SYN(p) > 0 && TCP_ISSET_FLAG_ACK(p) == 0) { // 又是一个syn数据包
                    PACKET_FREE(p);
                    continue;
                }
                else if (TCP_ISSET_FLAG_SYN(p) > 0 && TCP_ISSET_FLAG_ACK(p) > 0) { // 又是syn/ack数据包
                    PACKET_FREE(p);
                    continue;
                }
                else {
                    logxw("Wow, should not be the case!");
                    PACKET_FREE(p);
                    continue;
                }
            }
            // tuple->dir = CLIENT_PACKET;
            PACKET_FREE(p);
            continue;
        }

        // 根据服务器地址判断该数据包是客户端数据包还是服务器数据包
        if (tuple->server_ip == GET_IPV4_DST_ADDR_U32(p))
            tuple->dir = CLIENT_PACKET;
        else if (tuple->server_ip = GET_IPV4_SRC_ADDR_U32(p))
            tuple->dir = SERVER_PACKET;
        else {
            logxw("This is not possible");
            PACKET_FREE(p);
            continue;
        }

        // 接收到了 fin/ack 数据包
        if (tuple->state > TCP_OFF && tuple->state != TCP_DISCONNECT_OK) {
            if (TCP_ISSET_FLAG_FIN(p) > 0 && TCP_ISSET_FLAG_ACK(p) > 0) {
                if (tuple->dir == CLIENT_PACKET) {
                    logd("It's FIN/ACK packet, C->S");
                    tuple->state =
                        (tuple->state == TCP_CONNECT_OK
                         ? TCP_DISCONNECT_CLIENT : (tuple->state | TCP_DISCONNECT_CLIENT));
                }
                else {
                    logd("It's FIN/ACK packet, S->C");
                    tuple->state =
                        (tuple->state == TCP_CONNECT_OK
                         ? TCP_DISCONNECT_SERVER : (tuple->state | TCP_DISCONNECT_SERVER));
                }
            }

            if (tuple->state == TCP_DISCONNECT_OK) {
                struct timeval tv;
                unsigned long expires;

                get_monotonic(&tv);
                expires = tv.tv_sec * 1000 + tv.tv_usec / 1000 + 10000; // 30秒释放
                if (0 != MinHeapAddNode(timer, tuple, expires)) {
                    logxw("Wow, tuple add to tuple_timer failed");
                }
                if (MinHeapTimerIsWait())
                    TellMinHeapTimer(CMD_HAVE_DATA);
            }
        }

        if (tuple->state == TCP_DISCONNECT_OK && TCP_ISSET_FLAG_ACK(p) > 0
                && TCP_ISSET_FLAG_FIN(p) == 0 && TCP_ISSET_FLAG_SYN(p) == 0) {
            /* release tuple */
            PPktDeleteTuple(tuple_hash, tuple);
            PACKET_FREE(p);
            continue;
        }
#endif

        logd("start process packet...");
        // logm("p %p ether type %04x", p, ntohs(p->ethh->eth_type));
        // char s[16], d[16];
        // inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), s, sizeof(s));
        // inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), d, sizeof(d));

        // logm("IPV4 %s->%s PROTO: %" PRIu32 " OFFSET: %" PRIu32 " %s %s %s "
        //         "RF: %" PRIu32 " DF: %" PRIu32 " MF: %" PRIu32 " ID: %" PRIu32 "", s,d,
        //         IPV4_GET_IPPROTO(p), IPV4_GET_IPOFFSET(p),
        //         (TCP_ISSET_FLAG_SYN(p) > 0) ? "SYN":" ",
        //         (TCP_ISSET_FLAG_ACK(p)>0)?"ACK":" ",
        //         (TCP_ISSET_FLAG_FIN(p)>0)?"FIN":" ",
        //         IPV4_GET_RF(p),
        //         IPV4_GET_DF(p), IPV4_GET_MF(p), IPV4_GET_IPID(p));

        // logm("TCP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 "  %s%s%s%s%s",
        //         GET_TCP_SRC_PORT(p), GET_TCP_DST_PORT(p), TCP_GET_HLEN(p),
        //         TCP_HAS_SACKOK(p) ? "SACKOK " : "", TCP_HAS_SACK(p) ? "SACK " : "",
        //         TCP_HAS_WSCALE(p) ? "WS " : "", TCP_HAS_TS(p) ? "TS " : "",
        //         TCP_HAS_MSS(p) ? "MSS " : "");

        // logm("%s", p->payload);
        if (p->payload_len > 0 && 0 == PPktParseHttpHeader(tuple, p->payload, p->payload_len)) {
            logm("====dir: %d", tuple->dir);
            logm("====domain: %.*s", tuple->context.http->domain_len, tuple->context.http->domain);
            logm("====url: %s", tuple->context.http->url);
        }

        if (!tuple->context.http) {
            int ret;
            if (0 != (ret = PPktParseHttpHeader(tuple, p->payload, p->payload_len)))
                ret = PPktParseHttpsHeader(tuple, p->payload, p->payload_len);
            if (ret == 0) {
                logm("====dir: %d", tuple->dir);
                logm("====domain: %.*s", tuple->context.http->domain_len, tuple->context.http->domain);
                logm("====url: %s", tuple->context.http->url);
            }
        }

        if (p->payload_len > 0 && GET_TCP_DST_PORT(p) == 25) {
            PPktParseEmailInfo(tuple, p->payload, p->payload_len);
            if (tuple->context.email->get_ok == 4) {
                logm("====date: %s", tuple->context.email->date);
                logm("====From: %s", tuple->context.email->sender);
                logm("====To:   %s", tuple->context.email->recver);
                logm("====Subject: %s", tuple->context.email->subject);
            }
        }

        // p->ReleasePacket(p);
        PACKET_FREE(p);
    }
    stop_save_packet();
    logd("The process packet thread exit.");

    return NULL;
}



int PPktProcessTimerNode(void *data)
{
    logd("Enter PPktProcessTimerNode >>>");

    hashmap_t *tuple_hash = parse_pkt_cfg->tuple_hash;
    minheap_t *timer = parse_pkt_cfg->tuple_timer;
    BUG_ON(tuple_hash == NULL);


    if (!data) return 0;
    tuple_t *tuple = (tuple_t *)data;

    // tuple 没有被使用
    if (tuple->flags & TUPLE_IS_SPARE) {
        logd("The tuple is spare, alreadly delete from other");
        return 0;
    }

    // 如果在最近EXPIRES/2之内通信过，重新将该tuple放入定时器中，并重设EXPIRES
    if ((tuple->expires - tuple->last_communicate) < EXPIRES / 2) {
        logd("The tuple (expires-last_communicate = %lu) < %d",
                tuple->expires-tuple->last_communicate, EXPIRES/2);
        tuple->expires += EXPIRES;
        PPktAddTupleToTimer(timer, tuple, EXPIRES);
        return 0;
    }

    PPktDeleteTuple(tuple_hash, tuple);
    logd("Exit PPktProcessTimerNode <<<");
    return 0;
}


void PPktSignalHandler(int signo, siginfo_t *info, void *ucontext)
{
    if (signo != SIGUSR1 && signo != SIGINT) return;
    logd("I get a signal: %d", signo);

    TellMinHeapTimer(CMD_EXIT);
    is_exit = 1;
    main_exit = 1;

    // may have problem
    if (parse_pkt_cfg->pktq->size == 0)
        pthread_cond_signal(&parse_pkt_cfg->pktq->cont);
}


void PPktInit()
{
    debug_backtrace_init();

    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = PPktSignalHandler;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL) != 0
            || sigaction(SIGINT, &sa, NULL) != 0) {
        fprintf(stderr, "backtrace failed to set signal handler for %s(%d)!\n",
                strsignal(SIGUSR1), SIGUSR1);
    }

    log_init(GH_LOG_DEBUG, NULL);

    if (!parse_pkt_cfg) {
        parse_pkt_cfg = calloc(1, sizeof(*parse_pkt_cfg));
        if (!parse_pkt_cfg)
            loge("Can't calloc");
    }

    PacketQueue **pktq = &parse_pkt_cfg->pktq;;
    hashmap_t **tuple_hash = &parse_pkt_cfg->tuple_hash;
    minheap_t **tuple_timer = &parse_pkt_cfg->tuple_timer;
    tuple_t **tuple = &parse_pkt_cfg->tuple;
    tuple_t **spare_tuple = &parse_pkt_cfg->spare_tuple;
    // tuple_t **consume_tuple = &parse_pkt_cfg->consume_tuple;


    if (!(*pktq)) {
        *pktq = calloc(1, sizeof(PacketQueue));
        if (!(*pktq))
            loge("Can't calloc");
        pthread_mutex_init(&(*pktq)->mutex, NULL);
        pthread_cond_init(&(*pktq)->cont, NULL);
    }

    if (!(*tuple_hash) && (*tuple_hash = hashmap_create(10000000, PPktReleaceTuple)) == NULL) {
        logxw("Wow, hashmap_create failed.");
        goto FAILED;
    }

    if (!(*tuple_timer) && (*tuple_timer = MinHeapInit(1000000, PPktProcessTimerNode)) == NULL) {
        logxw("Wow, MinHeapInit failed.");
        goto FAILED;
    }

    if (!(*tuple)) {
        *tuple = calloc(tuple_max, sizeof(tuple_t));
        if (!(*tuple)) {
            logw("Can't calloc.");
            goto FAILED;
        }
        logd("%p  %p  %p  %p", *tuple, (*tuple)+1,(*tuple)+2,(*tuple)+3);

        int i = 0;
        tuple_t *t1 = *tuple;
        for (i = 1; i < tuple_max; i++) {
            PPKT_TUPLE_INIT(t1);
#ifdef MAIN_MULTI_PTHREAD
            pthread_mutex_init(&t1->mutex, NULL);
#endif
            t1->next = ((*tuple)+i);
            t1 = t1->next;
        }
        t1->next = NULL;

        logd(">%p %p %p %p", *tuple, (*tuple)->next, (*tuple)->next->next,
                (*tuple)->next->next->next);

        BUG_ON((*tuple)+1 != (*tuple)->next);
        BUG_ON((*tuple)+2 != (*tuple)->next->next);

        *spare_tuple = *tuple;
        parse_pkt_cfg->spare_tuple_count = tuple_max;

        // *consume_tuple = NULL;
        // parse_pkt_cfg->consume_tuple_count = 0;
    }

    return ;

FAILED:
    if (*pktq) free(*pktq);
    if (*tuple_hash) free(*tuple_hash);
    if (*tuple_timer) free(*tuple_timer);
    if (!(*tuple)) free(*tuple);
    exit(1);
}


void PPktExit()
{
    pcap_t **handle = &parse_pkt_cfg->handle;
    unsigned long *pcap_capture_packet_count = &parse_pkt_cfg->pcap_capture_packet_count;
    PacketQueue **pktq = &parse_pkt_cfg->pktq;;
    hashmap_t **tuple_hash = &parse_pkt_cfg->tuple_hash;
    minheap_t **tuple_timer = &parse_pkt_cfg->tuple_timer;
    tuple_t **tuple = &parse_pkt_cfg->tuple;

    if (*handle) {
        pcap_close(*handle);
    }

    if (*pktq) {
        pthread_mutex_lock(&(*pktq)->mutex);
        Packet *p = (*pktq)->head, *next;
        while ((*pktq)->size > 0 && p != NULL) {
            next = p->next;
            PACKET_FREE(p);
            p = next;
            (*pktq)->size--;
        }
        pthread_mutex_unlock(&(*pktq)->mutex);
        free(*pktq);
    }

    if (*tuple_timer)
        MinHeapDestroy(*tuple_timer);

    if (*tuple_hash)
        hashmap_destroy(*tuple_hash);

    if (*tuple)
        free(*tuple);

    logm("Total capture packet count: %lu", *pcap_capture_packet_count);
}


/**
 * @brief PPktProcessTimerThread 处理定时器的线程
 *
 * @param data
 *
 * @return
 */
void *PPktProcessTimerThread(void *data)
{
    if (!data) {
        logxw("Why? You don't give me parameter values.");
        exit(1);
        // return NULL;
    }
    minheap_t *mp = (minheap_t *)data;

    if (-1 == MinHeapTimerLoop(mp)) {
        logxw("Call MinHeapTimerLoop failed.");
        exit(1);
        // return NULL;
    }
    logd("The process timer thread exit.");

    return NULL;
}


int main(int argc, char *argv[])
{
    int ret;
    const uint16_t pkt_queue_n = 64;
    pthread_t pid, pid2;

    PPktInit();

    if (0 != pthread_create(&pid, NULL, PPktProcessPacket, NULL)) {
        logw("Can't create thread");
        exit(1);
    }

    if (0 != pthread_create(&pid2, NULL, PPktProcessTimerThread,
                (void *)parse_pkt_cfg->tuple_timer)) {
        logw("Can't create thread");
        exit(1);
    }

    pcap_t **handle = &parse_pkt_cfg->handle;

    // create pcap handle
    *handle = PPktPcapCreate(NULL);
    if (NULL == (*handle))
        logxe("PPktPcapCreate failed.");

    while(1) {
        if (1 == main_exit) break;
        ret = pcap_dispatch(*handle, pkt_queue_n, (pcap_handler)PPktPcapCallback, NULL);
        if (ret < 0) { // have error
            logw("Pcap dispatch error: %s.", pcap_geterr(*handle));

            // try reopen handle
            if (PPktPcapTryReopen(*handle) != 0)
                break; // reopen failed
        } else if (ret == 0) { // timeout
            // logm("Pcap dispatch timeout.");
            continue;
        }
    }
    logd("The main thread exit.");
    pthread_join(pid, NULL);
    pthread_join(pid2, NULL);

    PPktExit();

    return 0;
}



