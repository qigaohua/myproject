#ifndef __PARSE_PKT_H_
#define __PARSE_PKT_H_

#include "hashmap.h"
#include "min_heap_timer.h"
#include "packet/decode.h"

// #define EXPIRES 600000UL  // 10 * 60 * 1000 默认10min后tuple释放
#define EXPIRES 20000 // 20sec  for test

enum TCP_STATE {
    TCP_OFF = 0,
    TCP_CONNECT_1, // syn c->s
    TCP_CONNECT_2, // syn ack  s->c
    TCP_CONNECT_OK, // ack c->s   connect ok
    TCP_DISCONNECT_CLIENT = 4, // fin/ack  c->s  0100
    TCP_DISCONNECT_SERVER = 8, // fin/ack  s->c  1000
    TCP_DISCONNECT_OK = 12  // TCP_DISCONNECT_CLIENT | TCP_DISCONNECT_SERVER,
};

enum {
    NO_PACKET = 0,
    CLIENT_PACKET = 1,
    SERVER_PACKET = 2,
};

enum TUPLE_FLAGS {
    TUPLE_NO_FLAGS = 0,
    TUPLE_IS_SPARE = 1,
    TUPLE_IS_CONSUME = 2,
    TUPLE_IS_ALLOC = 4,
};

typedef struct tuple_ {
    struct tuple_ *next;
    enum TUPLE_FLAGS flags;

    Packet *p;
    int  dir;     // server or client
    enum TCP_STATE state;
    uint32_t server_ip; // 用来判断数据包是服务器发的包还是客户端发的包
    unsigned long cs;  // create tuple time
    unsigned long expires; // 到期时间，释放掉
    unsigned long last_communicate; // 最近通信时间

    pthread_mutex_t mutex;

    struct http_ {
        char url[256];
        int  url_len;
        char *domain;
        int  domain_len;
        int  service; // http / https / other
    } http_info;

    struct email_ {
        char date[128]; // 发送时间
        char sender[128];
        char recver[128];
        char *subject;
        // char *message;
        int get_ok; // 等于4表示所有信息都获取到了
    } email_info;

} tuple_t;

#define PPKT_TUPLE_INIT(tuple) do {     \
    (tuple)->next = NULL;                                           \
    (tuple)->flags = TUPLE_NO_FLAGS;                                \
    (tuple)->p = NULL;                                              \
    (tuple)->dir = NO_PACKET;                                       \
    (tuple)->state = TCP_OFF;                                       \
    (tuple)->server_ip = 0;                                         \
    (tuple)->cs = 0;                                                \
    (tuple)->expires = 0;                                           \
    (tuple)->last_communicate = 0;                                  \
    memset(&(tuple)->http_info, 0, sizeof((tuple)->http_info));     \
    memset(&(tuple)->email_info, 0, sizeof((tuple)->email_info));   \
} while(0)


typedef struct parse_pkt_ {
    tuple_t *tuple;
    tuple_t *spare_tuple; // 空闲的tuple
    unsigned int spare_tuple_count;
    // tuple_t *consume_tuple; // 占用的tuple
    // unsigned int consume_tuple_count;
    int max_tuple;

    pcap_t *handle;
    unsigned long pcap_capture_packet_count;

    PacketQueue *pktq;
    hashmap_t *tuple_hash;
    minheap_t *tuple_timer;
} parse_pkt_t;


#endif
