#ifndef __QDNS_H_ 
#define __QDNS_H_
#include <inttypes.h>

#define _DEBUG_

#define False  0
#define Ture  (!(False))

typedef int  BOOL;


#define BITS_ANY_SET(val, bits)  (0 != ((val) & (bits)))
#define BITS_ALL_SET(val, bits)  ((bits) == ((val) & (bits)))


#define DEFAULT_DNS_FILE "/etc/resolv.conf"
#define DNS_SERVER  "8.8.8.8"

#define QDNS_SERVER  "0.0.0.0"
#define QDNS_PORT    12345

#define LOG_FILE "/tmp/qdns.log"

#define LOCK_FILE "/var/run/qdns.pid"   
#define LOCK_MODE (S_IRUSR|S_IWUSR|S_IRGRP)

#define PROGREM "Qdns"


/* dns header flags options */
enum {
    RCODE_TURE = (0 << 0), /* 返回码 成功 */
    RCODE_ERROR = (1 << 0), /* 名字差错 */ 
    RCODE_SERVER_FAILURE = (2 << 0), /* 服务器错误 */
    FLAGS_RA = (1 << 7), /* 表示可用递归 */
    FLAGS_RD = (1 << 8), /* 表示期望递归 */
    FLAGS_TC = (1 << 9), /* 表示可截断的 */
    FLAGS_AA = (1 << 10),/* 表示授权回答 */
    OPCODE_STANDARD_QUERY = (0 << 11), /* 标准查询 */
    OPCODE_INVERSE_QUERY = (1 << 11),  /* 反向查询 */
    OPCODE_SERVER_STATUS_QUERY = (2 << 11), /* 服务器状态请求 */
    QUERY = (0 << 15), /* 查询/响应标志，0为查询，1为响应 */
    ANSWER = (1 << 15),
};


enum {
    DNS_TYPE_A = 1, /* 由域名获得IPv4地址 */
    DNS_TYPE_NS = 2,/* 查询域名服务器 */
    DNS_TYPE_CNAME = 5,/* 查询规范名称 */
    DNS_TYPE_PTR = 12, /* 把IP地址转换成域名 */
    DNS_TYPE_AAAA = 28,/* 由域名获得IPv6地址 */
};

typedef struct _dns_server {
    BOOL valid;
    char *server;
    struct _dns_server *next;
} dns_server_t, *dns_server_p;


typedef struct _dns_header {
    uint16_t TransactionID;
    uint16_t Flags;
    uint16_t Questions;
    uint16_t AnswerRRs;
    uint16_t AuthorityRRs;
    uint16_t AdditionalRRS;
} dns_header_t, *dns_header_p;
#define DNS_HEADER_LENGTH  12


typedef struct _dns_queries {
    uint8_t *Name;
    uint16_t Type;
    uint16_t Class;
} dns_queries_t, *dns_queries_p;


typedef struct _dns_answers {
    uint8_t *Name;
    uint16_t Type;
    uint16_t Class;
    uint32_t TTL;
    uint16_t DataLen;
    uint8_t *Data;
    struct _dns_answers *next;
} dns_answers_t, *ans_answers_p;


typedef struct _dns_result {
    struct _dns_header header;
    struct _dns_queries queries;
    struct _dns_answers *answers;
} dns_result_t, *dns_result_p;


struct domain_info {
    uint8_t doit_num;
    uint8_t each_paragraph_count[5];
};

// typedef struct _Qdns_conf {
//     int dns_fd;

// } Qdns_conf;



int dns_parse_userdata(char *buff, int fd);
#endif



