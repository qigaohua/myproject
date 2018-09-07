#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>

#include "GHdns.h"
#include "log.h"
#include "eloop.h"
// #include "gh_list.h"
#include "util.h"

// gh_list_t dns_parse_ok;


int is_already_running(const char *lock_file, mode_t lock_mode) {
    int ret, fd;
    char buf[32];
    struct flock fl;

    fd = open(lock_file, O_RDWR|O_CREAT, lock_mode);
    if (fd < 0) {
#ifdef DEBUG
        syslog(LOG_INFO, "open lock file[%s] error.\n", lock_file);
#endif
        exit(1);
    }
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    ret = fcntl(fd, F_SETLK, &fl);
    if (ret) {
        /* already running or some error. */
        close(fd);
        return 1;
    }
    /* O.K. write the pid */
    ret = ftruncate(fd,0);
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)getpid());
    ret = write(fd, buf, strlen(buf) + 1);

    return 0;
}

// 域名限制 (63letters).(63 letters).(63 letters).(62 letters)
int is_ture_domain(char *domain)
{
    int doit_count = 0;
    int each_paragraph_count = 0;
    int len = 0;
    char *p;

    len = strlen(domain);
    if (len < 4 || len > 255) {
        LOGG_WARN("domain not valid, maxlen is 255");
        return 0;
    }

    p = domain + len - 1;
    while(len--) {
        if (isalnum(*p) || *p == '-') {
            each_paragraph_count ++;
            if (doit_count == 0) {
                if (each_paragraph_count > 62) {
                    LOGG_WARN("domain not valid.");
                    return 0;
                }
            } else {
                if (each_paragraph_count > 63) {
                    LOGG_WARN("domain not valid.");
                    return 0;
                }
            }
        } else if (*p == '.') {
            doit_count ++;

            /* .com  '.' 开始的域名 */
            if (doit_count > 3 || len == 0) {
                LOGG_WARN("domain not valied.");
                return 0;
            }
            each_paragraph_count = 0;

        } else {
            LOGG_WARN("domain contains unlawful characters");
            return 0;
        }

        p --;
    }

    return 1;
}

int set_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1 ||
            fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_recold_file(GH_LOG_WARN, LOG_FILE, "set_nonblock() failed");
        return -1;
    }

    return 0;
}

int set_cloexec(int fd) 
{
    int flags;

    if ((flags = fcntl(fd, F_GETFD, 0)) == -1 ||
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
        log_recold_file(GH_LOG_WARN, LOG_FILE, "set_cloexec() failed");
        return -1;
    }

    return 0;
}


int tcp_socket(const char *host, uint16_t port)
{
    int sock, ret;
    struct sockaddr_in addr;

    if (-1 == (sock = socket(AF_INET, SOCK_STREAM, 0))) {
        log_recold_file(GH_LOG_ERROR, LOG_FILE, "socket() failed");
        exit(EXIT_FAILURE);
    }

    set_nonblock(sock);
    set_cloexec(sock);

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        /* maybe host name */
        struct hostent *hp;
        hp = gethostbyname(host);
        if (NULL == hp) {
            log_recold_file(GH_LOG_ERROR, LOG_FILE, "host not valid.");
            exit(EXIT_FAILURE);
        } 
        
        memcpy(&addr.sin_addr, &hp->h_addr, hp->h_length);
    }

    int len = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&len, sizeof(int));
    if (ret) {
        log_recold_file(GH_LOG_ERROR, LOG_FILE, "setsockopt() failed.");
        exit(EXIT_FAILURE);
    }

    if (-1 == bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr))) {
        log_debug("bind() failed");
        return -1;
    }

    listen(sock, 1024);

    return sock;
}

ssize_t Recvfrom(int sockfd, void *buff, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen )
{
    BOOL isOK = False;
    ssize_t r_len, offset = 0;

    uint8_t *p = (uint8_t*)buff;
    do {
        r_len = recvfrom(sockfd, p, len - offset, flags, (struct sockaddr *)&src_addr, addrlen);
        
        if (r_len == 0) 
            isOK = Ture;
        else if (r_len < 0) {
            if (errno == EINTR)
                continue;
            else if(errno == EAGAIN) {
                log_debug("Recvform() EAGAIN");
                isOK = Ture;
            } else {
                LOGG_WARN("Recvfrom() error (%m)");
                isOK = Ture;
            }
        } else {
            offset += r_len;
            p += r_len; 
        }


    } while (isOK == False);

    return p - (uint8_t*)buff;
}


/**
 * @brief 递归的解析dns数据中的域名信息
 *
 * @param p_dns  接收的dns数据开始指针
 * @param dns_offset 当前解析dns数据的指针
 * @param name 存放解析后的数据
 *
 * @return 返回解析数据实际的偏移量
 *
 * 因为DNS报文中域名重复出现的时候，该字段使用2个字节的
 * 偏移指针来表示。比如，在资源记录中，域名通常是查
 * 询问题部分的域名的重复，因此用2字节的指针来表示，
 * 具体格式是最前面的两个高位是 11，用于识别指针。
 * 其余的14位从DNS报文的开始处计数（从0开始），指出
 * 该报文中的相应字节数。一个典型的例子，C00C(1100000000001100，
 * 12正好是头部的长度，其正好指向Queries区域的查询名字字段)
 * [查询一下dns报文的格式]  
 */
int dns_resolve_name(void *p_dns, void *dns_offset, char *name)
{
    ssize_t len, ret;
    // uint8_t buff[1024] = {0};

    uint8_t *p = (uint8_t *)dns_offset;

    if (*p == '\0') {
        /* 去掉最后的 ‘.’ */
        *(name-1) = '\0';
        ret = 1;
    }
    else if (BITS_ALL_SET(*p, 0xc0)) {
        uint8_t offset = *++p;
        // uint8_t *p_current = (uint8_t *)p_dns + offset;
        dns_resolve_name(p_dns, (uint8_t*)p_dns + offset, name);
        return 2;
    } else {
        len = *p; 
        memcpy(name, ++p, len);
        name[len] = '.';
        p += len; ret = len + 1;

        ret += dns_resolve_name(p_dns, p, name + len + 1);
    }


    return ret;
}

void dns_result_free(void *ptr)
{
    dns_answers_t *next, *dns_answers;
    dns_result_t *dns_result = (dns_result_t *)ptr;

    if (dns_result) {
        if (dns_result->queries.Name)
            free(dns_result->queries.Name);
        
        dns_answers = dns_result->answers;

        while (dns_answers) {
            if (dns_answers->Name)
                free(dns_answers->Name);

            next = dns_answers->next;
            free(dns_answers);

            dns_answers = next;
        }
    }

    free(dns_result);
}

dns_result_p parse_dns_recvdata(void *buff, ssize_t len)
{
    uint8_t *p = (uint8_t*)buff;
    dns_result_t *dns_result =  NULL;

    if (len > 0) {
        dns_result = xzalloc(sizeof(*dns_result));
        // if (dns_result)
        //     memset(dns_result, 0, sizeof(*dns_result));
        // else 
        //     LOG_ERROR("malloc() failed [%m]");

        // dns header
        {
#if 0
            uint16_t tid = 0;
            copy_uint16(&tid, (uint16_t*)p);
            dns_result->header.TransactionID = tid;
#endif
            dns_result->header.TransactionID = *(uint16_t*)p;
            // LOGG_INFO("tid>> %d", tid);
            p += 2;

            dns_result->header.Flags = *(uint16_t*)p;
            // LOGG_INFO("flags>> %04X", *(uint16_t*)p);
            p += 2;
            dns_result->header.Questions = ntohs(*(uint16_t*)p);
            // LOGG_INFO("Questions>> %d", ntohs(*(uint16_t*)p));
            p += 2;
            dns_result->header.AnswerRRs = ntohs(*(uint16_t*)p);
            // LOGG_INFO("AnswerRRs>> %d", ntohs(*(uint16_t*)p));
            p += 2;
            dns_result->header.AuthorityRRs = ntohs(*(uint16_t*)p);
            // LOGG_INFO("AuthorityRRs>> %d", ntohs(*(uint16_t*)p));
            p += 2;
            dns_result->header.AdditionalRRS = ntohs(*(uint16_t*)p);
            // LOGG_INFO("AdditionalRRS>> %d", ntohs(*(uint16_t*)p));
            p += 2;

        }

        // Questions
        {
            // uint8_t len, offset = 0;
            // uint8_t buff[1024] = {0};
            // while (*p != '\0') {
            //    len = *p; 
            //    memcpy(buff + offset, ++p, len);
            //    offset += len;
            //    buff[offset++] = '.';
            //    p += len;
            // }
            // p ++;
            // if (buff[0] != '\0') {
            //     dns_result->queries.Name = malloc(offset+1);
            //     memcpy(dns_result->queries.Name, (char*)buff, offset+1);
            // }
            // dns_result->queries.Type = ntohs(*(u_int16_t*)p);
            // p += 2;
            // dns_result->queries.Class = ntohs(*(uint16_t*)p);
            // p += 2;
            
            char name[255] = {0};
            p += dns_resolve_name(buff, p, name);
            if (name[0] != '\0') {
                uint8_t len = strlen((char*)name) + 1;
                dns_result->queries.Name = xzalloc(len);
                memcpy(dns_result->queries.Name, name, len);
            }
            dns_result->queries.Type = ntohs(*(u_int16_t*)p);
            p += 2;
            dns_result->queries.Class = ntohs(*(uint16_t*)p);
            p += 2;
        }

        // AnswerRRs
        int answers_num = dns_result->header.AnswerRRs;
        while (answers_num --) {
            dns_answers_t *dns_answers = NULL;
            dns_answers = xzalloc(sizeof(dns_answers_t));
            // if (dns_answers) 
            //     memset(dns_answers, 0, sizeof(dns_answers_t));
            // else 
            //     LOG_ERROR("malloc() failed");

            char name[255] = {0};
            p += dns_resolve_name(buff, p, name);
            if (name[0] != '\0') {
                uint8_t len = strlen((char*)name) + 1;
                dns_answers->Name = xzalloc(len);
                memcpy(dns_answers->Name, name, len);
            }

            /* if 成立，则此区域域名与请求区相同，后面数据记录域名所在位置的偏移量 */
            // if (BITS_ALL_SET(*p, 0xC0)) {
            //     int len = strlen((char*)dns_result->queries.Name) + 1;
            //     dns_answers->Name = malloc(len);
            //     memcpy(dns_answers->Name, dns_result->queries.Name, len);
            //     p += 2;
            // } else {
            //     uint8_t len, offset = 0;
            //     uint8_t buff[1024] = {0};

            //     while (*p != '\0') {
            //         len = *p; 
            //         memcpy(buff + offset, ++p, len);
            //         offset += len;
            //         buff[offset++] = '.';
            //         p += len;
            //     }
            //     p ++;
            //     if (buff[0] != '\0') {
            //         dns_answers->Name = malloc(offset+1);
            //         memcpy(dns_answers->Name, (char*)buff, offset+1);
            //     }
            // }
                
            dns_answers->Type = ntohs(*(uint16_t*)p);
            p += 2;
            dns_answers->Class = ntohs(*(uint16_t*)p);
            p += 2;
            dns_answers->TTL = ntohl(*(uint32_t*)p);
            p += 4;
            // p +=  copy_uint32(&dns_answers->TTL, p);
            dns_answers->DataLen = ntohs(*(uint16_t*)p);
            p += 2;

            dns_answers->Data = xzalloc(dns_answers->DataLen + 1);


            if (dns_answers->Type == DNS_TYPE_CNAME) {
                dns_resolve_name(buff, p, (char*)dns_answers->Data);
                // memcpy(dns_answers->Data, p, dns_answers->DataLen);
            } else 
                memcpy(dns_answers->Data, p, dns_answers->DataLen);

            p += dns_answers->DataLen;

            if (dns_result->answers == NULL) {
                dns_answers->next = NULL;
                dns_result->answers = dns_answers;
            } else {
                dns_answers->next = dns_result->answers;
                dns_result->answers = dns_answers;
            }
        }
    }

#ifdef _DEBUG_
    if (dns_result) {
        printf("TransactionID: %d\n", dns_result->header.TransactionID);
        printf("Flags: %04X\n", dns_result->header.Flags);
        printf("Questions: %d\n", dns_result->header.Questions);
        printf("AnswerRRs: %d\n", dns_result->header.AnswerRRs);
        printf("AuthorityRRs: %d\n", dns_result->header.AuthorityRRs);
        printf("AdditionalRRS: %d\n", dns_result->header.AdditionalRRS);

        printf ("queries domain: %s\n", dns_result->queries.Name);
        printf("queries Type: %d\n", dns_result->queries.Type);
        printf("queries Class: %d\n", dns_result->queries.Class);

        if (dns_result->answers) {
            dns_answers_t *next = dns_result->answers;
            while (next) {
                printf ("answers domain: %s\n", next->Name);
                printf("answers Type: %d\n", next->Type);
                printf("answers class: %d\n", next->Class);
                printf("answers TTL: %d\n", next->TTL);
                if (next->DataLen == 4) 
                    printf("answers ip: %d.%d.%d.%d\n", next->Data[0], next->Data[1], next->Data[2], next->Data[3]);
                else 
                    printf("answers Data: %s\n", (char *)next->Data);


                next = next->next;
            }
        }
    }
#endif

    return dns_result;
}


/**
 * @brief 将dns结果发送给客户端
 *
 * @param sockfd 客户端socket
 * @param dns_result dns结果结构体
 *
 * @return -1 失败 0 成功
 */
int dns_send_result(int sockfd, dns_result_t *dns_result)
{
    int s_len = 0;
    dns_answers_t *next = NULL;
    // char s_buff[1024] = {0};
    uint16_t u16;

    if (dns_result == NULL) 
        return -1;

    uint16_t result_num = dns_result->header.AnswerRRs;

    u16 = htons(result_num);
    s_len = send(sockfd, &u16, sizeof(uint16_t), 0);
    if (s_len != sizeof(uint16_t)) {
        log_recold_file(GH_LOG_ERROR, LOG_FILE, "send() dns result to client failed.");
        return -1;
    }

    next = dns_result->answers;
    while (next && result_num --) {
        // LOGG_INFO("type: %d", next->Type);
        u16 = htons(next->Type);
        s_len = send(sockfd, &u16, sizeof(uint16_t), 0);
        if (s_len != sizeof(uint16_t)) {
            log_recold_file(GH_LOG_ERROR, LOG_FILE, "send() dns result to client failed.");
            return -1;
        }

        uint16_t datalen = strlen((char*)next->Data) + 1;
        u16 = htons(datalen);
        s_len = send(sockfd, &u16, sizeof(uint16_t), 0);
        if (s_len != sizeof(uint16_t)) {
            log_recold_file(GH_LOG_ERROR, LOG_FILE, "send() dns result to client failed.");
            return -1;
        }

        s_len = send(sockfd, next->Data, datalen, 0);
        if (s_len != datalen) {
            log_recold_file(GH_LOG_ERROR, LOG_FILE, "send() dns result to client failed.");
            return -1;
        }

        next = next->next;
    }

    return 0;
}


void Qdns_result_callback(void *data, int dns_fd)
{
    int cli_fd = *(int *)data;
    char r_buff[1024] = {0};
    struct sockaddr_in s_addr;
    ssize_t r_len;
    dns_result_t *dns_result = NULL;
    socklen_t addrlen = sizeof(s_addr);

    r_len = Recvfrom(dns_fd, r_buff, sizeof(r_buff), 0, (struct sockaddr *)&s_addr, &addrlen);

#ifdef _DEBUG_
    dump(stdout, r_buff, r_len);
#endif

    dns_result = parse_dns_recvdata(r_buff, r_len);
    if (dns_result == NULL) {
        log_recold_file(GH_LOG_ERROR, LOG_FILE, "dns query failed, maybe dns server not valid.");
        goto END;
    }

    // send(cli_fd, dns_result->answers->Name, strlen((char*)dns_result->answers->Name)+1, 0);
    dns_send_result(cli_fd, dns_result);

    dns_result_free(dns_result);
    
END:
    delete_event(dns_fd);
    close(dns_fd);
    free(data); /* 释放add_event时申请的内存，防止内存泄露*/
}

int dns_recv_result(int sockfd)
{
    ssize_t r_len;
    char r_buff[1024] = {0};
    struct sockaddr_in s_addr;

    dns_result_t *dns_result = NULL;

    socklen_t addrlen = sizeof(s_addr);

    // r_len = Recvfrom(sockfd, r_buff, sizeof(r_buff), 0, (struct sockaddr *)&s_addr, &addrlen);
    r_len = recvfrom(sockfd, r_buff, sizeof(r_buff), 0, (struct sockaddr *)&s_addr, &addrlen);

    dump(stdout, r_buff, r_len);

    dns_result = parse_dns_recvdata(r_buff, r_len);
    dns_result_free(dns_result);

    return 0;
}

void Qdns_recvuserdata_callback(void *data, int fd)
{
    // int fd = *(int *)data;
    char r_buff[1024] = {0};
    ssize_t r_len;
    
    // LOGG_INFO("fd = %d", fd);
    r_len = recv(fd, r_buff, sizeof(r_buff), 0);
    if (r_len < 0) {
        log_recold_file(GH_LOG_ERROR, LOG_FILE, "recv() failed");
        return ; 
    } else if(r_len == 0) {
        log_recold_file(GH_LOG_MSG, LOG_FILE, "client close");
        delete_event(fd);
        return ;
    }
        
#ifdef _DEBUG_ 
    log_debug("recv_data: %s", r_buff);
#endif

    dns_parse_userdata(r_buff, fd);
} 

// int cli_fd;
void Qdns_recvclient_callback(void *data, int fd)
{
    int cli_fd;
    struct sockaddr_in cli_addr;
    socklen_t addrlen = sizeof(cli_addr);

    cli_fd = accept(fd, (struct sockaddr *)&cli_addr, &addrlen);
    if (cli_fd < 0) {
        log_recold_file(GH_LOG_ERROR, LOG_FILE, "accept() failed %m");
        return ;
    }

#ifdef _DEBUG_ 
    LOGG_INFO("%s connect from port %d", inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
#endif
    
    // LOGG_INFO("fd = %d", cli_fd);
    add_event(cli_fd, Qdns_recvuserdata_callback, NULL);
}

int get_dns_server(char *dns_server, const char *filename)
{
    int i;
    FILE *fp;
    char line[1024] = {0};

    if (NULL == dns_server) LOG_ERROR("param not valid");
    if (NULL == filename) filename = DEFAULT_DNS_FILE; 

    fp = fopen(filename, "r");
    if (!fp) LOG_ERROR("fopen() failed  %s", strerror(errno));

    while (fgets(line, sizeof(line), fp)) {
        i = 0;
        while (isspace(line[i])) i++;
        if (line[i] == '#') continue;
        char *p1 = &line[i];
        while (line[i] != '\0' && !isspace(line[i])) i++;
        line[i++] = '\0';
        if (strncmp(p1, "nameserver", 10) != 0) continue;
        while (isspace(line[i])) i++;
        char *p2 = &line[i];
        while (line[i] != '\0' && !isspace(line[i])) i++;
        line[i] = '\0';
        
        strncpy(dns_server, p2, strlen(p2));
        break;
    }

    return 0;
}

uint16_t _set_dns_header_flags()
{
    uint16_t flags = 0;

    flags |= FLAGS_RD | OPCODE_STANDARD_QUERY | QUERY;

    return flags;
}

void create_dns_header(dns_header_t *dns_header)
{
    dns_header->TransactionID = htons(random_uint16());
    // LOGG_INFO("send tid :%d", dns_header->TransactionID);
    dns_header->Flags = htons(_set_dns_header_flags());
    dns_header->Questions = htons(1);
    dns_header->AnswerRRs = 0;
    dns_header->AuthorityRRs = 0;
    dns_header->AdditionalRRS = 0;
}



/* 分析域名有几个段，每段多少字符，方便生成dns数据包格式 */
void parse_domain (char *domain, struct domain_info *dinfo)
{
    char *p = domain;

    if (!dinfo) LOG_ERROR("param not valid");
    memset(dinfo, 0, sizeof(*dinfo));

    while (*p != '\0') {
        if (*p == '.') 
            dinfo->doit_num ++;
        else 
            dinfo->each_paragraph_count[dinfo->doit_num]++;

        p ++;
    }
}


void create_dns_queries(dns_queries_t *dns_queries, char *domain)
{
    int i = 0; 
    char buff[1024] = {0};
    char *pbuff = buff;
    char *pdomain = domain;
    struct domain_info dinfo;

    parse_domain(domain, &dinfo);
    for (; i <= dinfo.doit_num; i++) {
        // memcpy(pbuff, &dinfo.each_paragraph_count[i], sizeof(uint8_t));
        // *pbuff = dinfo.each_paragraph_count[i] + '0';
        *pbuff = (char) dinfo.each_paragraph_count[i];
        // pbuff += sizeof(uint8_t);
        pbuff += 1;
        memcpy(pbuff, pdomain, dinfo.each_paragraph_count[i]);
        pbuff += dinfo.each_paragraph_count[i];
        pdomain += dinfo.each_paragraph_count[i] + 1;
    }
    *pbuff = '\0';


    int len = strlen(buff)+1;

    dns_queries->Name = xzalloc(len);
    memcpy(dns_queries->Name, buff, len);

    dns_queries->Type = htons(DNS_TYPE_A);
    /* 通常为1，表明是Internet数据 */
    dns_queries->Class = htons(1);
}



int create_dns_senddata(char *buff,  char *domain)
{
    char *p = buff;
    dns_header_t dns_header;
    dns_queries_t dns_queries;

    if (!is_ture_domain(domain)) {
        LOGG_WARN("domain[%s] not vaild", domain);
        return 0;
    }

    create_dns_header(&dns_header);
    memcpy(p, &dns_header, DNS_HEADER_LENGTH);
    p += DNS_HEADER_LENGTH;

    // dump(stdout, buff, 12);

    create_dns_queries(&dns_queries, domain);
    memcpy(p, dns_queries.Name, strlen((char*)dns_queries.Name)+1);

    p += strlen((char*)dns_queries.Name)+1;

    p += copy_uint16(p, &dns_queries.Type);
    p += copy_uint16(p, &dns_queries.Class);

    // memcpy(p, &dns_queries.Type, 2);
    // memcpy(p, &dns_queries.Class, 2);
    // dump(stdout, buff, 31);

    if (dns_queries.Name)
        free(dns_queries.Name);

    return p - buff;;
}


int send_dns_request(int sockfd, char *domain)
{
    char sendbuff[1024] = {0};
    char dns_server[512] = {0};
    struct sockaddr_in dns_addr;

    bzero(&dns_addr, sizeof(dns_addr));
    // memset(&dns_addr, 0, sizeof(struct sockaddr_in));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);

    get_dns_server(dns_server, NULL);
#ifdef _DEBUG_
    LOGG_INFO("dns_server: %s", dns_server);
#endif
    if (-1 == inet_pton(AF_INET, dns_server, &(dns_addr.sin_addr))) {
        LOGG_WARN("dns_server not vaild, use default server");
        inet_pton(AF_INET, DNS_SERVER, &dns_addr.sin_addr);
    }

    int len = create_dns_senddata(sendbuff, domain);
    if (len < DNS_HEADER_LENGTH)
       return -1; 

    if (-1 == sendto(sockfd, (void*)sendbuff, len, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr))){
        log_recold_file(GH_LOG_WARN, LOG_FILE, "dns request failed [%d:%m]", errno);
        return -1;
    } 

    return 0;
}

int dns_parse_userdata(char *buff, int fd)
{
    int dns_fd;

    if (-1 == (dns_fd = socket(AF_INET, SOCK_DGRAM, 0))) {
        log_debug("socket() failed");
        return -1;
    }
    set_nonblock(dns_fd);

    if (-1 == send_dns_request(dns_fd, buff))
        goto ERROR;

    int *cli_fd = (int*)xzalloc(sizeof(int)); 
    *cli_fd = fd;
    add_event(dns_fd, Qdns_result_callback, cli_fd);
    // dns_recv_result(dns_fd);

    return 0;

ERROR: 
    close(dns_fd);
    return -1;
}

int main()
{
    int server_fd;

    if (is_already_running(LOCK_FILE, LOCK_MODE)) {
        log_recold_file(GH_LOG_WARN, LOG_FILE, PROGREM" is running");       
        exit(1);
    }
    LOGG_INFO(PROGREM" start running");

    // gh_list_init (&dns_parse_ok, 100, dns_result_free);

    server_fd = tcp_socket(QDNS_SERVER, QDNS_PORT); /* port is 0, system automatic assign a port*/
    add_event(server_fd, Qdns_recvclient_callback, NULL);

    // send_dns_request("gmail.com");

    start_eloop();
    return 0;
}



