/**
 * \file decode-gre.h
 *
 * Generic Route Encapsulation (GRE) from RFC 1701.
 */

#ifndef __DECODE_GRE_H__
#define __DECODE_GRE_H__




#if 0
IPv6的部署大致要经历一个渐进的过程，在初始阶段，IPv4的网络海洋中会出现若干局部零散的IPv6孤岛，
为了保持通信，这些孤岛通过跨越IPv4的隧道彼此连接；随着IPv6规模的应用，原来的孤岛逐渐聚合成为
了骨干的IPv6 Internet网络，形成于IPv4骨干网并存的局面，在IPv6骨干上可以引入了大量的新业务，同
时可以充分发挥IPv6的诸多优势。为了实现IPv6和IPv4网络资源的互访，还需要转换服务器以实现v6和v4的
互通；最后，IPv4骨干网逐步萎缩成局部的孤岛，通过隧道连接，IPv6占据了主导地位，具备全球范围的连
通性。
IPv6提供很多过渡技术来实现上述这样一个演进过程。这些过渡技术围绕两类问题解决：
IPv6孤岛互通技术：实现IPv6网络和IPv6网络的互通
IPv6和IPv4互通技术：实现两个不同网络之间互相访问资源
目前，解决上述问题的基本过渡技术有两种：双栈和隧道。
双栈：即设备升级到IPv6的同时保留IPv4支持，可以同时访问IPv6和IPv4设备，包含双协议栈支持，应用程
序依靠DNS地址解析返回的地址类型，来决定使用何种协议栈。
隧道：通过在一种协议中承载另一种协议，实现跨越不同域的互通，具体可以是IPv6-in-IPv4,IPv6-in-MPLS,IPv4-in-IPv6等隧道类型。

GRE隧道（VPN）
GRE与IP in IP、IPX over IP等封装形式很相似，但比他们更通用。在GRE的处理中，很多协议的席位差异都被忽略，
这使得GRE不限于某个特定的“X over Y”应用，而是一种最基本的封装形式。
在最简单的情况下，路由器接收到一个需要封装和路由的原始数据报文（Payload），这个报文首先被GRE封装而成
GRE报文，接着被封装在IP协议中，然后完全由IP层负责此报文的转发。原始报文的协议被称之为乘客协议，GRE被
称之为封装协议，而负责转发的IP协议被称之为传递（Delivery）协议或传输（Transport）协议。注意到在以上的
流程中不用关心乘客协议的具体格式或内容，整个被封装的报文格式：

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Checksum (optional)      |       Offset (optional)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Key (optional)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (optional)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Routing (optional)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

字段    解释
C   校验和验证位。1-GRE头插入了校验和（Checksum）字段。0-GRE头不包含校验和字段。
K   关键字位。1-GRE头插入了关键字（Key）字段。0-GRE头不包含关键字字段。
Recursion   GRE报文被封装的层数。一次GRE封装后将该字段加1。如果封装层数大于3，则丢弃该报文。
            该字段的作用是防止报文被无限次的封装。RFC1701规定该字段默认值为0。RFC2784规定当
            发送和接受端该字段不一致时不会引起异常，且接收端必须忽略该字段。设备实现时该字段
            仅在加封装报文时用作标记隧道嵌套层数，GRE解封装报文时不感知该字段，不会影响报文的处理。
Flags   预留字段。当前必须置为0。
Version 版本字段。必须置为0。
Protocol    标识乘客协议的协议类型。常见的乘客协议为IPv4协议，协议代码为0800。
Checksum    对GRE头及其负载的校验和字段。
Key 关键字字段，隧道接收端用于对收到的报文进行验证。

#endif



#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

// #include "packet.h"

typedef struct GREHdr_
{
    uint8_t flags; /**< GRE packet flags */
    uint8_t version; /**< GRE version */
    uint16_t ether_type; /**< ether type of the encapsulated traffic */

} __attribute__((__packed__)) GREHdr;

/* Generic Routing Encapsulation Source Route Entries (SREs).
 * The header is followed by a variable amount of Routing Information.
 */
typedef struct GRESreHdr_
{
    uint16_t af; /**< Address family */
    uint8_t sre_offset;
    uint8_t sre_length;
} __attribute__((__packed__)) GRESreHdr;

#define GRE_VERSION_0           0x0000
#define GRE_VERSION_1           0x0001

#define GRE_HDR_LEN             4
#define GRE_CHKSUM_LEN          2
#define GRE_OFFSET_LEN          2
#define GRE_KEY_LEN             4
#define GRE_SEQ_LEN             4
#define GRE_SRE_HDR_LEN         4
#define GRE_PROTO_PPP           0x880b

#define GRE_FLAG_ISSET_CHKSUM(r)    (r->flags & 0x80)
#define GRE_FLAG_ISSET_ROUTE(r)     (r->flags & 0x40)
#define GRE_FLAG_ISSET_KY(r)        (r->flags & 0x20)
#define GRE_FLAG_ISSET_SQ(r)        (r->flags & 0x10)
#define GRE_FLAG_ISSET_SSR(r)       (r->flags & 0x08)
#define GRE_FLAG_ISSET_RECUR(r)     (r->flags & 0x07)
#define GRE_GET_VERSION(r)   (r->version & 0x07)
#define GRE_GET_FLAGS(r)     (r->version & 0xF8)
#define GRE_GET_PROTO(r)     ntohs(r->ether_type)

#define GREV1_HDR_LEN           8
#define GREV1_ACK_LEN           4
#define GREV1_FLAG_ISSET_FLAGS(r)  (r->version & 0x78)
#define GREV1_FLAG_ISSET_ACK(r)    (r->version & 0x80)

void DecodeGRERegisterTests(void);

#endif /* __DECODE_GRE_H__ */

