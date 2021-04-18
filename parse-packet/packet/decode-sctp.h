/**
 * \file
 *
 */

#ifndef __DECODE_SCTP_H__
#define __DECODE_SCTP_H__


#if 0


0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
----------------------------------------------------------------
    16bit 源端口               |     16bit 目的端口            |
----------------------------------------------------------------
                     32bit 验证标签                            |
----------------------------------------------------------------
                     32bit 校验码                              |
----------------------------------------------------------------
----------------------------------------------------------------
 8b Chunk Type | 8b Chunk Flags|    16bit Chunk length         |
----------------------------------------------------------------  Chunk #1
                  Chunk Value                                  |
                                                               |
----------------------------------------------------------------
                         。
                         。
                         。
----------------------------------------------------------------
 8b Chunk Type | 8b Chunk Flags|    16bit Chunk length         |
---------------------------------------------------------------- Chunk #n
                  Chunk Value                                  |
                                                               |
----------------------------------------------------------------

一个SCTP包含了一个公共的报文头（CommonHeader）和若干数据块（Chunk），每个数据块中既可以包含控制信息，也可以包含用户数据。
除了INIT、INITACK和SHUTDOWNCOMPLETE数据块外，其他类型的多个数据块可以捆绑在一个SCTP报文中，以满足对MTU大小的要求。当然，
这些数据块也可以不与其他数据块捆绑在一个报文中。如果一个用户消息不能放在一个SCTP报文中，这个消息可以被分成若干个数据块。

公共头的各个部分及其含义：
源端口号和目地端口号：用于STCP的多路复用和多路分解，即标识发端和收端应用进程。
验证标签：耦联建立时，本端为这个偶联生成一个随机标识。偶联建立过程中，双方会交换这个TAG，
          到了数据传递时，发送端必须在公共报文头中带上对端的这个TAG，以备校验。
校验码：  用于数据完整性校验。发送端产生，接收端验证。

数据块的各个部分及其含义：
块类型：块类型定义在块值（ChunkValue）中消息所属的类型。如果接收端点不能识别块类型时，
        块类型最高位2bit用于标识需要进行的各种操作。此时最高两位含义如下：
停止处理并丢弃此SCTP报文，不再处理该SCTP报文中的其他消息块。
停止处理并丢弃此SCTP报文，不再处理该SCTP报文中的其他消息块，并且在“ERROR”或“INITACK”中向发起端点返回不能识别的参数。
跳过此数据块并继续执行。
跳过此数据块并继续执行，并且在“ERROR”或“INITACK”中向发起端点返回不能识别的参数。

数据块标志位：块标志位用法由块类型决定。
块长度：      块长度包括块类型（ChunkType）、块标记（ChunkFlags）、块长度（ChunkLength）和块值（ChunkValue），长度使用二进制表示。
块值：        该块包含的数据内容。

#endif



#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
/** size of the packet header without any chunk headers */
#define SCTP_HEADER_LEN                       12

/* XXX RAW* needs to be really 'raw', so no ntohs there */
#define SCTP_GET_RAW_SRC_PORT(sctph)          ntohs((sctph)->sh_sport)
#define SCTP_GET_RAW_DST_PORT(sctph)          ntohs((sctph)->sh_dport)

#define SCTP_GET_SRC_PORT(p)                  SCTP_GET_RAW_SRC_PORT(p->sctph)
#define SCTP_GET_DST_PORT(p)                  SCTP_GET_RAW_DST_PORT(p->sctph)

typedef struct SCTPHdr_
{
    uint16_t sh_sport;     /* source port */
    uint16_t sh_dport;     /* destination port */
    uint32_t sh_vtag;      /* verification tag, defined per flow */
    uint32_t sh_sum;       /* checksum, computed via crc32 */
} __attribute__((__packed__)) SCTPHdr;

#define CLEAR_SCTP_PACKET(p) { \
    (p)->sctph = NULL; \
} while (0)

void DecodeSCTPRegisterTests(void);

#endif /* __DECODE_SCTP_H__ */
