/**
 * \file
 *
 * Decode Teredo Tunneling protocol.
 *
 * Treodo 是一种互联网协议的隧道技术，用来解决ipv4向ipv6过渡过程的问题
 * Teredo报文是一项 IPv6 / IPv4 过渡技术，为能够通过 IPv4 NAT
 * IPv6 数据包作为基于 IPv4 的用户数据包协议(UDP) 消息发送出去
 *
 * Teredo 是作为实现 IPv6 连接最后一种转换技术而设计的，认识到这一点很重要。如果
 * 原来的 IPv6 、 6to4 或者ISATAP连接可用，那么主机就不必作为 Teredo 的客户端。
 * 越来越多的 IPv4 NAT 经过了升级以便能够支持 6to4 ，而且 IPv6 连接变得越来越普
 * 遍， Teredo 将会使用得越来越少，直到最后完全被放弃。
 *
 * 常见的teredo报文格式: |eth|ipv4|udp(目的端口3544)|ipv6|tcp/udp/|data|
 *
 * This implementation is based upon RFC 4380: http://www.ietf.org/rfc/rfc4380.txt
 */

#include "packet.h"
#include "decode-ipv6.h"
#include "decode-teredo.h"

#define TEREDO_ORIG_INDICATION_LENGTH    8

static int g_teredo_enabled = TRUE;

/**
 * \brief Function to decode Teredo packets
 *
 * \retval DECODE_FAILED if packet is not a Teredo packet, TM_ECODE_OK if it is
 */
int DecodeTeredo(Packet *p, uint8_t *pkt, uint16_t len)
{
    if (!g_teredo_enabled)
        return DECODE_FAILED;

    uint8_t *start = pkt;

    /* Is this packet to short to contain an IPv6 packet ? */
    if (len < IPV6_HEADER_LEN)
        return DECODE_FAILED;

    /* Teredo encapsulate IPv6 in UDP and can add some custom message
     * part before the IPv6 packet. In our case, we just want to get
     * over an ORIGIN indication. So we just make one offset if needed. */
    if (start[0] == 0x0) {
        switch (start[1]) {
            /* origin indication: compatible with tunnel */
            case 0x0:
                /* offset is coherent with len and presence of an IPv6 header */
                if (len >= TEREDO_ORIG_INDICATION_LENGTH + IPV6_HEADER_LEN)
                    start += TEREDO_ORIG_INDICATION_LENGTH;
                else
                    return DECODE_FAILED;
                break;
            /* authentication: negotiation not real tunnel */
            case 0x1:
                return DECODE_FAILED;
            /* this case is not possible in Teredo: not that protocol */
            default:
                return DECODE_FAILED;
        }
    }

    /* There is no specific field that we can check to prove that the packet
     * is a Teredo packet. We've zapped here all the possible Teredo header
     * and we should have an IPv6 packet at the start pointer.
     * We then can only do a few checks before sending the encapsulated packets
     * to decoding:
     *  - The packet has a protocol version which is IPv6.
     *  - The IPv6 length of the packet matches what remains in buffer.
     *  - HLIM is 0. This would technically be valid, but still weird.
     *  - NH 0 (HOP) and not enough data.
     *
     *  If all these conditions are met, the tunnel decoder will be called.
     *  If the packet gets an invalid event set, it will still be rejected.
     */
    if (IP_GET_RAW_VER(start) == 6) {
        IPV6Hdr *thdr = (IPV6Hdr *)start;

        /* ignore hoplimit 0 packets, most likely an artifact of bad detection */
        if (IPV6_GET_RAW_HLIM(thdr) == 0)
            return DECODE_FAILED;

        /* if nh is 0 (HOP) with little data we have a bogus packet */
        if (IPV6_GET_RAW_NH(thdr) == 0 && IPV6_GET_RAW_PLEN(thdr) < 8)
            return DECODE_FAILED;

        if (len ==  IPV6_HEADER_LEN +
                IPV6_GET_RAW_PLEN(thdr) + (start - pkt)) {
#if 0
            if (pq != NULL) {
                int blen = len - (start - pkt);
                /* spawn off tunnel packet */
                Packet *tp = PacketTunnelPktSetup(tv, dtv, p, start, blen,
                                                  DECODE_TUNNEL_IPV6_TEREDO, pq);
                if (tp != NULL) {
                    PKT_SET_SRC(tp, PKT_SRC_DECODER_TEREDO);
                    /* add the tp to the packet queue. */
                    PacketEnqueue(pq,tp);
                    StatsIncr(tv, dtv->counter_teredo);
                    return TM_ECODE_OK;
                }
            }
#endif
        }
        return DECODE_FAILED;
    }

    return DECODE_FAILED;
}

/**
 * @}
 */
