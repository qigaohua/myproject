/**
 * \file
 *
 * Decode Ethernet
 */

// #include <stdlib.h>
// #include <stdint.h>
#include <inttypes.h>
#include <limits.h>

// #include "packet.h"
// #include "decode-ethernet.h"
#include "decode.h"


int DecodeEthernet(Packet *p, uint8_t *pkt, uint32_t len)
{
    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        return DECODE_FAILED;
    }

    if (unlikely(len > ETHERNET_HEADER_LEN + USHRT_MAX)) {
        return DECODE_FAILED;
    }

    p->ethh = (EthernetHdr *)pkt;
    if (unlikely(p->ethh == NULL))
        return DECODE_FAILED;

    LogDebug("p %p pkt %p ether type %04x", p, pkt, ntohs(p->ethh->eth_type));

    switch (ntohs(p->ethh->eth_type)) {
        case ETHERNET_TYPE_IP:
            // printf("DecodeEthernet ip4\n");
            DecodeIPV4(p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);
            break;
#if 0
        case ETHERNET_TYPE_VLAN:
        case ETHERNET_TYPE_8021QINQ:
            DecodeVLAN(p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);
            break;
        case ETHERNET_TYPE_IPV6:
            //printf("DecodeEthernet ip6\n");
            DecodeIPV6(p, pkt + ETHERNET_HEADER_LEN,
                       len - ETHERNET_HEADER_LEN);
            break;
#if 0
        case ETHERNET_TYPE_PPPOE_SESS:
            //printf("DecodeEthernet PPPOE Session\n");
            DecodePPPOESession(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                               len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_PPPOE_DISC:
            //printf("DecodeEthernet PPPOE Discovery\n");
            DecodePPPOEDiscovery(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                                 len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_MPLS_UNICAST:
        case ETHERNET_TYPE_MPLS_MULTICAST:
            DecodeMPLS(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                       len - ETHERNET_HEADER_LEN, pq);
            break;
#endif
        case ETHERNET_TYPE_DCE:
            if (unlikely(len < ETHERNET_DCE_HEADER_LEN)) {
                LogWarn("ETHERNET_DCE_HEADER_LEN");
            } else {
                DecodeEthernet(p, pkt + ETHERNET_DCE_HEADER_LEN,
                    len - ETHERNET_DCE_HEADER_LEN);
            }
            break;
#endif
        default:
            LogDebug("p %p pkt %p ether type %04x not supported", p,
                       pkt, ntohs(p->ethh->eth_type));
    }

    return DECODE_OK;
}

// #define UNITTESTS
#ifdef UNITTESTS
#include <util-unittest.h>
/** DecodeEthernettest01
 *  \brief Valid Ethernet packet
 *  \retval 0 Expected test value
 */
static int DecodeEthernetTest01 (void)
{
    /* ICMP packet wrapped in PPPOE */
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x88, 0x64, 0x11, 0x00,
        0x00, 0x01, 0x00, 0x68, 0x00, 0x21, 0x45, 0xc0,
        0x00, 0x64, 0x00, 0x1e, 0x00, 0x00, 0xff, 0x01,
        0xa7, 0x78, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00,
        0x00, 0x01, 0x08, 0x00, 0x4a, 0x61, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x3b, 0xd4, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd };

    Packet *p = malloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    SCFree(p);
    return 1;
}

/**
 * Test a DCE ethernet frame that is too small.
 */
static int DecodeEthernetTestDceTooSmall(void)
{
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x89, 0x03,
    };

    Packet *p = malloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, DCE_PKT_TOO_SMALL));

    SCFree(p);
    PASS;
}

/**
 * Test that a DCE ethernet frame, followed by data that is too small
 * for an ethernet header.
 *
 * Redmine issue:
 * https://redmine.openinfosecfoundation.org/issues/2887
 */
static int DecodeEthernetTestDceNextTooSmall(void)
{
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x89, 0x03, //0x88, 0x64,

        0x00, 0x00,

        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01,
    };

    Packet *p = malloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, ETHERNET_PKT_TOO_SMALL));

    SCFree(p);
    PASS;
}

#endif /* UNITTESTS */


/**
 * \brief Registers Ethernet unit tests
 * \todo More Ethernet tests
 */
void DecodeEthernetRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeEthernetTest01", DecodeEthernetTest01);
    UtRegisterTest("DecodeEthernetTestDceNextTooSmall",
            DecodeEthernetTestDceNextTooSmall);
    UtRegisterTest("DecodeEthernetTestDceTooSmall",
            DecodeEthernetTestDceTooSmall);
#endif /* UNITTESTS */
}
/**
 * @}
 */
