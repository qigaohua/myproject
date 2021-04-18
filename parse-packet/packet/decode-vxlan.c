/**
 * \file
 *
 * VXLAN decoder.
 */





#include "packet.h"
#include "decode-vxlan.h"

#define VXLAN_HEADER_LEN        8
#define VXLAN_DEFAULT_PORT      4789
#define VXLAN_DEFAULT_PORT_S    "4789"

static int g_vxlan_enabled = FALSE;
static int g_vxlan_ports[4] = { VXLAN_DEFAULT_PORT, -1, -1, -1 };
static int g_vxlan_ports_idx = 0;

int DecodeVXLANEnabledForPort(const uint16_t sp, const uint16_t dp)
{
    LogDebug("ports %u->%u ports %d %d %d %d", sp, dp,
            g_vxlan_ports[0], g_vxlan_ports[1],
            g_vxlan_ports[2], g_vxlan_ports[3]);

    if (g_vxlan_enabled) {
        int i;
        for (i = 0; i < g_vxlan_ports_idx; i++) {
            if (g_vxlan_ports[i] == -1)
                return FALSE;
            const int port = g_vxlan_ports[i];
            if (port == (const int)sp ||
                port == (const int)dp)
                return TRUE;
        }
    }
    return FALSE;
}


/*
 *  \param pkt payload data directly above UDP header
 *  \param len length in bytes of pkt
 *
 * vxlan 报文格式：
 * |外部ip头|外部udp头|vxlan头|内部网络数据帧|
 */
int DecodeVXLAN(Packet *p, uint8_t *pkt, uint32_t len)
{
    if (len < (sizeof(VXLANHeader) + sizeof(EthernetHdr)))
        return DECODE_FAILED;

    const VXLANHeader *vxlanh = (const VXLANHeader *)pkt;
    if ((vxlanh->flags[0] & 0x08) == 0 || vxlanh->res != 0) {
        return DECODE_FAILED;
    }

#ifdef DEBUG
    uint32_t vni = (vxlanh->vni[0] << 16) + (vxlanh->vni[1] << 8) + (vxlanh->vni[2]);
    LogDebug("VXLAN vni %u", vni);
#endif

    /* VXLAN encapsulate Layer 2 in UDP, most likely IPv4 and IPv6  */
    EthernetHdr *ethh = (EthernetHdr *)(pkt + VXLAN_HEADER_LEN);
    LogDebug("VXLAN ethertype 0x%04x", ntohs(ethh->eth_type));

    /* Best guess at inner packet. */
    switch (ntohs(ethh->eth_type)) {
        case ETHERNET_TYPE_ARP:
            LogDebug("VXLAN found ARP");
            break;
        case ETHERNET_TYPE_IP:
            LogDebug("VXLAN found IPv4");
#if 0
            if (pq != NULL) {
                Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN,
                        len - (VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN), DECODE_TUNNEL_IPV4, pq);
                if (tp != NULL) {
                    PKT_SET_SRC(tp, PKT_SRC_DECODER_VXLAN);
                    PacketEnqueue(pq, tp);
                }
            }
#endif
            break;
        case ETHERNET_TYPE_IPV6:
            LogDebug("VXLAN found IPv6");
#if 0
            if (pq != NULL) {
                Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN,
                        len - (VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN), DECODE_TUNNEL_IPV6, pq);
                if (tp != NULL) {
                    PKT_SET_SRC(tp, PKT_SRC_DECODER_VXLAN);
                    PacketEnqueue(pq, tp);
                }
            }
#endif
            break;
        default:
            LogDebug("VXLAN found no known Ethertype - only checks for IPv4, IPv6, ARP");
            /* ENGINE_SET_INVALID_EVENT(p, VXLAN_UNKNOWN_PAYLOAD_TYPE);*/
            break;
    }

    return DECODE_OK;
}

#ifdef UNITTESTS

/**
 * \test DecodeVXLANTest01 test a good vxlan header.
 * Contains a DNS request packet
 */
static int DecodeVXLANtest01 (void)
{
    uint8_t raw_vxlan[] = {
        0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, /* VXLAN header */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00, /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5, /* inner source MAC */
        0x08, 0x00, /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06,  /* IPv4 hdr */
        0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };
    bool orig_g_vxlan_enabled = g_vxlan_enabled;
    g_vxlan_enabled = TRUE;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;

    DecodeVXLANConfigPorts("4789");

    memset(&pq, 0, sizeof(PacketQueue));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan), &pq);

    FAIL_IF(p->udph == NULL);
    FAIL_IF(pq.top == NULL);
    Packet *tp = PacketDequeue(&pq);
    FAIL_IF(tp->udph == NULL);
    FAIL_IF_NOT(tp->sp == 53);

    g_vxlan_enabled = orig_g_vxlan_enabled; /* reset global variable */
    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}

/**
 * \test test port disabled in config
 */
static int DecodeVXLANtest02 (void)
{
    uint8_t raw_vxlan[] = {
        0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, /* VXLAN header */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00, /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5, /* inner source MAC */
        0x08, 0x00, /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06,  /* IPv4 hdr */
        0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };
    bool orig_g_vxlan_enabled = g_vxlan_enabled;
    g_vxlan_enabled = TRUE;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;

    DecodeVXLANConfigPorts("1");

    memset(&pq, 0, sizeof(PacketQueue));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan), &pq);
    FAIL_IF(p->udph == NULL);
    FAIL_IF(pq.top != NULL);

    DecodeVXLANConfigPorts("4789"); /* reset */
    g_vxlan_enabled = orig_g_vxlan_enabled; /* reset global variable */

    FlowShutdown();
    PacketFree(p);
    PASS;
}
#endif /* UNITTESTS */

void DecodeVXLANRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeVXLANtest01",
                   DecodeVXLANtest01);
    UtRegisterTest("DecodeVXLANtest02",
                   DecodeVXLANtest02);
#endif /* UNITTESTS */
}
