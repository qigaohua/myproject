#ifndef __PACKET_H_
#define __PACKET_H_

#include <inttypes.h>
#include <time.h>
#include <netinet/in.h>

// #include "decode-erspan.h"
#include "decode-ethernet.h"
#include "decode-gre.h"
#include "decode-ppp.h"
#include "decode-pppoe.h"
#include "decode-sll.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"
#include "decode-icmpv4.h"
#include "decode-icmpv6.h"
#include "decode-tcp.h"
#include "decode-udp.h"
#include "decode-sctp.h"
// #include "decode-raw.h"
// #include "decode-null.h"
#include "decode-vlan.h"
#include "decode-vxlan.h"
// #include "decode-mpls.h"

#include "queue.h"

#define DEFAULT_MTU 1500
#define MINIMUM_MTU 68      /**< ipv4 minimum: rfc791 */

#define DEFAULT_PACKET_SIZE (DEFAULT_MTU + ETHERNET_HEADER_LEN)
/* storage: maximum ip packet size + link header */
#define MAX_PAYLOAD_SIZE (IPV6_HEADER_LEN + 65536 + 28)
extern uint32_t default_packet_size;
#define SIZE_OF_PACKET (default_packet_size + sizeof(Packet))

#define MAX_DEVNAME 10
/** storage for live device names */
typedef struct LiveDevice_ {
    char *dev;  /**< the device (e.g. "eth0") */
    char dev_short[MAX_DEVNAME + 1];

    int ignore_checksum;
    int id;

    // SC_ATOMIC_DECLARE(uint64_t, pkts);
    // SC_ATOMIC_DECLARE(uint64_t, drop);
    // SC_ATOMIC_DECLARE(uint64_t, bypassed);
    // SC_ATOMIC_DECLARE(uint64_t, invalid_checksums);
    // TAILQ_ENTRY(LiveDevice_) next;

    // int tenant_id_set;
    // uint32_t tenant_id;     /**< tenant id in multi-tenancy */
    uint32_t offload_orig;  /**< original offload settings to restore @exit */
} LiveDevice;

typedef uint16_t Port;

typedef struct Address_ {
    char family;
    union {
        uint32_t address_un_data32[4];
        uint16_t address_un_data16[8];
        uint8_t  address_un_data8[16];
        struct in6_addr address_un_in6;
    } address;
} Address;
#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8
#define addr_in6addr    address.address_un_in6

#define COPY_ADDRESS(a, b) do {                    \
        (b)->family = (a)->family;                 \
        (b)->addr_data32[0] = (a)->addr_data32[0]; \
        (b)->addr_data32[1] = (a)->addr_data32[1]; \
        (b)->addr_data32[2] = (a)->addr_data32[2]; \
        (b)->addr_data32[3] = (a)->addr_data32[3]; \
    } while (0)

/* Set the IPv4 addresses into the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define SET_IPV4_SRC_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

#define SET_IPV4_DST_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a) do {       \
        (a)->family = 0;         \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

/* Set the IPv6 addresses into the Addrs of the Packet.
 * Make sure p->ip6h is initialized and validated. */
#define SET_IPV6_SRC_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_src[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_src[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_src[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_src[3];  \
    } while (0)

#define SET_IPV6_DST_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_dst[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_dst[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_dst[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_dst[3];  \
    } while (0)



#define SET_PORT(s, d) ((d) = (s))

// arg 2 is pointer, because set value
#define SET_TCP_SRC_PORT(p, sp) \
    SET_PORT(TCP_GET_SRC_PORT((p)), *(sp))
#define SET_TCP_DST_PORT(p, dp) \
    SET_PORT(TCP_GET_DST_PORT((p)), *(dp))

// arg 2 is pointer, because set value
#define SET_UDP_SRC_PORT(p, sp) \
    SET_PORT(UDP_GET_SRC_PORT((p)), *(sp))
#define SET_UDP_DST_PORT(p, dp) \
    SET_PORT(UDP_GET_DST_PORT((p)), *(dp))

#define SET_SCTP_SRC_PORT(p, sp) \
    SET_PORT(SCTP_GET_SRC_PORT((p)), *(sp))
#define SET_SCTP_DST_PORT(p, dp) \
    SET_PORT(SCTP_GET_DST_PORT((p)), *(dp))


#define GET_IPV4_SRC_ADDR_U32(p) ((p)->src.addr_data32[0])
#define GET_IPV4_DST_ADDR_U32(p) ((p)->dst.addr_data32[0])
#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)

#define GET_IPV6_SRC_IN6ADDR(p) ((p)->src.addr_in6addr)
#define GET_IPV6_DST_IN6ADDR(p) ((p)->dst.addr_in6addr)
#define GET_IPV6_SRC_ADDR(p) ((p)->src.addr_data32)
#define GET_IPV6_DST_ADDR(p) ((p)->dst.addr_data32)
#define GET_TCP_SRC_PORT(p)  ((p)->sp)
#define GET_TCP_DST_PORT(p)  ((p)->dp)

#define GET_PKT_LEN(p) ((p)->pktlen)
#define GET_PKT_DATA(p) ((((p)->ext_pkt) == NULL ) ? (uint8_t *)((p) + 1) : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p) (uint8_t *)((p) + 1)
#define GET_PKT_DIRECT_MAX_SIZE(p) (default_packet_size)

#define SET_PKT_LEN(p, len) do { \
(p)->pktlen = (len); \
} while (0)


#define CMP_ADDR(a1, a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1, p2) \
    ((p1) == (p2))



/*Given a packet pkt offset to the start of the ip header in a packet
 *We determine the ip version. */
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))

#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))

#define IPH_IS_VALID(p) (PKT_IS_IPV4((p)) || PKT_IS_IPV6((p)))

/* Retrieve proto regardless of IP version */
#define IP_GET_IPPROTO(p) \
    (p->proto ? p->proto : \
    (PKT_IS_IPV4((p))? IPV4_GET_IPPROTO((p)) : (PKT_IS_IPV6((p))? IPV6_GET_L4PROTO((p)) : 0)))


/*Packet Flags*/
#define PKT_NOPACKET_INSPECTION         (1)         /**< Flag to indicate that packet header or contents should not be inspected*/
#define PKT_NOPAYLOAD_INSPECTION        (1<<2)      /**< Flag to indicate that packet contents should not be inspected*/
#define PKT_ALLOC                       (1<<3)      /**< Packet was alloc'd this run, needs to be freed */
#define PKT_HAS_TAG                     (1<<4)      /**< Packet has matched a tag */
#define PKT_STREAM_ADD                  (1<<5)      /**< Packet payload was added to reassembled stream */
#define PKT_STREAM_EST                  (1<<6)      /**< Packet is part of established stream */
#define PKT_STREAM_EOF                  (1<<7)      /**< Stream is in eof state */
#define PKT_HAS_FLOW                    (1<<8)
#define PKT_PSEUDO_STREAM_END           (1<<9)      /**< Pseudo packet to end the stream */
#define PKT_STREAM_MODIFIED             (1<<10)     /**< Packet is modified by the stream engine, we need to recalc the csum and reinject/replace */
#define PKT_MARK_MODIFIED               (1<<11)     /**< Packet mark is modified */
#define PKT_STREAM_NOPCAPLOG            (1<<12)     /**< Exclude packet from pcap logging as it's part of a stream that has reassembly depth reached. */

#define PKT_TUNNEL                      (1<<13)
#define PKT_TUNNEL_VERDICTED            (1<<14)

#define PKT_IGNORE_CHECKSUM             (1<<15)     /**< Packet checksum is not computed (TX packet for example) */
#define PKT_ZERO_COPY                   (1<<16)     /**< Packet comes from zero copy (ext_pkt must not be freed) */

#define PKT_HOST_SRC_LOOKED_UP          (1<<17)
#define PKT_HOST_DST_LOOKED_UP          (1<<18)

#define PKT_IS_FRAGMENT                 (1<<19)     /**< Packet is a fragment */
#define PKT_IS_INVALID                  (1<<20)
#define PKT_PROFILE                     (1<<21)

/** indication by decoder that it feels the packet should be handled by
 *  flow engine: Packet::flow_hash will be set */
#define PKT_WANTS_FLOW                  (1<<22)

/** protocol detection done */
#define PKT_PROTO_DETECT_TS_DONE        (1<<23)
#define PKT_PROTO_DETECT_TC_DONE        (1<<24)

#define PKT_REBUILT_FRAGMENT            (1<<25)     /**< Packet is rebuilt from
                                                     * fragments. */
#define PKT_DETECT_HAS_STREAMDATA       (1<<26)     /**< Set by Detect() if raw stream data is available. */

#define PKT_PSEUDO_DETECTLOG_FLUSH      (1<<27)     /**< Detect/log flush for protocol upgrade */

/** \brief return 1 if the packet is a pseudo packet */
#define PKT_IS_PSEUDOPKT(p) \
    ((p)->flags & (PKT_PSEUDO_STREAM_END|PKT_PSEUDO_DETECTLOG_FLUSH))


#define PACKET_CLEAR_L4VARS(p) do {               \
    memset(&((p)->l4vars), 0x00, sizeof((p)->l4vars)); \
} while(0)




typedef struct PacketQueue_ {
    struct Packet_ *head;
    struct Packet_ *tail;
    uint32_t size; // 当前packet个数
    pthread_mutex_t mutex;
    pthread_cond_t cont;
} PacketQueue;


typedef struct Packet_
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    Address src;
    Address dst;
    union {
        Port sp;
        // icmp type and code of this packet
        struct {
            uint8_t type;
            uint8_t code;
        } icmp_s;
    };
    union {
        Port dp;
        // icmp type and code of the expected counterpart (for flows)
        struct {
            uint8_t type;
            uint8_t code;
        } icmp_d;
    };
    uint8_t proto;

    uint16_t vlan_id[2];
    uint8_t vlan_idx;

    /* flow */
    uint8_t flowflags;
    /* coccinelle: Packet:flowflags:FLOW_PKT_ */

    /* Pkt Flags */
    uint32_t flags;

#ifdef HAVE_FLOW   /* 有流结构 */
    struct Flow_ *flow;

    /* raw hash value for looking up the flow, will need to modulated to the
     * hash size still */
    uint32_t flow_hash;
#endif

    struct timeval ts;

    /** The release function for packet structure and data */
    void (*ReleasePacket)(struct Packet_ *);

    /** The function triggering bypass the flow in the capture method.
     * Return 1 for success and 0 on error */
    // int (*BypassPacketsFlow)(struct Packet_ *);

    /* header pointers */
    EthernetHdr *ethh;

    /* Checksum for IP packets. */
    int32_t level3_comp_csum;
    /* Check sum for TCP, UDP or ICMP packets */
    int32_t level4_comp_csum;

    IPV4Hdr *ip4h;

    IPV6Hdr *ip6h;

    /* IPv4 and IPv6 are mutually exclusive */
    union {
        IPV4Vars ip4vars;
        struct {
            IPV6Vars ip6vars;
            IPV6ExtHdrs ip6eh;
        };
    };
    /* Can only be one of TCP, UDP, ICMP at any given time */
    union {
        TCPVars tcpvars;
        ICMPV4Vars icmpv4vars;
        ICMPV6Vars icmpv6vars;
    } l4vars;
#define tcpvars     l4vars.tcpvars
#define icmpv4vars  l4vars.icmpv4vars
#define icmpv6vars  l4vars.icmpv6vars

    TCPHdr *tcph;

    UDPHdr *udph;

    SCTPHdr *sctph;

    ICMPV4Hdr *icmpv4h;

    ICMPV6Hdr *icmpv6h;

    PPPHdr *ppph;
    PPPOESessionHdr *pppoesh;
    PPPOEDiscoveryHdr *pppoedh;

    GREHdr *greh;

    VLANHdr *vlanh[2];

    /* ptr to the payload of the packet
     * with it's length. */
    uint8_t *payload;
    uint16_t payload_len;

    /* IPS action to take */
    // uint8_t action;

    uint8_t pkt_src;

    /* storage: set to pointer to heap and extended via allocation if necessary */
    uint32_t pktlen;
    uint8_t *ext_pkt;

    /* Incoming interface */
    struct LiveDevice_ *livedev;

    /** packet number in the pcap file, matches wireshark */
    // uint64_t pcap_cnt;

    /* double linked list ptrs */
    struct Packet_ *next;
    struct Packet_ *prev;


/** libpcap shows us the way to linktype codes*/
#define LINKTYPE_NULL        DLT_NULL
#define LINKTYPE_ETHERNET    DLT_EN10MB
#define LINKTYPE_LINUX_SLL   113
#define LINKTYPE_PPP         9
#define LINKTYPE_RAW         DLT_RAW
/* http://www.tcpdump.org/linktypes.html defines DLT_RAW as 101, yet others don't.
* Libpcap on at least OpenBSD returns 101 as datalink type for RAW pcaps though. */
#define LINKTYPE_RAW2        101
#define LINKTYPE_IPV4        228
#define LINKTYPE_GRE_OVER_IP 778
#define PPP_OVER_GRE         11
#define VLAN_OVER_GRE        13
    /** data linktype in host order */
    int datalink; // for decode



#ifdef HAVE_TUNNEL_PACKET
    /* make sure we can't be attacked on when the tunneled packet
     * has the exact same tuple as the lower levels */
    uint8_t recursion_level;

    /* tunnel/encapsulation handling */
    struct Packet_ *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */

    /** mutex to protect access to:
     *  - tunnel_rtv_cnt
     *  - tunnel_tpr_cnt
     */
    pthread_mutex_t tunnel_mutex;
    /* ready to set verdict counter, only set in root */
    uint16_t tunnel_rtv_cnt;
    /* tunnel packet ref count */
    uint16_t tunnel_tpr_cnt;
#endif

    /** tenant id for this packet, if any. If 0 then no tenant was assigned. */
    // uint32_t tenant_id;

    /* The Packet pool from which this packet was allocated. Used when returning
     * the packet to its owner's stack. If NULL, then allocated with malloc.
     */
    // struct PktPool_ *pool;

}
#ifdef HAVE_MPIPE
    /* mPIPE requires packet buffers to be aligned to 128 byte boundaries. */
    __attribute__((aligned(128)))
#endif
Packet;



#define PACKET_RESET_CHECKSUMS(p) do { \
        (p)->level3_comp_csum = -1;   \
        (p)->level4_comp_csum = -1;   \
    } while (0)

/* if p uses extended data, free them */
#define PACKET_FREE_EXTDATA(p) do {                 \
        if ((p)->ext_pkt) {                         \
            if (!((p)->flags & PKT_ZERO_COPY)) {    \
                free((p)->ext_pkt);               \
            }                                       \
            (p)->ext_pkt = NULL;                    \
        }                                           \
    } while(0)

/**
 *  \brief Cleanup a packet so that we can free it. No memset needed..
 */
// TODO destroy tunnel_mutex when HAVE_TUNNEL
#define PACKET_DESTRUCTOR(p) do {                  \
        PACKET_FREE_EXTDATA((p));               \
    } while (0)

/**
 * \brief Return a malloced packet.
 */

// TODO init tunnel_mutex when HAVE_TUNNEL
#define PACKET_INITIALIZE(p) {         \
    PACKET_RESET_CHECKSUMS((p)); \
    (p)->livedev = NULL; \
}


#define PACKET_REINIT(p) do {             \
        CLEAR_ADDR(&(p)->src);                  \
        CLEAR_ADDR(&(p)->dst);                  \
        (p)->sp = 0;                            \
        (p)->dp = 0;                            \
        (p)->proto = 0;                         \
        PACKET_FREE_EXTDATA((p));               \
        (p)->flags = (p)->flags & PKT_ALLOC;    \
        (p)->flowflags = 0;                     \
        (p)->pkt_src = 0;                       \
        (p)->vlan_id[0] = 0;                    \
        (p)->vlan_id[1] = 0;                    \
        (p)->vlan_idx = 0;                      \
        (p)->ts.tv_sec = 0;                     \
        (p)->ts.tv_usec = 0;                    \
        (p)->datalink = 0;                      \
        (p)->ethh = NULL;                       \
        if ((p)->ip4h != NULL) {                \
            CLEAR_IPV4_PACKET((p));             \
        }                                       \
        if ((p)->ip6h != NULL) {                \
            CLEAR_IPV6_PACKET((p));             \
        }                                       \
        if ((p)->tcph != NULL) {                \
            CLEAR_TCP_PACKET((p));              \
        }                                       \
        if ((p)->udph != NULL) {                \
            CLEAR_UDP_PACKET((p));              \
        }                                       \
        if ((p)->sctph != NULL) {               \
            CLEAR_SCTP_PACKET((p));             \
        }                                       \
        if ((p)->icmpv4h != NULL) {             \
            CLEAR_ICMPV4_PACKET((p));           \
        }                                       \
        if ((p)->icmpv6h != NULL) {             \
            CLEAR_ICMPV6_PACKET((p));           \
        }                                       \
        (p)->ppph = NULL;                       \
        (p)->pppoesh = NULL;                    \
        (p)->pppoedh = NULL;                    \
        (p)->greh = NULL;                       \
        (p)->vlanh[0] = NULL;                   \
        (p)->vlanh[1] = NULL;                   \
        (p)->payload = NULL;                    \
        (p)->payload_len = 0;                   \
        (p)->pktlen = 0;                        \
        (p)->next = NULL;                       \
        (p)->prev = NULL;                       \
        (p)->livedev = NULL;                    \
        PACKET_RESET_CHECKSUMS((p));            \
    } while (0)


#define PACKET_FREE(p) do {         \
        PACKET_FREE_EXTDATA(p);                 \
        free(p);                                \
        p = NULL;                               \
    } while (0)


#define PACKET_SET_FAILED(p, event) do {\
    LogWarn("packet failed: %s", #event); \
    p->flags |= event; \
} while(0)



enum {
    DECODE_OK = 0,
    DECODE_FAILED,
    DECODE_DONE,
};

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif



// #define DEBUG
#ifdef DEBUG
#include <stdio.h>
#define LogDebug(fmt, ...) do {\
    fprintf(stdout, "%s:%d : "fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)
#else
#define LogDebug(fmt, ...)
#endif
#define LogWarn(fmt, ...) do {\
    fprintf(stderr, "%s:%d : "fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)


typedef int bool;

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define PKT_MALLOC malloc
#define PKT_CALLOC calloc
#define PKT_FREE   free


// api
Packet *PacketGetFromAlloc(void);



#endif /* ifndef __PACKET_H_ */


