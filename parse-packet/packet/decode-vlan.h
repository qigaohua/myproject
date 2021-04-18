/**
 * \file
 *
 */

#ifndef __DECODE_VLAN_H__
#define __DECODE_VLAN_H__

#include "packet.h"


/** Vlan type */
#define ETHERNET_TYPE_VLAN          0x8100

/** Vlan macros to access Vlan priority, Vlan CFI and VID */
#define GET_VLAN_PRIORITY(vlanh)    ((ntohs((vlanh)->vlan_cfi) & 0xe000) >> 13)
#define GET_VLAN_CFI(vlanh)         ((ntohs((vlanh)->vlan_cfi) & 0x0100) >> 12)
#define GET_VLAN_ID(vlanh)          ((uint16_t)(ntohs((vlanh)->vlan_cfi) & 0x0FFF))
#define GET_VLAN_PROTO(vlanh)       ((ntohs((vlanh)->protocol)))

/* return vlan id in host byte order */
#define VLAN_GET_ID1(p)             DecodeVLANGetId((p), 0)
#define VLAN_GET_ID2(p)             DecodeVLANGetId((p), 1)

/** Vlan header struct */
typedef struct VLANHdr_ {
    uint16_t vlan_cfi;
    uint16_t protocol;  /**< protocol field */
} __attribute__((__packed__)) VLANHdr;

/** VLAN header length */
#define VLAN_HEADER_LEN 4

/* return vlan id in host byte order */
// uint16_t DecodeVLANGetId(struct Packet_ *p, uint8_t layer);
void DecodeVLANRegisterTests(void);

#endif /* __DECODE_VLAN_H__ */

