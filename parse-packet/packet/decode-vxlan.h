#ifndef __DECODE_VXLAN_H__
#define __DECODE_VXLAN_H__

#include "packet.h"


// 了解vxlan阅读doc/read_vxlan.txt


typedef struct VXLANHeader_ {
    uint8_t flags[2];
    uint16_t gdp;
    uint8_t vni[3];
    uint8_t res;
} VXLANHeader;


void DecodeVXLANRegisterTests(void);
int DecodeVXLANEnabledForPort(const uint16_t sp, const uint16_t dp);

#endif /* !__DECODE_VXLAN_H__ */
