#ifndef __DECODE_H_
#define __DECODE_H_



#include "packet.h"



//api
int DecodeEthernet(Packet *p, uint8_t *pkt, uint32_t len);
int DecodeIPV4(Packet *p, uint8_t *pkt, uint16_t len);
int DecodeIPV6(Packet *p, uint8_t *pkt, uint16_t len);
int DecodeTCP(Packet *p, uint8_t *pkt, uint16_t len);
int DecodeUDP(Packet *p, uint8_t *pkt, uint16_t len);
int DecodeSCTP(Packet *p, uint8_t *pkt, uint16_t len);
int DecodeICMPV4(Packet *p, uint8_t *pkt, uint32_t len);
int DecodeVLAN(Packet *p, uint8_t *pkt, uint32_t len);
int DecodeVXLAN(Packet *p, uint8_t *pkt, uint32_t len);
int DecodeGRE(Packet *p, uint8_t *pkt, uint32_t len);







#endif /* ifndef __DECODE_H_ */
