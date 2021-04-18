/**
 * \file
 *
 * Decode SCTP
 */

#include "packet.h"
#include "decode.h"
#include "decode-sctp.h"

static int DecodeSCTPPacket(Packet *p, uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < SCTP_HEADER_LEN)) {
        // ENGINE_SET_INVALID_EVENT(p, SCTP_PKT_TOO_SMALL);
        p->flags |= PKT_IS_INVALID;
        return -1;
    }

    p->sctph = (SCTPHdr *)pkt;

    SET_SCTP_SRC_PORT(p,&p->sp);
    SET_SCTP_DST_PORT(p,&p->dp);

    p->payload = pkt + sizeof(SCTPHdr);
    p->payload_len = len - sizeof(SCTPHdr);

    p->proto = IPPROTO_SCTP;

    return 0;
}

// int DecodeSCTP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
int DecodeSCTP(Packet *p, uint8_t *pkt, uint16_t len)
{
    // StatsIncr(tv, dtv->counter_sctp);

    if (unlikely(DecodeSCTPPacket(p,pkt,len) < 0)) {
        CLEAR_SCTP_PACKET(p);
        return DECODE_FAILED;
    }

#ifdef DEBUG
    LogDebug("SCTP sp: %" PRIu32 " -> dp: %" PRIu32,
        SCTP_GET_SRC_PORT(p), SCTP_GET_DST_PORT(p));
#endif

    // FlowSetupPacket(p);

    return DECODE_OK;
}
/**
 * @}
 */
