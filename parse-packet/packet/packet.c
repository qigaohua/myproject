#include <string.h>
#include <stdlib.h>

#include "packet.h"


// 14 + 1500 + 4
uint32_t default_packet_size = 1518;


void PacketFree(Packet *p)
{
    PACKET_DESTRUCTOR(p);
    free(p);
}

/**
 * \brief Get a malloced packet.
 *
 * \retval p packet, NULL on error
 */
Packet *PacketGetFromAlloc(void)
{
    Packet *p = PKT_MALLOC(SIZE_OF_PACKET);
    if (unlikely(p == NULL)) {
        return NULL;
    }

    memset(p, 0, SIZE_OF_PACKET);
    PACKET_INITIALIZE(p);
    p->ReleasePacket = PacketFree;
    p->flags |= PKT_ALLOC;

    LogDebug("allocated a new packet only using alloc...");

    return p;
}

