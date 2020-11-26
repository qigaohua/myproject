#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if 0
#include "rpc.h"
#include "log.h"


enum {
    RPC_GROUP_EXTER_0 = RPC_GROUP_EXTER,
    RPC_GROUP_EXTER_1 ,
    RPC_GROUP_EXTER_2 ,
    RPC_GROUP_EXTER_3 ,
    RPC_GROUP_EXTER_4 ,
};


enum {
    RPC_CMD_EXTER_0 = RPC_CMD_EXTER,
    RPC_CMD_EXTER_1 ,
    RPC_CMD_EXTER_2 ,
    RPC_CMD_EXTER_3 ,
    RPC_CMD_EXTER_4 ,
};

int main(int argc, char *argv[])
{
    rpc_t *r;

    r = rpc_init("127.0.0.1", 12345, rpc_client);
    if (!r) {
        logxw("rpc init failed");
        exit(1);
    }

    uint32_t msgid = RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, 0, 0, 0, RPC_CMD_EXTER_0);
    rpc_call(r, msgid, NULL, 0);

    while(1)
        sleep(10);

    return 0;
}
#endif
