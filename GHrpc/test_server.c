#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#if 1
#include "rpc.h"
#include "log.h"
#include "hashmap/hashmap.h"

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


void help(void *args)
{
    printf("help !!!\n");
}


RPC_WORK_MAP_BEGIN(test)
    RPC_WORK_MAP_ADD(RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, 0,0,0, RPC_CMD_EXTER_0), help)
RPC_WORK_MAP_END()


extern hashmap_t *works_hash;


int rpc_register_works(work_map_t w[], unsigned int size)
{
    int  i = 0;
    char buff[128] = {0};
    work_map_t *wm;

    if (size == 0)
        return -1;

    if (works_hash)
        works_hash = hashmap_create(10000000, NULL);

    for (; i < size; i++) {
        snprintf(buff, sizeof buff, "%08x", w[i].msgid);

        if((wm = hashmap_get(works_hash, buff)) && wm->msgid == w[i].msgid) {
            logm("work[%d] already exist", i);
            continue;
        }

        if (0 != hashmap_put(works_hash, buff, &w[i])) {
            logxw("hashmap_put failed");
            continue;
        }
    }

    return 0;
}


int main(int argc, char *argv[])
{
    rpc_t *r;

    signal(SIGPIPE,SIG_IGN);

    r = rpc_init("127.0.0.1", 12345, rpc_server);
    if (!r) {
        logxw("rpc init failed");
        exit(1);
    }

    works_hash = hashmap_create(10000000, NULL);
    RPC_REGISTER_WORKS_MAP(test);

    // uint32_t msgid = RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0,0,0,0, RPC_CMD_EXTER_0);
    // work_map_t *wm = rpc_find_work_map(msgid);
    // if (wm) {
    //     logd(">>>msgid: %u  %u", wm->msgid, msgid);
    //     wm->work("111");
    // }


    while(1)
        sleep(10);

    return 0;
}
#endif
