#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#if 1
#include "rpc.h"
#include "log.h"
// #include "hashmap/hashmap.h"
// #include "workq/workq.h"

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

// extern hashmap_t *ret_hash;
// extern hashmap_t *works_hash;
// extern int fds[2];

void help(void *args)
{
    work_args_t *wa = (work_args_t *)args;

    printf("recv msg: %s\n", (char *)wa->args);
}

void get_info(void *args)
{
    logd("call get_info()");
    work_args_t *wa = (work_args_t *)args;
    char buf[128] = {0};

    char *info = "get info from server";

    snprintf(buf, sizeof buf, "%08x", wa->msgid);
    hashmap_put(wa->r->ret_hash, buf, info);

    rpc_call_send_thread(wa->r->writefd, wa, sizeof(work_args_t));
    logd("call get_info return");
}


RPC_WORK_MAP_BEGIN(test)
    RPC_WORK_MAP_ADD(RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, NEED_RETURN,
                RPC_UP, RPC_UNUSE1, RPC_CMD_EXTER_0), get_info)
    RPC_WORK_MAP_ADD(RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, NO_NEED_RETURN,
                RPC_UP, RPC_UNUSE1, RPC_CMD_EXTER_1), help)
RPC_WORK_MAP_END()



// int rpc_register_works(rpc_t *r, work_map_t w[], unsigned int size)
// {
//     int  i = 0;
//     char buff[128] = {0};
//     work_map_t *wm;

//     if (size == 0) return -1;

//     if (r->works_hash)
//         r->works_hash = hashmap_create(10000000, NULL);

//     for (; i < size; i++) {
//         snprintf(buff, sizeof buff, "%08x", w[i].msgid);

//         logd("register msgid: %s", buff);
//         if((wm = hashmap_get(r->works_hash, buff)) && wm->msgid == w[i].msgid) {
//             logm("work[%d] already exist", i);
//             continue;
//         }

//         if (0 != hashmap_put(r->works_hash, buff, &w[i])) {
//             logxw("hashmap_put failed");
//             continue;
//         }
//         logd("register ok");
//     }

//     return 0;
// }


int main(int argc, char *argv[])
{
    rpc_t *r;

    signal(SIGPIPE,SIG_IGN);

    log_init(GH_LOG_WARN, NULL);
    r = rpc_init("127.0.0.1", 12345, rpc_server);
    if (!r) {
        logxw("rpc init failed");
        exit(1);
    }

    r->works_hash = hashmap_create(10000000, NULL);
    RPC_REGISTER_WORKS_MAP(r, test);
    workq_start(r->workq);

    while(1)
        sleep(10);

    return 0;
}
#endif
