#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if 1
#include "rpc.h"
#include "log.h"


enum {
    RPC_GROUP_EXTER_0 = RPC_GROUP_EXTER,
    RPC_GROUP_EXTER_1 , RPC_GROUP_EXTER_2 , RPC_GROUP_EXTER_3 , RPC_GROUP_EXTER_4 ,
};


enum {
    RPC_CMD_EXTER_0 = RPC_CMD_EXTER,
    RPC_CMD_EXTER_1 ,
    RPC_CMD_EXTER_2 ,
    RPC_CMD_EXTER_3 ,
    RPC_CMD_EXTER_4 ,
};


void print_return_info(void *args)
{
    work_args_t *wargs = (work_args_t *)args;

    printf("server return info: %s\n", (char *)wargs->args);
}


/* 需要server返回信息的添加处理函数 */
RPC_WORK_MAP_BEGIN(test)
    RPC_WORK_MAP_ADD(RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, NEED_RETURN,
                RPC_UP, RPC_UNUSE1, RPC_CMD_EXTER_0), print_return_info)
    // RPC_WORK_MAP_ADD(RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, NO_NEED_RETURN,
    //             RPC_UP, RPC_UNUSE1, RPC_CMD_EXTER_1), print_return_info)
RPC_WORK_MAP_END()

int main(int argc, char *argv[])
{
    rpc_t *r;

    log_init(GH_LOG_WARN, NULL);
    r = rpc_init("127.0.0.1", 12345, rpc_client);
    if (!r) {
        logxw("rpc init failed");
        exit(1);
    }

    workq_start(r->workq);
    RPC_REGISTER_WORKS_MAP(r, test);


    uint32_t msgid = RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, NEED_RETURN, RPC_UP,
            RPC_UNUSE1, RPC_CMD_EXTER_0);
    rpc_call(r, msgid, NULL, 0);
    uint32_t msgid2 = RPC_BUILD_MSG_ID(RPC_GROUP_EXTER_0, NO_NEED_RETURN, RPC_UP,
            RPC_UNUSE1, RPC_CMD_EXTER_1);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);
    rpc_call(r, msgid2, "hello rpc", 10);

    while(1)
        sleep(10);

    return 0;
}
#endif
