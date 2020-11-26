#ifndef __GH_RPC_H
#define __GH_RPC_H

#include <inttypes.h>


/******************************************************************************
 * rpc_packet define (little endian)
 * [rpc_header][rpc_payload]
 *
 * rpc_header define
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           source_uuid=32                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         destination_uuid=32                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         message_id=32                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+ time_stamp=64 +-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         payload_len=32                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         checksum=32                           |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *
 * uuid is hash_of(connect_ip_info), generated by rpc server
 *
 * connect_ip_info define
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          socket_fd=32                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           ip_addr=32                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            ip_port=16         |x x x x x x x x x x x x x x x x|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * destination_uuid is message send to
 * source_uuid is message send from
 *
 * message_id define
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  group_id=7 |unused=5 |R|D|P=2|         cmd_id=16             |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *  [31~25]: group id
 *         - max support 128 group, can be used to service group
 *  [24~20]: unused
 *  [   19]: return indicator
 *         - 0: no need return
 *         - 1: need return
 *  [   18]: direction
 *         - 0: UP client to server
 *         - 1: DOWN server to client
 *  [17~16]: parser of payload message
 *         - 0 json
 *         - 1 protobuf
 *         - 2 unused
 *         - 3 unused
 *  [15~ 0]: cmd id, defined in librpc_stub.h
 *         - 0 ~ 7 inner cmd
 *         - 8 ~ 255 user cmd
 *
 * Note: how to add a new bit define, e.g. foo:
 *       1. add foo define in this commet;
 *       2. define RPC_FOO_BIT and RPC_FOO_MASK, and add into BUILD_RPC_MSG_ID;
 *       3. define GET_RPC_FOO;
 *       4. define enum of foo value;
 ******************************************************************************/

#define CHECK_ARGS(x, ret) {\
    if (x) {\
        fprintf(stderr, "%s:%d invailed args !!!", __FILE__, __LINE__); \
        return ret; \
    }\
}

typedef struct _GHepoll rpc_eventbases_t;
typedef struct _event   rpc_event_t;

typedef enum {
    rpc_client,
    rpc_server
} rpc_role;

typedef enum {
    rpc_inited,
    rpc_connected,
    rpc_disconnected,
} rpc_state;


struct rpc_header {
    uint32_t s_uuid;
    uint32_t d_uuid;
    uint32_t msg_id;
    uint64_t timestamp;
    uint32_t payload_len;
    uint32_t checksum;
};
typedef struct rpc_header rpc_header_t;
#define RPC_HDR_LEN  (sizeof(rpc_header_t))


struct rpc_packet {
    struct rpc_header hdr;
    void *value;
};
typedef struct rpc_packet rpc_packet_t;

typedef struct rpc_msg {
    uint8_t  gid;
    uint8_t  ret;
    uint8_t  dir;
    uint8_t  parse;
    uint8_t  cmdid;
} rpc_msg_t;

struct rpc {
    int  fd;
    rpc_role role;
    rpc_state state;
    struct rpc_ops *ops;
    rpc_eventbases_t *eventbases;
    struct rpc_packet send_pkt;
    struct rpc_packet recv_pkt;
    char *s_host;               /* rpc server host */
    uint16_t s_port;            /* rpc server port */
    uint32_t server_uuid;       /* rpc server uuid */
    uint32_t local_uuid;         /* local uuid*/
};
typedef struct rpc rpc_t;


struct rpc_ops {
    int (*init)(rpc_t *r);
    int (*deinit)(rpc_t *r);
    size_t (*send)(rpc_t *r);
    size_t (*recv)(rpc_t *r);
    int (*connect)(rpc_t *r);
    int (*acept)(rpc_t *r);
    int (*bind)(rpc_t *r);
};


typedef void (*work_cb)(void *args);
typedef struct work_map {
    unsigned int msgid;
    work_cb work;
} work_map_t;


// rpc 内部使用组id
enum {
    RPC_GROUP_INNER_0,
    RPC_GROUP_INNER_1,
    RPC_GROUP_INNER_2,
    RPC_GROUP_INNER_3,
    RPC_GROUP_INNER_4,
    RPC_GROUP_INNER_5,
    RPC_GROUP_INNER_6,
    RPC_GROUP_INNER_7,
    RPC_GROUP_EXTER
};


enum {
    RPC_CMD_INNER_0,
    RPC_CMD_INNER_1,
    RPC_CMD_INNER_2,
    RPC_CMD_INNER_3,
    RPC_CMD_INNER_4,
    RPC_CMD_INNER_5,
    RPC_CMD_INNER_6,
    RPC_CMD_INNER_7,
    RPC_CMD_EXTER
};


#define RPC_GROUP_MASK    0x3F
#define RPC_GROUP_BIT     (25)

#define RPC_RET_MASK      0x01
#define RPC_RET_BIT       (19)

#define RPC_DIR_MASK      0x01
#define RPC_DIR_BIT       (18)

#define RPC_PARSE_MASK    0x03
#define RPC_PARSE_BIT     (16)

#define RPC_CMDID_MASK    0xFFFF
#define RPC_CMDID_BIT     (0)

#define RPC_BUILD_MSG_ID(gid, ret, dir, parse, cmdid) \
    (((((uint32_t)gid)   & RPC_GROUP_MASK)  << RPC_GROUP_BIT) | \
     ((((uint32_t)ret)   & RPC_RET_MASK)    << RPC_RET_BIT)   | \
     ((((uint32_t)dir)   & RPC_DIR_MASK)    << RPC_DIR_BIT)   | \
     ((((uint32_t)parse) & RPC_PARSE_MASK)  << RPC_PARSE_BIT) | \
     ((((uint32_t)cmdid) & RPC_CMDID_MASK) << RPC_CMDID_BIT) )

#define RPC_MSG_GROUP_ID(msgid) \
    ((((uint32_t)msgid) >> RPC_GROUP_BIT) & RPC_GROUP_MASK)

#define RPC_MSG_RET(msgid) \
    ((((uint32_t)msgid) >> RPC_RET_BIT) & RPC_RET_MASK)

#define RPC_MSG_DIR(msgid) \
    ((((uint32_t)msgid) >> RPC_DIR_BIT) & RPC_DIR_MASK)

#define RPC_MSG_PARSE(msgid) \
    ((((uint32_t)msgid) >> RPC_PARSE_BIT) & RPC_PARSE_MASK)

#define RPC_MSG_CMDID(msgid) \
    ((((uint32_t)msgid) >> RPC_CMDID_BIT) & RPC_CMDID_MASK)



#define RPC_WORK_MAP_BEGIN(name) \
static work_map_t rpc_work_map_##name[] = {

#define RPC_WORK_MAP_END()   };
#define RPC_WORK_MAP_ADD(msgid, work) {msgid, work},

#define RPC_REGISTER_WORKS_MAP(name) \
    rpc_register_works(rpc_work_map_##name,   \
            sizeof(rpc_work_map_##name)/sizeof(rpc_work_map_##name[0]))


// client APIs
int rpc_call(rpc_t *r, uint32_t msg_id, void *payload, size_t payload_len);
int rpc_peer_call(rpc_t *r, uint32_t *d_uuid, uint32_t msg_id);



// commom APIs
rpc_t * rpc_init(const char *host, uint16_t port, rpc_role role);
work_map_t * rpc_find_work_map(uint32_t msgid);


#endif /* ifndef __GH_RPC_H */
