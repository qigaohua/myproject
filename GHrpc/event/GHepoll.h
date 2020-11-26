#ifndef __Q_EPOLL_H_
#define __Q_EPOLL_H_
#include <inttypes.h>
#include <sys/epoll.h>


#define False 0
#define True (!(False))
typedef int BOOL;

#define BITS_ANY_SET(val, bits) (0 != ((val) & (bits)))
#define BITS_ALL_SET(val, bits) ((bits) != ((val) & (bits)))


#define EPOLL_MAX_SIZE 512
#define SIGNAL_NUM_MAX   64


struct _event;
struct _GHepoll;
typedef void (*proc_callback)(struct _event *);

// add  for timeout loop
struct timeout_t {
    /* 定时事件下一次启动时间 */
    struct timeval start_time;

    /* 以后循环执行时间 */
    struct timeval loop_time;
};


typedef enum {
    GHEPOLL_TYPE_ERROR,
    GHEPOLL_TYPE_FD,
    GHEPOLL_TYPE_TIMEOUT,
    GHEPOLL_TYPE_SIGNAL,

    GHEPOLL_TYPE_TIMEOUT_LOOP, // add 循环执行定时任务
} GHEPOLL_TYPE_E;

typedef enum {
    EVENT_TYPE_TIMEOUT = (1 << 0),
    EVENT_TYPE_SIGNAL  = (1 << 1),
    EVENT_TYPE_READ    = (1 << 2), // 读
    EVENT_TYPE_WRITE   = (1 << 3), // 写
    EVENT_TYPE_PRI     = (1 << 4), //
    EVENT_TYPE_ERROR   = (1 << 5), //
    EVENT_TYPE_ET      = (1 << 6),
    EVENT_TYPE_ONESHOT = (1 << 7),
} EVENT_TYPE_E;

typedef struct _GHepoll {
    int epoll_fd;
    struct timeval now;
    struct _event *fd_event;
    struct _event *timeouts;
    size_t timeout_curr_size;
    size_t epoll_curr_size;
    size_t epoll_event_size;
    struct epoll_event events[0];
} GHepoll_s, *GHepoll_p;


typedef struct _event {
    GHepoll_s *owner;
    /* 事件类型 */
    GHEPOLL_TYPE_E type;
    uint32_t event;
    int fd;
    int signal;
    struct timeout_t when;
    void *args;
    uint32_t args_len;
    proc_callback callback;
    struct _event *next;
} event_s;


event_s* create_fd_event (int fd, uint32_t events, proc_callback cfunc, void *data, size_t datalen);
int _add_fd_event(GHepoll_s *base, event_s *event);
event_s* create_timeout_event (struct timeout_t *tt, proc_callback cfunc, void *data, size_t datalen);
int _add_timeout_event (GHepoll_s *base, event_s *event);
void _signal_handler(int signum);
void _GHepoll_global_signal_init();
int _GHepoll_signal_pipe(int pipefd[2]) ;
int _GHepoll_signal_hander(int signum);
event_s* create_signal_event (int signum, uint32_t events, proc_callback cfunc, void *data, size_t datalen);
int _add_signal_event (GHepoll_s *base, event_s *event);
GHepoll_s *create_new_epoll (size_t epoll_size) ;
uint32_t GHepoll_event_convert(uint32_t events);
int _epoll_mod (GHepoll_s *base, event_s *event) ;
void _event_free(event_s *event);
GHEPOLL_TYPE_E GHepoll_check_event_type(uint32_t events);



/* API */
event_s* GHepoll_create_event (int fd, struct timeout_t *tt, uint32_t events,proc_callback pfunc, void *data, size_t datalen);
int GHepoll_add_event (GHepoll_s *base, event_s *event);
int GHepoll_del_event (GHepoll_s *base, event_s *event);
void GHepoll_loop (GHepoll_s *base);
void GHepoll_event_free(event_s *event);


#endif
