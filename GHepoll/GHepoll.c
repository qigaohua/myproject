#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "GHepoll.h"
#include "util.h"




/*********************************fd*************************************/

event_s* create_fd_event (int fd, uint32_t events, proc_callback cfunc, void *data, size_t datalen)
{
    event_s *new_event = NULL;

    if (fd <= 0 || cfunc == NULL) {
        _error("Invalid param");
        return NULL;
    }

    new_event = (event_s *)xzalloc(sizeof(event_s));
    new_event->type = GHEPOLL_TYPE_FD;
    new_event->event = GHepoll_event_convert(events);
    new_event->fd = fd;
    new_event->callback = cfunc;

    if (data) {
        new_event->args = xzalloc(datalen);
        memcpy(new_event->args, data, datalen);
    }

    new_event->next = NULL;

    return new_event;
}


int GHepoll_del_event (GHepoll_s *base, event_s *event)
{
    event_s *ev, *last = NULL;

    if (!base || !event) {
        _error("Invalid param");
        return -1;
    }

    for(ev = base->fd_event; ev; ev = ev->next) {
        if (ev->fd == event->fd) {
            if (last)
                last->next = ev->next;
            else
                base->fd_event = ev->next;

            epoll_ctl(base->epoll_fd, EPOLL_CTL_DEL, ev->fd, NULL);

            /* 如果是信号处理事件，恢复信号默认处理 */
            if (ev->type == GHEPOLL_TYPE_SIGNAL)
                signal(ev->signal, SIG_DFL);

            base->epoll_curr_size --;
            _event_free(ev);
            return 0;
        }
        last = ev;
    }

    _warn("del event: %d [not exist]", event->fd);
    return -1;
}

int _add_fd_event(GHepoll_s *base, event_s *event)
{
    if (base->epoll_curr_size != 0) {
        event_s *ev = base->fd_event;
        while (ev) {
            if (ev->fd == event->fd) {
                _epoll_mod(base, event);
                return 0;
            }
            ev = ev->next;
        }
    }

    struct epoll_event ev;

    ev.events = event->event;
    // ev.data.fd = event->fd;
    ev.data.ptr = event;

    if (epoll_ctl(base->epoll_fd, EPOLL_CTL_ADD, event->fd, &ev) == -1) {
        _error("epoll_ctl[ADD] failed");
        return -1;
    }
    event->owner = base;

    if (base->epoll_curr_size == 0)
        base->fd_event = event;
    else {
        event->next = base->fd_event;
        base->fd_event = event;
    }
    base->epoll_curr_size ++;

    _debug("add event: %d, num: %lu", event->fd, base->epoll_curr_size);
    return 0;
}

/******************************timeout********************************************/

event_s* create_timeout_event (struct timeout_t *tt, proc_callback cfunc, void *data, size_t datalen)
{
    event_s *new_event = NULL;
    struct timeval tv;

    if (tt->start_time.tv_sec <= 0 || NULL == cfunc) {
        _error("Invalid param");
        return NULL;
    }
    new_event = (event_s *)xzalloc(sizeof(event_s));

    if (tt->loop_time.tv_sec == 0 && tt->loop_time.tv_usec == 0)
        new_event->type = GHEPOLL_TYPE_TIMEOUT;
    else
        new_event->type = GHEPOLL_TYPE_TIMEOUT_LOOP;

    new_event->callback = cfunc;

    get_monotonic(&tv);
    new_event->when.start_time.tv_sec = tv.tv_sec + tt->start_time.tv_sec;
    new_event->when.start_time.tv_usec = tv.tv_usec + tt->start_time.tv_usec;

    new_event->when.loop_time.tv_sec = tt->loop_time.tv_sec;
    new_event->when.loop_time.tv_usec = tt->loop_time.tv_usec;

    if (data) {
        new_event->args = xzalloc(datalen);
        memcpy(new_event->args, data, datalen);
    }
    new_event->next = NULL;

    return new_event;
}


int _add_timeout_event (GHepoll_s *base, event_s *event)
{
    event_s *ev, *last = NULL;

    get_monotonic(&base->now);
    if (timercmp(&event->when.start_time, &base->now, <)) {
        _error("set time param invalid");
        return -1;
    }
    event->owner = base;

    /* remove existing timeout event */
    for (ev = base->timeouts; ev; ev = ev->next) {
        if (ev->callback == event->callback &&
                ev->args == event->args) {
            if (last)
                last->next = ev->next;
            else
                base->timeouts = ev->next;

            _event_free (ev);
            break;
        }
        last = ev;
    }

    /* 如果插入超时事件最接近现在，将此事件插入在最前面 */
    if (base->timeout_curr_size == 0 ||
            timercmp(&(event->when.start_time), &(base->timeouts->when.start_time), <)) {
        event->next = base->timeouts;
        base->timeouts = event;
        base->timeout_curr_size ++;
        goto END;
    }

    for (ev = base->timeouts; ev; ev = ev->next) {
        if (timercmp(&event->when.start_time, &ev->when.start_time, <)) {
            last->next = event;
            event->next = ev;
            base->timeout_curr_size ++;
            goto END;
        }
        last = ev;
    }

    /* 如果此事件离现在时间最远，插入到最后 */
    last->next = event;
    base->timeout_curr_size ++;

END:
    _debug("add timeout %lu sec after call", event->when.start_time.tv_sec - base->now.tv_sec);
    return 0;
}


/***********************signal**********************************************/

#define PIPE_READ   0
#define PIPE_WRITE  1

static int global_pipe_fd[SIGNAL_NUM_MAX + 1];
static BOOL global_signal_init = False;

void _signal_handler(int signum)
{
    if (signum > 0 || signum <= SIGNAL_NUM_MAX) {
        int fd = global_pipe_fd[signum];
        if (fd != -1)
            write(fd, &signum, sizeof(signum));
    } else
        _debug("_signal_handler error, signum out of range");

    return ;
}

void _GHepoll_global_signal_init()
{
    if (global_signal_init == False) {
        memset(global_pipe_fd, -1, sizeof(global_pipe_fd));
        global_signal_init = True;
    }
}

int _GHepoll_signal_pipe(int pipefd[2])
{
    if (pipe(pipefd) == -1) {
        _error("pipe() falied");
        return -1;
    }

    set_nonblock(pipefd[PIPE_READ]);
    set_cloexec(pipefd[PIPE_READ]);

    set_nonblock(pipefd[PIPE_WRITE]);
    set_cloexec(pipefd[PIPE_WRITE]);

    return 0;
}

int _GHepoll_signal_hander(int signum)
{
    struct sigaction sigAct;
    sigemptyset(&(sigAct.sa_mask));
    sigAct.sa_handler = _signal_handler;
    sigAct.sa_flags = 0;

    return sigaction(signum, &sigAct, NULL);
}

event_s* create_signal_event (int signum, uint32_t events, proc_callback cfunc, void *data, size_t datalen)
{
    event_s *new_event = NULL;

    if (signum <=0 || signum > SIGNAL_NUM_MAX) {
        _error("Invalid param, signal out of range");
        return NULL;
    }

    if (NULL == cfunc) {
        _error("Invalid param, callback is null'");
        return NULL;
    }

    new_event = (event_s *)xzalloc(sizeof(event_s));
    new_event->type = GHEPOLL_TYPE_SIGNAL;
    new_event->fd = -1;
    new_event->signal = signum;
    new_event->event = GHepoll_event_convert(events);
    new_event->callback = cfunc;

    if (data) {
        new_event->args = xzalloc(datalen);
        memcpy(new_event->args, data, datalen);
    }
    new_event->next = NULL;

    return new_event;
}

int _add_signal_event (GHepoll_s *base, event_s *event)
{
    int pipe_fd[2];
    event_s *ev, *last = NULL;

    event->owner = base;
    _GHepoll_global_signal_init();

    if (_GHepoll_signal_pipe(pipe_fd) == -1)
        return -1;

    /* 判断是否已经存在 */
    for (ev = base->fd_event; ev; ev = ev->next) {
        if (ev->signal != 0 && ev->signal == event->signal) {
            event->next = ev->next;
            last->next = event;
            _event_free(ev);ev = NULL;
            return 0;
        }
        last = ev;
    }

    event->fd = pipe_fd[PIPE_READ];
    if (global_pipe_fd[event->signal] == -1)
        global_pipe_fd[event->signal] = pipe_fd[PIPE_WRITE];
    else {
        _error("maybe is error there");
        goto ERROR;
    }
    _GHepoll_signal_hander(event->signal);
    if (_add_fd_event(base, event) == -1)
        goto ERROR;

    return 0;

ERROR:
    close(pipe_fd[PIPE_READ]);
    close(pipe_fd[PIPE_WRITE]);

    return -1;
}


/***************************common**********************************/

GHepoll_s *create_new_epoll (size_t epoll_size)
{
    GHepoll_s *base = NULL;

    if (epoll_size == 0)
        epoll_size = EPOLL_MAX_SIZE;
    base = (GHepoll_s *)xzalloc(sizeof(GHepoll_s) + epoll_size * sizeof(struct epoll_event));

    base->epoll_fd = epoll_create(epoll_size);
    if (base->epoll_fd == -1) {
        _error("epoll_create failed");
        free (base);
        return NULL;
    }
    base->epoll_event_size = epoll_size;
    get_monotonic(&base->now);

    return base;
}

void _event_free(event_s *event)
{
    if (event) {
        if (event->args)
            free(event->args);

        if (event->type == GHEPOLL_TYPE_SIGNAL) {
            // close(event->fd);
            close(global_pipe_fd[event->signal]);
            global_pipe_fd[event->signal] = -1;
        }

        free(event);
    }
    event = NULL;
}

void GHepoll_event_free(event_s *event)
{
    _event_free(event);
}

uint32_t GHepoll_event_convert(uint32_t events)
{
    uint32_t ret = 0;

    if (events == 0) {
        _error("Invalid events");
        return 0;
    }

    /* 表示对应的文件描述符可以读（包括对端SOCKET正常关闭） */
    if (BITS_ANY_SET(events, EVENT_TYPE_READ))
        ret |= EPOLLIN;

    /* 表示对应的文件描述符可以写 */
    if (BITS_ANY_SET(events, EVENT_TYPE_WRITE))
        ret |= EPOLLOUT;

    /* 表示对应的文件描述符有紧急的数据可读（这里应该表示有带外数据到来）*/
    if (BITS_ANY_SET(events, EVENT_TYPE_PRI))
        ret |= EPOLLPRI;

    /* 示对应的文件描述符发生错误 或被挂断 */
    if (BITS_ANY_SET(events, EVENT_TYPE_ERROR))
        ret |=  EPOLLERR | EPOLLHUP;

    /* 将EPOLL设为边缘触发(Edge Triggered)模式，这是相对于水平触发(Level Triggered)来说的 */
    if (BITS_ANY_SET(events, EVENT_TYPE_ET))
        ret |= EPOLLET;

    /* 只监听一次事件，当监听完这次事件之后，如果还需要继续监听这个socket的话，需要再次把这个socket加入到EPOLL队列里 */
    if (BITS_ANY_SET(events, EVENT_TYPE_ONESHOT))
        ret |= EPOLLONESHOT;

    return ret;
}

int _epoll_mod (GHepoll_s *base, event_s *event)
{
    struct epoll_event ev;

    if (!base || !event) {
        _error("Invalid param");
        return -1;
    }

    ev.events = event->event;
    ev.data.ptr = event;

    if (-1 == epoll_ctl(base->epoll_fd, EPOLL_CTL_MOD, event->fd, &ev)) {
        _error("epoll_ctl[MOD] failed");
        return -1;
    }

    return 0;
}


int GHepoll_add_event (GHepoll_s *base, event_s *event)
{
    int ret = 0;

    if (!base || !event) {
        _error("Invalid param");
        return -1;
    }

    switch (event->type) {
        case GHEPOLL_TYPE_FD:
            ret = _add_fd_event(base, event);
            break;
        case GHEPOLL_TYPE_TIMEOUT_LOOP:
        case GHEPOLL_TYPE_TIMEOUT:
           ret = _add_timeout_event(base, event);
          break;
        case GHEPOLL_TYPE_SIGNAL:
          ret = _add_signal_event(base, event);
          break;
        default:
          _warn("GHepoll nonsuport the type");
          break;
    }

    return ret;
}

inline BOOL GHepoll_isFdEvent(uint32_t events)
{
    if (BITS_ANY_SET(events, EVENT_TYPE_READ | EVENT_TYPE_WRITE))
        return True;

    return False;
}

inline BOOL GHepoll_isTimeoutEvent(uint32_t events)
{
    if (BITS_ANY_SET(events, EVENT_TYPE_TIMEOUT))
        return True;

    return False;
}

inline BOOL GHepoll_isSignalEvent(uint32_t events)
{
    if (BITS_ANY_SET(events, EVENT_TYPE_SIGNAL))
        return True;

    return False;
}

GHEPOLL_TYPE_E GHepoll_check_event_type(uint32_t events)
{
    if (events == 0) {
        _warn("Invalid param");
        return GHEPOLL_TYPE_ERROR;
    }

    if (GHepoll_isFdEvent(events)) {
        return GHEPOLL_TYPE_FD;
    }
    else if (GHepoll_isTimeoutEvent(events)) {
        return GHEPOLL_TYPE_TIMEOUT;
    }
    else if (GHepoll_isSignalEvent(events)) {
        return GHEPOLL_TYPE_SIGNAL;
    } else {
        _error("Invalid events type");
    }

    return GHEPOLL_TYPE_ERROR;
}


/**
 * @brief GHepoll_create_event
 *
 * @param fd: 对于fd事件，代表描述符；对于定时事件，没用； 对于信号事件，代表信号
 * @param tt: 只用于定时事件，当tt中loop_time不为0时，则是循环定时事件
 * @param events: 事件类型(枚举类型EVENT_TYPE_E)
 * @param pfunc: 事件回调处理函数
 * @param data: 传入给回调函数的额外数据
 * @param datalen: 额外数据长度
 *
 * @return 成功返回event_s结构体， 失败返回NULL
 */
event_s* GHepoll_create_event (int fd, struct timeout_t *tt, uint32_t events,
                    proc_callback pfunc, void *data, size_t datalen)
{
    event_s *ev = NULL;
    GHEPOLL_TYPE_E type = GHepoll_check_event_type(events);

    switch (type) {
        case GHEPOLL_TYPE_FD:
            ev = create_fd_event(fd, events, pfunc, data, datalen);
            break;
        case GHEPOLL_TYPE_SIGNAL:
            /* 此处fd代表信号*/
           ev = create_signal_event(fd, EVENT_TYPE_READ, pfunc, data, datalen);
           break;
        case GHEPOLL_TYPE_TIMEOUT:
           ev = create_timeout_event(tt, pfunc, data, datalen);
          break;
        default:
          _warn("Invalid param [event type]");
          break;
    }

    return ev;
}

void GHepoll_loop (GHepoll_s *base)
{
    // event_s *events;
    int nfds, i, msecs;
    struct epoll_event *events = base->events;
    struct timeval tv;

    if (NULL == base) {
        _error("Invalid param");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        if (base->epoll_curr_size == 0 && base->timeout_curr_size == 0) {
            _info("no events, exit");
            exit(EXIT_FAILURE);
        }

        if (base->timeout_curr_size > 0) {
            get_monotonic(&base->now);
            if (timercmp(&base->now, &(base->timeouts->when.start_time), >)) {
                event_s *ev = base->timeouts;
                base->timeouts = ev->next;

                ev->callback(ev);

                if (ev->type == GHEPOLL_TYPE_TIMEOUT_LOOP) {
                    ev->when.start_time.tv_sec += ev->when.loop_time.tv_sec;
                    if (base->timeouts == NULL)
                        base->timeouts = ev;
                    else {
                        event_s *last = NULL, *cur;
                        for (cur = base->timeouts; cur; cur = cur->next) {
                            if (timercmp(&cur->when.start_time, &ev->when.start_time, >)) {
                                ev->next = cur;
                                if (cur == base->timeouts) {
                                    base->timeouts = ev;
                                }
                                else {
                                    last->next = ev;
                                }
                                break;
                            }
                            last = cur;
                        }
                        if (!cur) {
                            ev->next = NULL;
                            last->next = ev;
                        }
                    }
                } else {
                    _event_free(ev);
                    base->timeout_curr_size --;
                }
                continue;
            }

            timersub(&(base->timeouts->when.start_time), &base->now, &tv);
            /* 防止msces超出int范围 */
            if (tv.tv_sec > INT_MAX / 1000 ||
                    (tv.tv_sec == INT_MAX && (tv.tv_usec + 999) / 1000 > INT_MAX % 1000))
                msecs = INT_MAX;
            else
                msecs = tv.tv_sec * 1000 + (tv.tv_usec + 999) / 1000;
        } else
            msecs = -1;

        _debug("all fd event: %lu, msecs: %d", base->epoll_curr_size, msecs);
        nfds = epoll_wait(base->epoll_fd, events, base->epoll_event_size, msecs);
        if (-1 == nfds) {
            if (errno == EINTR)
                continue;
            _error("epoll_wait failed, %m.");
            exit(EXIT_FAILURE);
        } else if (0 == nfds) {
            _debug("epoll_wait timeout");
            continue;
        }

        for (i = 0; i < nfds; i ++) {
            event_s *event = (event_s *) events[i].data.ptr;
            event->callback(event);
        }
    }
}



/*************************************************************************/
/*        测试 GHepoll (gcc -DTEST GHepoll.c util.c -o GHepoll)          */
/*****************************test****************************************/

#ifdef TEST
int tcp_socket(const char *host, uint16_t port)
{
    int sock, ret;
    struct sockaddr_in addr;

    if (-1 == (sock = socket(AF_INET, SOCK_STREAM, 0))) {
        _error("socket() failed");
        exit(EXIT_FAILURE);
    }

    set_nonblock(sock);
    set_cloexec(sock);

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        /* maybe host name */
        struct hostent *hp;
        hp = gethostbyname(host);
        if (NULL == hp) {
            _error("host not valid.");
            exit(EXIT_FAILURE);
        }

        memcpy(&addr.sin_addr, &hp->h_addr, hp->h_length);
    }

    int len = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&len, sizeof(int));
    if (ret) {
        _error("setsockopt() failed.");
        exit(EXIT_FAILURE);
    }

    if (-1 == bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr))) {
        _error("bind() failed");
        return -1;
    }

    listen(sock, 1024);

    return sock;
}

void client_callback(event_s *ev)
{
    const char *sbuff = "GHepoll test ok";
    char rbuff[1024] = {0};
    ssize_t rlen = 0;

    if (NULL == ev->owner || NULL == ev)
        return ;
    GHepoll_s *base = ev->owner;

    rlen = recv (ev->fd, rbuff, sizeof(rbuff), 0);
    if (rlen < 0) {
        _error("recv() failed [%m].");
        return ;
    } else if (rlen == 0) {
        _warn("client maybe close");
        close(ev->fd);
        GHepoll_del_event(base, ev);
        return ;
    }

    _debug("recv msg from client: %s", rbuff);
    send(ev->fd, sbuff, strlen(sbuff) + 1, 0);
}

void accept_callback(event_s *ev)
{
    int clifd;
    struct sockaddr_in cliaddr;
    socklen_t clilen = sizeof(cliaddr);

    if (NULL == ev->owner || NULL == ev)
        return ;
    GHepoll_s *base = ev->owner;
    clifd = accept(ev->fd, (struct sockaddr *)&cliaddr, &clilen);
    if (clifd < 0 ) {
        _error("accept() failed [%m].");
        return ;
    }
    event_s *event = create_fd_event(clifd, EVENT_TYPE_READ, client_callback, NULL, 0);
    GHepoll_add_event(base, event);
}

void timeout_callback(event_s *ev)
{
    if (NULL == ev->owner || NULL == ev)
        return ;

    _info ("GHepoll %s event test", ev->args);
}

void signal_callback(event_s *ev)
{
    int signal = 0;
    ssize_t rlen ;

    if (NULL == ev->owner || NULL == ev)
        return ;

    rlen = read(ev->fd, &signal, sizeof(signal));
    if (rlen < 0) {
        _error("signal read falied");
        return;
    }
    else if (rlen == 0) {
        return;
    }

    _info ("GHepoll %s event test, recv singal %d", ev->args, signal);
}

int main ()
{
    int sockfd;
    GHepoll_s *base = NULL;

    /* 设置日志等级为调试 */
    util_set_log_level (LOG_LEVEL_DEBUG);
    base = create_new_epoll(16);

    sockfd = tcp_socket("127.0.0.1", 12345);

    /* 添加一个socke监听事件 */
    // event_s *event = create_fd_event(sockfd, EVENT_TYPE_READ, accept_callback, NULL, 0);
    event_s *event = GHepoll_create_event(sockfd, NULL, EVENT_TYPE_READ, accept_callback, NULL, 0);
    if (event) {
        if (-1 == GHepoll_add_event(base, event))
            GHepoll_event_free(event);
    }

    struct timeout_t tt;

    tt.start_time.tv_sec = 5;
    tt.start_time.tv_usec = 0;
    tt.loop_time.tv_sec = 5;
    tt.loop_time.tv_usec = 0;

    /* 添加一个循环定时事件 */
    // event_s *event_timeout = create_timeout_event(10, timeout_callback, "timeout", 8);
    event_s *event_timeout = GHepoll_create_event(0, &tt, EVENT_TYPE_TIMEOUT, timeout_callback, "timeout", 8);
    if (event_timeout) {
        if (-1 == GHepoll_add_event(base, event_timeout))
            GHepoll_event_free(event_timeout);
    }

    tt.start_time.tv_sec = 8;
    tt.loop_time.tv_sec = 0;
    /* 添加一个定时事件, 非循环 */
    event_s *event_timeout2 = GHepoll_create_event(0, &tt, EVENT_TYPE_TIMEOUT, timeout_callback, "timeout2", 9);
    if (event_timeout2) {
        if (-1 == GHepoll_add_event(base, event_timeout2))
            GHepoll_event_free(event_timeout2);
    }

    /* 添加一个信号处理事件 */
    event_s *event_signal = GHepoll_create_event(SIGQUIT, NULL, EVENT_TYPE_SIGNAL, signal_callback, "signal", 7);
    if (event_signal) {
        if (-1 == GHepoll_add_event(base, event_signal))
            GHepoll_event_free(event_signal);
    }

    GHepoll_loop(base);
    return 0;
}
#endif
