#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/time.h>

// #ifdef MULTI_PTHREAD
#include <pthread.h>
// #endif

#include "min_heap_timer.h"


/*
 * 通过数组构成最小堆
 *   |  | a | b | c | d | e | f | g |  |  |
 * 第一个元素空着，minheap_t->headindex 指向 a,
 * minheap_t->lastindex 指向g后面的空元素
 *
 */


static void swap(minheap_node_t *a, minheap_node_t *b)
{
    minheap_node_t temp;

    temp.data = a->data;
    temp.time_ms = a->time_ms;

    a->data = b->data;
    a->time_ms = b->time_ms;

    b->data = temp.data;
    b->time_ms = temp.time_ms;
}



minheap_t *MinHeapInit(unsigned int node_num, ProcessFunc func)
{
    minheap_t *minheap;

    minheap = calloc(1, sizeof(*minheap));
    if (!minheap) {
        fprintf(stderr, "Calloc mem(%ld) failed\r\n", sizeof(*minheap));
        exit(1);
    }

    minheap->node_list = calloc(node_num, sizeof(minheap_node_t));
    if (!minheap->node_list) {
        fprintf(stderr, "Calloc mem(%ld) failed\r\n", sizeof(*minheap));
        exit(1);
    }

#ifdef MULTI_PTHREAD
    pthread_mutex_init(&minheap->mutex, NULL);
    pthread_cond_init(&minheap->cond, NULL);
#endif

    minheap->headindex = 1; // 从node_list[1]开始插入, [0]不用
    minheap->lastindex = 1; // 指向堆中最后一个节点的后一个
    minheap->max_num = node_num - 1;
    minheap->ProcessMinHeapNodeData = func;

    return minheap;
}


void MinHeapDestroy(minheap_t *mp)
{
    if (!mp) return ;
#ifdef MULTI_PTHREAD
    pthread_mutex_lock(&mp->mutex);
#endif
    if (mp->node_list)
        free(mp->node_list);
    free(mp);
#ifdef MULTI_PTHREAD
    pthread_mutex_unlock(&mp->mutex);
#endif
}


static void MinHeapAddAdjest(minheap_t *mp, uint32_t index)
{
    if (index <= mp->headindex)
        return;

    int i = index;
    minheap_node_t *left;
    minheap_node_t *right;
    minheap_node_t *parent;


    parent = &mp->node_list[PARENT(i)];
    // 奇数为右节点，偶数为左节点
    if (i % 2 == 0) {
        left = &mp->node_list[i];
        if (i == mp->lastindex) {
            right = NULL;
        }
        else
            right = &mp->node_list[i+1];
    }
    else {
        right = &mp->node_list[i];
        left = &mp->node_list[i-1];
    }

    // if (right == NULL) {
    //     if (left->time_ms < parent->time_ms)
    //         swap(left, parent);
    // }
    // else if (left->time_ms <= right->time_ms && left->time_ms < parent->time_ms) {
    //     swap(left, parent);
    // }
    // else if (left->time_ms > right->time_ms && right->time_ms < parent->time_ms) {
    //     swap(right, parent);
    // }
    // else
    //     return;

    minheap_node_t *small_node;
    if (right == NULL || left->time_ms <= right->time_ms) {
        small_node = left;
    }
    else
        small_node = right;

    if (small_node->time_ms < parent->time_ms)
        swap(small_node, parent);
    else
        return;

    MinHeapAddAdjest(mp, PARENT(i));
}


int MinHeapAddNode(minheap_t *mp, void *data, unsigned long time_ms)
{
#ifdef MULTI_PTHREAD
    pthread_mutex_lock(&mp->mutex);
#endif
    if (mp->lastindex == mp->max_num) {
        fprintf(stderr, "Wow, the minheap already full\r\n");
#ifdef MULTI_PTHREAD
        pthread_mutex_unlock(&mp->mutex);
#endif
        return -1;
    }

    minheap_node_t *last_node = &mp->node_list[mp->lastindex];

    last_node->data = data;
    last_node->time_ms = time_ms;

    // printf(">>>>>>>%s %d\n", mp->node_list[mp->lastindex].data, mp->node_list[mp->lastindex].time_ms);

    if (mp->lastindex <= 2) {
        if (mp->node_list[mp->headindex].time_ms < time_ms)
            swap(&mp->node_list[mp->headindex], last_node);
    }
    else {
        MinHeapAddAdjest(mp, mp->lastindex);
    }

    mp->lastindex++;
#ifdef MULTI_PTHREAD
    pthread_mutex_unlock(&mp->mutex);
#endif

    return 0;
}



static void MinHeapDelAdjuet(minheap_t *mp, uint32_t index)
{
    minheap_node_t *left;
    minheap_node_t *right = NULL;
    minheap_node_t *parent;
    uint32_t total_node = mp->lastindex-1;

    parent = &mp->node_list[index];
    if (total_node >= RIGHTCHILD(index)) {
        left = &mp->node_list[LEFTCHILD(index)];
        right = &mp->node_list[RIGHTCHILD(index)];
    }
    else if (total_node >= LEFTCHILD(index)) {
        left = &mp->node_list[LEFTCHILD(index)];
    }
    else
        return ;

    if (right == NULL) {
        if (left->time_ms < parent->time_ms)
            swap(left, parent);
        return ;
    }
    else if (left->time_ms <= right->time_ms && left->time_ms < parent->time_ms) {
        swap(left, parent);
        MinHeapDelAdjuet(mp, LEFTCHILD(index));
    }
    else if (left->time_ms > right->time_ms && right->time_ms < parent->time_ms) {
        swap(right, parent);
        MinHeapDelAdjuet(mp, RIGHTCHILD(index));
    }

    return ;
}



int MinHeapDelNode(minheap_t *mp, void **data, unsigned long *time_ms)
{
#ifdef MULTI_PTHREAD
    pthread_mutex_lock(&mp->mutex);
#endif
    if (mp->lastindex == mp->headindex) {
#ifdef MULTI_PTHREAD
        pthread_mutex_unlock(&mp->mutex);
#endif
        fprintf(stderr, "Wow, minheap is empty !\r\n");
        return -1;
    }

    *data = mp->node_list[mp->headindex].data;
    *time_ms = mp->node_list[mp->headindex].time_ms;

    minheap_node_t *last_node = &mp->node_list[mp->lastindex-1]; // mp->lastindex 是最后节点的后一个空节点
    swap(last_node, &mp->node_list[mp->headindex]);
    last_node->data = NULL;
    last_node->time_ms = 0;

    mp->lastindex--;
    MinHeapDelAdjuet(mp, mp->headindex);

#ifdef MULTI_PTHREAD
    pthread_mutex_unlock(&mp->mutex);
#endif

    return 0;
}


static int get_monotonic(struct timeval *tv)
{
    struct timespec ts;

    if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
        fprintf(stderr, "Call clock_gettime[CLOCK_MONOTONIC] failed %m\r\n");
        return gettimeofday(tv, NULL);
    }

    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000 ;

    return 0;
}



static int pipe_fd[2];
#define READER pipe_fd[0]
#define WRITER pipe_fd[1]
#define MAX_EVENTS  8

#include "atomic.h"

// volatile static int is_wait = 0;
atomic32_t is_wait;

// 是否在阻塞中， 1是0否
int MinHeapTimerIsWait()
{
    return atomic32_read(&is_wait) == 1;
}

int TellMinHeapTimer(enum minheaptimer_cmd cmd)
{
    if (WRITER <= 0) {
        fprintf(stderr, "Wow, Did you call MinHeapTimerInit? \r\n ");
        return -1;
    }

    // 如果不在阻塞中，直接返回
    if (cmd == CMD_HAVE_DATA) {
        if (MinHeapTimerIsWait() == 0)
            return 0;
        else
            atomic32_set(&is_wait, 0);
    }

    if (4 != write(WRITER, &cmd, 4)) {
        fprintf(stderr, "Call write failed: %m\r\n");
        return -1;
    }

    return 0;
}


int MinHeapTimerLoop(minheap_t *mp)
{
    int epoll_fd;
    struct epoll_event *events;
    struct epoll_event ev;
    struct timeval tv;
    static int is_exit = 0;
    atomic32_init(&is_wait);

    epoll_fd = epoll_create(MAX_EVENTS);
    if (epoll_fd == -1) {
        fprintf(stderr, "Call epoll_create() failed: %m\r\n");
        return -1;
    }

    if (0 != pipe(pipe_fd)) {
        fprintf(stderr, "Call pipe() failed: %m\r\n");
        return -1;
    }

    events = calloc(MAX_EVENTS, sizeof(*events));
    if (!events) {
        fprintf(stderr, "Calloc mem(%ld) failed: %m\r\n", sizeof(*events) * MAX_EVENTS);
        return -1;
    }

    ev.data.fd = READER;
    ev.events = EPOLLIN;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, READER, &ev) == -1) {
        fprintf(stderr, "Call epoll_ctl[ADD] failed: %m\r\n");
        return -1;
    }

    int i, nfds;
    unsigned long now_msecs, expires = 0;
    long long timeout;
    void *data;

    while(!is_exit) {
        if (expires == 0 && 0 != MinHeapDelNode(mp, &data, &expires)) {
            /* 最小堆中没有定时事件 */
            timeout = -1;
            atomic32_set(&is_wait, 1); // 在epoll_wait阻塞中
        }
        else {
            get_monotonic(&tv);
            now_msecs = tv.tv_sec * 1000 + tv.tv_usec / 1000;

            timeout = expires - now_msecs;
            if (timeout <= 0) {
                /* do something */
                mp->ProcessMinHeapNodeData(data);
                expires = 0;
                continue;
            }

            // 防止timeout超出int范围
            if (timeout > INT_MAX) {
                timeout = INT_MAX;
                expires -= INT_MAX; // 到期时间重设
            }
            else
                expires = 0;
        }

        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout);
        if (-1 == nfds) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Call epoll_wait failed, %m\r\n");
            exit(EXIT_FAILURE);
        } else if (0 == nfds) {
            // fprintf(stdout, "timeout\r\n");
            if (expires == 0) {
                /* TODO */
                mp->ProcessMinHeapNodeData(data);
            }
            continue;
        }

        for (i = 0; i < nfds; i ++) {
            int fd = events[i].data.fd;
            /* TODO */

            /*例子1： 传输退出命令*/
            int cmd;
            if (read(fd, &cmd, 4) != 4) {
                fprintf(stderr, "Wow, read fd(%d) 4 bytes failed\r\n", fd);
                continue;
            }
            switch(cmd) {
                case CMD_HAVE_DATA:
                    atomic32_set(&is_wait, 0);
                    fprintf(stdout, "minheap already has data\r\n");
                    break;
                case CMD_EXIT:
                    fprintf(stdout, "Exit minheap timer.\r\n");
                    is_exit = 1;
                    break;
                default:
                    fprintf(stderr, "Wow, don't know cmd: %d\r\n", cmd);
            }

            /* 或者传输数据，添加到最小堆中 */
        }
    }
    fprintf(stdout, "The minheap timer exit.\r\n");

    return 0;
}



#if 0
#define TEST_NUM  20

unsigned long now_msecs;

void *test_pthread(void *data)
{
    pthread_detach(pthread_self());
    minheap_t *mp = (minheap_t *)data;

    int i = 0;
    // struct timeval tv;
    // get_monotonic(&tv);
    // unsigned long now_msecs = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    for (i = 0; i < TEST_NUM; i++) {
        int random = rand() % TEST_NUM;
        char *str = calloc(1, 20);
        snprintf(str, 20, "%lu|%d", now_msecs + random * 1000, random);

        printf("== 运行时添加  %u -> \"%s\"\n", random,  (char *)str);
        MinHeapAddNode(mp, (void *)str, now_msecs + random * 1000);
        sleep(1);
    }

    if (MinHeapTimerIsWait())
        TellMinHeapTimer(CMD_HAVE_DATA);

    sleep(60);
    TellMinHeapTimer(CMD_EXIT);

    return NULL;
}


int process_data(void *data)
{
    if (!data)
        return -1;

    printf("== \"%s\"\n", (char *)data);
    free(data);
    return 0;
}


int main(int argc, char *argv[])
{
    minheap_t *mp;
    int i = 0;

    mp = MinHeapInit(1000, process_data);
    if (!mp)
        exit(1);
    srand((unsigned int)time(0));

    // const char *str1 = "a";
    // const char *str2 = "b";
    // const char *str3 = "c";
    // const char *str4 = "d";
    // const char *str5 = "e";
    // const char *str6 = "f";
    // const char *str7 = "g";
    // const char *str8 = "h";
    // const char *str9 = "i";
    // const char *str10 = "j";
    // const char *str11 = "k";

    // MinHeapAddNode(mp, (void *)str11, now_msecs + 11 * 1000);
    // MinHeapAddNode(mp, (void *)str3, now_msecs + 3 * 1000);
    // MinHeapAddNode(mp, (void *)str1, now_msecs + 1 * 1000);
    // MinHeapAddNode(mp, (void *)str9, now_msecs + 9 * 1000);
    // MinHeapAddNode(mp, (void *)str2, 2);
    // MinHeapAddNode(mp, (void *)str4, 4);
    // MinHeapAddNode(mp, (void *)str5, 5);
    // MinHeapAddNode(mp, (void *)str7, 7);
    // MinHeapAddNode(mp, (void *)str8, 8);
    // MinHeapAddNode(mp, (void *)str6, 6);
    // MinHeapAddNode(mp, (void *)str10, 10);
    //

    // char string[TEST_NUM][50];

    // for(; i < TEST_NUM; i++) {
    //     snprintf(string[i], 5, "%d", i);
    // }

    struct timeval tv;
    get_monotonic(&tv);
    now_msecs = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    for (i = 0; i < TEST_NUM; i++) {
        int random = rand() % TEST_NUM;
        char *str = calloc(1, 20);
        snprintf(str, 20, "%lu|%d", now_msecs + random * 1000, random);

        printf("== %u -> \"%s\"\n", random,  (char *)str);
        MinHeapAddNode(mp, (void *)str, now_msecs + random * 1000);
    }

    printf("==========================================\n");

    pthread_t pid;
    pthread_create(&pid, NULL, test_pthread, mp);

    MinHeapTimerLoop(mp);

    // void *str;
    // uint64_t time_ms;
    // for(i = 1; i < TEST_NUM + 2; i++) {
    //     MinHeapDelNode(mp, &str, &time_ms);
    //     printf("== %u -> \"%s\"\n", time_ms,  (char *)str);
    // }
    printf("\r\n");

    MinHeapDestroy(mp);
    return 0;
}

#endif


