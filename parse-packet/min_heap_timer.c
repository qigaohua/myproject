/**
 * @file min_heap_timer.c
 * @brief 最小堆定时器实现代码
 * @author qigaohua, qigaohua168@163.com
 * @version 1.0.0
 * @date 2021-04-19
 */


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



static int pipe_fd[2];
#define READER pipe_fd[0]
#define WRITER pipe_fd[1]
#define MAX_EVENTS  8

volatile static int is_wait = 0;

// 是否在阻塞中， 1是0否
int MinHeapTimerIsWait()
{
    // return atomic32_read(&is_wait) == 1;
    return is_wait == 1;
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
            is_wait = 0;
            // atomic32_set(&is_wait, 0);
    }

    if (4 != write(WRITER, &cmd, 4)) {
        fprintf(stderr, "Call write failed: %m\r\n");
        return -1;
    }

    return 0;
}


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
    if (MinHeapIsFull(mp)) {
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
#if 0
    // fix bug: 优化代码, 这段代码比较冗余，选用使用下段代码
    if (mp->lastindex <= 2) {
        if (mp->node_list[mp->headindex].time_ms > time_ms)
            swap(&mp->node_list[mp->headindex], last_node);
    }
    else {
        MinHeapAddAdjest(mp, mp->lastindex);
    }
#else
    int child = mp->lastindex, parent = child / 2;

    for (;parent > 0; parent /= 2) {
        if (mp->node_list[child].time_ms >= mp->node_list[parent].time_ms)
            break;
        swap(&mp->node_list[child], &mp->node_list[parent]);
        child = parent;
    }
#endif


    mp->lastindex++;
#ifdef MULTI_PTHREAD
    pthread_mutex_unlock(&mp->mutex);
#endif

    // 当添加的定时器到期时间最小时，发送命令
    if (time_ms == mp->node_list[mp->headindex].time_ms)
        TellMinHeapTimer(CMD_ADD_NODE);

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

    if (data != NULL && time_ms != NULL) {
        *data = mp->node_list[mp->headindex].data;
        *time_ms = mp->node_list[mp->headindex].time_ms;
    }

#if 0
    // fix bug: 优化代码, 这段代码比较冗余，选用使用下段代码
    minheap_node_t *last_node = &mp->node_list[mp->lastindex-1]; // mp->lastindex 是最后节点的后一个空节点
    swap(last_node, &mp->node_list[mp->headindex]);
    last_node->data = NULL;
    last_node->time_ms = 0;

    mp->lastindex--;
    MinHeapDelAdjuet(mp, mp->headindex);
#else

    int lastindex = mp->lastindex-1; // 最后一个节点索引
    int parent = mp->headindex;
    int child = LEFTCHILD(parent);
    uint32_t total_node = mp->lastindex-2;  // 去掉最小节点后剩余的总节点数量

    for (; child <= total_node; child = LEFTCHILD(parent)) {
        // 判断左节点与右节点谁更小
        if (child + 1 <= total_node
                && mp->node_list[child].time_ms > mp->node_list[child+1].time_ms)
            child += 1; // right node min

        // 判断child节点与最后的节点最小
        if (mp->node_list[child].time_ms < mp->node_list[lastindex].time_ms) {
            swap(&mp->node_list[child], &mp->node_list[parent]);
            parent = child;
        }
        else
            break;
    }
    swap(&mp->node_list[parent], &mp->node_list[lastindex]);
    mp->lastindex--;
#endif

#ifdef MULTI_PTHREAD
    pthread_mutex_unlock(&mp->mutex);
#endif

    return 0;
}


int MinHeapIsFull(minheap_t *mp)
{
    return mp->lastindex > mp->max_num; // 因为lastindex指向最后一个空节点
}


int MinHeapIsEmpty(minheap_t *mp)
{
    return mp->lastindex == mp->headindex;
}


int MinHeapGetMinNode(minheap_t *mp, void **data, unsigned long *time_ms)
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
    pthread_mutex_unlock(&mp->mutex);

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



int MinHeapTimerLoop(minheap_t *mp)
{
    int epoll_fd;
    struct epoll_event *events;
    struct epoll_event ev;
    struct timeval tv;
    static int is_exit = 0;


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
    long long timeout = -1;
    void *data;

    while(!is_exit) {
        // if (expires == 0 && 0 != MinHeapDelNode(mp, &data, &expires)) {
        if (0 != MinHeapGetMinNode(mp, &data, &expires)) {
            /* 最小堆中没有定时事件 */
            timeout = -1;
            is_wait = 1;
        }
        else {
            get_monotonic(&tv);
            now_msecs = tv.tv_sec * 1000 + tv.tv_usec / 1000;

            timeout = expires - now_msecs;
            if (timeout <= 0) {
                /* do something */
                MinHeapDelNode(mp, NULL, NULL);
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

        fprintf(stdout, ">>>>>>>>>>>>>>>>>timeout: %lld\n", timeout);
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
                MinHeapDelNode(mp, NULL, NULL);
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
                case CMD_HAVE_DATA: // 这个是在没有CMD_ADD_NODE命令前添加的
                    is_wait = 0;
                    fprintf(stdout, "minheap already has data\r\n");
                    break;
                case CMD_EXIT:
                    fprintf(stdout, "Exit minheap timer.\r\n");
                    is_exit = 1;
                    break;
                case CMD_ADD_NODE: // 防止在运行时添加比较小的定时器，而epoll在比较大的定时器上wait
                    fprintf(stdout, "minheap add node.\r\n");
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
        int random = rand() % 100;
        char *str = calloc(1, 20);
        snprintf(str, 20, "%lu|%d", now_msecs + random * 100, random);

        printf("== %u -> \"%s\"\n", random,  (char *)str);
        MinHeapAddNode(mp, (void *)str, now_msecs + random * 100);
    }

    printf("==========================================\n");

    // 多线程运行时添加
    // pthread_t pid;
    // pthread_create(&pid, NULL, test_pthread, mp);

    MinHeapTimerLoop(mp);

    MinHeapDestroy(mp);
    return 0;
}

#endif


