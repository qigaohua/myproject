#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "threadpool.h"

#define _DEBUG_       // 打印调试信息


#define _ERROR(fmt, ...) do { \
   fprintf(stderr, "[%s:%d] " fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)

#ifdef _DEBUG_
#define _DEBUG(fmt, ...) do { \
   fprintf(stdout, "[%s:%d] " fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)
#else 
#define _DEBUG(fmt, ...)
#endif


INT32 thread_pool_init(thread_pool_info_t *tp);
INT32 thread_pool_destroy(thread_pool_info_t *tp);
INT32 thread_pool_process_job(thread_pool_info_t *tp, void* (*job)(void *), void *args);
INT32 thread_pool_exaggerate(thread_pool_info_t *tp);
float thread_pool_get_use_rate(thread_pool_info_t *tp);
INT32 thread_pool_minify(thread_pool_info_t *tp);



/**
 * @brief create_thread_pool 创建线程池函数
 *
 * @param min   线程池中最小线程数量
 * @param max   线程池中最大线程数量
 *
 * @return  成功: 线程池结构体   失败: 退出程序 
 */
thread_pool_info_t *create_thread_pool(UINT32 min, UINT32 max)
{
    thread_pool_info_t *tp = NULL;

    if (min > max || max <= 0) {
        _ERROR("create thread pool failed, param error(%d ~ %d)", min, max);
        exit(EXIT_FAILURE);
    }

    tp = (thread_pool_info_t *)malloc(sizeof(thread_pool_info_t));
    if (!tp) {
        _ERROR("create thread pool failed, malloc failed(%m)");
        exit(EXIT_FAILURE);
    }

    tp->min = min;
    tp->cur = min;
    tp->max = max;

    tp->tp_init = thread_pool_init;
    tp->tp_destroy = thread_pool_destroy;
    tp->tp_process_job = thread_pool_process_job;
    tp->tp_exaggerate = thread_pool_exaggerate;
    tp->tp_get_use_rate = thread_pool_get_use_rate;
    tp->tp_minify = thread_pool_minify;

    tp->threads = (thread_info_t *)malloc(tp->max * sizeof(thread_info_t));

    return tp; 
}


void thread_func_hander(int signal)
{
    if (signal != SIGUSR1)
        return ; 

    pthread_t pid = pthread_self(); 
    _DEBUG("thread exit, pid is %lu", pid);
    pthread_exit(NULL);
}


/**
 * 线程池中创建的线程，在这里使用信号阻塞,设置线程为等待状态
 * 等待用户分配任务，发送信号
 */
void *thread_pool_func(void *args)
{
    thread_info_t *ti = (thread_info_t*)args;
    if (ti->pid <= 0)
        return (void*)0;
    signal(SIGUSR1, thread_func_hander);

    while (True) {
        pthread_mutex_lock(&ti->mutex);
        ti->is_wait = True;
        pthread_cond_wait(&ti->cond, &ti->mutex);
        ti->is_wait = False;
        pthread_mutex_unlock(&ti->mutex);

        _DEBUG("a job start, pid is %lu", ti->pid);
        if (ti->thread_work) {
            ti->thread_work(ti->param);
        }

        pthread_mutex_lock(&ti->mutex);
        ti->thread_work = NULL;
        ti->is_busy = False;
        pthread_mutex_unlock(&ti->mutex);

        if (ti->is_exit) {
            _DEBUG("thread normal exit , pid is %lu", ti->pid);
            return (void*)0;
        }
    }

    return (void*)0;
}

#define MAX(a, b)                       (((a) > (b)) ? (a) : (b))
#define MIN_USE_RATE                    (0.5)           // 当线程池的使用率低于该值时，释放一些线程
#define GET_USE_RATE_INTERVAL           (1)             // 单位 秒   每多少秒检测一次线程池的使用率
#define MINIFY_THREAD_POOL_INTERVAL     (6)             // 单位 秒   没多少秒根据实时使用率释放一次线程池

/**
 * 线程池的管理线程，实时检测线程池的使用率，
 * 通过使用情况释放一些线程
 */
void *thread_pool_manage_func(void *args)
{
    thread_pool_info_t *tp = (thread_pool_info_t *)args;
    INT32 minify_tp_number = MINIFY_THREAD_POOL_INTERVAL / GET_USE_RATE_INTERVAL;
    signal(SIGUSR1, thread_func_hander);

    UINT32 i = 0;
    float  max = 0.0, use = 0.0;
    do {
        sleep(GET_USE_RATE_INTERVAL);
        use = tp->tp_get_use_rate(tp);
        if (use < 0) {
            _ERROR("thread pool get use rate failed");
            continue;
        }
        max = MAX(max, use);
        if ((++i) % minify_tp_number == 0) {
            _DEBUG("within %d second, max use rate is %0.2f", MINIFY_THREAD_POOL_INTERVAL, max);
            if (max < MIN_USE_RATE)
                tp->tp_minify(tp);
            max = 0.0;
        }
    } while(True);

    return (void*)0;
}


/**
 * @brief thread_pool_init 线程池初始化，创建tp->min个线程等待分配任务
 *
 * @param tp
 *
 * @return 
 */
INT32 thread_pool_init(thread_pool_info_t *tp)
{
    if (!tp) {
        _ERROR("init thread pool failed, param is NULL");
        return -1;
    }

    pthread_mutex_init(&tp->mutex, NULL);

    UINT32 i = 0;
    for (; i < tp->min; i ++) {
        pthread_mutex_init(&tp->threads[i].mutex, NULL);
        pthread_cond_init(&tp->threads[i].cond, NULL);

        tp->threads[i].is_busy = False;
        tp->threads[i].is_exit = False;
        tp->threads[i].is_wait = False;

        // pthread_attr_t  attr;
        // pthread_attr_init(&attr);
        // pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&tp->threads[i].pid, NULL, thread_pool_func, &tp->threads[i]) != 0) {
            _ERROR("init thread pool failed, pthread create error(%m)");
            exit(EXIT_FAILURE);
        }
        _DEBUG("create thread success: pid = %lu", tp->threads[i].pid);
    }

    if (pthread_create(&tp->tp_manage_pid, NULL, thread_pool_manage_func, tp) != 0) {
        _ERROR("init thread pool failed, pthread create error(%m)");
        return -1;
    }
    _DEBUG("create manage thread success: pid = %lu", tp->tp_manage_pid);

    return 0;
} 

INT32 thread_pool_destroy(thread_pool_info_t *tp)
{
    if (!tp) {
        _ERROR("init thread pool failed, param is NULL");
        return -1;
    }

    UINT32 i = 0;
    void *status;
    for (; i < tp->cur; i++) {
        /* 0 为保留信号，测试这个线程是否存在 */
        if (pthread_kill(tp->threads[i].pid, 0) != ESRCH) {
            _DEBUG("kill thread, pid is %lu", tp->threads[i].pid);
            pthread_kill(tp->threads[i].pid, SIGUSR1);
            if(pthread_join(tp->threads[i].pid, &status) != 0)
                _DEBUG("%m");
            pthread_mutex_destroy(&tp->threads[i].mutex);
            pthread_cond_destroy(&tp->threads[i].cond);
        } 
    }
        
    if (pthread_kill(tp->tp_manage_pid, 0) != ESRCH) {
            _DEBUG("kill manage thread, pid is %lu", tp->tp_manage_pid);
            pthread_kill(tp->tp_manage_pid, SIGUSR1);
            if(pthread_join(tp->tp_manage_pid, &status) != 0)
                _DEBUG("%m");
            pthread_mutex_destroy(&tp->mutex);
    }

    free(tp->threads);
    free(tp);

    return 0;
}


/**
 * @brief thread_pool_exaggerate 扩容线程池
 *
 * @param tp 线程池
 *
 * @return 扩容成功的数量
 */
INT32 thread_pool_exaggerate(thread_pool_info_t *tp)
{
    if (!tp || tp->cur >= tp->max) 
        return -1;

    UINT32 i;
    UINT32 exage = (tp->min < tp->max - tp->cur) ? tp->min : tp->max-tp->cur ;
    // tp->cur += exage;

    pthread_mutex_lock(&tp->mutex);

    /**
    thread_info_t *p = tp->threads;
    tp->threads = (thread_info_t *)realloc(tp->threads, sizeof(thread_info_t) * (tp->cur + exage));
    if (!tp->threads) {
        tp->threads = p;
        _ERROR("exaggerate thread pool failed, realloc failed(%m)");
        pthread_mutex_unlock(&tp->mutex);
        return -1;
    }
    */

    UINT32 old = tp->cur;
    UINT32 news = tp->cur + exage;
    for (i = old; i < news; i++) {
        pthread_mutex_init(&tp->threads[i].mutex, NULL);
        pthread_cond_init(&tp->threads[i].cond, NULL);

        tp->threads[i].is_busy = False;
        tp->threads[i].is_exit = False;
        tp->threads[i].is_wait = False;

        if (pthread_create(&tp->threads[i].pid, NULL, thread_pool_func, &tp->threads[i]) != 0) {
            _ERROR("Expansion thread pool failed, pthread create error(%m)");
            return (tp->cur - old);
        }
        _DEBUG("create thread success: pid = %lu", tp->threads[i].pid);
        tp->cur ++;
    } 

    // tp->cur = news;
    pthread_mutex_unlock(&tp->mutex);

    return (tp->cur - old);
}


/**
 * @brief thread_pool_get_use_rate 获取线程池的使用情况
 *
 * @param tp
 *
 * @return 成功: 线程池的使用率  失败: <0 
 */
float thread_pool_get_use_rate(thread_pool_info_t *tp)
{
    if(!tp)
        return -1.0;

    float use_rate = 0.0;
    UINT32 i = 0;

    UINT32 busy = 0;
    for (; i < tp->cur; i ++) {
        if (tp->threads[i].is_busy)
            busy ++;
    }
    use_rate = (float)busy / (float)tp->cur;
    _DEBUG("The thread pool use rate is %0.2f, cur thread number is %d", use_rate, tp->cur);

    return use_rate;
}



/**
 * @brief thread_pool_minify 释放线程池中的一些线程
 *
 * @param tp
 *
 * @return 成功:0 失败: <0 
 */
INT32 thread_pool_minify(thread_pool_info_t *tp)
{
    if (!tp) {
        _ERROR("minify thread pool failed, param is NULL");
        return -1;
    }

    if (tp->cur <= tp->min) {
        _DEBUG("thread pool cur thread number is min");
        return 0;
    }

    pthread_mutex_lock(&tp->mutex);
    /* max_num 为一次销毁线程的最大数量 */
    UINT32 max_num = tp->min < tp->cur - tp->min ? tp->min : tp->cur - tp->min; 
    UINT32 i = tp->cur - 1;
    void *status;
    for (; i >= 0; i--) {
        /* 如果该线程是忙碌状态，直接退出，所以一次销毁线程的数量可能为0，最大为max_num */
        pthread_mutex_lock(&tp->threads[i].mutex);
        if (tp->threads[i].is_busy) {
            pthread_mutex_unlock(&tp->threads[i].mutex);
            break;
        }
        if (pthread_kill(tp->threads[i].pid, 0) != ESRCH) {
            tp->threads[i].is_busy = True;
            tp->threads[i].is_exit = True;
            pthread_mutex_unlock(&tp->threads[i].mutex);

            // _DEBUG("kill thread, pid is %lu", tp->threads[i].pid);
            pthread_cond_signal(&tp->threads[i].cond);
            // pthread_kill(tp->threads[i].pid, SIGUSR1);
            if(pthread_join(tp->threads[i].pid, &status) != 0)
                _DEBUG("%m");
            pthread_mutex_destroy(&tp->threads[i].mutex);
            pthread_cond_destroy(&tp->threads[i].cond);
        } 

        tp->cur --;
        if(--max_num == 0)
            break;
    }
    pthread_mutex_unlock(&tp->mutex);

    return 0;
}

// 等待直到线程is_wait为True
#define TP_THREAD_IS_WAIT(tp, i) do {   \
    if (tp->threads[i].is_wait)         \
        break;                          \
    usleep(10000);                      \
} while(True)


/**
 * @brief thread_pool_process_job 给线程池分配任务
 *
 * @param tp  线程池
 * @param job 分配的工作任务函数
 * @param args 任务函数参数
 *
 * @return 成功:0 失败: <0
 */
INT32 thread_pool_process_job(thread_pool_info_t *tp, void* (*job)(void *), void *args)
{
    if (!tp || !job) {
        _ERROR("process job falied, param is NULL");
        return -1;
    }

    UINT32 i = 0;
    pthread_mutex_lock(&tp->mutex);
    for (; i < tp->cur; i ++) {
        pthread_mutex_lock(&tp->threads[i].mutex);
        if (!tp->threads[i].is_busy) {
            tp->threads[i].is_busy = True;
            pthread_mutex_unlock(&tp->threads[i].mutex);

            tp->threads[i].param = args; 
            tp->threads[i].thread_work = job;

            /* 这里要等待线程的is_wait为True, 因为可能我们调用此函数前，在初始化或扩容线程池的函数中所有线程还没创建完 */
            /* 我们已经判断该线程is_busy为False，理论上该线程is_wait是True, 但是如果线程还未创建完成的情况下，is_wait 为False */
            /* 因此可能出现pthread_cond_signal信号失效的情况，所以在这要加上TP_THREAD_IS_WAIT*/
            TP_THREAD_IS_WAIT(tp, i);
            pthread_cond_signal(&tp->threads[i].cond);
            _DEBUG("a job prepare, pid is %lu", tp->threads[i].pid);

            pthread_mutex_unlock(&tp->mutex);
            return 0;
        }
        else 
            pthread_mutex_unlock(&tp->threads[i].mutex);
    }
    pthread_mutex_unlock(&tp->mutex);

    _DEBUG("Expansion thread pool");

    if (tp->tp_exaggerate(tp) <= 0)
        return -1;

    pthread_mutex_lock(&tp->mutex);
    for (; i < tp->cur; i ++) {
        pthread_mutex_lock(&tp->threads[i].mutex);
        if (!tp->threads[i].is_busy) {
            tp->threads[i].is_busy = True;
            pthread_mutex_unlock(&tp->threads[i].mutex);

            tp->threads[i].param = args; 
            tp->threads[i].thread_work = job;

            TP_THREAD_IS_WAIT(tp, i);
            pthread_cond_signal(&tp->threads[i].cond);
            _DEBUG("a job prepare, pid is %lu", tp->threads[i].pid);
            break;
        }
    }
    pthread_mutex_unlock(&tp->mutex);

    return 0;
}



#define TEST 
#ifdef TEST
void* user_job(void* args)
{
    int a = *(int*)args;

    fprintf(stdout, "test job %d\n", a);
    sleep(4);

    return NULL;
}

void* user_job2(void* args)
{
    int a = *(int*)args;

    fprintf(stdout, "test job2 %d\n", a);
    sleep(2);

    return NULL;
}

void* user_job3(void* args)
{
    int a = *(int*)args;

    fprintf(stdout, "test job3 %d\n", a);
    sleep(8);

    return NULL;
}

void* user_job4(void* args)
{
    int a = *(int*)args;

    fprintf(stdout, "test job4 %d\n", a);
    sleep(12);

    return NULL;
}
int main()
{
    thread_pool_info_t *tp = NULL;

    tp = create_thread_pool(10, 100);
    tp->tp_init(tp);

    int a = 1;
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job3, &a);
    tp->tp_process_job(tp, user_job, &a);
    tp->tp_process_job(tp, user_job4, &a);
    tp->tp_process_job(tp, user_job4, &a);
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job, &a);
    tp->tp_process_job(tp, user_job3, &a);
    tp->tp_process_job(tp, user_job3, &a);
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job4, &a);


    sleep(5);
    tp->tp_process_job(tp, user_job, &a);
    tp->tp_process_job(tp, user_job3, &a);
    tp->tp_process_job(tp, user_job3, &a);
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job4, &a);
    sleep(4);
    tp->tp_process_job(tp, user_job, &a);
    tp->tp_process_job(tp, user_job3, &a);
    tp->tp_process_job(tp, user_job3, &a);
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job2, &a);
    tp->tp_process_job(tp, user_job4, &a);

    sleep(20);
    printf("cur : %d\n", tp->cur);
    tp->tp_destroy(tp);

    return 0;
}

#endif
