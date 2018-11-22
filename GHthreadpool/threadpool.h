#ifndef __THREAD_POOL_H_
#define __THREAD_POOL_H_ 
#include <pthread.h>


#define BOOL int
#define False (0)
#define True  (!(False))

typedef int          INT32;
typedef unsigned int UINT32;


typedef struct thread_pool_info_s thread_pool_info_t;
typedef struct thread_info_s thread_info_t;


struct thread_info_s {
    pthread_t pid;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    void* (*thread_work)(void *args);
    void *param;

    BOOL is_wait;
    BOOL is_busy;
    BOOL is_exit;
};

struct thread_pool_info_s {
    /* 初始化线程池 */
    INT32 (*tp_init)(thread_pool_info_t*);
    /* 销毁线程池 */
    INT32 (*tp_destroy)(thread_pool_info_t*);
    /* 将一个线程任务添加到线程池中 */
    INT32 (*tp_process_job)(thread_pool_info_t*, void* (*thread_callback_func)(void *), void *args);
    /* 通过线程id找到线程信息 */
    INT32 (*tp_get_thread_by_id)(pthread_t pid);
    /* 扩容线程池 */
    INT32 (*tp_exaggerate)(thread_pool_info_t*);
    /* 减小线程池 */
    INT32 (*tp_minify)(thread_pool_info_t*);
    /* 获取线程池当前时刻使用率 */
    float (*tp_get_use_rate)(thread_pool_info_t*);

    /* 管理线程id */
    pthread_t tp_manage_pid;
    /*线程池线程锁*/
    pthread_mutex_t mutex;

    UINT32 min;  // 最小线程数
    UINT32 max;  // 最大线程数
    UINT32 cur;  // 当前线程数

    thread_info_t *threads;
};



#endif
