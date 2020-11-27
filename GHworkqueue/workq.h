#ifndef __WORK_Q_H_
#define __WORK_Q_H_


#include "list.h"

typedef void (*work_func_t)(void *args);
typedef void (*free_func_t)(void *args);

typedef struct workr {
    struct timeval timeout;
    void *args;
    work_func_t func;
    struct list_head entry;
    struct work_queue *wq;
} workr_t;

typedef struct work_queue {
    struct list_head wlist;
    int loop;
    char *name;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    free_func_t free_args;
} work_queue_t;


work_queue_t * workq_create(const char *workq_name, free_func_t func);
void workq_destory(work_queue_t *wq);
int  workq_add(work_queue_t *wq, work_func_t func, void *args,
        size_t args_len, struct timeval *timeout);
void workq_del(work_queue_t *wq, workr_t *w);
void workq_start(work_queue_t *wq);

#endif /* ifndef __WORK_Q_H_ */
