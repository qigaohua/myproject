#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>



#include "workq.h"
#include "list.h"

#define logw(fmt, ...)   \
    fprintf(stderr, "%s:%d "fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__)


work_queue_t * workq_create(const char *workq_name, free_func_t func)
{
    work_queue_t *workq = NULL;

    workq = calloc(1, sizeof *workq);
    if (!workq) {
        logw("calloc failed !");
        return NULL;
    }

    if (workq_name)
        workq->name = strdup(workq_name);

    if (func)
        workq->free_args = func;

    workq->loop = 1;
    INIT_LIST_HEAD(&workq->wlist);
    pthread_mutex_init(&workq->mutex, NULL);
    pthread_cond_init(&workq->cond, NULL);

    return workq;
}


int workq_add(work_queue_t *wq, work_func_t func, void *args,
        size_t args_len, struct timeval *timeout)
{
    if (!wq || !func) {
        logw("why ? ? ?");
        return -1;
    }

    workr_t *wk = NULL;

    wk = calloc(1, sizeof *wk);
    if (!wk) {
        logw("calloc failed !");
        return -1;
    }

    wk->func = func;
    if (args_len) {
        wk->args = calloc(1, args_len);
        memcpy(wk->args, args, args_len);
    }
    wk->wq = wq;
    if (timeout) {
        wk->timeout.tv_sec = timeout->tv_sec;
        wk->timeout.tv_usec = timeout->tv_usec;
    }
    INIT_LIST_HEAD(&wk->entry);
    pthread_mutex_lock(&wq->mutex);
    list_add_tail(&wk->entry, &wq->wlist);
    pthread_mutex_unlock(&wq->mutex);

    return 0;
}



void workq_destory(work_queue_t *wq)
{
    if (!wq)
        return;

    if (wq->name)
        free(wq->name);

    workr_t *w, *n;
    list_for_each_entry_safe(w, n, &wq->wlist, entry) {
        if (w->args) {
            if (wq->free_args) {
                wq->free_args(w->args);
                continue;
            }
            free(w->args);
        }
    }
    pthread_mutex_destroy(&wq->mutex);
    pthread_cond_destroy(&wq->cond);
    free(wq);

}


void workq_del(work_queue_t *wq, workr_t *w)
{
    if (!wq || !w) {
        logw("why ? ? ?");
        return;
    }
    pthread_mutex_lock(&wq->mutex);
    list_del_init(&w->entry);
    pthread_mutex_unlock(&wq->mutex);
    if (w->args)
        free(w->args);
    free(w);
}


void * workq_thread(void *args)
{
    work_queue_t *wq = (work_queue_t *)args;

    workr_t *w, *n;
    while(wq->loop) {
        pthread_mutex_lock(&wq->mutex);
        list_for_each_entry_safe(w, n, &wq->wlist, entry) {
            pthread_mutex_unlock(&wq->mutex);
            if (w->func) {
                w->func(w->args);
            }
            workq_del(wq, w);
            pthread_mutex_lock(&wq->mutex);
        }

        pthread_cond_wait(&wq->cond, &wq->mutex);
        pthread_mutex_unlock(&wq->mutex);
    }

}


void workq_start(work_queue_t *wq)
{
    if (!wq)
        return;

    pthread_t pid;
    if (-1 == pthread_create(&pid, NULL, workq_thread, wq)) {
        logw("pthread create failed !");
        return ;
    }
}







#if 1

struct st {
    int a;
    char c;
};

void tttt(void *args)
{
    char *p = (char *)args;

    logw("%s", p);
}

void tttt2(void *args)
{
    struct st *s = (struct st *)args;

    logw(">>%d:%c", s->a, s->c);
}


int main(int argc, char *argv[])
{
    work_queue_t *wq = NULL;

    wq = workq_create("test_queue", NULL);

    int i = 0;
    for(;i < 10;i++) {
        workq_add(wq, tttt, "111111", 7, NULL);
    }

    workq_start(wq);

    while(1) {
        sleep(3);

        struct st tt = {1,'a'};
        workq_add(wq, tttt2, &tt, sizeof tt, NULL);
        pthread_cond_signal(&wq->cond);

        sleep(3);

        struct st tt2 = {2,'b'};
        workq_add(wq, tttt2, &tt2, sizeof tt, NULL);
        // pthread_cond_signal(&wq->cond);

        struct st tt3 = {3,'c'};
        workq_add(wq, tttt2, &tt3, sizeof tt, NULL);
        pthread_cond_signal(&wq->cond);

        sleep(3);

        struct st tt4 = {4,'d'};
        workq_add(wq, tttt2, &tt4, sizeof tt, NULL);
        pthread_cond_signal(&wq->cond);

        sleep(2);
        break;
    }

    workq_destory(wq);
    return 0;
}



#endif





