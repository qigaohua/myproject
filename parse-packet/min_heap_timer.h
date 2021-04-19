#ifndef __MIN_HEAP_TIMER_H__
#define __MIN_HEAP_TIMER_H__


#define MAX_INT    0x0fffffff
#define PARENT(i)       ((i)/(2))
#define LEFTCHILD(i)    ((i)*(2))
#define RIGHTCHILD(i)   (((i)*(2))+(1))

#define MULTI_PTHREAD

typedef struct heap_node_s {
    unsigned long time_ms;
    void *data;
} minheap_node_t ;

typedef int (*ProcessFunc)(void *);

typedef struct min_heap_s {
    minheap_node_t   *node_list ;
    int                  headindex ;
    int                  lastindex ;
    unsigned int        max_num   ;

    ProcessFunc ProcessMinHeapNodeData;

#ifdef MULTI_PTHREAD
    pthread_mutex_t mutex;
    pthread_cond_t cond;
#endif
} minheap_t;

enum minheaptimer_cmd {
    CMD_OFF = 0,
    CMD_EXIT,
    CMD_HAVE_DATA,
    CMD_ADD_NODE,
};



minheap_t *MinHeapInit(unsigned int node_num, ProcessFunc func);
void MinHeapDestroy(minheap_t *mp);
int MinHeapAddNode(minheap_t *mp, void *data, unsigned long time_ms);
int MinHeapDelNode(minheap_t *mp, void **data, unsigned long *time_ms);
int MinHeapTimerIsWait();
int TellMinHeapTimer(enum minheaptimer_cmd cmd);
int MinHeapTimerLoop(minheap_t *mp);




#endif
