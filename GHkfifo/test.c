#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "kfifo.h"




#define _unused   __attribute__((__unused__))


struct t {
    unsigned char b;
    int a;
};
struct t tbuff[512];


// DECLARE_KFIFO(g_fifobuf, int, 16);
// DEFINE_KFIFO(g_fifobuf, int, 16);

// struct uc_kfifo g_fifobuf;

DECLARE_KFIFO_PTR(g_fifobuf, struct t);

void* write_thread(_unused void* arg) 
{
    struct t tw;
    int i;
    for (i = 0; i < 20; i++) {
        tw.a = i;
        tw.b = i * 10;
        if (kfifo_is_full(&g_fifobuf)) {
            struct t tx =  {0,0} ;
            kfifo_out(&g_fifobuf, &tx, 1);
            printf("discard %d, %d\n", tx.a, tx.b);
        }
        if (kfifo_in(&g_fifobuf, &tw, 1) == 1) {
            printf("write %d, %d\n", tw.a, tw.b);
        } else {
            printf("write fail\n");
        }
    }
    printf("write over\n");
    return NULL;
}

void* read_thread(_unused void* arg) 
{
    printf("read...\n");
    struct t tr;
    int i;
    for (i = 0; i < 8; i++) {
        if (kfifo_out(&g_fifobuf, &tr, 1) == 1)
            printf("read %d, %d\n", tr.a, tr.b);
    }
    return NULL;
}

int main() 
{
    // INIT_KFIFO(g_fifobuf);
    // kfifo_alloc(&g_fifobuf, 16);
    kfifo_init(&g_fifobuf, tbuff, 512 * sizeof(struct t));
    int n = kfifo_avail(&g_fifobuf);
    printf("hello kfifo, avail: %d\n", n);

    pthread_t r, w;
    pthread_create(&w, NULL, write_thread, NULL);
    printf("..............\n");
    pthread_create(&r, NULL, read_thread, NULL);
    pthread_join(r, NULL);
    pthread_create(&r, NULL, read_thread, NULL);
    pthread_join(r, NULL);
    pthread_join(w, NULL);

    printf("over\n");
    return 0;
}
